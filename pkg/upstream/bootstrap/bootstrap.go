/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	minimumUpdateInterval = time.Minute * 5
	retryInterval         = time.Second * 2
	queryTimeout          = time.Second * 5
	dualStackPublishDelay = time.Millisecond * 250
	DualStackVersion      = 46
)

var (
	errNoAddrInResp = errors.New("resp does not have ip address")
)

func New(
	host string,
	port uint16,
	bootstrapServer netip.AddrPort,
	bootstrapVer int, // 0,4,6,46
	logger *zap.Logger, // not nil
) (*Bootstrap, error) {
	dp := new(Bootstrap)
	dp.fqdn = dns.Fqdn(host)
	dp.port = port
	if !bootstrapServer.IsValid() {
		return nil, errors.New("invalid bootstrap server address")
	}
	dp.bootstrap = net.UDPAddrFromAddrPort(bootstrapServer)
	qts, ok := bootstrapVer2Qts(bootstrapVer)
	if !ok {
		return nil, fmt.Errorf("invalid bootstrap version %d", bootstrapVer)
	}
	dp.qts = qts
	dp.logger = logger

	dp.readyNotify = make(chan struct{})
	return dp, nil
}

type Bootstrap struct {
	fqdn      string
	port      uint16
	bootstrap *net.UDPAddr
	qts       []uint16
	logger    *zap.Logger // not nil

	updating   atomic.Bool
	nextUpdate time.Time

	readyNotify chan struct{}
	m           sync.Mutex
	ready       bool
	addrStrs    []string
	nextAddr    int
}

func (sp *Bootstrap) GetAddrPortStr(ctx context.Context) (string, error) {
	addrs, err := sp.GetAddrPortStrs(ctx)
	if err != nil {
		return "", err
	}
	return addrs[0], nil
}

func (sp *Bootstrap) GetAddrPortStrs(ctx context.Context) ([]string, error) {
	sp.tryUpdate()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-sp.readyNotify:
	}

	sp.m.Lock()
	start := sp.nextAddr % len(sp.addrStrs)
	addrs := make([]string, 0, len(sp.addrStrs))
	addrs = append(addrs, sp.addrStrs[start:]...)
	addrs = append(addrs, sp.addrStrs[:start]...)
	sp.nextAddr = (sp.nextAddr + 1) % len(sp.addrStrs)
	sp.m.Unlock()
	return addrs, nil
}

func (sp *Bootstrap) tryUpdate() {
	if sp.updating.CompareAndSwap(false, true) {
		if time.Now().After(sp.nextUpdate) {
			go func() {
				defer sp.updating.Store(false)
				ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
				defer cancel()
				start := time.Now()
				addrs, ttl, complete, err := sp.updateAddr(ctx)
				if err != nil {
					sp.logger.Check(zap.WarnLevel, "failed to update bootstrap addr").Write(
						zap.String("fqdn", sp.fqdn),
						zap.Error(err),
					)
					sp.nextUpdate = time.Now().Add(retryInterval)
				} else if !complete {
					sp.nextUpdate = time.Now().Add(retryInterval)
				} else {
					updateInterval := time.Second * time.Duration(ttl)
					if updateInterval < minimumUpdateInterval {
						updateInterval = minimumUpdateInterval
					}
					sp.logger.Check(zap.DebugLevel, "bootstrap addr updated").Write(
						zap.String("fqdn", sp.fqdn),
						zap.Stringers("addrs", addrs),
						zap.Duration("ttl", updateInterval),
						zap.Duration("elapse", time.Since(start)),
					)
					sp.nextUpdate = time.Now().Add(updateInterval)
				}
			}()
		} else {
			sp.updating.Store(false)
		}
	}
}

func (sp *Bootstrap) updateAddr(ctx context.Context) ([]netip.Addr, uint32, bool, error) {
	addrs, ttl, complete, err := sp.resolveAll(ctx, sp.storeAddrs)
	if err != nil {
		return nil, 0, complete, err
	}
	return addrs, ttl, complete, nil
}

func (sp *Bootstrap) storeAddrs(addrs []netip.Addr, _ uint32) {
	addrStrs := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addrStrs = append(addrStrs, netip.AddrPortFrom(addr, sp.port).String())
	}
	sp.m.Lock()
	sp.addrStrs = addrStrs
	sp.nextAddr = 0
	if !sp.ready {
		sp.ready = true
		close(sp.readyNotify)
	}
	sp.m.Unlock()
}

func (sp *Bootstrap) resolveAll(ctx context.Context, publish func([]netip.Addr, uint32)) ([]netip.Addr, uint32, bool, error) {
	type result struct {
		index int
		addrs []netip.Addr
		ttl   uint32
		err   error
	}
	resolveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, len(sp.qts))
	for i, qt := range sp.qts {
		go func(index int, qtype uint16) {
			addrs, ttl, err := sp.resolve(resolveCtx, qtype)
			results <- result{index: index, addrs: addrs, ttl: ttl, err: err}
		}(i, qt)
	}

	ordered := make([]result, len(sp.qts))
	received := make([]bool, len(sp.qts))
	merge := func() ([]netip.Addr, uint32, error) {
		var addrs []netip.Addr
		var errs []error
		var ttl uint32
		ttlSet := false
		for i, result := range ordered {
			if !received[i] {
				continue
			}
			if result.err != nil {
				errs = append(errs, fmt.Errorf("%s lookup: %w", dns.TypeToString[sp.qts[i]], result.err))
			}
			if len(result.addrs) > 0 && (!ttlSet || result.ttl < ttl) {
				ttl = result.ttl
				ttlSet = true
			}
		}
		seen := make(map[netip.Addr]struct{})
		for index := 0; ; index++ {
			added := false
			for i, result := range ordered {
				if !received[i] || index >= len(result.addrs) {
					continue
				}
				added = true
				addr := result.addrs[index]
				if _, exists := seen[addr]; exists {
					continue
				}
				seen[addr] = struct{}{}
				addrs = append(addrs, addr)
			}
			if !added {
				break
			}
		}
		if len(addrs) == 0 {
			return nil, 0, errors.Join(errs...)
		}
		return addrs, ttl, nil
	}
	completed := 0
	published := false
	var publishTimer <-chan time.Time
	for completed < len(sp.qts) {
		select {
		case <-ctx.Done():
			addrs, ttl, err := merge()
			if len(addrs) > 0 {
				if !published {
					publish(addrs, ttl)
				}
				return addrs, ttl, false, nil
			}
			return nil, 0, false, errors.Join(err, context.Cause(ctx))
		case <-publishTimer:
			addrs, ttl, _ := merge()
			publish(addrs, ttl)
			published = true
			publishTimer = nil
		case result := <-results:
			ordered[result.index] = result
			received[result.index] = true
			completed++
			if len(result.addrs) > 0 {
				if completed == len(sp.qts) || published {
					addrs, ttl, _ := merge()
					publish(addrs, ttl)
					published = true
				} else if publishTimer == nil {
					publishTimer = time.After(dualStackPublishDelay)
				}
			}
		}
	}
	addrs, ttl, err := merge()
	if len(addrs) > 0 && !published {
		publish(addrs, ttl)
	}
	return addrs, ttl, true, err
}

func (sp *Bootstrap) resolve(ctx context.Context, qt uint16) ([]netip.Addr, uint32, error) {
	const edns0UdpSize = 1200

	q := new(dns.Msg)
	q.SetQuestion(sp.fqdn, qt)
	q.SetEdns0(edns0UdpSize, false)

	c, err := net.DialUDP("udp", nil, sp.bootstrap)
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()

	writeErrC := make(chan error, 1)
	type res struct {
		resp *dns.Msg
		err  error
	}
	readResC := make(chan res, 1)

	cancelWrite := make(chan struct{})
	defer close(cancelWrite)
	go func() {
		if _, err := dnsutils.WriteMsgToUDP(c, q); err != nil {
			writeErrC <- err
			return
		}

		retryTicker := time.NewTicker(time.Second)
		defer retryTicker.Stop()
		for {
			select {
			case <-cancelWrite:
				return
			case <-retryTicker.C:
				if _, err := dnsutils.WriteMsgToUDP(c, q); err != nil {
					writeErrC <- err
					return
				}
			}
		}
	}()

	go func() {
		m, _, err := dnsutils.ReadMsgFromUDP(c, edns0UdpSize)
		readResC <- res{resp: m, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, 0, context.Cause(ctx)
	case err := <-writeErrC:
		return nil, 0, fmt.Errorf("failed to write query, %w", err)
	case r := <-readResC:
		resp := r.resp
		err := r.err
		if err != nil {
			return nil, 0, fmt.Errorf("failed to read resp, %w", err)
		}
		if !resp.Response || resp.Id != q.Id || resp.Opcode != dns.OpcodeQuery || resp.Rcode != dns.RcodeSuccess || resp.Truncated || len(resp.Question) != 1 || !strings.EqualFold(resp.Question[0].Name, q.Question[0].Name) || resp.Question[0].Qtype != qt || resp.Question[0].Qclass != dns.ClassINET {
			return nil, 0, errors.New("invalid bootstrap response")
		}

		var addrs []netip.Addr
		var minTTL uint32
		ttlSet := false
		allowedNames := map[string]struct{}{strings.ToLower(dns.Fqdn(sp.fqdn)): {}}
		for changed := true; changed; {
			changed = false
			for _, answer := range resp.Answer {
				cname, ok := answer.(*dns.CNAME)
				if !ok || cname.Hdr.Class != dns.ClassINET {
					continue
				}
				if _, allowed := allowedNames[strings.ToLower(dns.Fqdn(cname.Hdr.Name))]; !allowed {
					continue
				}
				target := strings.ToLower(dns.Fqdn(cname.Target))
				if _, exists := allowedNames[target]; !exists {
					allowedNames[target] = struct{}{}
					changed = true
				}
				if !ttlSet || cname.Hdr.Ttl < minTTL {
					minTTL = cname.Hdr.Ttl
					ttlSet = true
				}
			}
		}
		for _, v := range resp.Answer {
			if v.Header().Class != dns.ClassINET {
				continue
			}
			if _, allowed := allowedNames[strings.ToLower(dns.Fqdn(v.Header().Name))]; !allowed {
				continue
			}
			var ip net.IP
			var ttl uint32
			switch rr := v.(type) {
			case *dns.A:
				if qt != dns.TypeA {
					continue
				}
				ip = rr.A
				ttl = rr.Hdr.Ttl
			case *dns.AAAA:
				if qt != dns.TypeAAAA {
					continue
				}
				ip = rr.AAAA
				ttl = rr.Hdr.Ttl
			default:
				continue
			}
			addr, ok := netip.AddrFromSlice(ip)
			if ok {
				addrs = append(addrs, addr.Unmap())
				if !ttlSet || ttl < minTTL {
					minTTL = ttl
					ttlSet = true
				}
			}
		}
		if len(addrs) == 0 {
			return nil, 0, errNoAddrInResp
		}
		return addrs, minTTL, nil
	}
}

func bootstrapVer2Qts(ver int) ([]uint16, bool) {
	switch ver {
	case 0, 4:
		return []uint16{dns.TypeA}, true
	case 6:
		return []uint16{dns.TypeAAAA}, true
	case DualStackVersion:
		return []uint16{dns.TypeA, dns.TypeAAAA}, true
	default:
		return nil, false
	}
}
