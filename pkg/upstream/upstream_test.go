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

package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
)

func newUDPTestServer(t testing.TB, handler dns.Handler) (addr string, shutdownFunc func()) {
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpAddr := udpConn.LocalAddr().String()
	udpServer := dns.Server{
		PacketConn: udpConn,
		Handler:    handler,
	}
	go udpServer.ActivateAndServe()
	return udpAddr, func() {
		udpServer.Shutdown()
	}
}

func newTCPTestServer(t testing.TB, handler dns.Handler) (addr string, shutdownFunc func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := l.Addr().String()
	tcpServer := dns.Server{
		Listener:      l,
		Handler:       handler,
		MaxTCPQueries: -1,
	}
	go tcpServer.ActivateAndServe()
	return tcpAddr, func() {
		tcpServer.Shutdown()
	}
}

func newDoTTestServer(t testing.TB, handler dns.Handler) (addr string, shutdownFunc func()) {
	serverName := "test"
	cert, err := utils.GenerateCertificate(serverName)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := new(tls.Config)
	tlsConfig.Certificates = []tls.Certificate{cert}
	tlsListener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	doTAddr := tlsListener.Addr().String()
	doTServer := dns.Server{
		Net:           "tcp-tls",
		Listener:      tlsListener,
		TLSConfig:     tlsConfig,
		Handler:       handler,
		MaxTCPQueries: -1,
	}
	go doTServer.ActivateAndServe()
	return doTAddr, func() {
		doTServer.Shutdown()
	}
}

type newTestServerFunc func(t testing.TB, handler dns.Handler) (addr string, shutdownFunc func())

var m = map[string]newTestServerFunc{
	"udp": newUDPTestServer,
	"tcp": newTCPTestServer,
	"tls": newDoTTestServer,
}

func Test_fastUpstream(t *testing.T) {

	// TODO: add test for doh
	// TODO: add test for socks5

	// server config
	for scheme, f := range m {
		for _, bigMsg := range [...]bool{true, false} {
			for _, latency := range [...]time.Duration{0, time.Millisecond * 10} {

				// client specific
				for _, idleTimeout := range [...]time.Duration{0, time.Second} {

					testName := fmt.Sprintf(
						"test: protocol: %s, bigMsg: %v, latency: %s, getIdleTimeout: %s",
						scheme,
						bigMsg,
						latency,
						idleTimeout,
					)

					t.Run(testName, func(t *testing.T) {
						addr, shutdownServer := f(t, &vServer{
							latency: latency,
							bigMsg:  bigMsg,
						})
						defer shutdownServer()
						u, err := NewUpstream(
							scheme+"://"+addr,
							Opt{
								IdleTimeout: time.Second,
								TLSConfig:   &tls.Config{InsecureSkipVerify: true},
							},
						)
						if err != nil {
							t.Fatal(err)
						}

						if err := testUpstream(u); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		}

	}
}

func TestHostnameUpstreamsUseBootstrap(t *testing.T) {
	var bootstrapQueries atomic.Int32
	bootstrapAddr, shutdownBootstrap := newUDPTestServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		bootstrapQueries.Add(1)
		response := new(dns.Msg)
		response.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")}}
		}
		_ = w.WriteMsg(response)
	}))
	defer shutdownBootstrap()

	for _, scheme := range []string{"udp", "tcp", "tls"} {
		t.Run(scheme, func(t *testing.T) {
			addr, shutdownTarget := m[scheme](t, &vServer{})
			defer shutdownTarget()
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatal(err)
			}
			u, err := NewUpstream(scheme+"://bootstrap-target.invalid:"+port, Opt{Bootstrap: bootstrapAddr, BootstrapVer: 46, TLSConfig: &tls.Config{InsecureSkipVerify: true}})
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			if err := testUpstream(u); err != nil {
				t.Fatal(err)
			}
		})
	}
	if bootstrapQueries.Load() < 6 {
		t.Fatalf("bootstrap received %d queries, want A and AAAA for every protocol", bootstrapQueries.Load())
	}
}

func TestDualStackBootstrapFallsBackWithinSameExchange(t *testing.T) {
	bootstrapAddr, shutdownBootstrap := newUDPTestServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(q)
		switch q.Question[0].Qtype {
		case dns.TypeA:
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.2")}}
		case dns.TypeAAAA:
			response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("::1")}}
		}
		_ = w.WriteMsg(response)
	}))
	defer shutdownBootstrap()

	for _, scheme := range []string{"udp", "tcp"} {
		t.Run(scheme, func(t *testing.T) {
			var server dns.Server
			var addr string
			if scheme == "udp" {
				conn, err := net.ListenPacket("udp6", "[::1]:0")
				if err != nil {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				addr = conn.LocalAddr().String()
				server = dns.Server{PacketConn: conn, Handler: &vServer{}}
			} else {
				listener, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				addr = listener.Addr().String()
				server = dns.Server{Listener: listener, Handler: &vServer{}, MaxTCPQueries: -1}
			}
			go func() { _ = server.ActivateAndServe() }()
			defer server.Shutdown()
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatal(err)
			}
			u, err := NewUpstream(scheme+"://dual-stack-target.invalid:"+port, Opt{Bootstrap: bootstrapAddr, BootstrapVer: 46})
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)
			payload, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			response, err := u.ExchangeContext(ctx, payload)
			if err != nil {
				t.Fatal(err)
			}
			if response == nil {
				t.Fatal("empty DNS response")
			}
		})
	}
}

func testUpstream(u Upstream) error {
	wg := sync.WaitGroup{}
	errs := make([]error, 0)
	errsLock := sync.Mutex{}
	logErr := func(err error) {
		errsLock.Lock()
		errs = append(errs, err)
		errsLock.Unlock()
	}
	errsToString := func() string {
		s := fmt.Sprintf("%d err(s) occured during the test: ", len(errs))
		for i := range errs {
			s = s + errs[i].Error() + "|"
		}
		return s
	}

	for i := uint16(0); i < 10; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()

			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			q.Id = i
			queryPayload, err := q.Pack()
			if err != nil {
				logErr(err)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r, err := u.ExchangeContext(ctx, queryPayload)
			if err != nil {
				logErr(err)
				return
			}

			resp := new(dns.Msg)
			err = resp.Unpack(*r)
			if err != nil {
				logErr(err)
				return
			}
			if q.Id != resp.Id {
				logErr(dns.ErrId)
				return
			}
			if !resp.Response {
				logErr(fmt.Errorf("resp is not a resp bit"))
				return
			}
		}()
	}

	wg.Wait()
	if len(errs) != 0 {
		return errors.New(errsToString())
	}
	return nil
}

type vServer struct {
	latency time.Duration
	bigMsg  bool // with 1kb padding
}

var padding = make([]byte, 1024)

func (s *vServer) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	r := new(dns.Msg)
	r.SetReply(q)
	if s.bigMsg {
		r.SetEdns0(dns.MaxMsgSize, false)
		opt := r.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: padding})
	}

	time.Sleep(s.latency)
	w.WriteMsg(r)
}
