package upstream

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	upstreambootstrap "github.com/IrineSistiana/mosdns/v5/pkg/upstream/bootstrap"
	"go.uber.org/zap"
)

const dualStackDialDelay = 250 * time.Millisecond

type dualStackBootstrapUpstream struct {
	addr      string
	opt       Opt
	resolver  *upstreambootstrap.Bootstrap
	mu        sync.Mutex
	children  map[string]*dualStackChild
	preferred string
	closed    bool
}

type dualStackChild struct {
	upstream Upstream
	refs     int
	stale    bool
}

type dualStackCandidate struct {
	addr  string
	child *dualStackChild
}

func maybeNewDualStackBootstrapUpstream(addr, scheme, urlHost string, bootstrapServer netip.AddrPort, opt Opt) (Upstream, bool, error) {
	if opt.BootstrapVer != upstreambootstrap.DualStackVersion || !bootstrapServer.IsValid() {
		return nil, false, nil
	}
	defaultPort, ok := map[string]uint16{"": 53, "udp": 53, "tcp": 53, "tls": 853, "https": 443, "quic": 853, "doq": 853}[scheme]
	if !ok {
		return nil, false, nil
	}
	host, port, err := parseDialAddr(urlHost, opt.DialAddr, defaultPort)
	if err != nil {
		return nil, true, err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, false, nil
	}
	resolver, err := upstreambootstrap.New(host, port, bootstrapServer, upstreambootstrap.DualStackVersion, opt.Logger)
	if err != nil {
		return nil, true, err
	}
	childOpt := opt
	childOpt.Bootstrap = ""
	childOpt.BootstrapVer = 0
	childOpt.DialAddr = ""
	return &dualStackBootstrapUpstream{addr: addr, opt: childOpt, resolver: resolver, children: make(map[string]*dualStackChild)}, true, nil
}

func (u *dualStackBootstrapUpstream) candidates(ctx context.Context) ([]dualStackCandidate, []error) {
	addrs, err := u.resolver.GetAddrPortStrs(ctx)
	if err != nil {
		return nil, []error{err}
	}
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil, []error{errors.New("upstream is closed")}
	}
	if u.preferred != "" {
		for i, addr := range addrs {
			if addr == u.preferred {
				addrs[0], addrs[i] = addrs[i], addrs[0]
				break
			}
		}
	}
	current := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		current[addr] = struct{}{}
	}
	var stale []Upstream
	for addr, child := range u.children {
		_, exists := current[addr]
		child.stale = !exists
		if child.stale && child.refs == 0 {
			delete(u.children, addr)
			stale = append(stale, child.upstream)
		}
	}
	if _, exists := current[u.preferred]; !exists {
		u.preferred = ""
	}
	candidates := make([]dualStackCandidate, 0, len(addrs))
	var errs []error
	for _, addr := range addrs {
		child := u.children[addr]
		if child == nil {
			childOpt := u.opt
			childOpt.DialAddr = addr
			upstream, err := NewUpstream(u.addr, childOpt)
			if err != nil {
				errs = append(errs, fmt.Errorf("initialize bootstrap candidate %s: %w", addr, err))
				continue
			}
			child = &dualStackChild{upstream: upstream}
			u.children[addr] = child
		}
		child.refs++
		candidates = append(candidates, dualStackCandidate{addr: addr, child: child})
	}
	u.mu.Unlock()
	u.closeStale(stale)
	return candidates, errs
}

func (u *dualStackBootstrapUpstream) closeStale(children []Upstream) {
	for _, child := range children {
		if err := child.Close(); err != nil {
			u.opt.Logger.Warn("failed to close stale bootstrap candidate", zap.Error(err))
		}
	}
}

func (u *dualStackBootstrapUpstream) release(candidates []dualStackCandidate) {
	var stale []Upstream
	u.mu.Lock()
	for _, candidate := range candidates {
		candidate.child.refs--
		if candidate.child.refs == 0 && candidate.child.stale {
			if current := u.children[candidate.addr]; current == candidate.child {
				delete(u.children, candidate.addr)
				stale = append(stale, candidate.child.upstream)
			}
		}
	}
	u.mu.Unlock()
	u.closeStale(stale)
}

func (u *dualStackBootstrapUpstream) ExchangeContext(ctx context.Context, query []byte) (*[]byte, error) {
	candidates, errs := u.candidates(ctx)
	if len(candidates) == 0 {
		return nil, errors.Join(errs...)
	}
	type result struct {
		addr     string
		response *[]byte
		err      error
	}
	racingCtx, cancel := context.WithCancel(ctx)
	results := make(chan result, len(candidates))
	kick := make(chan struct{})
	var kickOnce sync.Once
	var workers sync.WaitGroup
	for i, candidate := range candidates {
		workers.Add(1)
		go func(index int, candidate dualStackCandidate) {
			defer workers.Done()
			if index > 0 {
				timer := time.NewTimer(time.Duration(index) * dualStackDialDelay)
				defer timer.Stop()
				select {
				case <-racingCtx.Done():
					return
				case <-kick:
				case <-timer.C:
				}
			}
			response, err := candidate.child.upstream.ExchangeContext(racingCtx, query)
			if err != nil {
				kickOnce.Do(func() { close(kick) })
			}
			results <- result{addr: candidate.addr, response: response, err: err}
		}(i, candidate)
	}

	var selected *result
	defer func() {
		cancel()
		workers.Wait()
		close(results)
		for result := range results {
			if result.response != nil && (selected == nil || result.response != selected.response) {
				pool.ReleaseBuf(result.response)
			}
		}
		u.release(candidates)
	}()
	for range candidates {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case result := <-results:
			if result.err != nil {
				if result.response != nil {
					pool.ReleaseBuf(result.response)
				}
				errs = append(errs, fmt.Errorf("bootstrap candidate %s: %w", result.addr, result.err))
				continue
			}
			if result.response == nil {
				kickOnce.Do(func() { close(kick) })
				errs = append(errs, fmt.Errorf("bootstrap candidate %s returned an empty response", result.addr))
				continue
			}
			selected = &result
			u.mu.Lock()
			u.preferred = result.addr
			u.mu.Unlock()
			return result.response, nil
		}
	}
	return nil, errors.Join(errs...)
}

func (u *dualStackBootstrapUpstream) Close() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	children := make([]Upstream, 0, len(u.children))
	for _, child := range u.children {
		children = append(children, child.upstream)
	}
	u.children = make(map[string]*dualStackChild)
	u.mu.Unlock()
	var errs []error
	for _, child := range children {
		errs = append(errs, child.Close())
	}
	return errors.Join(errs...)
}
