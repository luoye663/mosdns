// Package dynamic_forward provides reusable upstream group runtimes.
package dynamic_forward

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	fastforward "github.com/IrineSistiana/mosdns/v5/plugin/executable/forward"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

var tagPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

const (
	maxConcurrentQueries = 16
	maxUpstreams         = 16
	defaultTimeoutMS     = 1000
	minimumTimeoutMS     = 100
	maximumTimeoutMS     = 4000
)

type Upstream struct {
	Tag       string `json:"tag" yaml:"tag"`
	Addr      string `json:"addr" yaml:"addr"`
	Priority  int    `json:"priority" yaml:"priority"`
	Weight    int    `json:"weight" yaml:"weight"`
	TimeoutMS int    `json:"timeout_ms" yaml:"timeout_ms"`
}

type RuntimeConfig struct {
	Mode       string
	Concurrent int
	Socks5     string
	Upstreams  []Upstream
}

func CanonicalRuntimeConfig(config RuntimeConfig) (RuntimeConfig, error) {
	if config.Concurrent < 1 || config.Concurrent > maxConcurrentQueries {
		return RuntimeConfig{}, errors.New("concurrent must be within 1..16")
	}
	if config.Mode == "" {
		config.Mode = "race"
	}
	if config.Mode != "race" && config.Mode != "weighted" && config.Mode != "failover" {
		return RuntimeConfig{}, errors.New("mode must be race, weighted or failover")
	}
	if len(config.Upstreams) < 1 || len(config.Upstreams) > maxUpstreams {
		return RuntimeConfig{}, errors.New("upstreams must contain 1..16 entries")
	}
	config.Socks5 = strings.TrimSpace(config.Socks5)
	config.Upstreams = append([]Upstream(nil), config.Upstreams...)
	seen := make(map[string]struct{}, len(config.Upstreams))
	for i := range config.Upstreams {
		item := &config.Upstreams[i]
		item.Tag, item.Addr = strings.TrimSpace(item.Tag), strings.TrimSpace(item.Addr)
		if !strings.Contains(item.Addr, "://") {
			if ip, err := netip.ParseAddr(item.Addr); err == nil && ip.Is6() {
				item.Addr = "udp://[" + ip.String() + "]"
			} else {
				item.Addr = "udp://" + item.Addr
			}
		}
		if item.Priority == 0 {
			item.Priority = 100
		}
		if item.Weight == 0 {
			item.Weight = 1
		}
		if item.TimeoutMS == 0 {
			item.TimeoutMS = defaultTimeoutMS
		}
		if item.Priority < 1 || item.Priority > 1000 {
			return RuntimeConfig{}, fmt.Errorf("upstream %d priority must be within 1..1000", i+1)
		}
		if item.Weight < 1 || item.Weight > 100 {
			return RuntimeConfig{}, fmt.Errorf("upstream %d weight must be within 1..100", i+1)
		}
		if item.TimeoutMS < minimumTimeoutMS || item.TimeoutMS > maximumTimeoutMS {
			return RuntimeConfig{}, fmt.Errorf("upstream %d timeout_ms must be within 100..4000", i+1)
		}
		if !tagPattern.MatchString(item.Tag) {
			return RuntimeConfig{}, fmt.Errorf("upstream %d has an invalid tag", i+1)
		}
		if _, exists := seen[item.Tag]; exists {
			return RuntimeConfig{}, errors.New("upstream tags must be unique")
		}
		seen[item.Tag] = struct{}{}
		parsed, err := url.ParseRequestURI(item.Addr)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return RuntimeConfig{}, fmt.Errorf("upstream %d address must be a valid [protocol://]host[:port][/path]", i+1)
		}
		switch parsed.Scheme {
		case "https", "tls", "tcp", "udp", "quic":
		default:
			return RuntimeConfig{}, fmt.Errorf("upstream %d uses an unsupported scheme", i+1)
		}
	}
	return config, nil
}

type Runtime struct {
	forward *fastforward.Forward
	mode    string
	count   int
	items   []Upstream
	levels  [][]string
}

func NewRuntime(mode string, concurrent int, socks5 string, upstreams []Upstream, logger *zap.Logger, metricsTag string) (*Runtime, error) {
	config, err := CanonicalRuntimeConfig(RuntimeConfig{Mode: mode, Concurrent: concurrent, Socks5: socks5, Upstreams: upstreams})
	if err != nil {
		return nil, err
	}
	forward, err := fastforward.NewForward(&fastforward.Args{Concurrent: config.Concurrent, Socks5: config.Socks5, Upstreams: forwardUpstreams(config.Upstreams)}, fastforward.Opts{Logger: logger, MetricsTag: metricsTag})
	if err != nil {
		return nil, errors.New("invalid upstream configuration")
	}
	return &Runtime{forward: forward, mode: config.Mode, count: config.Concurrent, items: config.Upstreams, levels: priorityLevels(config.Upstreams)}, nil
}

func (r *Runtime) Exec(ctx context.Context, qCtx *query_context.Context) error {
	switch r.mode {
	case "weighted":
		accepted, err := r.execCandidates(ctx, qCtx, weightedTags(r.items, len(r.items)))
		if accepted || qCtx.R() != nil {
			return nil
		}
		return err
	case "failover":
		var lastErr error
		for _, level := range r.levels {
			candidates := append([]string(nil), level...)
			rand.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })
			accepted, err := r.execCandidates(ctx, qCtx, candidates)
			if accepted {
				return nil
			}
			if err != nil {
				lastErr = err
			}
		}
		if qCtx.R() != nil {
			return nil
		}
		return lastErr
	default:
		return r.forward.ExecAll(ctx, qCtx)
	}
}

func (r *Runtime) execCandidates(ctx context.Context, qCtx *query_context.Context, candidates []string) (bool, error) {
	var lastErr error
	for start := 0; start < len(candidates); start += r.count {
		if err := context.Cause(ctx); err != nil {
			return false, err
		}
		end := min(start+r.count, len(candidates))
		if err := r.forward.ExecWithTags(ctx, qCtx, candidates[start:end]); err != nil {
			lastErr = err
			continue
		}
		response := qCtx.R()
		if response == nil || (response.Rcode != dns.RcodeServerFailure && response.Rcode != dns.RcodeRefused) {
			return true, nil
		}
	}
	return false, lastErr
}

func (r *Runtime) Close() error { return r.forward.Close() }

func forwardUpstreams(items []Upstream) []fastforward.UpstreamConfig {
	result := make([]fastforward.UpstreamConfig, 0, len(items))
	for _, item := range items {
		result = append(result, fastforward.UpstreamConfig{Tag: item.Tag, Addr: item.Addr, QueryTimeout: time.Duration(item.TimeoutMS) * time.Millisecond})
	}
	return result
}

func priorityLevels(upstreams []Upstream) [][]string {
	byPriority := make(map[int][]string)
	priorities := make([]int, 0, len(upstreams))
	for _, upstream := range upstreams {
		if _, exists := byPriority[upstream.Priority]; !exists {
			priorities = append(priorities, upstream.Priority)
		}
		byPriority[upstream.Priority] = append(byPriority[upstream.Priority], upstream.Tag)
	}
	sort.Ints(priorities)
	levels := make([][]string, 0, len(priorities))
	for _, priority := range priorities {
		levels = append(levels, byPriority[priority])
	}
	return levels
}

func weightedTags(upstreams []Upstream, count int) []string {
	available := append([]Upstream(nil), upstreams...)
	selected := make([]string, 0, count)
	for len(available) > 0 && len(selected) < count {
		total := 0
		for _, upstream := range available {
			total += upstream.Weight
		}
		choice := rand.IntN(total)
		for index, upstream := range available {
			choice -= upstream.Weight
			if choice < 0 {
				selected = append(selected, upstream.Tag)
				available = append(available[:index], available[index+1:]...)
				break
			}
		}
	}
	return selected
}
