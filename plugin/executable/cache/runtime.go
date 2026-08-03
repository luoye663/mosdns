package cache

import (
	"context"
	"errors"
	"sync"

	cachepkg "github.com/IrineSistiana/mosdns/v5/pkg/cache"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	fastforward "github.com/IrineSistiana/mosdns/v5/plugin/executable/forward"
	"github.com/miekg/dns"
)

// RuntimeConfig is the bounded cache policy used by composed runtimes.
type RuntimeConfig struct {
	Enabled            bool
	Size               int
	LazyCacheTTL       int
	NegativeEnabled    bool
	NegativeTTLSeconds uint32
}

// Runtime is a cache instance without plugin API or dump lifecycle.
type Runtime struct {
	config     RuntimeConfig
	backend    *cachepkg.Cache[key, *item]
	mu         sync.Mutex
	generation uint64
	refreshing map[string]struct{}
	closed     bool
	wg         sync.WaitGroup
}

func NewRuntime(config RuntimeConfig) (*Runtime, error) {
	if config.Size < 1 {
		return nil, errors.New("cache size must be positive")
	}
	if config.LazyCacheTTL < 0 || config.LazyCacheTTL > 604800 {
		return nil, errors.New("lazy_cache_ttl must be within 0..604800")
	}
	if config.NegativeTTLSeconds < 1 || config.NegativeTTLSeconds > maxNegativeCacheTTL {
		return nil, errors.New("negative cache ttl_seconds must be within 1..86400")
	}
	return &Runtime{config: config, backend: cachepkg.New[key, *item](cachepkg.Opts{Size: config.Size}), refreshing: make(map[string]struct{})}, nil
}

// Exec performs lookup, optional lazy refresh, and store around forward.
func (r *Runtime) Exec(ctx context.Context, qCtx *query_context.Context, forward func(context.Context, *query_context.Context) error) (bool, string, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return false, "", errors.New("cache runtime is closed")
	}
	r.wg.Add(1)
	generation := r.generation
	r.mu.Unlock()
	defer r.wg.Done()

	if !r.config.Enabled {
		err := forward(ctx, qCtx)
		return false, fastforward.SelectedUpstreamTag(qCtx), err
	}
	msgKey := getMsgKey(qCtx.Q())
	if msgKey == "" {
		err := forward(ctx, qCtx)
		return false, fastforward.SelectedUpstreamTag(qCtx), err
	}
	r.mu.Lock()
	response, lazy, upstreamTag := getRespFromCacheWithTag(msgKey, r.backend, r.config.LazyCacheTTL > 0, expiredMsgTtl)
	r.mu.Unlock()
	if response != nil {
		response.Id = qCtx.Q().Id
		qCtx.SetResponse(response)
		if lazy {
			r.refresh(msgKey, generation, qCtx, forward)
		}
		return true, upstreamTag, nil
	}
	if err := forward(ctx, qCtx); err != nil {
		return false, "", err
	}
	upstreamTag = fastforward.SelectedUpstreamTag(qCtx)
	r.store(msgKey, generation, qCtx.R(), upstreamTag)
	return false, upstreamTag, nil
}

func (r *Runtime) refresh(msgKey string, generation uint64, qCtx *query_context.Context, forward func(context.Context, *query_context.Context) error) {
	r.mu.Lock()
	if r.closed || r.generation != generation {
		r.mu.Unlock()
		return
	}
	if _, ok := r.refreshing[msgKey]; ok {
		r.mu.Unlock()
		return
	}
	r.refreshing[msgKey] = struct{}{}
	r.wg.Add(1)
	refreshCtx := qCtx.Copy()
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.refreshing, msgKey)
			r.mu.Unlock()
			r.wg.Done()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), defaultLazyUpdateTimeout)
		defer cancel()
		refreshCtx.SetResponse(nil)
		if err := forward(ctx, refreshCtx); err != nil {
			return
		}
		r.store(msgKey, generation, refreshCtx.R(), fastforward.SelectedUpstreamTag(refreshCtx))
	}()
}

func (r *Runtime) store(msgKey string, generation uint64, response *dns.Msg, upstreamTag string) {
	if response == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.generation != generation {
		return
	}
	saveRespToCacheWithTag(msgKey, response, r.backend, r.config.LazyCacheTTL, negativeCacheConfig{Enabled: r.config.NegativeEnabled, TTLSeconds: r.config.NegativeTTLSeconds}, upstreamTag)
}

func (r *Runtime) Flush() {
	r.mu.Lock()
	r.generation++
	r.backend.Flush()
	r.mu.Unlock()
}
func (r *Runtime) Len() int { return r.backend.Len() }
func (r *Runtime) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.generation++
	r.mu.Unlock()
	r.wg.Wait()
	return r.backend.Close()
}
