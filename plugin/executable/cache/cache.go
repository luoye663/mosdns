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

package cache

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/cache"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/klauspost/compress/gzip"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/proto"
)

const (
	PluginType = "cache"
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, quickSetupCache)
}

const (
	defaultLazyUpdateTimeout = time.Second * 5
	expiredMsgTtl            = 5
	defaultNegativeCacheTTL  = 30
	maxNegativeCacheTTL      = 86400

	minimumChangesToDump   = 1024
	dumpHeader             = "mosdns_cache_v2"
	dumpBlockSize          = 128
	dumpMaximumBlockLength = 1 << 20 // 1M block. 8kb pre entry. Should be enough.
)

var _ sequence.RecursiveExecutable = (*Cache)(nil)

type Args struct {
	Size         int    `yaml:"size"`
	LazyCacheTTL int    `yaml:"lazy_cache_ttl"`
	DumpFile     string `yaml:"dump_file"`
	DumpInterval int    `yaml:"dump_interval"`
	// AuthTokenFile 仅保护通过 mosdns HTTP API 暴露的缓存操作，不参与 DNS 查询路径。
	AuthTokenFile string `yaml:"auth_token_file"`
}

func (a *Args) init() {
	utils.SetDefaultUnsignNum(&a.Size, 1024)
	utils.SetDefaultUnsignNum(&a.DumpInterval, 600)
}

type Cache struct {
	args *Args

	logger        *zap.Logger
	backend       *cache.Cache[key, *item]
	lazyUpdateSF  singleflight.Group
	closeOnce     sync.Once
	closeNotify   chan struct{}
	updatedKey    atomic.Uint64
	enabled       atomic.Bool
	lazyCacheTTL  atomic.Int64
	negativeCache atomic.Pointer[negativeCacheConfig]
	controlToken  []byte

	queryTotal   prometheus.Counter
	hitTotal     prometheus.Counter
	lazyHitTotal prometheus.Counter
	size         prometheus.GaugeFunc
}

type negativeCacheConfig struct {
	Enabled    bool   `json:"enabled"`
	TTLSeconds uint32 `json:"ttl_seconds"`
}

func Init(bp *coremain.BP, args any) (any, error) {
	cacheArgs := args.(*Args)
	if len(cacheArgs.AuthTokenFile) == 0 {
		return nil, errors.New("auth_token_file is required for cache plugin API")
	}
	token, err := os.ReadFile(cacheArgs.AuthTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read auth_token_file: %w", err)
	}
	token = []byte(strings.TrimSpace(string(token)))
	if len(token) == 0 {
		return nil, errors.New("auth_token_file is empty")
	}
	c := NewCache(cacheArgs, Opts{
		Logger:     bp.L(),
		MetricsTag: bp.Tag(),
	})
	c.controlToken = token

	if err := c.RegMetricsTo(prometheus.WrapRegistererWithPrefix(PluginType+"_", bp.M().GetMetricsReg())); err != nil {
		return nil, fmt.Errorf("failed to register metrics, %w", err)
	}
	bp.RegAPI(c.Api())
	return c, nil
}

// QuickSetup format: [size]
// default is 1024. If size is < 1024, 1024 will be used.
func quickSetupCache(bq sequence.BQ, s string) (any, error) {
	size := 0
	if len(s) > 0 {
		i, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid size, %w", err)
		}
		size = i
	}
	// Don't register metrics in quick setup.
	return NewCache(&Args{Size: size}, Opts{Logger: bq.L()}), nil
}

type Opts struct {
	Logger     *zap.Logger
	MetricsTag string
}

func NewCache(args *Args, opts Opts) *Cache {
	args.init()

	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	backend := cache.New[key, *item](cache.Opts{Size: args.Size})
	lb := map[string]string{"tag": opts.MetricsTag}
	p := &Cache{
		args:        args,
		logger:      logger,
		backend:     backend,
		closeNotify: make(chan struct{}),

		queryTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "query_total",
			Help:        "The total number of processed queries",
			ConstLabels: lb,
		}),
		hitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "hit_total",
			Help:        "The total number of queries that hit the cache",
			ConstLabels: lb,
		}),
		lazyHitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "lazy_hit_total",
			Help:        "The total number of queries that hit the expired cache",
			ConstLabels: lb,
		}),
		size: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "size_current",
			Help:        "Current cache size in records",
			ConstLabels: lb,
		}, func() float64 {
			return float64(backend.Len())
		}),
	}
	p.enabled.Store(true)
	p.lazyCacheTTL.Store(int64(args.LazyCacheTTL))
	p.negativeCache.Store(&negativeCacheConfig{Enabled: true, TTLSeconds: defaultNegativeCacheTTL})

	if err := p.loadDump(); err != nil {
		p.logger.Error("failed to load cache dump", zap.Error(err))
	}
	p.startDumpLoop()

	return p
}

func (c *Cache) RegMetricsTo(r prometheus.Registerer) error {
	for _, collector := range [...]prometheus.Collector{c.queryTotal, c.hitTotal, c.lazyHitTotal, c.size} {
		if err := r.Register(collector); err != nil {
			return err
		}
	}
	return nil
}

func (c *Cache) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	if !c.enabled.Load() {
		return next.ExecNext(ctx, qCtx)
	}
	c.queryTotal.Inc()
	q := qCtx.Q()

	msgKey := getMsgKey(q)
	if len(msgKey) == 0 { // skip cache
		return next.ExecNext(ctx, qCtx)
	}

	lazyTTL := int(c.lazyCacheTTL.Load())
	cachedResp, lazyHit := getRespFromCache(msgKey, c.backend, lazyTTL > 0, expiredMsgTtl)
	if lazyHit {
		c.lazyHitTotal.Inc()
		c.doLazyUpdate(msgKey, qCtx, next)
	}
	if cachedResp != nil { // cache hit
		c.hitTotal.Inc()
		cachedResp.Id = q.Id // change msg id
		qCtx.SetResponse(cachedResp)
	}

	err := next.ExecNext(ctx, qCtx)

	if r := qCtx.R(); err == nil && r != nil && cachedResp != r { // pointer compare. r is not cachedResp
		if saveRespToCache(msgKey, r, c.backend, lazyTTL, *c.negativeCache.Load()) {
			c.updatedKey.Add(1)
		}
	}
	return err
}

// doLazyUpdate starts a new goroutine to execute next node and update the cache in the background.
// It has an inner singleflight.Group to de-duplicate same msgKey.
func (c *Cache) doLazyUpdate(msgKey string, qCtx *query_context.Context, next sequence.ChainWalker) {
	qCtxCopy := qCtx.Copy()
	lazyUpdateFunc := func() (any, error) {
		defer c.lazyUpdateSF.Forget(msgKey)
		qCtx := qCtxCopy

		c.logger.Debug("start lazy cache update", qCtx.InfoField())
		ctx, cancel := context.WithTimeout(context.Background(), defaultLazyUpdateTimeout)
		defer cancel()

		err := next.ExecNext(ctx, qCtx)
		if err != nil {
			c.logger.Warn("failed to update lazy cache", qCtx.InfoField(), zap.Error(err))
		}

		r := qCtx.R()
		if err == nil && r != nil {
			if saveRespToCache(msgKey, r, c.backend, int(c.lazyCacheTTL.Load()), *c.negativeCache.Load()) {
				c.updatedKey.Add(1)
			}
		}
		c.logger.Debug("lazy cache updated", qCtx.InfoField())
		return nil, nil
	}
	c.lazyUpdateSF.DoChan(msgKey, lazyUpdateFunc) // DoChan won't block this goroutine
}

func (c *Cache) Close() error {
	if err := c.dumpCache(); err != nil {
		c.logger.Error("failed to dump cache", zap.Error(err))
	}
	c.closeOnce.Do(func() {
		close(c.closeNotify)
	})
	return c.backend.Close()
}

func (c *Cache) loadDump() error {
	if len(c.args.DumpFile) == 0 {
		return nil
	}
	f, err := os.Open(c.args.DumpFile)
	if err != nil {
		return err
	}
	defer f.Close()
	en, err := c.readDump(f)
	if err != nil {
		return err
	}
	c.logger.Info("cache dump loaded", zap.Int("entries", en))
	return nil
}

// startDumpLoop starts a dump loop in another goroutine. It does not block.
func (c *Cache) startDumpLoop() {
	if len(c.args.DumpFile) == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Duration(c.args.DumpInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Check if we have enough changes to dump.
				keyUpdated := c.updatedKey.Swap(0)
				if keyUpdated < minimumChangesToDump { // Nop.
					c.updatedKey.Add(keyUpdated)
					continue
				}

				if err := c.dumpCache(); err != nil {
					c.logger.Error("dump cache", zap.Error(err))
				}
			case <-c.closeNotify:
				return
			}
		}
	}()
}

func (c *Cache) dumpCache() error {
	if len(c.args.DumpFile) == 0 {
		return nil
	}

	f, err := os.Create(c.args.DumpFile)
	if err != nil {
		return err
	}
	defer f.Close()

	en, err := c.writeDump(f)
	if err != nil {
		return fmt.Errorf("failed to write dump, %w", err)
	}
	c.logger.Info("cache dumped", zap.Int("entries", en))
	return nil
}

func (c *Cache) Api() *chi.Mux {
	r := chi.NewRouter()
	r.Use(c.requireControlToken)
	r.Get("/flush", func(w http.ResponseWriter, req *http.Request) {
		c.backend.Flush()
	})
	r.Get("/status", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": c.enabled.Load()})
	})
	r.Put("/enabled", func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		decoder := json.NewDecoder(io.LimitReader(req.Body, 1025))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		c.enabled.Store(body.Enabled)
		if !body.Enabled {
			c.backend.Flush()
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": body.Enabled})
	})
	r.Put("/ttl", func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			TTL int `json:"ttl"`
		}
		decoder := json.NewDecoder(io.LimitReader(req.Body, 1025))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || decoder.Decode(&struct{}{}) != io.EOF || body.TTL < 0 || body.TTL > 604800 {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		c.lazyCacheTTL.Store(int64(body.TTL))
		c.backend.Flush()
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"ttl": body.TTL})
	})
	r.Get("/negative-cache", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(c.negativeCache.Load())
	})
	r.Put("/negative-cache", func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Enabled    *bool   `json:"enabled"`
			TTLSeconds *uint32 `json:"ttl_seconds"`
		}
		decoder := json.NewDecoder(io.LimitReader(req.Body, 1025))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || decoder.Decode(&struct{}{}) != io.EOF || body.Enabled == nil || body.TTLSeconds == nil || *body.TTLSeconds < 1 || *body.TTLSeconds > maxNegativeCacheTTL {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		config := &negativeCacheConfig{Enabled: *body.Enabled, TTLSeconds: *body.TTLSeconds}
		if current := c.negativeCache.Load(); *current != *config {
			c.negativeCache.Store(config)
			c.backend.Flush()
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(config)
	})
	r.Get("/dump", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("content-type", "application/octet-stream")
		_, err := c.writeDump(w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	r.Post("/load_dump", func(w http.ResponseWriter, req *http.Request) {
		if _, err := c.readDump(req.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return r
}

// requireControlToken 保护 flush、dump 和 load_dump，避免内部 API 被未认证调用。
func (c *Cache) requireControlToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		const bearerPrefix = "Bearer "
		authorization := req.Header.Get("Authorization")
		provided := strings.TrimPrefix(authorization, bearerPrefix)
		if len(c.controlToken) == 0 || !strings.HasPrefix(authorization, bearerPrefix) || subtle.ConstantTimeCompare([]byte(provided), c.controlToken) != 1 {
			http.Error(w, "authorization required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (c *Cache) writeDump(w io.Writer) (int, error) {
	en := 0

	gw, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
	gw.Name = dumpHeader

	block := new(CacheDumpBlock)
	writeBlock := func() error {
		b, err := proto.Marshal(block)
		if err != nil {
			return fmt.Errorf("failed to marshal protobuf, %w", err)
		}

		l := make([]byte, 8)
		binary.BigEndian.PutUint64(l, uint64(len(b)))
		_, err = gw.Write(l)
		if err != nil {
			return fmt.Errorf("failed to write header, %w", err)
		}
		_, err = gw.Write(b)
		if err != nil {
			return fmt.Errorf("failed to write data, %w", err)
		}

		en += len(block.GetEntries())
		block.Reset()
		return nil
	}

	now := time.Now()
	rangeFunc := func(k key, v *item, cacheExpirationTime time.Time) error {
		if cacheExpirationTime.Before(now) {
			return nil
		}
		msg, err := v.resp.Pack()
		if err != nil {
			return fmt.Errorf("failed to pack msg, %w", err)
		}
		e := &CachedEntry{
			Key:                 []byte(k),
			CacheExpirationTime: cacheExpirationTime.Unix(),
			MsgExpirationTime:   v.expirationTime.Unix(),
			MsgStoredTime:       v.storedTime.Unix(),
			Msg:                 msg,
		}
		block.Entries = append(block.Entries, e)

		// Block is big enough for a write operation.
		if len(block.Entries) >= dumpBlockSize {
			return writeBlock()
		}
		return nil
	}
	if err := c.backend.Range(rangeFunc); err != nil {
		return en, err
	}

	if len(block.GetEntries()) > 0 {
		if err := writeBlock(); err != nil {
			return en, err
		}
	}
	return en, gw.Close()
}

// readDump reads dumped data from r. It returns the number of bytes read,
// number of entries read and any error encountered.
func (c *Cache) readDump(r io.Reader) (int, error) {
	en := 0
	gr, err := gzip.NewReader(r)
	if err != nil {
		return en, fmt.Errorf("failed to read gzip header, %w", err)
	}
	if gr.Name != dumpHeader {
		return en, fmt.Errorf("invalid or old cache dump, header is %s, want %s", gr.Name, dumpHeader)
	}

	var errReadHeaderEOF = errors.New("")
	readBlock := func() error {
		h := pool.GetBuf(8)
		defer pool.ReleaseBuf(h)
		_, err := io.ReadFull(gr, *h)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errReadHeaderEOF
			}
			return fmt.Errorf("failed to read block header, %w", err)
		}
		u := binary.BigEndian.Uint64(*h)
		if u > dumpMaximumBlockLength {
			return fmt.Errorf("invalid header, block length is big, %d", u)
		}

		b := pool.GetBuf(int(u))
		defer pool.ReleaseBuf(b)
		_, err = io.ReadFull(gr, *b)
		if err != nil {
			return fmt.Errorf("failed to read block data, %w", err)
		}

		block := new(CacheDumpBlock)
		if err := proto.Unmarshal(*b, block); err != nil {
			return fmt.Errorf("failed to decode block data, %w", err)
		}

		for _, entry := range block.GetEntries() {
			if entry.GetMsgStoredTime() <= 0 {
				continue
			}
			cacheExpTime := time.Unix(entry.GetCacheExpirationTime(), 0)
			msgExpTime := time.Unix(entry.GetMsgExpirationTime(), 0)
			storedTime := time.Unix(entry.GetMsgStoredTime(), 0)
			resp := new(dns.Msg)
			if err := resp.Unpack(entry.GetMsg()); err != nil {
				return fmt.Errorf("failed to decode dns msg, %w", err)
			}
			negativeTTL, negative := getNegativeTTL(resp, *c.negativeCache.Load())
			if resp.Truncated || negative && negativeTTL == 0 || !negative && resp.Rcode != dns.RcodeSuccess {
				continue
			}
			if negative {
				configuredExpiration := storedTime.Add(time.Duration(negativeTTL) * time.Second)
				if configuredExpiration.Before(msgExpTime) {
					msgExpTime = configuredExpiration
				}
				if configuredExpiration.Before(cacheExpTime) {
					cacheExpTime = configuredExpiration
				}
				capNegativeSOATTL(resp, negativeTTL)
			}
			if !time.Now().Before(msgExpTime) || !time.Now().Before(cacheExpTime) {
				continue
			}

			i := &item{
				resp:           resp,
				storedTime:     storedTime,
				expirationTime: msgExpTime,
			}
			c.backend.Store(key(entry.GetKey()), i, cacheExpTime)
			en++
		}
		return nil
	}

	for {
		err = readBlock()
		if err != nil {
			if err == errReadHeaderEOF {
				err = nil // This is expected if there is no block to read.
			}
			break
		}
	}

	if err != nil {
		return en, err
	}
	return en, gr.Close()
}
