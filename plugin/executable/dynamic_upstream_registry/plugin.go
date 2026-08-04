// Package dynamic_upstream_registry provides an atomically swappable set of
// independently configured upstream runtimes.
package dynamic_upstream_registry

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	cacheplugin "github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_ecs"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_forward"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_rule_engine"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

const (
	PluginType            = "dynamic_upstream_registry"
	registrySchemaVersion = 1
	defaultCacheSize      = 1024
	maximumCacheEntries   = 65536
	maximumBodyBytes      = 4 << 20
)

var groupIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

type Args struct {
	AuthTokenFile   string   `yaml:"auth_token_file"`
	SnapshotFile    string   `yaml:"snapshot_file"`
	BackupFile      string   `yaml:"backup_file"`
	CacheDumpDir    string   `yaml:"cache_dump_dir"`
	InitialSnapshot Snapshot `yaml:"initial_snapshot"`
}

type Snapshot struct {
	SchemaVersion          uint32            `json:"schema_version" yaml:"schema_version"`
	Version                uint64            `json:"version" yaml:"version"`
	ExpectedCurrentVersion uint64            `json:"expected_current_version" yaml:"expected_current_version"`
	DefaultGroupID         string            `json:"default_group_id" yaml:"default_group_id"`
	Groups                 []Group           `json:"groups" yaml:"groups"`
	Cache                  GlobalCacheConfig `json:"cache" yaml:"cache"`
}

type Group struct {
	ID         string                     `json:"id" yaml:"id"`
	Name       string                     `json:"name" yaml:"name"`
	Enabled    bool                       `json:"enabled" yaml:"enabled"`
	Mode       string                     `json:"mode" yaml:"mode"`
	Concurrent int                        `json:"concurrent" yaml:"concurrent"`
	Socks5     string                     `json:"socks5,omitempty" yaml:"socks5"`
	Upstreams  []dynamic_forward.Upstream `json:"upstreams" yaml:"upstreams"`
	ECS        dynamic_ecs.Config         `json:"ecs" yaml:"ecs"`
	Cache      GroupCacheConfig           `json:"cache" yaml:"cache"`
}

type GroupCacheConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
	Size    int  `json:"size" yaml:"size"`
}

type GlobalCacheConfig struct {
	Enabled  bool                `json:"enabled" yaml:"enabled"`
	LazyTTL  int                 `json:"lazy_ttl" yaml:"lazy_ttl"`
	Negative NegativeCacheConfig `json:"negative" yaml:"negative"`
}

type NegativeCacheConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	TTL     uint32 `json:"ttl" yaml:"ttl"`
}

type runtimeGroup struct {
	config  Group
	forward *dynamic_forward.Runtime
	cache   *cacheplugin.Runtime
}

func (g *runtimeGroup) close() {
	_ = g.cache.Close()
	_ = g.forward.Close()
}

type runtimeState struct {
	snapshot    Snapshot
	groups      map[string]*runtimeGroup
	refs        atomic.Int64
	retired     atomic.Bool
	closed      atomic.Bool
	beforeClose func(*runtimeState)
	done        chan struct{}
}

func (s *runtimeState) retire() { s.retired.Store(true); s.closeWhenIdle() }
func (s *runtimeState) closeWhenIdle() {
	if s.retired.Load() && s.refs.Load() == 0 && s.closed.CompareAndSwap(false, true) {
		if s.beforeClose != nil {
			s.beforeClose(s)
		}
		for _, group := range s.groups {
			group.close()
		}
		close(s.done)
	}
}

type Plugin struct {
	current      atomic.Pointer[runtimeState]
	stateMu      sync.RWMutex
	applyMu      sync.Mutex
	cacheDumpMu  sync.Mutex
	closed       atomic.Bool
	token        []byte
	snapshotFile string
	backupFile   string
	cacheDumpDir string
	logger       *zap.Logger
	metricsTag   string
}

var _ sequence.Executable = (*Plugin)(nil)
var _ io.Closer = (*Plugin)(nil)

func init() { coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) }) }

func Init(bp *coremain.BP, raw any) (any, error) {
	args, ok := raw.(*Args)
	if !ok {
		return nil, fmt.Errorf("invalid dynamic_upstream_registry arguments %T", raw)
	}
	p, err := newPlugin(*args, bp.L(), bp.Tag())
	if err != nil {
		return nil, err
	}
	bp.RegAPI(p.router())
	return p, nil
}

func newPlugin(args Args, logger *zap.Logger, metricsTag string) (*Plugin, error) {
	if args.AuthTokenFile == "" || args.SnapshotFile == "" || args.BackupFile == "" {
		return nil, errors.New("auth_token_file, snapshot_file and backup_file are required")
	}
	if args.SnapshotFile == args.BackupFile {
		return nil, errors.New("snapshot_file and backup_file must differ")
	}
	token, err := os.ReadFile(args.AuthTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read auth_token_file: %w", err)
	}
	token = []byte(strings.TrimSpace(string(token)))
	if len(token) == 0 {
		return nil, errors.New("auth_token_file is empty")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	cacheDumpDir := args.CacheDumpDir
	if cacheDumpDir == "" {
		cacheDumpDir = args.SnapshotFile + ".cache"
	}
	p := &Plugin{token: token, snapshotFile: args.SnapshotFile, backupFile: args.BackupFile, cacheDumpDir: cacheDumpDir, logger: logger, metricsTag: metricsTag}
	snapshot, source, err := loadSnapshot(args.SnapshotFile, args.BackupFile)
	if err != nil {
		return nil, err
	}
	if source == "" {
		snapshot = args.InitialSnapshot
	}
	state, err := p.buildState(snapshot, true)
	if err != nil {
		return nil, fmt.Errorf("build initial snapshot: %w", err)
	}
	if source == "" {
		if err := persistSnapshot(state.snapshot, p.snapshotFile, p.backupFile); err != nil {
			state.retire()
			return nil, err
		}
	} else if source == p.backupFile {
		if err := writeSnapshotAtomic(state.snapshot, p.snapshotFile); err != nil {
			state.retire()
			return nil, fmt.Errorf("restore backup snapshot: %w", err)
		}
	}
	p.current.Store(state)
	p.cleanupCacheDumps(state)
	return p, nil
}

func (p *Plugin) buildState(snapshot Snapshot, loadCacheDumps bool) (*runtimeState, error) {
	canonicalSnapshot, err := canonicalWithoutRuntime(snapshot)
	if err != nil {
		return nil, err
	}
	state := &runtimeState{snapshot: canonicalSnapshot, groups: make(map[string]*runtimeGroup, len(canonicalSnapshot.Groups)), done: make(chan struct{})}
	for _, config := range canonicalSnapshot.Groups {
		forward, err := dynamic_forward.NewRuntime(config.Mode, config.Concurrent, config.Socks5, config.Upstreams, p.logger, p.metricsTag+"_"+config.ID)
		if err != nil {
			state.retire()
			return nil, fmt.Errorf("group %s forward: %w", config.ID, err)
		}
		cache, err := cacheplugin.NewRuntime(cacheplugin.RuntimeConfig{Enabled: canonicalSnapshot.Cache.Enabled && config.Cache.Enabled, Size: config.Cache.Size, LazyCacheTTL: canonicalSnapshot.Cache.LazyTTL, NegativeEnabled: canonicalSnapshot.Cache.Negative.Enabled, NegativeTTLSeconds: canonicalSnapshot.Cache.Negative.TTL})
		if err != nil {
			_ = forward.Close()
			state.retire()
			return nil, fmt.Errorf("group %s cache: %w", config.ID, err)
		}
		if loadCacheDumps {
			if f, err := os.Open(p.cacheDumpFile(canonicalSnapshot.Version, config.ID)); err == nil {
				if _, err := cache.ReadDump(f); err != nil {
					cache.Flush()
					p.logger.Warn("skip invalid cache dump", zap.String("group", config.ID), zap.Error(err))
				}
				_ = f.Close()
			} else if !errors.Is(err, os.ErrNotExist) {
				p.logger.Warn("skip unreadable cache dump", zap.String("group", config.ID), zap.Error(err))
			}
		}
		state.groups[config.ID] = &runtimeGroup{config: config, forward: forward, cache: cache}
	}
	return state, nil
}

// canonicalWithoutRuntime validates values without opening network transports.
func canonicalWithoutRuntime(snapshot Snapshot) (Snapshot, error) {
	// canonical uses dynamic_forward only as a strict validator; close each
	// temporary runtime immediately to avoid leaking transports.
	if snapshot.Version == 0 {
		return Snapshot{}, errors.New("version must be positive")
	}
	// The shared validator below performs all structural normalization.
	return canonicalSnapshotValues(snapshot)
}

func (p *Plugin) acquire() (*runtimeState, error) {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	if p.closed.Load() {
		return nil, errors.New("dynamic upstream registry is closed")
	}
	state := p.current.Load()
	if state == nil {
		return nil, errors.New("no upstream registry loaded")
	}
	state.refs.Add(1)
	return state, nil
}

func (p *Plugin) release(state *runtimeState) { state.refs.Add(-1); state.closeWhenIdle() }

func (p *Plugin) Exec(ctx context.Context, qCtx *query_context.Context) error {
	state, err := p.acquire()
	if err != nil {
		return err
	}
	defer p.release(state)
	groupID, source := state.snapshot.DefaultGroupID, "default"
	if explicit, ok := query_context.UpstreamGroupID(qCtx); ok {
		groupID, source = explicit, "subscription"
		if decision, ok := dynamic_rule_engine.RuntimeDecisionFromContext(qCtx); ok && decision.RouteSource != "" {
			source = decision.RouteSource
		}
	}
	group := state.groups[groupID]
	meta := query_context.UpstreamRuntimeMeta{GroupID: groupID, RouteSource: source}
	if group != nil {
		meta.GroupName = group.config.Name
	}
	query_context.SetUpstreamRuntimeMeta(qCtx, meta)
	if group == nil {
		return fmt.Errorf("selected upstream group %q does not exist", groupID)
	}
	if !group.config.Enabled {
		return fmt.Errorf("selected upstream group %q is disabled", groupID)
	}
	if err := dynamic_ecs.ApplyConfig(qCtx, group.config.ECS); err != nil {
		return err
	}
	hit, upstreamTag, err := group.cache.Exec(ctx, qCtx, group.forward.Exec)
	if err == nil {
		meta.UpstreamTag, meta.CacheHit = upstreamTag, hit
		query_context.SetUpstreamRuntimeMeta(qCtx, meta)
	}
	return err
}

func (p *Plugin) Close() error {
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	p.stateMu.Lock()
	p.closed.Store(true)
	state := p.current.Swap(nil)
	if state != nil {
		state.beforeClose = p.closeAndDumpCaches
		state.retire()
	}
	p.stateMu.Unlock()
	if state != nil {
		<-state.done
	}
	return nil
}

func (p *Plugin) router() *chi.Mux {
	r := chi.NewRouter()
	r.Use(p.authorize)
	r.Get("/status", p.handleStatus)
	r.Put("/snapshot", p.handleSnapshot)
	r.Post("/flush", p.handleFlush)
	return r
}

func (p *Plugin) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		provided := []byte(strings.TrimPrefix(auth, prefix))
		if !strings.HasPrefix(auth, prefix) || len(provided) != len(p.token) || subtle.ConstantTimeCompare(provided, p.token) != 1 {
			writeError(w, http.StatusUnauthorized, "authorization required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Plugin) handleStatus(w http.ResponseWriter, _ *http.Request) {
	state, err := p.acquire()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	defer p.release(state)
	writeJSON(w, http.StatusOK, state.snapshot)
}

func (p *Plugin) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	var requested Snapshot
	if err := decodeJSON(r, &requested, false); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	current := p.current.Load()
	if current == nil {
		writeError(w, http.StatusServiceUnavailable, "no upstream registry loaded")
		return
	}
	if requested.ExpectedCurrentVersion != current.snapshot.Version {
		writeJSON(w, http.StatusConflict, map[string]uint64{"current_version": current.snapshot.Version})
		return
	}
	if requested.Version <= current.snapshot.Version {
		writeError(w, http.StatusBadRequest, "version must increase")
		return
	}
	next, err := p.buildState(requested, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := persistSnapshot(next.snapshot, p.snapshotFile, p.backupFile); err != nil {
		next.retire()
		writeError(w, http.StatusInternalServerError, "persist snapshot: "+err.Error())
		return
	}
	p.stateMu.Lock()
	if p.closed.Load() || p.current.Load() != current {
		p.stateMu.Unlock()
		next.retire()
		writeError(w, http.StatusServiceUnavailable, "upstream registry changed while applying snapshot")
		return
	}
	if err := p.removeCacheDumps(); err != nil {
		p.logger.Warn("remove stale cache dumps", zap.Error(err))
	}
	old := p.current.Swap(next)
	p.stateMu.Unlock()
	old.retire()
	writeJSON(w, http.StatusOK, next.snapshot)
}

func (p *Plugin) handleFlush(w http.ResponseWriter, r *http.Request) {
	var request struct {
		GroupID                string `json:"group_id"`
		ExpectedCurrentVersion uint64 `json:"expected_current_version"`
	}
	if err := decodeJSON(r, &request, true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	state, err := p.acquire()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	defer p.release(state)
	if request.ExpectedCurrentVersion != state.snapshot.Version {
		writeJSON(w, http.StatusConflict, map[string]uint64{"current_version": state.snapshot.Version})
		return
	}
	if request.GroupID != "" {
		group := state.groups[request.GroupID]
		if group == nil {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		group.cache.Flush()
		if err := p.removeCacheDump(state.snapshot.Version, request.GroupID); err != nil {
			writeError(w, http.StatusInternalServerError, "remove cache dump: "+err.Error())
			return
		}
	} else {
		for _, group := range state.groups {
			group.cache.Flush()
		}
		if err := p.removeCacheDumps(); err != nil {
			writeError(w, http.StatusInternalServerError, "remove cache dumps: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"flushed": true, "group_id": request.GroupID})
}

func (p *Plugin) cacheDumpFile(version uint64, groupID string) string {
	return filepath.Join(p.cacheDumpDir, fmt.Sprintf("%d-%s.dump", version, groupID))
}

func decodeJSON(r *http.Request, target any, allowEmpty bool) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, maximumBodyBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maximumBodyBytes {
		return errors.New("request body exceeds limit")
	}
	if allowEmpty && len(strings.TrimSpace(string(data))) == 0 {
		data = []byte("{}")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("request contains trailing JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
