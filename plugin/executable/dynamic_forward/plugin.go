// Package dynamic_forward provides atomically swappable upstream groups.
package dynamic_forward

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	fastforward "github.com/IrineSistiana/mosdns/v5/plugin/executable/forward"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PluginType = "dynamic_forward"

var tagPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type Args struct {
	SnapshotFile  string   `yaml:"snapshot_file"`
	BackupFile    string   `yaml:"backup_file"`
	AuthTokenFile string   `yaml:"auth_token_file"`
	Initial       Snapshot `yaml:"initial"`
	MaxBodyBytes  int64    `yaml:"max_request_body_bytes"`
}

type Snapshot struct {
	Version                uint64     `json:"version" yaml:"version"`
	ExpectedCurrentVersion uint64     `json:"expected_current_version" yaml:"expected_current_version"`
	Mode                   string     `json:"mode" yaml:"mode"`
	Concurrent             int        `json:"concurrent" yaml:"concurrent"`
	Socks5                 string     `json:"socks5,omitempty" yaml:"socks5"`
	Upstreams              []Upstream `json:"upstreams" yaml:"upstreams"`
	Checksum               string     `json:"checksum,omitempty" yaml:"-"`
}

type Upstream struct {
	Tag      string `json:"tag" yaml:"tag"`
	Addr     string `json:"addr" yaml:"addr"`
	Priority int    `json:"priority" yaml:"priority"`
	Weight   int    `json:"weight" yaml:"weight"`
}

type runtimeForward struct {
	forward  *fastforward.Forward
	refs     atomic.Int64
	retired  atomic.Bool
	closed   atomic.Bool
	snapshot Snapshot
	levels   [][]string
}

func (r *runtimeForward) retire() {
	r.retired.Store(true)
	r.closeWhenIdle()
}

func (r *runtimeForward) closeWhenIdle() {
	if r.retired.Load() && r.refs.Load() == 0 && r.closed.CompareAndSwap(false, true) {
		_ = r.forward.Close()
	}
}

type Plugin struct {
	current      atomic.Pointer[runtimeForward]
	snapshot     atomic.Pointer[Snapshot]
	applyMu      sync.Mutex
	closed       atomic.Bool
	token        []byte
	snapshotFile string
	backupFile   string
	maxBodyBytes int64
	logger       *zap.Logger
	metricsTag   string
}

var _ sequence.Executable = (*Plugin)(nil)
var _ interface{ Close() error } = (*Plugin)(nil)

func init() { coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) }) }

func Init(bp *coremain.BP, raw any) (any, error) {
	args, ok := raw.(*Args)
	if !ok {
		return nil, fmt.Errorf("invalid dynamic_forward arguments %T", raw)
	}
	p, err := newPlugin(*args, bp.L(), bp.Tag())
	if err != nil {
		return nil, err
	}
	bp.RegAPI(p.router())
	return p, nil
}

func newPlugin(args Args, logger *zap.Logger, metricsTag string) (*Plugin, error) {
	if args.SnapshotFile == "" || args.BackupFile == "" || args.AuthTokenFile == "" || args.SnapshotFile == args.BackupFile {
		return nil, errors.New("snapshot_file, backup_file and auth_token_file are required and must differ")
	}
	token, err := os.ReadFile(args.AuthTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read auth_token_file: %w", err)
	}
	token = []byte(strings.TrimSpace(string(token)))
	if len(token) == 0 {
		return nil, errors.New("auth_token_file is empty")
	}
	p := &Plugin{token: token, snapshotFile: args.SnapshotFile, backupFile: args.BackupFile, maxBodyBytes: args.MaxBodyBytes, logger: logger, metricsTag: metricsTag}
	if p.maxBodyBytes == 0 {
		p.maxBodyBytes = 1 << 20
	}
	if p.maxBodyBytes < 1 || p.maxBodyBytes > 64<<20 {
		return nil, errors.New("max_request_body_bytes must be within 1..67108864")
	}
	for _, filename := range []string{p.snapshotFile, p.backupFile} {
		data, readErr := os.ReadFile(filename)
		if readErr != nil {
			continue
		}
		var snapshot Snapshot
		if json.Unmarshal(data, &snapshot) != nil {
			continue
		}
		if err := p.install(snapshot, false); err == nil {
			return p, nil
		}
	}
	if args.Initial.Version == 0 {
		args.Initial.Version = 1
	}
	if err := p.install(args.Initial, true); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Plugin) install(snapshot Snapshot, persist bool) error {
	canonical, err := canonical(snapshot)
	if err != nil {
		return err
	}
	forward, err := fastforward.NewForward(&fastforward.Args{Concurrent: canonical.Concurrent, Socks5: canonical.Socks5, Upstreams: forwardUpstreams(canonical.Upstreams)}, fastforward.Opts{Logger: p.logger, MetricsTag: p.metricsTag})
	if err != nil {
		return errors.New("invalid upstream configuration")
	}
	if persist && p.snapshotFile != "" {
		if err := persistSnapshot(canonical, p.snapshotFile, p.backupFile); err != nil {
			_ = forward.Close()
			return err
		}
	}
	next := &runtimeForward{forward: forward, snapshot: canonical, levels: priorityLevels(canonical.Upstreams)}
	old := p.current.Swap(next)
	p.snapshot.Store(&canonical)
	if old != nil {
		old.retire()
	}
	return nil
}

func forwardUpstreams(items []Upstream) []fastforward.UpstreamConfig {
	result := make([]fastforward.UpstreamConfig, 0, len(items))
	for _, item := range items {
		result = append(result, fastforward.UpstreamConfig{Tag: item.Tag, Addr: item.Addr})
	}
	return result
}

func canonical(snapshot Snapshot) (Snapshot, error) {
	if snapshot.Version == 0 {
		return Snapshot{}, errors.New("version must be positive")
	}
	if snapshot.Concurrent < 1 || snapshot.Concurrent > 3 {
		return Snapshot{}, errors.New("concurrent must be within 1..3")
	}
	if snapshot.Mode == "" {
		snapshot.Mode = "race"
	}
	if snapshot.Mode != "race" && snapshot.Mode != "weighted" && snapshot.Mode != "failover" {
		return Snapshot{}, errors.New("mode must be race, weighted or failover")
	}
	if len(snapshot.Upstreams) == 0 || len(snapshot.Upstreams) > 16 {
		return Snapshot{}, errors.New("upstreams must contain 1..16 entries")
	}
	seen := make(map[string]struct{}, len(snapshot.Upstreams))
	for i := range snapshot.Upstreams {
		item := &snapshot.Upstreams[i]
		item.Tag, item.Addr = strings.TrimSpace(item.Tag), strings.TrimSpace(item.Addr)
		if item.Priority == 0 {
			item.Priority = 100
		}
		if item.Weight == 0 {
			item.Weight = 1
		}
		if item.Priority < 1 || item.Priority > 1000 {
			return Snapshot{}, fmt.Errorf("upstream %d priority must be within 1..1000", i+1)
		}
		if item.Weight < 1 || item.Weight > 100 {
			return Snapshot{}, fmt.Errorf("upstream %d weight must be within 1..100", i+1)
		}
		if !tagPattern.MatchString(item.Tag) {
			return Snapshot{}, fmt.Errorf("upstream %d has an invalid tag", i+1)
		}
		if _, exists := seen[item.Tag]; exists {
			return Snapshot{}, errors.New("upstream tags must be unique")
		}
		seen[item.Tag] = struct{}{}
		parsed, err := url.ParseRequestURI(item.Addr)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return Snapshot{}, fmt.Errorf("upstream %d has an invalid address", i+1)
		}
		switch parsed.Scheme {
		case "https", "tls", "tcp", "udp", "quic":
		default:
			return Snapshot{}, fmt.Errorf("upstream %d uses an unsupported scheme", i+1)
		}
	}
	// expected_current_version is a CAS precondition, not part of the persisted configuration.
	snapshot.ExpectedCurrentVersion = 0
	snapshot.Checksum = ""
	data, err := json.Marshal(snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	digest := sha256.Sum256(data)
	snapshot.Checksum = "sha256:" + hex.EncodeToString(digest[:])
	return snapshot, nil
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
	for i := 0; i < len(priorities); i++ {
		for j := i + 1; j < len(priorities); j++ {
			if priorities[j] < priorities[i] {
				priorities[i], priorities[j] = priorities[j], priorities[i]
			}
		}
	}
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

func (p *Plugin) acquire() (*runtimeForward, error) {
	if p.closed.Load() {
		return nil, errors.New("dynamic forward is closed")
	}
	for {
		current := p.current.Load()
		if current == nil {
			return nil, errors.New("no upstream configuration loaded")
		}
		current.refs.Add(1)
		if p.current.Load() == current {
			return current, nil
		}
		p.release(current)
	}
}

func (p *Plugin) release(current *runtimeForward) {
	current.refs.Add(-1)
	current.closeWhenIdle()
}

func (p *Plugin) Exec(ctx context.Context, qCtx *query_context.Context) error {
	current, err := p.acquire()
	if err != nil {
		return err
	}
	defer p.release(current)
	switch current.snapshot.Mode {
	case "weighted":
		return current.forward.ExecWithTags(ctx, qCtx, weightedTags(current.snapshot.Upstreams, current.snapshot.Concurrent))
	case "failover":
		var lastErr error
		for _, level := range current.levels {
			err := current.forward.ExecWithTags(ctx, qCtx, level)
			if err != nil {
				lastErr = err
				continue
			}
			if response := qCtx.R(); response == nil || response.Rcode != dns.RcodeServerFailure {
				return nil
			}
		}
		return lastErr
	default:
		return current.forward.Exec(ctx, qCtx)
	}
}

func (p *Plugin) Close() error {
	p.closed.Store(true)
	if current := p.current.Swap(nil); current != nil {
		current.retire()
	}
	return nil
}

func (p *Plugin) router() *chi.Mux {
	router := chi.NewRouter()
	router.Use(p.authorize)
	router.Get("/status", p.handleStatus)
	router.Put("/snapshot", p.handleSnapshot)
	return router
}

func (p *Plugin) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, prefix)), p.token) != 1 {
			writeError(w, http.StatusUnauthorized, "authorization required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Plugin) handleStatus(w http.ResponseWriter, _ *http.Request) {
	snapshot := p.snapshot.Load()
	if snapshot == nil {
		writeError(w, http.StatusServiceUnavailable, "no upstream configuration loaded")
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (p *Plugin) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	var requested Snapshot
	if err := p.decodeJSON(r, &requested); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	current := p.snapshot.Load()
	if current == nil {
		writeError(w, http.StatusServiceUnavailable, "no upstream configuration loaded")
		return
	}
	if requested.ExpectedCurrentVersion != current.Version {
		writeJSON(w, http.StatusConflict, map[string]uint64{"current_version": current.Version})
		return
	}
	if requested.Version <= current.Version {
		writeError(w, http.StatusBadRequest, "version must increase")
		return
	}
	if err := p.install(requested, true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p.snapshot.Load())
}

func (p *Plugin) decodeJSON(r *http.Request, target any) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, p.maxBodyBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > p.maxBodyBytes {
		return errors.New("request body exceeds limit")
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

func persistSnapshot(snapshot Snapshot, currentFile, backupFile string) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(currentFile), 0o750); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(backupFile), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(currentFile), ".dynamic-forward-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Chmod(0o600)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if old, openErr := os.Open(currentFile); openErr == nil {
		defer old.Close()
		backup, createErr := os.CreateTemp(filepath.Dir(backupFile), ".dynamic-forward-backup-*.tmp")
		if createErr != nil {
			return createErr
		}
		backupName := backup.Name()
		defer os.Remove(backupName)
		_, err = io.Copy(backup, old)
		if err == nil {
			err = backup.Sync()
		}
		if closeErr := backup.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(backupName, backupFile)
		}
		if err == nil {
			err = syncDirectory(filepath.Dir(backupFile))
		}
		if err != nil {
			return err
		}
	}
	if err := os.Rename(tmpName, currentFile); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(currentFile))
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
