// Package dynamic_domain_set provides an atomically swappable domain matcher.
package dynamic_domain_set

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/go-chi/chi/v5"
)

const PluginType = "dynamic_domain_set"

type Args struct {
	SnapshotFile  string `yaml:"snapshot_file"`
	BackupFile    string `yaml:"backup_file"`
	AuthTokenFile string `yaml:"auth_token_file"`
	InitialFile   string `yaml:"initial_file"`
	MaxBytes      int64  `yaml:"max_bytes"`
}

type Snapshot struct {
	Version                uint64 `json:"version"`
	ExpectedCurrentVersion uint64 `json:"expected_current_version"`
	Checksum               string `json:"checksum,omitempty"`
	Rules                  string `json:"rules"`
}

type compiledSnapshot struct {
	snapshot Snapshot
	matcher  *domain.MixMatcher[struct{}]
	count    int
	loadedAt time.Time
}

type dynamicMatcher struct {
	current *atomic.Pointer[compiledSnapshot]
}

func (m dynamicMatcher) Match(name string) (struct{}, bool) {
	snapshot := m.current.Load()
	if snapshot == nil {
		return struct{}{}, false
	}
	return snapshot.matcher.Match(name)
}

type Plugin struct {
	current      atomic.Pointer[compiledSnapshot]
	applyMu      sync.Mutex
	token        []byte
	snapshotFile string
	backupFile   string
	maxBytes     int64
}

var memorySweepScheduled atomic.Bool

var _ data_provider.DomainMatcherProvider = (*Plugin)(nil)

func init() { coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) }) }

func Init(bp *coremain.BP, raw any) (any, error) {
	args, ok := raw.(*Args)
	if !ok {
		return nil, fmt.Errorf("invalid dynamic_domain_set arguments %T", raw)
	}
	p, err := newPlugin(*args)
	if err != nil {
		return nil, err
	}
	bp.RegAPI(p.router())
	return p, nil
}

func newPlugin(args Args) (*Plugin, error) {
	if args.SnapshotFile == "" || args.BackupFile == "" || args.AuthTokenFile == "" || args.SnapshotFile == args.BackupFile {
		return nil, errors.New("snapshot_file, backup_file and auth_token_file are required and snapshot files must differ")
	}
	if args.MaxBytes == 0 {
		args.MaxBytes = 20 << 20
	}
	if args.MaxBytes < 1 || args.MaxBytes > 20<<20 {
		return nil, errors.New("max_bytes must be within 1..20971520")
	}
	token, err := os.ReadFile(args.AuthTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read auth_token_file: %w", err)
	}
	p := &Plugin{token: []byte(strings.TrimSpace(string(token))), snapshotFile: args.SnapshotFile, backupFile: args.BackupFile, maxBytes: args.MaxBytes}
	if len(p.token) == 0 {
		return nil, errors.New("auth_token_file is empty")
	}
	for _, path := range []string{args.SnapshotFile, args.BackupFile, args.InitialFile} {
		if path == "" {
			continue
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		var snapshot Snapshot
		if path == args.InitialFile {
			snapshot = Snapshot{Version: 0, Rules: string(data)}
		} else if json.Unmarshal(data, &snapshot) != nil {
			continue
		}
		compiled, compileErr := compile(snapshot, p.maxBytes)
		if compileErr == nil {
			p.current.Store(compiled)
			return p, nil
		}
	}
	compiled, err := compile(Snapshot{Version: 0, Rules: ""}, p.maxBytes)
	if err != nil {
		return nil, err
	}
	p.current.Store(compiled)
	return p, nil
}

func (p *Plugin) GetDomainMatcher() domain.Matcher[struct{}] {
	return dynamicMatcher{current: &p.current}
}

func compile(snapshot Snapshot, maxBytes int64) (*compiledSnapshot, error) {
	if int64(len(snapshot.Rules)) > maxBytes {
		return nil, errors.New("rules exceed configured byte limit")
	}
	matcher := domain.NewDomainMixMatcher()
	// Subscription files commonly contain bare domains. Treat those as suffix
	// matches while retaining explicit domain_set expressions when present.
	matcher.SetDefaultMatcher(domain.MatcherDomain)
	if err := domain.LoadFromTextReader[struct{}](matcher, strings.NewReader(snapshot.Rules), nil); err != nil {
		return nil, fmt.Errorf("parse domain rules: %w", err)
	}
	snapshot.ExpectedCurrentVersion = 0
	snapshot.Checksum = ""
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	snapshot.Checksum = "sha256:" + hex.EncodeToString(sum[:])
	return &compiledSnapshot{snapshot: snapshot, matcher: matcher, count: matcher.Len(), loadedAt: time.Now().UTC()}, nil
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
	current := p.current.Load()
	writeJSON(w, http.StatusOK, map[string]any{"version": current.snapshot.Version, "checksum": current.snapshot.Checksum, "rule_count": current.count, "loaded_at": current.loadedAt})
}

func (p *Plugin) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	// JSON escaping can make a valid 20 MiB text source larger on the wire.
	// The payload follows the controller-wide 64 MiB API limit; compile still enforces maxBytes for Rules.
	const maxRequestBytes int64 = 64 << 20
	data, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil || int64(len(data)) > maxRequestBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds limit")
		return
	}
	var requested Snapshot
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&requested); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid snapshot")
		return
	}
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	current := p.current.Load()
	if requested.ExpectedCurrentVersion != current.snapshot.Version {
		writeJSON(w, http.StatusConflict, map[string]uint64{"current_version": current.snapshot.Version})
		return
	}
	if requested.Version <= current.snapshot.Version {
		writeError(w, http.StatusBadRequest, "version must increase")
		return
	}
	next, err := compile(requested, p.maxBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := persist(next.snapshot, p.snapshotFile, p.backupFile); err != nil {
		writeError(w, http.StatusInternalServerError, "persist snapshot: "+err.Error())
		return
	}
	p.current.Store(next)
	scheduleMemorySweep()
	p.handleStatus(w, r)
}

// Large source updates temporarily retain both matchers while compiling. Run a
// coalesced control-plane sweep after the pointer swap so unused heap pages can
// be returned without delaying DNS execution or the API response.
func scheduleMemorySweep() {
	if !memorySweepScheduled.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer memorySweepScheduled.Store(false)
		debug.FreeOSMemory()
	}()
}

func persist(snapshot Snapshot, currentFile, backupFile string) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	for _, path := range []string{currentFile, backupFile} {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
	}
	write := func(path string, content []byte) error {
		tmp, err := os.CreateTemp(filepath.Dir(path), ".dynamic-domain-set-*.tmp")
		if err != nil {
			return err
		}
		name := tmp.Name()
		defer os.Remove(name)
		if _, err = tmp.Write(content); err == nil {
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
		if err = os.Rename(name, path); err != nil {
			return err
		}
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	}
	if prior, err := os.ReadFile(currentFile); err == nil {
		if err := write(backupFile, prior); err != nil {
			return err
		}
	}
	return write(currentFile, data)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
