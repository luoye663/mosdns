// Package dynamic_address_family controls global A and AAAA response policy.
package dynamic_address_family

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
	"strings"
	"sync"
	"sync/atomic"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dual_selector"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
)

const PluginType = "dynamic_address_family"

const (
	ModeDualStack  = "dual_stack"
	ModePreferIPv4 = "prefer_ipv4"
	ModePreferIPv6 = "prefer_ipv6"
	ModeIPv4Only   = "ipv4_only"
	ModeIPv6Only   = "ipv6_only"
)

type Args struct {
	SnapshotFile  string   `yaml:"snapshot_file"`
	BackupFile    string   `yaml:"backup_file"`
	AuthTokenFile string   `yaml:"auth_token_file"`
	Initial       Snapshot `yaml:"initial"`
}

type Snapshot struct {
	Version                uint64 `json:"version" yaml:"version"`
	ExpectedCurrentVersion uint64 `json:"expected_current_version" yaml:"expected_current_version"`
	Mode                   string `json:"mode" yaml:"mode"`
}

type Plugin struct {
	snapshot                 atomic.Pointer[Snapshot]
	token                    []byte
	snapshotFile, backupFile string
	mu                       sync.Mutex
	preferIPv4               *dual_selector.Selector
	preferIPv6               *dual_selector.Selector
}

var _ sequence.RecursiveExecutable = (*Plugin)(nil)
var _ interface{ Close() error } = (*Plugin)(nil)

func init() { coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) }) }

func Init(bp *coremain.BP, raw any) (any, error) {
	args, ok := raw.(*Args)
	if !ok {
		return nil, fmt.Errorf("invalid dynamic_address_family arguments %T", raw)
	}
	token, err := os.ReadFile(args.AuthTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read auth_token_file: %w", err)
	}
	p := &Plugin{
		token:        []byte(strings.TrimSpace(string(token))),
		snapshotFile: args.SnapshotFile,
		backupFile:   args.BackupFile,
		preferIPv4:   dual_selector.NewPreferIpv4(bp),
		preferIPv6:   dual_selector.NewPreferIpv6(bp),
	}
	if len(p.token) == 0 {
		return nil, errors.New("auth_token_file is empty")
	}
	if p.snapshotFile == "" || p.backupFile == "" || p.snapshotFile == p.backupFile {
		return nil, errors.New("snapshot_file and backup_file are required")
	}

	snapshot, err := loadSnapshot(p.snapshotFile, p.backupFile, args.Initial)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(p.snapshotFile); errors.Is(err, os.ErrNotExist) {
		if err := persist(snapshot, p.snapshotFile, p.backupFile); err != nil {
			return nil, err
		}
	}
	p.snapshot.Store(&snapshot)
	bp.RegAPI(p.router())
	return p, nil
}

// loadSnapshot accepts only a syntactically and semantically valid persisted snapshot.
// A malformed primary must not prevent recovery from its last known-good backup.
func loadSnapshot(snapshotFile, backupFile string, initial Snapshot) (Snapshot, error) {
	for _, filename := range []string{snapshotFile, backupFile} {
		data, err := os.ReadFile(filename)
		if err != nil {
			continue
		}
		var snapshot Snapshot
		if err := json.Unmarshal(data, &snapshot); err != nil {
			continue
		}
		if snapshot, err = canonical(snapshot); err == nil {
			return snapshot, nil
		}
	}
	return canonical(initial)
}

func canonical(value Snapshot) (Snapshot, error) {
	if value.Version == 0 {
		value.Version = 1
	}
	if value.Mode == "" {
		value.Mode = ModeDualStack
	}
	switch value.Mode {
	case ModeDualStack, ModePreferIPv4, ModePreferIPv6, ModeIPv4Only, ModeIPv6Only:
	default:
		return Snapshot{}, errors.New("mode must be dual_stack, prefer_ipv4, prefer_ipv6, ipv4_only or ipv6_only")
	}
	value.ExpectedCurrentVersion = 0
	return value, nil
}

func (p *Plugin) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	snapshot := p.snapshot.Load()
	if snapshot == nil || snapshot.Mode == ModeDualStack || qCtx.QQuestion().Qclass != dns.ClassINET {
		return next.ExecNext(ctx, qCtx)
	}

	qtype := qCtx.QQuestion().Qtype
	switch snapshot.Mode {
	case ModePreferIPv4:
		return p.preferIPv4.Exec(ctx, qCtx, next)
	case ModePreferIPv6:
		return p.preferIPv6.Exec(ctx, qCtx, next)
	case ModeIPv4Only:
		if qtype == dns.TypeAAAA {
			qCtx.SetResponse(dnsutils.GenEmptyReply(qCtx.Q(), dns.RcodeSuccess))
			return nil
		}
	case ModeIPv6Only:
		if qtype == dns.TypeA {
			qCtx.SetResponse(dnsutils.GenEmptyReply(qCtx.Q(), dns.RcodeSuccess))
			return nil
		}
	}
	return next.ExecNext(ctx, qCtx)
}

func (p *Plugin) Close() error {
	return errors.Join(p.preferIPv4.Close(), p.preferIPv6.Close())
}

func (p *Plugin) router() *chi.Mux {
	r := chi.NewRouter()
	r.Use(p.authorize)
	r.Get("/status", p.status)
	r.Put("/snapshot", p.apply)
	return r
}

func (p *Plugin) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, prefix)), p.token) != 1 {
			http.Error(w, "authorization required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Plugin) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, p.snapshot.Load())
}

func (p *Plugin) apply(w http.ResponseWriter, r *http.Request) {
	var requested Snapshot
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4097))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&requested); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.snapshot.Load()
	if requested.ExpectedCurrentVersion != current.Version {
		writeJSON(w, http.StatusConflict, map[string]uint64{"current_version": current.Version})
		return
	}
	if requested.Version <= current.Version {
		http.Error(w, "version must increase", http.StatusBadRequest)
		return
	}
	next, err := canonical(requested)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := persist(next, p.snapshotFile, p.backupFile); err != nil {
		http.Error(w, "persist address family snapshot", http.StatusInternalServerError)
		return
	}
	p.snapshot.Store(&next)
	writeJSON(w, http.StatusOK, &next)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func persist(snapshot Snapshot, currentFile, backupFile string) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(currentFile), 0o750); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(backupFile), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(currentFile), ".dynamic-address-family-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(data); err == nil {
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
		backup, createErr := os.CreateTemp(filepath.Dir(backupFile), ".dynamic-address-family-backup-*.tmp")
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
		if err != nil {
			return err
		}
		if err = os.Rename(backupName, backupFile); err != nil {
			return err
		}
	}
	if err = os.Rename(tmpName, currentFile); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(currentFile))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
