// Package dynamic_ecs provides independently configurable ECS for each route.
package dynamic_ecs

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
)

const PluginType = "dynamic_ecs"

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
	Mask4                  int    `json:"mask4" yaml:"mask4"`
	Mask6                  int    `json:"mask6" yaml:"mask6"`
	Preset4                string `json:"preset4,omitempty" yaml:"preset4"`
	Preset6                string `json:"preset6,omitempty" yaml:"preset6"`
	// Preset is retained only to migrate snapshots written by the first ECS release.
	Preset string `json:"preset,omitempty" yaml:"preset"`
}

// LoadSnapshotFiles reads and normalizes a persisted dynamic_ecs snapshot.
// Current is preferred, backup is used if current is unreadable or invalid.
// The bool is false only when neither file exists.
func LoadSnapshotFiles(currentFile, backupFile string) (Snapshot, bool, error) {
	var failures []error
	found := false
	for _, filename := range []string{currentFile, backupFile} {
		data, err := os.ReadFile(filename)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		found = true
		if err != nil {
			failures = append(failures, fmt.Errorf("read %s: %w", filename, err))
			continue
		}
		var snapshot Snapshot
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&snapshot); err != nil {
			failures = append(failures, fmt.Errorf("parse %s: %w", filename, err))
			continue
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			failures = append(failures, fmt.Errorf("parse %s: trailing JSON", filename))
			continue
		}
		if snapshot.Version == 0 {
			failures = append(failures, fmt.Errorf("validate %s: version must be positive", filename))
			continue
		}
		snapshot, err = canonical(snapshot)
		if err != nil {
			failures = append(failures, fmt.Errorf("validate %s: %w", filename, err))
			continue
		}
		return snapshot, true, nil
	}
	if !found {
		return Snapshot{}, false, nil
	}
	return Snapshot{}, true, errors.Join(failures...)
}

// Config is the reusable ECS configuration embedded by dynamic runtimes.
type Config struct {
	Mode    string `json:"mode" yaml:"mode"`
	Mask4   int    `json:"mask4" yaml:"mask4"`
	Mask6   int    `json:"mask6" yaml:"mask6"`
	Preset4 string `json:"preset4,omitempty" yaml:"preset4"`
	Preset6 string `json:"preset6,omitempty" yaml:"preset6"`
}

func CanonicalConfig(config Config) (Config, error) {
	value, err := canonical(Snapshot{Version: 1, Mode: config.Mode, Mask4: config.Mask4, Mask6: config.Mask6, Preset4: config.Preset4, Preset6: config.Preset6})
	if err != nil {
		return Config{}, err
	}
	return Config{Mode: value.Mode, Mask4: value.Mask4, Mask6: value.Mask6, Preset4: value.Preset4, Preset6: value.Preset6}, nil
}

// ApplyConfig adds ECS to qCtx without owning any mutable plugin state.
func ApplyConfig(qCtx *query_context.Context, config Config) error {
	value := Snapshot{Version: 1, Mode: config.Mode, Mask4: config.Mask4, Mask6: config.Mask6, Preset4: config.Preset4, Preset6: config.Preset6}
	p := &Plugin{}
	p.snapshot.Store(&value)
	return p.Exec(context.Background(), qCtx)
}

type Plugin struct {
	snapshot                 atomic.Pointer[Snapshot]
	token                    []byte
	snapshotFile, backupFile string
	mu                       sync.Mutex
}

var _ sequence.Executable = (*Plugin)(nil)

func init() { coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) }) }
func Init(bp *coremain.BP, raw any) (any, error) {
	args := raw.(*Args)
	token, err := os.ReadFile(args.AuthTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read auth_token_file: %w", err)
	}
	p := &Plugin{token: []byte(strings.TrimSpace(string(token))), snapshotFile: args.SnapshotFile, backupFile: args.BackupFile}
	if len(p.token) == 0 {
		return nil, errors.New("auth_token_file is empty")
	}
	if p.snapshotFile == "" || p.backupFile == "" || p.snapshotFile == p.backupFile {
		return nil, errors.New("snapshot_file and backup_file are required")
	}
	var snapshot Snapshot
	for _, filename := range []string{p.snapshotFile, p.backupFile} {
		data, readErr := os.ReadFile(filename)
		if readErr == nil && json.Unmarshal(data, &snapshot) == nil {
			break
		}
	}
	if snapshot.Version == 0 {
		snapshot = args.Initial
	}
	snapshot, err = canonical(snapshot)
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
func canonical(value Snapshot) (Snapshot, error) {
	if value.Version == 0 {
		value.Version = 1
	}
	if value.Mode == "" {
		value.Mode = "off"
	}
	if value.Mode != "off" && value.Mode != "client_subnet" && value.Mode != "fixed_subnet" {
		return Snapshot{}, errors.New("mode must be off, client_subnet or fixed_subnet")
	}
	if value.Mask4 == 0 {
		value.Mask4 = 24
	}
	if value.Mask6 == 0 {
		value.Mask6 = 48
	}
	if value.Mask4 < 0 || value.Mask4 > 32 || value.Mask6 < 0 || value.Mask6 > 128 {
		return Snapshot{}, errors.New("invalid ECS mask")
	}
	value.Preset4, value.Preset6, value.Preset = strings.TrimSpace(value.Preset4), strings.TrimSpace(value.Preset6), strings.TrimSpace(value.Preset)
	if value.Mode == "fixed_subnet" {
		if value.Preset != "" {
			prefix, err := netip.ParsePrefix(value.Preset)
			if err != nil {
				return Snapshot{}, errors.New("preset must be a valid CIDR")
			}
			if prefix.Addr().Is4() {
				value.Preset4 = prefix.Masked().String()
			} else {
				value.Preset6 = prefix.Masked().String()
			}
			value.Preset = ""
		}
		if value.Preset4 == "" && value.Preset6 == "" {
			return Snapshot{}, errors.New("at least one fixed subnet is required")
		}
		for _, item := range []struct {
			value string
			want4 bool
		}{{value.Preset4, true}, {value.Preset6, false}} {
			if item.value == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(item.value)
			if err != nil || prefix.Addr().Is4() != item.want4 {
				return Snapshot{}, errors.New("fixed subnets must be valid IPv4 or IPv6 CIDRs")
			}
			if item.want4 {
				value.Preset4 = prefix.Masked().String()
			} else {
				value.Preset6 = prefix.Masked().String()
			}
		}
	} else if value.Preset4 != "" || value.Preset6 != "" || value.Preset != "" {
		return Snapshot{}, errors.New("fixed subnets are only allowed for fixed_subnet")
	}
	value.ExpectedCurrentVersion = 0
	return value, nil
}
func (p *Plugin) Exec(_ context.Context, qCtx *query_context.Context) error {
	value := p.snapshot.Load()
	if value == nil || value.Mode == "off" {
		return nil
	}
	opt := qCtx.QOpt()
	for _, item := range opt.Option {
		if item.Option() == dns.EDNS0SUBNET {
			return nil
		}
	}
	if qCtx.QQuestion().Qclass != dns.ClassINET {
		return nil
	}
	var addr netip.Addr
	bits := value.Mask6
	if value.Mode == "fixed_subnet" {
		preset := value.Preset6
		if qCtx.ServerMeta.ClientAddr.Unmap().Is4() {
			preset = value.Preset4
		}
		if preset == "" {
			return nil
		}
		prefix, _ := netip.ParsePrefix(preset)
		addr = prefix.Addr()
		bits = prefix.Bits()
	} else {
		addr = qCtx.ServerMeta.ClientAddr.Unmap()
	}
	if !addr.IsValid() {
		return nil
	}
	family := uint16(2)
	if addr.Is4() {
		bits, family = value.Mask4, 1
		if value.Mode == "fixed_subnet" {
			prefix, _ := netip.ParsePrefix(value.Preset4)
			bits = prefix.Bits()
		}
	}
	masked := netip.PrefixFrom(addr, bits).Masked().Addr()
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: family, SourceNetmask: uint8(bits), SourceScope: 0, Address: net.IP(masked.AsSlice())})
	return nil
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
		http.Error(w, "persist ECS snapshot", http.StatusInternalServerError)
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
	tmp, err := os.CreateTemp(filepath.Dir(currentFile), ".dynamic-ecs-*.tmp")
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
		backup, createErr := os.CreateTemp(filepath.Dir(backupFile), ".dynamic-ecs-backup-*.tmp")
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
