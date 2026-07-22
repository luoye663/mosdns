package dynamic_address_family

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestOnlyModesReturnEmptySuccessWithoutCallingNext(t *testing.T) {
	for _, test := range []struct {
		name, mode string
		qtype      uint16
	}{
		{name: "IPv4 only blocks AAAA", mode: ModeIPv4Only, qtype: dns.TypeAAAA},
		{name: "IPv6 only blocks A", mode: ModeIPv6Only, qtype: dns.TypeA},
	} {
		t.Run(test.name, func(t *testing.T) {
			plugin := new(Plugin)
			plugin.snapshot.Store(&Snapshot{Version: 1, Mode: test.mode})
			query := new(dns.Msg)
			query.SetQuestion("example.com.", test.qtype)
			qCtx := query_context.NewContext(query)
			called := false
			next := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
				called = true
				return nil
			})}}, nil)
			if err := plugin.Exec(context.Background(), qCtx, next); err != nil {
				t.Fatal(err)
			}
			if called || qCtx.R() == nil || qCtx.R().Rcode != dns.RcodeSuccess || len(qCtx.R().Answer) != 0 {
				t.Fatalf("called=%t response=%+v", called, qCtx.R())
			}
		})
	}
}

func TestDualStackDelegates(t *testing.T) {
	plugin := new(Plugin)
	plugin.snapshot.Store(&Snapshot{Version: 1, Mode: ModeDualStack})
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(query)
	called := false
	next := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
		called = true
		return nil
	})}}, nil)
	if err := plugin.Exec(context.Background(), qCtx, next); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("next chain was not called")
	}
}

func TestCanonicalRejectsInvalidMode(t *testing.T) {
	if _, err := canonical(Snapshot{Mode: "invalid"}); err == nil {
		t.Fatal("invalid mode was accepted")
	}
}

func TestLoadSnapshotFallsBackFromInvalidPrimary(t *testing.T) {
	directory := t.TempDir()
	primary := filepath.Join(directory, "primary.json")
	backup := filepath.Join(directory, "backup.json")
	if err := os.WriteFile(primary, []byte(`{"version":2,"mode":"invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte(`{"version":1,"mode":"ipv6_only"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := loadSnapshot(primary, backup, Snapshot{Version: 1, Mode: ModeDualStack})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Mode != ModeIPv6Only || snapshot.Version != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestSnapshotAPIRequiresAuthenticationAndPersists(t *testing.T) {
	directory := t.TempDir()
	plugin := &Plugin{
		token:        []byte("test-token"),
		snapshotFile: filepath.Join(directory, "snapshot.json"),
		backupFile:   filepath.Join(directory, "backup.json"),
	}
	plugin.snapshot.Store(&Snapshot{Version: 1, Mode: ModeDualStack})
	router := plugin.router()

	request := httptest.NewRequest(http.MethodGet, "/status", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPut, "/snapshot", bytes.NewBufferString(`{"version":2,"expected_current_version":1,"mode":"ipv4_only"}`))
	request.Header.Set("Authorization", "Bearer test-token")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", response.Code, response.Body.String())
	}
	if current := plugin.snapshot.Load(); current.Version != 2 || current.Mode != ModeIPv4Only {
		t.Fatalf("snapshot=%+v", current)
	}
	if _, err := os.Stat(plugin.snapshotFile); err != nil {
		t.Fatalf("snapshot was not persisted: %v", err)
	}

	request = httptest.NewRequest(http.MethodPut, "/snapshot", bytes.NewBufferString(`{"version":3,"expected_current_version":1,"mode":"ipv6_only"}`))
	request.Header.Set("Authorization", "Bearer test-token")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d", response.Code)
	}
}
