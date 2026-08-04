package dynamic_forward

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestSnapshotAPIHotSwapsAndPersists(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := Args{SnapshotFile: filepath.Join(dir, "current.json"), BackupFile: filepath.Join(dir, "backup.json"), AuthTokenFile: tokenFile, Initial: Snapshot{Version: 1, Concurrent: 1, Upstreams: []Upstream{{Tag: "first", Addr: "https://dns.example/dns-query"}}}}
	p, err := newPlugin(args, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/snapshot", bytes.NewBufferString(`{"version":2,"expected_current_version":1,"concurrent":1,"upstreams":[{"tag":"second","addr":"https://dns2.example/dns-query"}]}`))
	request.Header.Set("Authorization", "Bearer test-token")
	recorder := httptest.NewRecorder()
	p.router().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var applied Snapshot
	if err := json.NewDecoder(recorder.Body).Decode(&applied); err != nil {
		t.Fatal(err)
	}
	if applied.Version != 2 || applied.ExpectedCurrentVersion != 0 || applied.Upstreams[0].Tag != "second" {
		t.Fatalf("applied=%+v", applied)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newPlugin(args, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	if got := reloaded.snapshot.Load(); got.Version != 2 || got.Upstreams[0].Tag != "second" {
		t.Fatalf("reloaded=%+v", got)
	}
}

func TestSnapshotAPIRejectsUnauthorizedAndStaleUpdate(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := newPlugin(Args{SnapshotFile: filepath.Join(dir, "current.json"), BackupFile: filepath.Join(dir, "backup.json"), AuthTokenFile: tokenFile, Initial: Snapshot{Version: 1, Concurrent: 1, Upstreams: []Upstream{{Tag: "first", Addr: "https://dns.example/dns-query"}}}}, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, test := range []struct {
		token string
		want  int
	}{{"", http.StatusUnauthorized}, {"Bearer test-token", http.StatusConflict}} {
		req := httptest.NewRequest(http.MethodPut, "/snapshot", bytes.NewBufferString(`{"version":2,"expected_current_version":0,"concurrent":1,"upstreams":[{"tag":"next","addr":"https://dns.example/dns-query"}]}`))
		if test.token != "" {
			req.Header.Set("Authorization", test.token)
		}
		rec := httptest.NewRecorder()
		p.router().ServeHTTP(rec, req)
		if rec.Code != test.want {
			t.Fatalf("token=%q status=%d", test.token, rec.Code)
		}
	}
}

func TestCanonicalSnapshotDefaultsAndValidatesScheduling(t *testing.T) {
	snapshot, err := canonical(Snapshot{Version: 1, Concurrent: 1, Upstreams: []Upstream{{Tag: "first", Addr: "https://dns.example/dns-query"}}})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Mode != "race" || snapshot.Upstreams[0].Priority != 100 || snapshot.Upstreams[0].Weight != 1 {
		t.Fatalf("defaults=%+v", snapshot)
	}
	if _, err := canonical(Snapshot{Version: 1, Mode: "unknown", Concurrent: 1, Upstreams: snapshot.Upstreams}); err == nil {
		t.Fatal("invalid mode was accepted")
	}
}

func TestCanonicalSnapshotNormalizesDefaultUDPAddresses(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "IPv4", addr: "8.8.8.8", want: "udp://8.8.8.8"},
		{name: "IPv4 with port", addr: "8.8.8.8:5353", want: "udp://8.8.8.8:5353"},
		{name: "hostname", addr: "dns.example", want: "udp://dns.example"},
		{name: "IPv6", addr: "2001:4860:4860::8888", want: "udp://[2001:4860:4860::8888]"},
		{name: "IPv6 with port", addr: "[2001:4860:4860::8888]:5353", want: "udp://[2001:4860:4860::8888]:5353"},
		{name: "explicit protocol", addr: "tcp://8.8.8.8", want: "tcp://8.8.8.8"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := canonical(Snapshot{Version: 1, Concurrent: 1, Upstreams: []Upstream{{Tag: "first", Addr: test.addr}}})
			if err != nil {
				t.Fatal(err)
			}
			if got := snapshot.Upstreams[0].Addr; got != test.want {
				t.Fatalf("address=%q, want %q", got, test.want)
			}
		})
	}
}

func TestCanonicalSnapshotRejectsInvalidAddresses(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{addr: "", want: "address must be a valid"},
		{addr: "ftp://8.8.8.8", want: "unsupported scheme"},
	}
	for _, test := range tests {
		_, err := canonical(Snapshot{Version: 1, Concurrent: 1, Upstreams: []Upstream{{Tag: "first", Addr: test.addr}}})
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("address=%q error=%v, want substring %q", test.addr, err, test.want)
		}
	}
}

func TestPriorityLevelsSortAscending(t *testing.T) {
	levels := priorityLevels([]Upstream{{Tag: "backup", Priority: 200}, {Tag: "primary-a", Priority: 100}, {Tag: "primary-b", Priority: 100}})
	if len(levels) != 2 || len(levels[0]) != 2 || levels[0][0] != "primary-a" || levels[1][0] != "backup" {
		t.Fatalf("levels=%v", levels)
	}
}
