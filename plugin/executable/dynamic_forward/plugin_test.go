package dynamic_forward

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
