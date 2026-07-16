package dynamic_domain_set

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotSwapChangesMatcher(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := newPlugin(Args{SnapshotFile: filepath.Join(dir, "current.json"), BackupFile: filepath.Join(dir, "backup.json"), AuthTokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	matcher := p.GetDomainMatcher()
	if _, ok := matcher.Match("example.cn"); ok {
		t.Fatal("empty initial set matched")
	}
	payload, err := json.Marshal(Snapshot{Version: 1, ExpectedCurrentVersion: 0, Rules: "example.cn\n"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/snapshot", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	p.router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := matcher.Match("www.example.cn"); !ok {
		t.Fatal("new snapshot was not visible through existing matcher")
	}
	if _, ok := matcher.Match("example.com"); ok {
		t.Fatal("unexpected domain matched")
	}
}
