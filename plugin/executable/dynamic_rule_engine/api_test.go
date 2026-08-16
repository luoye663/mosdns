package dynamic_rule_engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

func newTestPlugin(t *testing.T, failOpen bool) (*Plugin, Args) {
	t.Helper()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := Args{
		SnapshotFile:  filepath.Join(dir, "current.json"),
		BackupFile:    filepath.Join(dir, "backup.json"),
		AuthTokenFile: tokenFile,
		FailOpen:      failOpen,
	}
	p, err := newPlugin(args)
	if err != nil {
		t.Fatal(err)
	}
	return p, args
}

func apiRequest(t *testing.T, p *Plugin, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	p.router().ServeHTTP(recorder, req)
	return recorder
}

func phase4Snapshot(version, expected uint64) Snapshot {
	return Snapshot{
		SchemaVersion: SchemaVersion, Version: version, ExpectedCurrentVersion: expected, BlockRCode: dns.RcodeNameError,
		Rules:            []Rule{{ID: int64(version), Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeFull, Pattern: "blocked.example"}},
		SubscriptionSets: []SubscriptionSet{routeBinding(1000+int64(version), int64(version), "published_group", 1, "blocked.example")},
	}
}

func TestAPIAuthenticationApplyAndStatusReconcile(t *testing.T) {
	p, _ := newTestPlugin(t, true)
	if response := apiRequest(t, p, http.MethodGet, "/status", nil, "wrong"); response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d", response.Code)
	}
	if response := apiRequest(t, p, http.MethodPut, "/snapshot", phase4Snapshot(1, 0), "test-token"); response.Code != http.StatusOK {
		t.Fatalf("apply status = %d, body = %s", response.Code, response.Body.String())
	}
	// 模拟 controller 在收到响应前断开后，通过 status 对账已发布版本。
	response := apiRequest(t, p, http.MethodGet, "/status", nil, "test-token")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var status statusResponse
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.State != "ready" || status.SnapshotVersion != 1 || !status.SnapshotFileOK || status.MemoryRSSBytes <= 0 {
		t.Fatalf("unexpected runtime status: %+v", status)
	}
}

func TestAPIRejectsUnknownJSONFields(t *testing.T) {
	p, _ := newTestPlugin(t, true)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewBufferString(`{"schema_version":4,"version":1,"block_rcode":3,"rules":[],"typo":true}`))
	req.Header.Set("Authorization", "Bearer test-token")
	recorder := httptest.NewRecorder()
	p.router().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestAPIVersionConflictAndPersistFailureDoNotSwap(t *testing.T) {
	p, _ := newTestPlugin(t, true)
	if response := apiRequest(t, p, http.MethodPut, "/snapshot", phase4Snapshot(1, 0), "test-token"); response.Code != http.StatusOK {
		t.Fatalf("initial apply = %d: %s", response.Code, response.Body.String())
	}
	if response := apiRequest(t, p, http.MethodPut, "/snapshot", phase4Snapshot(2, 0), "test-token"); response.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d", response.Code)
	}
	p.persist = func(Snapshot) error { return errors.New("disk unavailable") }
	if response := apiRequest(t, p, http.MethodPut, "/snapshot", phase4Snapshot(2, 1), "test-token"); response.Code != http.StatusInternalServerError {
		t.Fatalf("persist failure status = %d", response.Code)
	}
	if current := p.store.Load(); current == nil || current.Version() != 1 {
		t.Fatalf("current snapshot changed after persistence failure: %+v", current)
	}
}

func TestStartupFallsBackToBackupAndFailOpen(t *testing.T) {
	p, args := newTestPlugin(t, true)
	canonical, _, err := canonicalSnapshot(phase4Snapshot(1, 0), p.limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistSnapshot(canonical, args.SnapshotFile, args.BackupFile); err != nil {
		t.Fatal(err)
	}
	canonical.Version = 2
	canonical.ExpectedCurrentVersion = 1
	canonical.Checksum = ""
	canonical, _, err = canonicalSnapshot(canonical, p.limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistSnapshot(canonical, args.SnapshotFile, args.BackupFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(args.SnapshotFile, []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newPlugin(args)
	if err != nil {
		t.Fatal(err)
	}
	if current := reloaded.store.Load(); current == nil || current.Version() != 1 || reloaded.state() != "ready" {
		t.Fatalf("backup recovery failed: snapshot=%+v state=%s", current, reloaded.state())
	}
	brokenArgs := args
	brokenArgs.SnapshotFile = filepath.Join(t.TempDir(), "missing.json")
	brokenArgs.BackupFile = filepath.Join(t.TempDir(), "missing.bak")
	degraded, err := newPlugin(brokenArgs)
	if err != nil {
		t.Fatal(err)
	}
	if degraded.state() != "degraded" || degraded.store.Load() != nil {
		t.Fatalf("fail-open state = %s snapshot=%+v", degraded.state(), degraded.store.Load())
	}
}

func TestExecWritesMarksAndRuntimeMetadata(t *testing.T) {
	p, _ := newTestPlugin(t, true)
	compiled, err := Compile(Snapshot{
		SchemaVersion: SchemaVersion, Version: 1, BlockRCode: 3,
		Rules: []Rule{
			{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeFull, Pattern: "example.com"},
			{ID: 2, Category: CategoryRoute, Action: ActionUpstream, UpstreamGroupID: "manual_group", MatchType: MatchTypeFull, Pattern: "example.com"},
			{ID: 3, Category: CategoryLogging, Action: ActionNoLog, MatchType: MatchTypeFull, Pattern: "example.com"},
		},
	}, p.limits)
	if err != nil {
		t.Fatal(err)
	}
	p.store.Swap(compiled)
	message := new(dns.Msg)
	message.SetQuestion("example.com.", dns.TypeA)
	qCtx := query_context.NewContext(message)
	if err := p.Exec(t.Context(), qCtx); err != nil {
		t.Fatal(err)
	}
	groupID, groupOK := query_context.UpstreamGroupID(qCtx)
	if !qCtx.HasMark(p.marks.AccessBlock) || !qCtx.HasMark(p.marks.NoLog) || !groupOK || groupID != "manual_group" {
		t.Fatal("required dynamic rule marks were not written")
	}
	decision, ok := RuntimeDecisionFromContext(qCtx)
	if !ok || decision.SnapshotVersion != 1 || decision.AccessRuleID != 1 || decision.RouteRuleID != 2 || decision.LoggingRuleID != 3 {
		t.Fatalf("runtime decision = %+v, present=%t", decision, ok)
	}
}

func TestExecWritesSubscriptionBinding(t *testing.T) {
	p, _ := newTestPlugin(t, true)
	snapshot := testSnapshot()
	snapshot.SubscriptionSets = []SubscriptionSet{routeBinding(7, 11, "custom_group", 1, "example.com")}
	compiled, err := Compile(snapshot, p.limits)
	if err != nil {
		t.Fatal(err)
	}
	p.store.Swap(compiled)
	message := new(dns.Msg)
	message.SetQuestion("www.example.com.", dns.TypeA)
	qCtx := query_context.NewContext(message)
	if err := p.Exec(t.Context(), qCtx); err != nil {
		t.Fatal(err)
	}
	groupID, ok := query_context.UpstreamGroupID(qCtx)
	decision, decisionOK := RuntimeDecisionFromContext(qCtx)
	if !ok || groupID != "custom_group" || !decisionOK || decision.RouteSource != "subscription" || decision.BindingID != 11 || decision.UpstreamGroupID != "custom_group" {
		t.Fatalf("group=%q ok=%t decision=%+v present=%t", groupID, ok, decision, decisionOK)
	}
}

func TestBindingCASPersistenceAndMatchAPI(t *testing.T) {
	p, args := newTestPlugin(t, true)
	snapshot := testSnapshot()
	snapshot.SubscriptionSets = []SubscriptionSet{routeBinding(7, 11, "custom_group", 1, "example.com")}
	if response := apiRequest(t, p, http.MethodPut, "/snapshot", snapshot, "test-token"); response.Code != http.StatusOK {
		t.Fatalf("apply status = %d: %s", response.Code, response.Body.String())
	}
	snapshot.Version = 2
	snapshot.ExpectedCurrentVersion = 0
	snapshot.Checksum = ""
	if response := apiRequest(t, p, http.MethodPut, "/snapshot", snapshot, "test-token"); response.Code != http.StatusConflict {
		t.Fatalf("stale apply status = %d", response.Code)
	}
	data, err := os.ReadFile(args.SnapshotFile)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := ParseSnapshot(data)
	if err != nil || len(persisted.SubscriptionSets) != 1 || persisted.SubscriptionSets[0].BindingID != 11 || persisted.SubscriptionSets[0].UpstreamGroupID != "custom_group" || persisted.Checksum == "" {
		t.Fatalf("persisted snapshot = %+v, err=%v", persisted, err)
	}
	response := apiRequest(t, p, http.MethodPost, "/match", matchRequest{QName: "www.example.com"}, "test-token")
	var matched matchResponse
	if response.Code != http.StatusOK || json.NewDecoder(response.Body).Decode(&matched) != nil || matched.Route.SubscriptionBindingID != 11 || matched.Route.UpstreamGroupID != "custom_group" || matched.Route.Source != "subscription" {
		t.Fatalf("match response status=%d value=%+v body=%s", response.Code, matched, response.Body.String())
	}
}

func TestConcurrentApplyAndMatch(t *testing.T) {
	p, _ := newTestPlugin(t, true)
	if response := apiRequest(t, p, http.MethodPut, "/snapshot", phase4Snapshot(1, 0), "test-token"); response.Code != http.StatusOK {
		t.Fatalf("initial apply = %d", response.Code)
	}
	var wg sync.WaitGroup
	for version := uint64(2); version < 10; version++ {
		wg.Add(1)
		go func(version uint64) {
			defer wg.Done()
			response := apiRequest(t, p, http.MethodPut, "/snapshot", phase4Snapshot(version, 1), "test-token")
			if response.Code != http.StatusOK && response.Code != http.StatusConflict {
				t.Errorf("apply version %d status = %d", version, response.Code)
			}
		}(version)
	}
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := apiRequest(t, p, http.MethodPost, "/match", matchRequest{QName: "blocked.example"}, "test-token")
			if response.Code != http.StatusOK {
				t.Errorf("match status = %d", response.Code)
			}
		}()
	}
	wg.Wait()
}
