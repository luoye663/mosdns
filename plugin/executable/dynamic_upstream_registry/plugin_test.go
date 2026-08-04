package dynamic_upstream_registry

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_ecs"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_forward"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_rule_engine"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type testDNSServer struct {
	addr     string
	requests atomic.Int32
	server   *dns.Server
}

func startDNSServer(t *testing.T, ip string, rcode int, observe func(*dns.Msg)) *testDNSServer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	result := &testDNSServer{addr: "udp://" + conn.LocalAddr().String()}
	result.server = &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		result.requests.Add(1)
		if observe != nil {
			observe(request)
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = rcode
		if ip != "" && rcode == dns.RcodeSuccess {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}}
		}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = result.server.ActivateAndServe() }()
	t.Cleanup(func() { _ = result.server.Shutdown() })
	return result
}

func group(id, name, addr string) Group {
	return Group{ID: id, Name: name, Enabled: true, Mode: "race", Concurrent: 1, Upstreams: []dynamic_forward.Upstream{{Tag: id + "_upstream", Addr: addr}}, ECS: dynamic_ecs.Config{Mode: "off"}, Cache: GroupCacheConfig{Enabled: true, Size: 1024}}
}

func snapshot(version uint64, groups ...Group) Snapshot {
	defaultGroupID := ""
	if len(groups) > 0 {
		defaultGroupID = groups[0].ID
	}
	return Snapshot{SchemaVersion: registrySchemaVersion, Version: version, DefaultGroupID: defaultGroupID, Groups: groups, Cache: GlobalCacheConfig{Enabled: true, Negative: NegativeCacheConfig{Enabled: true, TTL: 30}}}
}

func newTestPlugin(t *testing.T, initial Snapshot) (*Plugin, Args) {
	t.Helper()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("registry-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := Args{AuthTokenFile: tokenFile, SnapshotFile: filepath.Join(dir, "current.json"), BackupFile: filepath.Join(dir, "backup.json"), InitialSnapshot: initial}
	p, err := newPlugin(args, zap.NewNop(), "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, args
}

func newTestArgs(t *testing.T, initial Snapshot) (Args, string) {
	t.Helper()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("registry-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Args{AuthTokenFile: tokenFile, SnapshotFile: filepath.Join(dir, "registry-current.json"), BackupFile: filepath.Join(dir, "registry-backup.json"), InitialSnapshot: initial}, dir
}

func query(name string) *query_context.Context {
	message := new(dns.Msg)
	message.SetQuestion(name, dns.TypeA)
	return query_context.NewContext(message)
}

func answerIP(t *testing.T, qCtx *query_context.Context) string {
	t.Helper()
	if qCtx.R() == nil || len(qCtx.R().Answer) != 1 {
		t.Fatalf("response = %#v", qCtx.R())
	}
	return qCtx.R().Answer[0].(*dns.A).A.String()
}

func authorizedRequest(method, path string, body []byte) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer registry-token")
	return req
}

func applySnapshot(t *testing.T, p *Plugin, value Snapshot) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	p.router().ServeHTTP(recorder, authorizedRequest(http.MethodPut, "/snapshot", body))
	return recorder
}

func TestCanonicalSnapshotValidation(t *testing.T) {
	validGroup := group("default", "Default", "udp://127.0.0.1:53")
	valid := snapshot(1, validGroup)
	canonical, err := canonicalWithoutRuntime(valid)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.Groups[0].Mode != "race" || canonical.Cache.Negative.TTL != 30 {
		t.Fatalf("canonical = %+v", canonical)
	}
	for name, mutate := range map[string]func(*Snapshot){
		"schema":           func(s *Snapshot) { s.SchemaVersion = 0 },
		"version":          func(s *Snapshot) { s.Version = 0 },
		"id":               func(s *Snapshot) { s.Groups[0].ID = "Invalid" },
		"missing default":  func(s *Snapshot) { s.DefaultGroupID = "missing" },
		"disabled default": func(s *Snapshot) { s.Groups[0].Enabled = false },
		"cache total":      func(s *Snapshot) { s.Groups[0].Cache.Size = maximumCacheEntries + 1 },
		"ecs":              func(s *Snapshot) { s.Groups[0].ECS = dynamic_ecs.Config{Mode: "fixed_subnet"} },
		"mode":             func(s *Snapshot) { s.Groups[0].Mode = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			value.Groups = append([]Group(nil), valid.Groups...)
			mutate(&value)
			if _, err := canonicalWithoutRuntime(value); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
}

func TestRegistryRejectsPersistedSnapshotWithoutSchemaVersion(t *testing.T) {
	initial := snapshot(1, group("default", "Default", "udp://127.0.0.1:53"))
	args, _ := newTestArgs(t, initial)
	if err := os.WriteFile(args.SnapshotFile, []byte(`{"version":1,"groups":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newPlugin(args, zap.NewNop(), "missing-schema"); err == nil {
		t.Fatal("persisted registry snapshot without schema_version was accepted")
	}
}

func TestSelectionPriorityAndMetadata(t *testing.T) {
	def := startDNSServer(t, "192.0.2.1", dns.RcodeSuccess, nil)
	custom := startDNSServer(t, "192.0.2.4", dns.RcodeSuccess, nil)
	p, _ := newTestPlugin(t, snapshot(1, group("default", "Default Group", def.addr), group("custom", "Custom", custom.addr)))
	for _, test := range []struct {
		name, wantIP, wantID, source string
		setup                        func(*query_context.Context)
	}{
		{name: "default", wantIP: "192.0.2.1", wantID: "default", source: "default", setup: func(*query_context.Context) {}},
		{name: "explicit", wantIP: "192.0.2.4", wantID: "custom", source: "subscription", setup: func(q *query_context.Context) {
			query_context.SetUpstreamGroupID(q, "custom")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			qCtx := query(test.name + ".example.")
			test.setup(qCtx)
			if err := p.Exec(context.Background(), qCtx); err != nil {
				t.Fatal(err)
			}
			if got := answerIP(t, qCtx); got != test.wantIP {
				t.Fatalf("answer = %s", got)
			}
			meta, ok := query_context.UpstreamRuntimeMetaFromContext(qCtx)
			if !ok || meta.GroupID != test.wantID || meta.RouteSource != test.source || meta.GroupName == "" || meta.UpstreamTag == "" || meta.CacheHit {
				t.Fatalf("metadata = %+v, ok=%v", meta, ok)
			}
		})
	}
}

func TestManualRuntimeDecisionWinsExplicitSubscriptionGroup(t *testing.T) {
	manual := startDNSServer(t, "192.0.2.2", dns.RcodeSuccess, nil)
	custom := startDNSServer(t, "192.0.2.4", dns.RcodeSuccess, nil)
	p, _ := newTestPlugin(t, snapshot(1, group("manual_group", "Manual", manual.addr), group("custom", "Custom", custom.addr)))

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "rule-token")
	snapshotFile := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(tokenFile, []byte("rule-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	ruleSnapshot := dynamic_rule_engine.Snapshot{
		SchemaVersion: dynamic_rule_engine.SchemaVersion, Version: 1, BlockRCode: dns.RcodeNameError,
		Rules: []dynamic_rule_engine.Rule{{ID: 1, Category: dynamic_rule_engine.CategoryRoute, Action: dynamic_rule_engine.ActionUpstream, UpstreamGroupID: "manual_group", MatchType: dynamic_rule_engine.MatchTypeFull, Pattern: "manual.example"}},
	}
	data, err := json.Marshal(ruleSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshotFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	m := coremain.NewTestMosdnsWithPlugins(nil)
	raw, err := dynamic_rule_engine.Init(coremain.NewBP("registry-priority-rules", m), &dynamic_rule_engine.Args{
		SnapshotFile: snapshotFile, BackupFile: filepath.Join(dir, "rules.bak"), AuthTokenFile: tokenFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := raw.(*dynamic_rule_engine.Plugin)
	defer engine.Close()

	qCtx := query("manual.example.")
	query_context.SetUpstreamGroupID(qCtx, "custom")
	if err := engine.Exec(t.Context(), qCtx); err != nil {
		t.Fatal(err)
	}
	if err := p.Exec(t.Context(), qCtx); err != nil {
		t.Fatal(err)
	}
	meta, ok := query_context.UpstreamRuntimeMetaFromContext(qCtx)
	if got := answerIP(t, qCtx); got != "192.0.2.2" || !ok || meta.GroupID != "manual_group" || meta.RouteSource != "dynamic_rule" {
		t.Fatalf("answer=%s metadata=%+v present=%t", got, meta, ok)
	}
}

func TestDisabledAndMissingSelectedGroup(t *testing.T) {
	server := startDNSServer(t, "192.0.2.1", dns.RcodeSuccess, nil)
	disabled := group("disabled", "Disabled", server.addr)
	disabled.Enabled = false
	p, _ := newTestPlugin(t, snapshot(1, group("default", "Default", server.addr), disabled))
	for _, id := range []string{"disabled", "missing"} {
		qCtx := query("selection.example.")
		query_context.SetUpstreamGroupID(qCtx, id)
		if err := p.Exec(context.Background(), qCtx); err == nil {
			t.Fatalf("group %s did not fail", id)
		}
		meta, ok := query_context.UpstreamRuntimeMetaFromContext(qCtx)
		if !ok || meta.GroupID != id || meta.RouteSource != "subscription" || meta.UpstreamTag != "" || meta.CacheHit {
			t.Fatalf("group %s failure metadata = %+v, ok=%v", id, meta, ok)
		}
		if id == "disabled" && meta.GroupName != "Disabled" {
			t.Fatalf("disabled group name = %q", meta.GroupName)
		}
	}
}

func TestForwardModes(t *testing.T) {
	success := startDNSServer(t, "192.0.2.10", dns.RcodeSuccess, nil)
	failed := startDNSServer(t, "", dns.RcodeServerFailure, nil)
	for _, mode := range []string{"race", "weighted", "failover"} {
		t.Run(mode, func(t *testing.T) {
			g := group("default", "Default", success.addr)
			g.Mode = mode
			if mode == "weighted" {
				g.Upstreams[0].Weight = 10
			}
			if mode == "failover" {
				g.Upstreams = []dynamic_forward.Upstream{{Tag: "primary", Addr: failed.addr, Priority: 1}, {Tag: "backup", Addr: success.addr, Priority: 2}}
			}
			p, _ := newTestPlugin(t, snapshot(1, g))
			qCtx := query(mode + ".example.")
			if err := p.Exec(context.Background(), qCtx); err != nil {
				t.Fatal(err)
			}
			if got := answerIP(t, qCtx); got != "192.0.2.10" {
				t.Fatalf("answer = %s", got)
			}
		})
	}
}

func TestECSCacheIsolationAndFlush(t *testing.T) {
	observed := make(chan *dns.EDNS0_SUBNET, 4)
	serverA := startDNSServer(t, "192.0.2.20", dns.RcodeSuccess, func(request *dns.Msg) {
		for _, option := range request.IsEdns0().Option {
			if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
				observed <- ecs
			}
		}
	})
	serverB := startDNSServer(t, "192.0.2.21", dns.RcodeSuccess, nil)
	first := group("first", "First", serverA.addr)
	first.ECS = dynamic_ecs.Config{Mode: "fixed_subnet", Preset4: "203.0.113.0/24"}
	second := group("second", "Second", serverB.addr)
	p, _ := newTestPlugin(t, snapshot(1, first, second))
	run := func(id string) query_context.UpstreamRuntimeMeta {
		qCtx := query("cache.example.")
		qCtx.ServerMeta.ClientAddr = netip.MustParseAddr("198.51.100.9")
		query_context.SetUpstreamGroupID(qCtx, id)
		if err := p.Exec(context.Background(), qCtx); err != nil {
			t.Fatal(err)
		}
		meta, _ := query_context.UpstreamRuntimeMetaFromContext(qCtx)
		return meta
	}
	if meta := run("first"); meta.CacheHit {
		t.Fatal("first lookup unexpectedly hit")
	}
	if ecs := <-observed; ecs.Address.String() != "203.0.113.0" || ecs.SourceNetmask != 24 {
		t.Fatalf("ECS = %+v", ecs)
	}
	if meta := run("first"); !meta.CacheHit {
		t.Fatal("same-group lookup missed")
	}
	if meta := run("second"); meta.CacheHit {
		t.Fatal("cache leaked across groups")
	}
	recorder := httptest.NewRecorder()
	p.router().ServeHTTP(recorder, authorizedRequest(http.MethodPost, "/flush", []byte(`{"group_id":"first","expected_current_version":1}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("flush status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if meta := run("first"); meta.CacheHit {
		t.Fatal("flushed cache hit")
	}
	if serverA.requests.Load() != 2 || serverB.requests.Load() != 1 {
		t.Fatalf("requests A=%d B=%d", serverA.requests.Load(), serverB.requests.Load())
	}
}

func TestCacheDumpsSurviveRestartWithIsolationAndDecreasingTTL(t *testing.T) {
	firstServer := startDNSServer(t, "192.0.2.50", dns.RcodeSuccess, nil)
	secondServer := startDNSServer(t, "192.0.2.51", dns.RcodeSuccess, nil)
	p, args := newTestPlugin(t, snapshot(1, group("first", "First", firstServer.addr), group("second", "Second", secondServer.addr)))

	lookup := func(plugin *Plugin, groupID string) (*dns.Msg, query_context.UpstreamRuntimeMeta) {
		qCtx := query("restart-cache.example.")
		query_context.SetUpstreamGroupID(qCtx, groupID)
		if err := plugin.Exec(t.Context(), qCtx); err != nil {
			t.Fatal(err)
		}
		meta, _ := query_context.UpstreamRuntimeMetaFromContext(qCtx)
		return qCtx.R(), meta
	}
	firstResponse, _ := lookup(p, "first")
	if _, meta := lookup(p, "second"); meta.CacheHit {
		t.Fatal("second group reused first group cache")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)

	restarted, err := newPlugin(args, zap.NewNop(), "restart")
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	secondResponse, meta := lookup(restarted, "first")
	if !meta.CacheHit {
		t.Fatal("persisted cache missed after restart")
	}
	if firstServer.requests.Load() != 1 || secondServer.requests.Load() != 1 {
		t.Fatalf("upstream requests first=%d second=%d", firstServer.requests.Load(), secondServer.requests.Load())
	}
	firstTTL := firstResponse.Answer[0].Header().Ttl
	secondTTL := secondResponse.Answer[0].Header().Ttl
	if secondTTL >= firstTTL {
		t.Fatalf("TTL did not decrease across restart: before=%d after=%d", firstTTL, secondTTL)
	}
}

func TestInvalidCacheDumpsAreSkipped(t *testing.T) {
	server := startDNSServer(t, "192.0.2.52", dns.RcodeSuccess, nil)
	for _, test := range []struct {
		name  string
		write func(*testing.T, string)
	}{
		{name: "corrupt", write: func(t *testing.T, filename string) {
			if err := os.WriteFile(filename, []byte("corrupt"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "old", write: func(t *testing.T, filename string) {
			f, err := os.Create(filename)
			if err != nil {
				t.Fatal(err)
			}
			w := gzip.NewWriter(f)
			w.Name = "mosdns_cache_v1"
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, _ := newTestArgs(t, snapshot(1, group("default", "Default", server.addr)))
			args.CacheDumpDir = filepath.Join(filepath.Dir(args.SnapshotFile), "cache")
			if err := os.MkdirAll(args.CacheDumpDir, 0o750); err != nil {
				t.Fatal(err)
			}
			test.write(t, filepath.Join(args.CacheDumpDir, "1-default.dump"))
			p, err := newPlugin(args, zap.NewNop(), "invalid-dump")
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if got := p.current.Load().groups["default"].cache.Len(); got != 0 {
				t.Fatalf("loaded %d entries from invalid dump", got)
			}
		})
	}
}

func TestCacheDumpCleanupOnGroupDeleteAndFlush(t *testing.T) {
	server := startDNSServer(t, "192.0.2.53", dns.RcodeSuccess, nil)
	p, _ := newTestPlugin(t, snapshot(1, group("first", "First", server.addr), group("removed", "Removed", server.addr)))
	qCtx := query("removed-cache.example.")
	query_context.SetUpstreamGroupID(qCtx, "removed")
	if err := p.Exec(t.Context(), qCtx); err != nil {
		t.Fatal(err)
	}
	p.dumpCaches(p.current.Load())
	next := snapshot(2, group("first", "First", server.addr))
	next.ExpectedCurrentVersion = 1
	if recorder := applySnapshot(t, p, next); recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if _, err := os.Stat(p.cacheDumpFile(1, "removed")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed group dump still exists: %v", err)
	}

	qCtx = query("flush-cache.example.")
	if err := p.Exec(t.Context(), qCtx); err != nil {
		t.Fatal(err)
	}
	p.dumpCaches(p.current.Load())
	recorder := httptest.NewRecorder()
	p.router().ServeHTTP(recorder, authorizedRequest(http.MethodPost, "/flush", []byte(`{"group_id":"first","expected_current_version":2}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("flush status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if _, err := os.Stat(p.cacheDumpFile(2, "first")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("flushed group dump still exists: %v", err)
	}
}

func TestFlushRejectsStaleVersion(t *testing.T) {
	server := startDNSServer(t, "192.0.2.22", dns.RcodeSuccess, nil)
	p, _ := newTestPlugin(t, snapshot(2, group("default", "Default", server.addr)))
	recorder := httptest.NewRecorder()
	p.router().ServeHTTP(recorder, authorizedRequest(http.MethodPost, "/flush", []byte(`{"expected_current_version":1}`)))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("flush status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestSnapshotCASPersistenceAndBackupRecovery(t *testing.T) {
	server := startDNSServer(t, "192.0.2.30", dns.RcodeSuccess, nil)
	p, args := newTestPlugin(t, snapshot(1, group("default", "v1", server.addr)))
	stale := snapshot(2, group("default", "stale", server.addr))
	stale.ExpectedCurrentVersion = 0
	if recorder := applySnapshot(t, p, stale); recorder.Code != http.StatusConflict {
		t.Fatalf("stale status = %d", recorder.Code)
	}
	second := snapshot(2, group("default", "v2", server.addr))
	second.ExpectedCurrentVersion = 1
	if recorder := applySnapshot(t, p, second); recorder.Code != http.StatusOK {
		t.Fatalf("v2 status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	third := snapshot(3, group("default", "v3", server.addr))
	third.ExpectedCurrentVersion = 2
	if recorder := applySnapshot(t, p, third); recorder.Code != http.StatusOK {
		t.Fatalf("v3 status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	_ = p.Close()
	if err := os.WriteFile(args.SnapshotFile, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := newPlugin(args, zap.NewNop(), "recovered")
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if got := recovered.current.Load().snapshot; got.Version != 2 || got.Groups[0].Name != "v2" {
		t.Fatalf("recovered = %+v", got)
	}
}

func TestConcurrentUpdateWaitsForInFlightGroup(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	server := startDNSServer(t, "192.0.2.40", dns.RcodeSuccess, func(*dns.Msg) { once.Do(func() { close(started) }); <-release })
	p, _ := newTestPlugin(t, snapshot(1, group("old", "Old", server.addr)))
	queryDone := make(chan error, 1)
	go func() { queryDone <- p.Exec(context.Background(), query("inflight.example.")) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("query did not reach old group")
	}
	nextServer := startDNSServer(t, "192.0.2.41", dns.RcodeSuccess, nil)
	next := snapshot(2, group("old", "Old", server.addr), group("new", "New", nextServer.addr))
	next.ExpectedCurrentVersion = 1
	if recorder := applySnapshot(t, p, next); recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	close(release)
	select {
	case err := <-queryDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("old query did not complete")
	}
	qCtx := query("new.example.")
	query_context.SetUpstreamGroupID(qCtx, "new")
	if err := p.Exec(context.Background(), qCtx); err != nil {
		t.Fatal(err)
	}
	if got := answerIP(t, qCtx); got != "192.0.2.41" {
		t.Fatalf("new answer = %s", got)
	}
}

func TestCloseWaitsForInFlightQueryBeforeDump(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	server := startDNSServer(t, "192.0.2.42", dns.RcodeSuccess, func(*dns.Msg) { once.Do(func() { close(started) }); <-release })
	p, args := newTestPlugin(t, snapshot(1, group("default", "Default", server.addr)))
	queryDone := make(chan error, 1)
	go func() { queryDone <- p.Exec(context.Background(), query("close-inflight.example.")) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("query did not reach upstream")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- p.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("close returned before query completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-queryDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	restarted, err := newPlugin(args, zap.NewNop(), "close-restart")
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	qCtx := query("close-inflight.example.")
	if err := restarted.Exec(context.Background(), qCtx); err != nil {
		t.Fatal(err)
	}
	meta, _ := query_context.UpstreamRuntimeMetaFromContext(qCtx)
	if !meta.CacheHit || server.requests.Load() != 1 {
		t.Fatalf("persisted in-flight result cache_hit=%t upstream_requests=%d", meta.CacheHit, server.requests.Load())
	}
}
