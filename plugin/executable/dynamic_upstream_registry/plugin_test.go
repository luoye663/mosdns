package dynamic_upstream_registry

import (
	"bytes"
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

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_ecs"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_forward"
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
	return Snapshot{Version: version, DefaultGroupID: groups[0].ID, Groups: groups, Cache: GlobalCacheConfig{Enabled: true, Negative: NegativeCacheConfig{Enabled: true, TTL: 30}}}
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

func newMigrationArgs(t *testing.T, initial Snapshot) (Args, string) {
	t.Helper()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("registry-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Args{AuthTokenFile: tokenFile, SnapshotFile: filepath.Join(dir, "registry-current.json"), BackupFile: filepath.Join(dir, "registry-backup.json"), InitialSnapshot: initial}, dir
}

func writeTestJSON(t *testing.T, filename string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
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
		"version":          func(s *Snapshot) { s.Version = 0 },
		"id":               func(s *Snapshot) { s.Groups[0].ID = "Invalid"; s.DefaultGroupID = "Invalid" },
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

func TestSelectionPriorityAndMetadata(t *testing.T) {
	def := startDNSServer(t, "192.0.2.1", dns.RcodeSuccess, nil)
	local := startDNSServer(t, "192.0.2.2", dns.RcodeSuccess, nil)
	remote := startDNSServer(t, "192.0.2.3", dns.RcodeSuccess, nil)
	custom := startDNSServer(t, "192.0.2.4", dns.RcodeSuccess, nil)
	p, _ := newTestPlugin(t, snapshot(1, group("default", "Default Group", def.addr), group("local_dns", "Local", local.addr), group("remote_dns", "Remote", remote.addr), group("custom", "Custom", custom.addr)))
	for _, test := range []struct {
		name, wantIP, wantID, source string
		setup                        func(*query_context.Context)
	}{
		{name: "default", wantIP: "192.0.2.1", wantID: "default", source: "default", setup: func(*query_context.Context) {}},
		{name: "local mark", wantIP: "192.0.2.2", wantID: "local_dns", source: "dynamic_rule", setup: func(q *query_context.Context) { q.SetMark(routeLocalMark) }},
		{name: "remote mark", wantIP: "192.0.2.3", wantID: "remote_dns", source: "dynamic_rule", setup: func(q *query_context.Context) { q.SetMark(routeRemoteMark) }},
		{name: "local subscription mark", wantIP: "192.0.2.2", wantID: "local_dns", source: "subscription", setup: func(q *query_context.Context) {
			q.SetMark(routeLocalMark)
			q.SetMark(subscriptionLocalMark)
		}},
		{name: "remote subscription mark", wantIP: "192.0.2.3", wantID: "remote_dns", source: "subscription", setup: func(q *query_context.Context) {
			q.SetMark(routeRemoteMark)
			q.SetMark(subscriptionRemoteMark)
		}},
		{name: "explicit wins", wantIP: "192.0.2.4", wantID: "custom", source: "subscription", setup: func(q *query_context.Context) {
			q.SetMark(routeLocalMark)
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

func TestLegacyMigrationKeepsInitialWhenFilesDoNotExist(t *testing.T) {
	initial := snapshot(1, group("default", "Initial", "udp://127.0.0.1:5301"))
	args, dir := newMigrationArgs(t, initial)
	args.LegacyGroups = []LegacyGroup{{
		ID: "default", ForwardSnapshotFile: filepath.Join(dir, "forward-current.json"), ForwardBackupFile: filepath.Join(dir, "forward-backup.json"),
		ECSSnapshotFile: filepath.Join(dir, "ecs-current.json"), ECSBackupFile: filepath.Join(dir, "ecs-backup.json"),
	}}
	p, err := newPlugin(args, zap.NewNop(), "legacy-none")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	got := p.current.Load().snapshot.Groups[0]
	if got.Name != "Initial" || got.Upstreams[0].Addr != "udp://127.0.0.1:5301" || got.ECS.Mode != "off" {
		t.Fatalf("initial group changed: %+v", got)
	}
	if _, err := os.Stat(args.SnapshotFile); err != nil {
		t.Fatalf("registry current was not persisted: %v", err)
	}
}

func TestLegacyMigrationImportsAndStopsReadingLegacyAfterPersist(t *testing.T) {
	initial := snapshot(7, group("default", "Initial", "udp://127.0.0.1:5301"))
	args, dir := newMigrationArgs(t, initial)
	legacy := LegacyGroup{
		ID: "default", ForwardSnapshotFile: filepath.Join(dir, "forward-current.json"), ForwardBackupFile: filepath.Join(dir, "forward-backup.json"),
		ECSSnapshotFile: filepath.Join(dir, "ecs-current.json"), ECSBackupFile: filepath.Join(dir, "ecs-backup.json"),
	}
	args.LegacyGroups = []LegacyGroup{legacy}
	writeTestJSON(t, legacy.ForwardSnapshotFile, dynamic_forward.Snapshot{Version: 4, Mode: "weighted", Concurrent: 2, Socks5: "127.0.0.1:1080", Upstreams: []dynamic_forward.Upstream{{Tag: "legacy", Addr: "udp://127.0.0.1:5353", Weight: 9, Priority: 20}}})
	writeTestJSON(t, legacy.ECSSnapshotFile, dynamic_ecs.Snapshot{Version: 3, Mode: "fixed_subnet", Preset4: "203.0.113.9/24"})
	p, err := newPlugin(args, zap.NewNop(), "legacy-success")
	if err != nil {
		t.Fatal(err)
	}
	got := p.current.Load().snapshot.Groups[0]
	if got.Mode != "weighted" || got.Concurrent != 2 || got.Socks5 != "127.0.0.1:1080" || got.Upstreams[0].Tag != "legacy" {
		t.Fatalf("forward migration = %+v", got)
	}
	if got.ECS.Mode != "fixed_subnet" || got.ECS.Preset4 != "203.0.113.0/24" {
		t.Fatalf("ECS migration = %+v", got.ECS)
	}
	if gotSnapshot := p.current.Load().snapshot; gotSnapshot.Version != initial.Version {
		t.Fatalf("registry version = %d, want %d", gotSnapshot.Version, initial.Version)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{legacy.ForwardSnapshotFile, legacy.ECSSnapshotFile} {
		if err := os.WriteFile(filename, []byte("corrupt after migration"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	restarted, err := newPlugin(args, zap.NewNop(), "legacy-restart")
	if err != nil {
		t.Fatalf("restart reread legacy files: %v", err)
	}
	defer restarted.Close()
	if got := restarted.current.Load().snapshot.Groups[0]; got.Upstreams[0].Tag != "legacy" || got.ECS.Preset4 != "203.0.113.0/24" {
		t.Fatalf("persisted migration = %+v", got)
	}
}

func TestLegacyMigrationRecoversBothSnapshotsFromBackup(t *testing.T) {
	initial := snapshot(1, group("default", "Initial", "udp://127.0.0.1:5301"))
	args, dir := newMigrationArgs(t, initial)
	legacy := LegacyGroup{
		ID: "default", ForwardSnapshotFile: filepath.Join(dir, "forward-current.json"), ForwardBackupFile: filepath.Join(dir, "forward-backup.json"),
		ECSSnapshotFile: filepath.Join(dir, "ecs-current.json"), ECSBackupFile: filepath.Join(dir, "ecs-backup.json"),
	}
	args.LegacyGroups = []LegacyGroup{legacy}
	for _, filename := range []string{legacy.ForwardSnapshotFile, legacy.ECSSnapshotFile} {
		if err := os.WriteFile(filename, []byte(`{"unknown":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeTestJSON(t, legacy.ForwardBackupFile, dynamic_forward.Snapshot{Version: 2, Mode: "failover", Concurrent: 1, Upstreams: []dynamic_forward.Upstream{{Tag: "backup", Addr: "udp://127.0.0.1:5354", Priority: 1}}})
	writeTestJSON(t, legacy.ECSBackupFile, dynamic_ecs.Snapshot{Version: 2, Mode: "client_subnet", Mask4: 20, Mask6: 56})
	p, err := newPlugin(args, zap.NewNop(), "legacy-backup")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	got := p.current.Load().snapshot.Groups[0]
	if got.Mode != "failover" || got.Upstreams[0].Tag != "backup" || got.ECS.Mode != "client_subnet" || got.ECS.Mask4 != 20 || got.ECS.Mask6 != 56 {
		t.Fatalf("backup migration = %+v", got)
	}
}

func TestLegacyMigrationFailsWhenExistingSnapshotsAreAllInvalid(t *testing.T) {
	initial := snapshot(1, group("default", "Initial", "udp://127.0.0.1:5301"))
	args, dir := newMigrationArgs(t, initial)
	legacy := LegacyGroup{
		ID: "default", ForwardSnapshotFile: filepath.Join(dir, "forward-current.json"), ForwardBackupFile: filepath.Join(dir, "forward-backup.json"),
		ECSSnapshotFile: filepath.Join(dir, "ecs-current.json"), ECSBackupFile: filepath.Join(dir, "ecs-backup.json"),
	}
	args.LegacyGroups = []LegacyGroup{legacy}
	for _, filename := range []string{legacy.ForwardSnapshotFile, legacy.ForwardBackupFile} {
		if err := os.WriteFile(filename, []byte(`{"version":1,"unknown":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := newPlugin(args, zap.NewNop(), "legacy-corrupt"); err == nil {
		t.Fatal("corrupt legacy snapshots were silently ignored")
	}
	if _, err := os.Stat(args.SnapshotFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("registry current exists after failed migration: %v", err)
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
	next := snapshot(2, group("new", "New", nextServer.addr))
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
	if err := p.Exec(context.Background(), qCtx); err != nil {
		t.Fatal(err)
	}
	if got := answerIP(t, qCtx); got != "192.0.2.41" {
		t.Fatalf("new answer = %s", got)
	}
}
