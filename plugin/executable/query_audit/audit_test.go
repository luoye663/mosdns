package query_audit

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	fastforward "github.com/IrineSistiana/mosdns/v5/plugin/executable/forward"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestInitRegistersWorkerWithMosdns(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("audit-init-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := coremain.NewTestMosdnsWithPlugins(nil)
	plugin, err := Init(coremain.NewBP("audit-init", m), &Args{Endpoint: "http://127.0.0.1:1", AuthTokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	p, ok := plugin.(*Plugin)
	if !ok {
		t.Fatalf("Init() type = %T", plugin)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func newTestAuditPlugin(t *testing.T, endpoint string, queueSize, batchSize int) *Plugin {
	t.Helper()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("audit-test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := newPlugin(Args{Endpoint: endpoint, AuthTokenFile: tokenFile, QueueSize: queueSize, BatchSize: batchSize, FlushInterval: "10ms", RequestTimeout: "100ms", MaxRetries: 1, IncludeErrorText: true, MaxErrorTextBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testContext(name string) *query_context.Context {
	message := new(dns.Msg)
	message.SetQuestion(name+".", dns.TypeA)
	qCtx := query_context.NewContext(message)
	qCtx.ServerMeta.ClientAddr = netip.MustParseAddr("192.168.1.23")
	qCtx.ServerMeta.FromUDP = true
	return qCtx
}

func TestExecObservesRejectAndCacheMark(t *testing.T) {
	events := make(chan QueryEvent, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch eventBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode batch: %v", err)
		}
		events <- batch.Events[0]
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	p := newTestAuditPlugin(t, server.URL, 8, 1)
	p.startWorker()
	defer p.Close()

	qCtx := testContext("blocked.example")
	qCtx.SetMark(p.marks.AccessBlock)
	qCtx.SetMark(p.marks.CacheHit)
	walker := sequence.NewChainWalker([]*sequence.ChainNode{{RE: sequence.ActionReject{Rcode: dns.RcodeNameError}}}, nil)
	if err := p.Exec(context.Background(), qCtx, walker); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Route != "block" || event.RCode != dns.RcodeNameError || !event.CacheHit || event.Protocol != "udp" || event.QName != "blocked.example" {
			t.Fatalf("unexpected audit event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("audit event was not sent")
	}
}

func TestExecObservesGotoAndAccept(t *testing.T) {
	events := make(chan QueryEvent, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch eventBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode batch: %v", err)
		}
		events <- batch.Events[0]
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	p := newTestAuditPlugin(t, server.URL, 8, 1)
	p.startWorker()
	defer p.Close()

	qCtx := testContext("goto.example")
	target := []*sequence.ChainNode{
		{E: sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
			response := new(dns.Msg)
			response.SetReply(qCtx.Q())
			response.Rcode = dns.RcodeSuccess
			qCtx.SetResponse(response)
			return nil
		})},
		{RE: sequence.ActionAccept{}},
	}
	walker := sequence.NewChainWalker([]*sequence.ChainNode{{RE: sequence.ActionGoto{To: target}}}, nil)
	if err := p.Exec(context.Background(), qCtx, walker); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.QName != "goto.example" || event.RCode != dns.RcodeSuccess || event.Route != "remote" {
			t.Fatalf("goto/accept event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("goto/accept event was not sent")
	}
}

func TestBuildEventIncludesOnlyUniqueAnswerIPs(t *testing.T) {
	p := newTestAuditPlugin(t, "http://127.0.0.1:1", 1, 1)
	defer p.Close()
	p.includeAnswers = true
	qCtx := testContext("answers.example")
	response := new(dns.Msg)
	response.SetReply(qCtx.Q())
	response.Answer = append(response.Answer,
		&dns.A{Hdr: dns.RR_Header{Name: "answers.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("192.0.2.1")},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "answers.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")},
		&dns.A{Hdr: dns.RR_Header{Name: "answers.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.1")},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "answers.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 90}, Target: "target.example."},
	)
	qCtx.SetResponse(response)
	event := p.buildEvent(qCtx, time.Now(), nil)
	if len(event.AnswerIPs) != 2 || event.AnswerIPs[0] != "192.0.2.1" || event.AnswerIPs[1] != "2001:db8::1" {
		t.Fatalf("answer IPs = %#v", event.AnswerIPs)
	}
	if len(event.AnswerRecords) != 4 || !strings.Contains(event.AnswerRecords[0], "192.0.2.1") || !strings.Contains(event.AnswerRecords[1], "2001:db8::1") || !strings.Contains(event.AnswerRecords[2], "192.0.2.1") || !strings.Contains(event.AnswerRecords[3], "CNAME") {
		t.Fatalf("answer records = %#v", event.AnswerRecords)
	}
	if event.AnswerMinTTLSeconds == nil || *event.AnswerMinTTLSeconds != 30 {
		t.Fatalf("minimum answer TTL = %v, want 30", event.AnswerMinTTLSeconds)
	}
}

func TestBuildEventOmitsMinimumTTLWithoutAnswer(t *testing.T) {
	p := newTestAuditPlugin(t, "http://127.0.0.1:1", 1, 1)
	defer p.Close()
	qCtx := testContext("empty-answer.example")
	response := new(dns.Msg)
	response.SetReply(qCtx.Q())
	qCtx.SetResponse(response)
	if event := p.buildEvent(qCtx, time.Now(), nil); event.AnswerMinTTLSeconds != nil {
		t.Fatalf("minimum answer TTL = %v, want nil", event.AnswerMinTTLSeconds)
	}
}

func TestRouteMarksFromFinalSequenceUseDefaultSource(t *testing.T) {
	p := newTestAuditPlugin(t, "http://127.0.0.1:1", 1, 1)
	defer p.Close()

	for _, test := range []struct {
		name       string
		mark       uint32
		wantRoute  string
		wantSource string
		wantGroup  string
	}{
		{name: "remote", mark: p.marks.RouteRemote, wantRoute: "remote", wantSource: "default", wantGroup: "remote_dns"},
		{name: "local", mark: p.marks.RouteLocal, wantRoute: "local", wantSource: "default", wantGroup: "local_dns"},
	} {
		t.Run(test.name, func(t *testing.T) {
			qCtx := testContext(test.name + ".example")
			qCtx.SetMark(test.mark)
			route, source, group := p.route(qCtx)
			if route != test.wantRoute || source != test.wantSource || group != test.wantGroup {
				t.Fatalf("route() = (%q, %q, %q), want (%q, %q, %q)", route, source, group, test.wantRoute, test.wantSource, test.wantGroup)
			}
		})
	}
}

func TestNoLogSkipsEvent(t *testing.T) {
	p := newTestAuditPlugin(t, "http://127.0.0.1:1", 1, 1)
	defer p.Close()
	qCtx := testContext("private.example")
	qCtx.SetMark(p.marks.NoLog)
	walker := sequence.NewChainWalker(nil, nil)
	if err := p.Exec(context.Background(), qCtx, walker); err != nil {
		t.Fatal(err)
	}
	if len(p.queue) != 0 {
		t.Fatal("no_log request was enqueued")
	}
}

func TestBuildEventReportsSelectedUpstreamTag(t *testing.T) {
	p := newTestAuditPlugin(t, "http://127.0.0.1:1", 1, 1)
	defer p.Close()
	qCtx := testContext("upstream.example")
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		_ = w.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	// 通过真实 forward 执行写入 metadata，确保审计不依赖推测的路由上游组。
	forward, err := fastforward.NewForward(&fastforward.Args{Upstreams: []fastforward.UpstreamConfig{{Tag: "audit-upstream", Addr: conn.LocalAddr().String()}}}, fastforward.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer forward.Close()
	if err := forward.Exec(context.Background(), qCtx); err != nil {
		t.Fatal(err)
	}
	event := p.buildEvent(qCtx, time.Now(), nil)
	if event.UpstreamTag != "audit-upstream" {
		t.Fatalf("upstream tag = %q, want audit-upstream", event.UpstreamTag)
	}
}

func TestBuildEventPrefersRegistryMetadata(t *testing.T) {
	p := newTestAuditPlugin(t, "http://127.0.0.1:1", 1, 1)
	defer p.Close()
	qCtx := testContext("registry.example")
	query_context.SetUpstreamRuntimeMeta(qCtx, query_context.UpstreamRuntimeMeta{GroupID: "custom", GroupName: "Custom", RouteSource: "subscription", UpstreamTag: "selected", CacheHit: true})
	event := p.buildEvent(qCtx, time.Now(), nil)
	if event.Route != "forward" || event.RouteSource != "subscription" || event.UpstreamGroup != "custom" || event.UpstreamTag != "selected" || !event.CacheHit {
		t.Fatalf("registry audit event = %+v", event)
	}
}

func TestQueueFullDoesNotBlockDNSPath(t *testing.T) {
	p := newTestAuditPlugin(t, "http://127.0.0.1:1", 1, 1)
	defer p.Close()
	p.queue <- QueryEvent{EventID: "already-full"}
	started := time.Now()
	if err := p.Exec(context.Background(), testContext("full.example"), sequence.NewChainWalker(nil, nil)); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("Exec blocked for %s on full queue", elapsed)
	}
	if len(p.queue) != 1 {
		t.Fatalf("queue length = %d, want 1", len(p.queue))
	}
}

func TestRetryKeepsEventID(t *testing.T) {
	var attempts atomic.Int32
	eventIDs := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch eventBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode batch: %v", err)
		}
		eventIDs <- batch.Events[0].EventID
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	p := newTestAuditPlugin(t, server.URL, 8, 1)
	p.startWorker()
	defer p.Close()
	if err := p.Exec(context.Background(), testContext("retry.example"), sequence.NewChainWalker(nil, nil)); err != nil {
		t.Fatal(err)
	}
	var first, second string
	select {
	case first = <-eventIDs:
	case <-time.After(time.Second):
		t.Fatal("first request not received")
	}
	select {
	case second = <-eventIDs:
	case <-time.After(time.Second):
		t.Fatal("retry request not received")
	}
	if first == "" || first != second {
		t.Fatalf("event IDs differ across retry: %q != %q", first, second)
	}
}

func TestCloseReturnsAfterWorkerFlush(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	p := newTestAuditPlugin(t, server.URL, 8, 8)
	p.startWorker()
	if err := p.Exec(context.Background(), testContext("shutdown.example"), sequence.NewChainWalker(nil, nil)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > shutdownFlushLimit+250*time.Millisecond {
		t.Fatalf("Close exceeded flush limit: %s", elapsed)
	}
}
