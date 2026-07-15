package query_audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
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
