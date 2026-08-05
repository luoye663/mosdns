package fastforward

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type testUpstream struct {
	delay time.Duration
	err   error
}

type observedUpstream struct {
	started  chan struct{}
	canceled atomic.Bool
	calls    atomic.Int32
	block    bool
}

func (u *observedUpstream) ExchangeContext(ctx context.Context, payload []byte) (*[]byte, error) {
	u.calls.Add(1)
	if u.started != nil {
		select {
		case <-u.started:
		default:
			close(u.started)
		}
	}
	if u.block {
		<-ctx.Done()
		u.canceled.Store(true)
		return nil, context.Cause(ctx)
	}
	query := new(dns.Msg)
	if err := query.Unpack(payload); err != nil {
		return nil, err
	}
	response := new(dns.Msg)
	response.SetReply(query)
	return pool.PackBuffer(response)
}

func (u *observedUpstream) Close() error { return nil }

var _ upstream.Upstream = (*testUpstream)(nil)

func (u *testUpstream) ExchangeContext(ctx context.Context, payload []byte) (*[]byte, error) {
	select {
	case <-time.After(u.delay):
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	if u.err != nil {
		return nil, u.err
	}
	query := new(dns.Msg)
	if err := query.Unpack(payload); err != nil {
		return nil, err
	}
	response := new(dns.Msg)
	response.SetReply(query)
	return pool.PackBuffer(response)
}

func (u *testUpstream) Close() error { return nil }

func testForward(upstreams ...struct {
	tag string
	u   upstream.Upstream
}) *Forward {
	f := &Forward{args: &Args{Concurrent: len(upstreams)}, logger: zap.NewNop()}
	for _, item := range upstreams {
		wrapper := newWrapper(0, UpstreamConfig{Tag: item.tag, Addr: "127.0.0.1:53"}, "test")
		wrapper.u = item.u
		f.us = append(f.us, wrapper)
	}
	return f
}

func testQueryContext() *query_context.Context {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	return query_context.NewContext(query)
}

func TestExecRecordsTagOfAcceptedFastestResponse(t *testing.T) {
	f := testForward(
		struct {
			tag string
			u   upstream.Upstream
		}{tag: "slow", u: &testUpstream{delay: 20 * time.Millisecond}},
		struct {
			tag string
			u   upstream.Upstream
		}{tag: "fast", u: &testUpstream{delay: time.Millisecond}},
	)
	qCtx := testQueryContext()
	if err := f.Exec(context.Background(), qCtx); err != nil {
		t.Fatal(err)
	}
	if got := SelectedUpstreamTag(qCtx); got != "fast" {
		t.Fatalf("selected upstream tag = %q, want fast", got)
	}
}

func TestExecDoesNotRecordTagWhenAllUpstreamsFail(t *testing.T) {
	f := testForward(struct {
		tag string
		u   upstream.Upstream
	}{tag: "failed", u: &testUpstream{err: errors.New("upstream unavailable")}})
	qCtx := testQueryContext()
	if err := f.Exec(context.Background(), qCtx); err == nil {
		t.Fatal("failed upstream was accepted")
	}
	if got := SelectedUpstreamTag(qCtx); got != "" {
		t.Fatalf("selected upstream tag = %q, want empty", got)
	}
}

func TestExecDoesNotSubstituteAddressForMissingTag(t *testing.T) {
	f := testForward(struct {
		tag string
		u   upstream.Upstream
	}{u: &testUpstream{}})
	qCtx := testQueryContext()
	if err := f.Exec(context.Background(), qCtx); err != nil {
		t.Fatal(err)
	}
	if got := SelectedUpstreamTag(qCtx); got != "" {
		t.Fatalf("selected upstream tag = %q, want empty", got)
	}
}

func TestExchangeCancelsAndWaitsForLosingWorkers(t *testing.T) {
	blocked := &observedUpstream{started: make(chan struct{}), block: true}
	fast := &testUpstream{delay: 20 * time.Millisecond}
	f := testForward(
		struct {
			tag string
			u   upstream.Upstream
		}{tag: "blocked", u: blocked},
		struct {
			tag string
			u   upstream.Upstream
		}{tag: "fast", u: fast},
	)
	if err := f.Exec(context.Background(), testQueryContext()); err != nil {
		t.Fatal(err)
	}
	if !blocked.canceled.Load() {
		t.Fatal("exchange returned before losing worker observed cancellation")
	}
}

func TestExchangeClampsConcurrencyToCandidateCount(t *testing.T) {
	only := &observedUpstream{}
	f := testForward(struct {
		tag string
		u   upstream.Upstream
	}{tag: "only", u: only})
	f.args.Concurrent = maxConcurrentQueries
	if err := f.Exec(context.Background(), testQueryContext()); err != nil {
		t.Fatal(err)
	}
	if got := only.calls.Load(); got != 1 {
		t.Fatalf("single candidate queried %d times", got)
	}
}

func TestExecBoundsConcurrencyButExecAllQueriesEveryCandidate(t *testing.T) {
	const upstreamCount = 18
	items := make([]struct {
		tag string
		u   upstream.Upstream
	}, upstreamCount)
	observed := make([]*observedUpstream, upstreamCount)
	for i := range items {
		observed[i] = new(observedUpstream)
		items[i].tag = fmt.Sprintf("upstream_%d", i)
		items[i].u = observed[i]
	}

	f := testForward(items...)
	if err := f.Exec(context.Background(), testQueryContext()); err != nil {
		t.Fatal(err)
	}
	var boundedCalls int32
	for _, item := range observed {
		boundedCalls += item.calls.Load()
		item.calls.Store(0)
	}
	if boundedCalls != maxConcurrentQueries {
		t.Fatalf("bounded forward queried %d upstreams, want %d", boundedCalls, maxConcurrentQueries)
	}

	if err := f.ExecAll(context.Background(), testQueryContext()); err != nil {
		t.Fatal(err)
	}
	for i, item := range observed {
		if calls := item.calls.Load(); calls != 1 {
			t.Fatalf("all-upstream forward queried upstream %d %d times, want 1", i, calls)
		}
	}
}

func BenchmarkExecWithSelectedUpstreamTag(b *testing.B) {
	f := testForward(struct {
		tag string
		u   upstream.Upstream
	}{tag: "benchmark", u: &testUpstream{}})
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := f.Exec(context.Background(), testQueryContext()); err != nil {
			b.Fatal(err)
		}
	}
}
