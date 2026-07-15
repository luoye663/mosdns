package fastforward

import (
	"context"
	"errors"
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
