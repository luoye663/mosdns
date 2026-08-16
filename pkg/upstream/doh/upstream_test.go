package doh

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type cancelRoundTripper struct {
	canceled chan struct{}
}

func (r *cancelRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	<-request.Context().Done()
	close(r.canceled)
	return nil, context.Cause(request.Context())
}

func TestExchangeUsesCallerContext(t *testing.T) {
	roundTripper := &cancelRoundTripper{canceled: make(chan struct{})}
	upstream, err := NewUpstream("https://dns.example/dns-query", roundTripper, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = upstream.ExchangeContext(ctx, make([]byte, 12))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exchange error = %v", err)
	}
	select {
	case <-roundTripper.canceled:
	case <-time.After(time.Second):
		t.Fatal("HTTP request did not observe caller cancellation")
	}
}
