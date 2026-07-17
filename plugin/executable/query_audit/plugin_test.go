package query_audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
)

func TestPluginTypeRegistered(t *testing.T) {
	info, ok := coremain.GetPluginType(PluginType)
	if !ok || info.NewPlugin == nil || info.NewArgs == nil {
		t.Fatalf("plugin type %q was not registered", PluginType)
	}
	if _, ok := info.NewArgs().(*Args); !ok {
		t.Fatalf("plugin args type = %T, want *Args", info.NewArgs())
	}
}

func TestStatusAPIRequiresTokenAndReportsQueueHealth(t *testing.T) {
	p := &Plugin{token: []byte("test-token"), queue: make(chan QueryEvent, 4)}
	p.queue <- QueryEvent{}
	unauthorized := httptest.NewRecorder()
	p.Api().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/status", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	p.Api().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "{\"dropped_events\":0,\"queue_capacity\":4,\"queue_depth\":1}\n" {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
