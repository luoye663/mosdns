package server_handler

import (
	"context"
	"errors"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestOverloadActions(t *testing.T) {
	for _, test := range []struct {
		name   string
		action query_context.OverloadAction
		rcode  int
		drop   bool
	}{
		{name: "servfail", action: query_context.OverloadSERVFAIL, rcode: dns.RcodeServerFailure},
		{name: "refused", action: query_context.OverloadREFUSED, rcode: dns.RcodeRefused},
		{name: "drop", action: query_context.OverloadDrop, drop: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
				query_context.SetOverloadAction(qCtx, test.action)
				return errors.New("overloaded")
			})
			handler := NewEntryHandler(EntryHandlerOpts{Entry: entry})
			query := new(dns.Msg)
			query.SetQuestion("overload.example.", dns.TypeA)
			payload := handler.Handle(context.Background(), query, server.QueryMeta{FromUDP: true}, pool.PackBuffer)
			if test.drop {
				if payload != nil {
					pool.ReleaseBuf(payload)
					t.Fatal("drop action returned a response")
				}
				return
			}
			if payload == nil {
				t.Fatal("overload action returned no response")
			}
			defer pool.ReleaseBuf(payload)
			response := new(dns.Msg)
			if err := response.Unpack(*payload); err != nil {
				t.Fatal(err)
			}
			if response.Rcode != test.rcode {
				t.Fatalf("rcode = %d, want %d", response.Rcode, test.rcode)
			}
		})
	}
}
