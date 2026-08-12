package dynamic_rule_engine

import (
	"context"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
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

func TestExecBuildsStaticAddressResponses(t *testing.T) {
	compiled, err := Compile(testSnapshot(Rule{ID: 9, Category: CategoryAnswer, Action: ActionStatic, MatchType: MatchTypeDomain, Pattern: "example.com", IPv4Addresses: []string{"192.0.2.9"}, TTL: 300}), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	p := &Plugin{marks: defaultMarks(), metrics: newPluginMetrics(nil)}
	p.store.Swap(compiled)
	for _, test := range []struct {
		qtype   uint16
		answers int
	}{{dns.TypeA, 1}, {dns.TypeAAAA, 0}} {
		query := new(dns.Msg)
		query.SetQuestion("www.example.com.", test.qtype)
		qCtx := query_context.NewContext(query)
		if err := p.Exec(context.Background(), qCtx); err != nil {
			t.Fatal(err)
		}
		if qCtx.R() == nil || qCtx.R().Rcode != dns.RcodeSuccess || len(qCtx.R().Answer) != test.answers || !qCtx.HasMark(p.marks.LocalAnswer) {
			t.Fatalf("qtype=%d response=%+v", test.qtype, qCtx.R())
		}
		decision, ok := RuntimeDecisionFromContext(qCtx)
		if !ok || decision.AnswerRuleID != 9 {
			t.Fatalf("decision=%+v ok=%t", decision, ok)
		}
	}
	query := new(dns.Msg)
	query.SetQuestion("www.example.com.", dns.TypeTXT)
	qCtx := query_context.NewContext(query)
	if err := p.Exec(context.Background(), qCtx); err != nil || qCtx.R() != nil || qCtx.HasMark(p.marks.LocalAnswer) {
		t.Fatalf("TXT response=%+v err=%v", qCtx.R(), err)
	}
}

func TestBlockSuppressesStaticAnswer(t *testing.T) {
	compiled, err := Compile(testSnapshot(
		Rule{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeFull, Pattern: "blocked.example"},
		Rule{ID: 2, Category: CategoryAnswer, Action: ActionStatic, MatchType: MatchTypeFull, Pattern: "blocked.example", IPv4Addresses: []string{"192.0.2.2"}, TTL: 60},
	), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	p := &Plugin{marks: defaultMarks(), metrics: newPluginMetrics(nil)}
	p.store.Swap(compiled)
	query := new(dns.Msg)
	query.SetQuestion("blocked.example.", dns.TypeA)
	qCtx := query_context.NewContext(query)
	if err := p.Exec(context.Background(), qCtx); err != nil {
		t.Fatal(err)
	}
	if !qCtx.HasMark(p.marks.AccessBlock) || qCtx.R() != nil || qCtx.HasMark(p.marks.LocalAnswer) {
		t.Fatalf("response=%+v", qCtx.R())
	}
}
