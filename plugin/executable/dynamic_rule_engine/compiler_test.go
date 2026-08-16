package dynamic_rule_engine

import (
	"fmt"
	"sync"
	"testing"
)

func testSnapshot(rules ...Rule) Snapshot {
	return Snapshot{SchemaVersion: SchemaVersion, Version: 1, BlockRCode: 3, Rules: rules}
}

func routeRule(id int64, group, matchType, pattern string, priority int) Rule {
	return Rule{ID: id, Category: CategoryRoute, Action: ActionUpstream, UpstreamGroupID: group, MatchType: matchType, Pattern: pattern, Priority: priority}
}

func routeBinding(sourceID, bindingID int64, group string, priority int, domains ...string) SubscriptionSet {
	return SubscriptionSet{SourceID: sourceID, SourceName: fmt.Sprintf("source-%d", sourceID), BindingID: bindingID, UpstreamGroupID: group, Category: CategoryRoute, Action: ActionUpstream, Priority: priority, Domains: domains}
}

func TestCompileAcceptsCurrentAndLegacySchema(t *testing.T) {
	for _, version := range []uint32{0, 1, 2, 3, 6} {
		snapshot := testSnapshot()
		snapshot.SchemaVersion = version
		if _, err := Compile(snapshot, DefaultLimits()); err == nil {
			t.Fatalf("schema %d accepted", version)
		}
	}
	legacy := testSnapshot()
	legacy.SchemaVersion = LegacySchemaVersion
	if _, err := Compile(legacy, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(testSnapshot(), DefaultLimits()); err != nil {
		t.Fatal(err)
	}
}

func TestRouteRulesRequireUpstreamGroup(t *testing.T) {
	for _, rule := range []Rule{
		{ID: 1, Category: CategoryRoute, Action: "local", MatchType: MatchTypeFull, Pattern: "example.com"},
		{ID: 1, Category: CategoryRoute, Action: ActionUpstream, MatchType: MatchTypeFull, Pattern: "example.com"},
		{ID: 1, Category: CategoryAccess, Action: ActionBlock, UpstreamGroupID: "group", MatchType: MatchTypeFull, Pattern: "example.com"},
	} {
		if _, err := Compile(testSnapshot(rule), DefaultLimits()); err == nil {
			t.Fatalf("invalid rule accepted: %+v", rule)
		}
	}
}

func TestSmallerPriorityWins(t *testing.T) {
	compiled, err := Compile(testSnapshot(
		routeRule(2, "specific", MatchTypeFull, "www.example.com", 20),
		routeRule(1, "preferred", MatchTypeDomain, "example.com", 10),
	), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := compiled.Match("www.example.com")
	if err != nil || result.Route.RuleID != 1 || result.Route.UpstreamGroupID != "preferred" {
		t.Fatalf("route = %+v, err = %v", result.Route, err)
	}
}

func TestSmallerPriorityWinsAcrossAccessMatchTypes(t *testing.T) {
	compiled, err := Compile(testSnapshot(
		Rule{ID: 2, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeFull, Pattern: "www.example.com", Priority: 20},
		Rule{ID: 1, Category: CategoryAccess, Action: ActionAllow, MatchType: MatchTypeDomain, Pattern: "example.com", Priority: 10},
	), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := compiled.Match("www.example.com")
	if err != nil || result.Access.RuleID != 1 || result.Access.Action != ActionAllow {
		t.Fatalf("access = %+v, err = %v", result.Access, err)
	}
}

func TestManualRouteAlwaysOverridesSubscription(t *testing.T) {
	for _, rule := range []Rule{
		routeRule(1, "manual-full", MatchTypeFull, "www.example.com", 1000),
		routeRule(2, "manual-domain", MatchTypeDomain, "example.com", 1000),
		routeRule(3, "manual-regexp", MatchTypeRegexp, `^www\.example\.com$`, 1000),
	} {
		snapshot := testSnapshot(rule)
		snapshot.SubscriptionSets = []SubscriptionSet{routeBinding(10, 20, "subscription", 0, "example.com")}
		compiled, err := Compile(snapshot, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		result, err := compiled.Match("www.example.com")
		if err != nil || result.Route.RuleID != rule.ID || result.Route.SourceID != 0 || result.Route.UpstreamGroupID != rule.UpstreamGroupID {
			t.Fatalf("manual route = %+v, err = %v", result.Route, err)
		}
	}
}

func TestSubscriptionPriorityAndBindingTieBreak(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.SubscriptionSets = []SubscriptionSet{
		routeBinding(1, 30, "deeper-but-lower-priority", 30, "www.example.com"),
		routeBinding(2, 20, "smaller-priority", 10, "example.com"),
		routeBinding(3, 10, "binding-tie-break", 10, "example.com"),
	}
	compiled, err := Compile(snapshot, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := compiled.Match("www.example.com")
	if err != nil || result.Route.BindingID != 10 || result.Route.UpstreamGroupID != "binding-tie-break" {
		t.Fatalf("subscription route = %+v, err = %v", result.Route, err)
	}
}

func TestAccessAndLoggingRemainIndependent(t *testing.T) {
	compiled, err := Compile(testSnapshot(
		Rule{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeDomain, Pattern: "example.com", Priority: 20},
		Rule{ID: 2, Category: CategoryAccess, Action: ActionAllow, MatchType: MatchTypeDomain, Pattern: "example.com", Priority: 10},
		Rule{ID: 3, Category: CategoryLogging, Action: ActionNoLog, MatchType: MatchTypeRegexp, Pattern: `\.example\.com$`, Priority: 1},
	), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, _ := compiled.Match("www.example.com")
	if result.Access.RuleID != 2 || result.Logging.RuleID != 3 {
		t.Fatalf("result = %+v", result)
	}
}

func TestStaticAnswerNormalizesAddressesAndMatchesRegexp(t *testing.T) {
	compiled, err := Compile(testSnapshot(Rule{ID: 7, Category: CategoryAnswer, Action: ActionStatic, MatchType: MatchTypeRegexp, Pattern: `^api\..+$`, Priority: 10, IPv4Addresses: []string{"192.0.2.2", "192.0.2.2"}, IPv6Addresses: []string{"2001:0db8::1"}, TTL: 600}), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := compiled.Match("api.example")
	if err != nil || result.Answer.RuleID != 7 || len(result.Answer.IPv4Addresses) != 1 || result.Answer.IPv6Addresses[0] != "2001:db8::1" || result.Answer.TTL != 600 {
		t.Fatalf("answer=%+v err=%v", result.Answer, err)
	}
}

func TestStaticAnswerRejectsInvalidFields(t *testing.T) {
	invalid := []Rule{
		{ID: 1, Category: CategoryAnswer, Action: ActionStatic, MatchType: MatchTypeFull, Pattern: "x.example", TTL: 300},
		{ID: 1, Category: CategoryAnswer, Action: ActionStatic, MatchType: MatchTypeFull, Pattern: "x.example", IPv4Addresses: []string{"2001:db8::1"}, TTL: 300},
		{ID: 1, Category: CategoryAccess, Action: ActionAllow, MatchType: MatchTypeFull, Pattern: "x.example", IPv4Addresses: []string{"192.0.2.1"}},
	}
	for _, rule := range invalid {
		if _, err := Compile(testSnapshot(rule), DefaultLimits()); err == nil {
			t.Fatalf("accepted %+v", rule)
		}
	}
}

func TestParseSnapshotRejectsUnknownFields(t *testing.T) {
	if _, err := ParseSnapshot([]byte(`{"schema_version":4,"version":1,"block_rcode":3,"rules":[],"unexpected":true}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestStoreConcurrentMatchAndSwap(t *testing.T) {
	first, err := Compile(testSnapshot(routeRule(1, "one", MatchTypeDomain, "example.com", 1)), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var store Store
	store.Swap(first)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if _, err := store.Load().Match("www.example.com"); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	for i := 2; i < 30; i++ {
		next, err := Compile(testSnapshot(routeRule(int64(i), "next", MatchTypeDomain, fmt.Sprintf("%d.example.com", i), 1)), DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		store.Swap(next)
	}
	wg.Wait()
}
