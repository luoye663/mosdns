package dynamic_rule_engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func testSnapshot(rules ...Rule) Snapshot {
	return Snapshot{
		SchemaVersion: SchemaVersion,
		Version:       1,
		BlockRCode:    3,
		Rules:         rules,
	}
}

func TestCompileMatchPrecedenceAndCategoryIndependence(t *testing.T) {
	snapshot := testSnapshot(
		Rule{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeDomain, Pattern: "example.com", Priority: 100},
		Rule{ID: 2, Category: CategoryAccess, Action: ActionAllow, MatchType: MatchTypeFull, Pattern: "api.example.com", Priority: 1},
		Rule{ID: 3, Category: CategoryRoute, Action: ActionLocal, MatchType: MatchTypeDomain, Pattern: "example.com", Priority: 100},
		Rule{ID: 4, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeDomain, Pattern: "dev.example.com", Priority: 100},
		Rule{ID: 5, Category: CategoryLogging, Action: ActionNoLog, MatchType: MatchTypeRegexp, Pattern: `^api\.[a-z]+\.com$`, Priority: 100},
	)
	compiled, err := Compile(snapshot, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	result, err := compiled.Match("API.EXAMPLE.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if result.Access.RuleID != 2 || result.Access.Action != ActionAllow {
		t.Fatalf("access = %+v, want full allow rule 2", result.Access)
	}
	if result.Route.RuleID != 3 || result.Route.Action != ActionLocal {
		t.Fatalf("route = %+v, want parent domain local rule 3", result.Route)
	}
	if result.Logging.RuleID != 5 || result.Logging.Action != ActionNoLog {
		t.Fatalf("logging = %+v, want regexp no_log rule 5", result.Logging)
	}

	result, err = compiled.Match("api.dev.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if result.Access.RuleID != 4 {
		t.Fatalf("access = %+v, want deeper domain rule 4", result.Access)
	}
	if result.Route.RuleID != 3 {
		t.Fatalf("route = %+v, want parent route rule 3", result.Route)
	}
}

func TestAccessAllowWinsExactTie(t *testing.T) {
	compiled, err := Compile(testSnapshot(
		Rule{ID: 20, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeFull, Pattern: "example.com", Priority: 100},
		Rule{ID: 10, Category: CategoryAccess, Action: ActionAllow, MatchType: MatchTypeFull, Pattern: "example.com", Priority: 100},
	), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := compiled.Match("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if result.Access.RuleID != 10 || result.Access.Action != ActionAllow {
		t.Fatalf("access = %+v, want allow rule", result.Access)
	}
}

func TestSubscriptionSetMatchesSuffixAndReportsSource(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.SchemaVersion = 2
	snapshot.SubscriptionSets = []SubscriptionSet{{SourceID: 42, SourceName: "domestic-list", Category: CategoryRoute, Action: ActionLocal, Priority: 100, Domains: []string{"example.cn", "api.example.cn"}}}
	compiled, err := Compile(snapshot, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	matched, err := compiled.Match("www.api.example.cn")
	if err != nil || matched.Route.SourceID != 42 || matched.Route.SourceName != "domestic-list" || matched.Route.Action != ActionLocal {
		t.Fatalf("match=%+v err=%v", matched, err)
	}
}

func routeBinding(sourceID, bindingID int64, group string, priority int, domains ...string) SubscriptionSet {
	return SubscriptionSet{SourceID: sourceID, SourceName: fmt.Sprintf("source-%d", sourceID), BindingID: bindingID, UpstreamGroupID: group, Category: CategoryRoute, Action: ActionUpstream, Priority: priority, Domains: domains}
}

func TestV2SubscriptionCompatibility(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.SchemaVersion = 2
	snapshot.SubscriptionSets = []SubscriptionSet{
		{SourceID: 1, SourceName: "route", Category: CategoryRoute, Action: ActionRemote, Priority: 50, Domains: []string{"route.example"}},
		{SourceID: 2, SourceName: "access", Category: CategoryAccess, Action: ActionAllow, Priority: 20, Domains: []string{"access.example"}},
	}
	compiled, err := Compile(snapshot, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result, _ := compiled.Match("www.route.example"); result.Route.Action != ActionRemote || result.Route.SourceID != 1 {
		t.Fatalf("v2 route = %+v", result.Route)
	}
	if result, _ := compiled.Match("www.access.example"); result.Access.Action != ActionAllow || result.Access.SourceID != 2 {
		t.Fatalf("v2 access = %+v", result.Access)
	}
}

func TestLegacySchemaCanonicalPersistenceRoundTrip(t *testing.T) {
	for _, schemaVersion := range []uint32{1, 2} {
		snapshot := testSnapshot(Rule{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeFull, Pattern: "legacy.example"})
		snapshot.SchemaVersion = schemaVersion
		canonical, compiled, err := canonicalSnapshot(snapshot, DefaultLimits())
		if err != nil {
			t.Fatalf("schema %d canonical snapshot: %v", schemaVersion, err)
		}
		data, err := marshalSnapshot(canonical)
		if err != nil {
			t.Fatalf("schema %d marshal snapshot: %v", schemaVersion, err)
		}
		parsed, err := ParseSnapshot(data)
		if err != nil {
			t.Fatalf("schema %d parse persisted snapshot: %v", schemaVersion, err)
		}
		reloaded, err := Compile(parsed, DefaultLimits())
		if err != nil {
			t.Fatalf("schema %d compile persisted snapshot: %v", schemaVersion, err)
		}
		if reloaded.SchemaVersion() != schemaVersion || reloaded.Checksum() != compiled.Checksum() {
			t.Fatalf("schema %d round trip = version %d checksum %q", schemaVersion, reloaded.SchemaVersion(), reloaded.Checksum())
		}
	}
}

func TestV3RouteBindingValidation(t *testing.T) {
	tests := []SubscriptionSet{
		routeBinding(1, 0, "custom", 10, "example.com"),
		routeBinding(1, 1, "UPPER", 10, "example.com"),
		routeBinding(1, 1, "-invalid", 10, "example.com"),
		{SourceID: 1, SourceName: "legacy", Category: CategoryRoute, Action: ActionLocal, Domains: []string{"example.com"}},
	}
	for _, set := range tests {
		snapshot := testSnapshot()
		snapshot.SubscriptionSets = []SubscriptionSet{set}
		if _, err := Compile(snapshot, DefaultLimits()); err == nil {
			t.Fatalf("invalid v3 binding accepted: %+v", set)
		}
	}

	for name, sets := range map[string][]SubscriptionSet{
		"source":  {routeBinding(1, 1, "one", 1, "one.example"), routeBinding(1, 2, "two", 1, "two.example")},
		"binding": {routeBinding(1, 1, "one", 1, "one.example"), routeBinding(2, 1, "two", 1, "two.example")},
	} {
		snapshot := testSnapshot()
		snapshot.SubscriptionSets = sets
		if _, err := Compile(snapshot, DefaultLimits()); err == nil {
			t.Fatalf("duplicate %s ID accepted", name)
		}
	}
	nonRoute := testSnapshot()
	nonRoute.SubscriptionSets = []SubscriptionSet{{SourceID: 1, SourceName: "access", Category: CategoryAccess, Action: ActionBlock, BindingID: 1, UpstreamGroupID: "custom", Domains: []string{"example.com"}}}
	if _, err := Compile(nonRoute, DefaultLimits()); err == nil {
		t.Fatal("binding fields on access subscription accepted")
	}
	legacy := testSnapshot()
	legacy.SchemaVersion = 2
	legacy.SubscriptionSets = []SubscriptionSet{{SourceID: 1, SourceName: "route", Category: CategoryRoute, Action: ActionLocal, BindingID: 1, UpstreamGroupID: "custom", Domains: []string{"example.com"}}}
	if _, err := Compile(legacy, DefaultLimits()); err == nil {
		t.Fatal("v3 binding fields in legacy schema accepted")
	}
}

func TestV3ManualRouteAlwaysOverridesBinding(t *testing.T) {
	for _, rule := range []Rule{
		{ID: 1, Category: CategoryRoute, Action: ActionLocal, MatchType: MatchTypeFull, Pattern: "www.example.com"},
		{ID: 2, Category: CategoryRoute, Action: ActionRemote, MatchType: MatchTypeDomain, Pattern: "example.com"},
		{ID: 3, Category: CategoryRoute, Action: ActionLocal, MatchType: MatchTypeRegexp, Pattern: `^www\.example\.com$`},
	} {
		snapshot := testSnapshot(rule)
		snapshot.SubscriptionSets = []SubscriptionSet{routeBinding(10, 20, "custom", 0, "example.com")}
		compiled, err := Compile(snapshot, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		result, err := compiled.Match("www.example.com")
		if err != nil || result.Route.RuleID != rule.ID || result.Route.SourceID != 0 {
			t.Fatalf("%s manual route did not override binding: %+v, err=%v", rule.MatchType, result.Route, err)
		}
	}
}

func TestV3BindingPrecedenceAndCompression(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.SubscriptionSets = []SubscriptionSet{
		routeBinding(1, 30, "parent", 10, "example.com", "duplicate.example"),
		routeBinding(2, 20, "deep", 100, "api.example.com"),
		routeBinding(3, 10, "priority", 5, "priority.example", "duplicate.example"),
		routeBinding(4, 5, "binding", 5, "priority.example"),
	}
	compiled, err := Compile(snapshot, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.routeBindings) != 4 {
		t.Fatalf("flat binding table size = %d, want 4", len(compiled.routeBindings))
	}
	for qname, want := range map[string]int64{
		"www.api.example.com": 20,
		"priority.example":    5,
		"duplicate.example":   10,
	} {
		result, err := compiled.Match(qname)
		if err != nil || result.Route.BindingID != want || result.Route.Action != ActionUpstream {
			t.Fatalf("Match(%q) route = %+v, err=%v, want binding %d", qname, result.Route, err, want)
		}
	}
}

func TestV3SubscriptionChecksumIsOrderIndependent(t *testing.T) {
	first := testSnapshot()
	first.SubscriptionSets = []SubscriptionSet{
		routeBinding(2, 20, "second", 20, "b.example", "a.example"),
		routeBinding(1, 10, "first", 10, "c.example"),
	}
	second := testSnapshot()
	second.SubscriptionSets = []SubscriptionSet{
		routeBinding(1, 10, "first", 10, "c.example"),
		routeBinding(2, 20, "second", 20, "a.example", "b.example"),
	}
	a, err := Compile(first, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compile(second, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if a.Checksum() != b.Checksum() {
		t.Fatalf("subscription checksums differ: %s != %s", a.Checksum(), b.Checksum())
	}
}

func TestV3ChecksumMatchesControllerContract(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		checksum string
	}{
		{
			name:     "empty subscription sets",
			json:     `{"schema_version":3,"version":7,"expected_current_version":6,"generated_at":"2026-08-04T01:02:03Z","block_rcode":3,"rules":[],"subscription_sets":[]}`,
			checksum: "sha256:b769858ae147f674e01c524e19c9cb1f0de93130a4e91f6690fdfac2ba28892a",
		},
		{
			name:     "route binding",
			json:     `{"schema_version":3,"version":8,"expected_current_version":7,"generated_at":"2026-08-04T01:02:03Z","block_rcode":3,"rules":[],"subscription_sets":[{"source_id":42,"source_name":"route-source","category":"route","action":"upstream","binding_id":9,"upstream_group_id":"custom_group","priority":10,"domains":["api.example.com","example.com"]}]}`,
			checksum: "sha256:5e9647b202b686096c078169ab7a677caf62e04d92e36bc06184517783715e3e",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := ParseSnapshot([]byte(test.json))
			if err != nil {
				t.Fatal(err)
			}
			snapshot.Checksum = test.checksum
			compiled, err := Compile(snapshot, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if compiled.Checksum() != test.checksum {
				t.Fatalf("checksum = %q, want %q", compiled.Checksum(), test.checksum)
			}
		})
	}
}

func TestV3SubscriptionRuleCapacityBoundary(t *testing.T) {
	domains := make([]string, DefaultLimits().MaxRules)
	for i := range domains {
		domains[i] = fmt.Sprintf("d%d.example", i)
	}
	snapshot := testSnapshot()
	snapshot.SubscriptionSets = []SubscriptionSet{routeBinding(1, 1, "capacity", 1, domains...)}
	compiled, err := Compile(snapshot, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if compiled.RuleCount() != DefaultLimits().MaxRules {
		t.Fatalf("rule count = %d", compiled.RuleCount())
	}
	snapshot.SubscriptionSets[0].Domains = append(snapshot.SubscriptionSets[0].Domains, "overflow.example")
	if _, err := Compile(snapshot, DefaultLimits()); err == nil {
		t.Fatal("snapshot above 200k rule capacity was accepted")
	}
}

func TestCompileRejectsRouteConflict(t *testing.T) {
	_, err := Compile(testSnapshot(
		Rule{ID: 1, Category: CategoryRoute, Action: ActionLocal, MatchType: MatchTypeDomain, Pattern: "example.com", Priority: 100},
		Rule{ID: 2, Category: CategoryRoute, Action: ActionRemote, MatchType: MatchTypeDomain, Pattern: "example.com", Priority: 100},
	), DefaultLimits())
	if err == nil {
		t.Fatal("Compile() error = nil, want route conflict")
	}
}

func TestNormalizeDomainIDNAndInvalidInput(t *testing.T) {
	normalized, err := NormalizeDomain("  BÜCHER.example. ")
	if err != nil {
		t.Fatal(err)
	}
	if normalized != "xn--bcher-kva.example" {
		t.Fatalf("NormalizeDomain() = %q", normalized)
	}
	for _, input := range []string{"", "a..example", "*.example", "a\x00.example"} {
		if _, err := NormalizeDomain(input); err == nil {
			t.Fatalf("NormalizeDomain(%q) error = nil", input)
		}
	}
}

func TestCompileMatchesNormalizedIDN(t *testing.T) {
	compiled, err := Compile(testSnapshot(
		Rule{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeFull, Pattern: "BÜCHER.example."},
	), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := compiled.Match("bücher.example")
	if err != nil {
		t.Fatal(err)
	}
	if result.Access.RuleID != 1 || result.NormalizedQName != "xn--bcher-kva.example" {
		t.Fatalf("IDN result = %+v", result)
	}
}

func TestChecksumIsCanonicalAndInputIsNotMutated(t *testing.T) {
	rules := []Rule{
		{ID: 2, Category: CategoryRoute, Action: ActionRemote, MatchType: MatchTypeFull, Pattern: "B.example", Priority: 50},
		{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeDomain, Pattern: "A.example.", Priority: 100},
	}
	first, err := Compile(testSnapshot(rules...), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(testSnapshot(rules[1], rules[0]), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if first.Checksum() != second.Checksum() {
		t.Fatalf("checksums differ: %s != %s", first.Checksum(), second.Checksum())
	}
	if rules[0].Pattern != "B.example" || rules[1].Pattern != "A.example." {
		t.Fatalf("Compile mutated input rules: %+v", rules)
	}
	withChecksum := testSnapshot(rules...)
	withChecksum.Checksum = first.Checksum()
	if _, err := Compile(withChecksum, DefaultLimits()); err != nil {
		t.Fatalf("Compile() with matching checksum error = %v", err)
	}
}

func TestParseSnapshotRejectsUnknownFields(t *testing.T) {
	_, err := ParseSnapshot([]byte(`{"schema_version":1,"version":1,"block_rcode":3,"rules":[],"unexpected":true}`))
	if err == nil {
		t.Fatal("ParseSnapshot() error = nil, want unknown field error")
	}
}

func TestCompileRejectsLimitsAndChecksumMismatch(t *testing.T) {
	_, err := Compile(testSnapshot(Rule{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeRegexp, Pattern: "a"}), Limits{MaxRegexpRules: 0, MaxRegexpBytes: 1})
	if err != nil {
		t.Fatalf("Compile() error = %v, want default limits when zero", err)
	}
	_, err = Compile(testSnapshot(Rule{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeRegexp, Pattern: "abcd"}), Limits{MaxRegexpBytes: 3})
	if err == nil {
		t.Fatal("Compile() error = nil, want regexp size error")
	}
	snapshot := testSnapshot()
	snapshot.Checksum = "sha256:not-a-real-checksum"
	if _, err := Compile(snapshot, DefaultLimits()); err == nil {
		t.Fatal("Compile() error = nil, want checksum mismatch")
	}
}

func TestCompileAcceptsChecksummedEmptyRulesArray(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.SchemaVersion = 2
	snapshot.Rules = []Rule{}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	snapshot.Checksum = "sha256:" + hex.EncodeToString(sum[:])

	compiled, err := Compile(snapshot, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if compiled.RuleCount() != 0 {
		t.Fatalf("rule count = %d, want 0", compiled.RuleCount())
	}
}

func TestCompileRejectsInvalidRuleFields(t *testing.T) {
	testCases := []Rule{
		{ID: 0, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeFull, Pattern: "example.com"},
		{ID: 1, Category: "unknown", Action: ActionBlock, MatchType: MatchTypeFull, Pattern: "example.com"},
		{ID: 1, Category: CategoryAccess, Action: ActionRemote, MatchType: MatchTypeFull, Pattern: "example.com"},
		{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: "keyword", Pattern: "example"},
		{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeFull, Pattern: "example.com", Priority: 1001},
	}
	for _, rule := range testCases {
		if _, err := Compile(testSnapshot(rule), DefaultLimits()); err == nil {
			t.Fatalf("Compile(%+v) error = nil", rule)
		}
	}
	invalidSchema := testSnapshot()
	invalidSchema.SchemaVersion = SchemaVersion + 1
	if _, err := Compile(invalidSchema, DefaultLimits()); err == nil {
		t.Fatal("Compile() error = nil, want schema validation error")
	}
}

func TestCompileRejectsDuplicateIDsAndCannotRelaxHardLimits(t *testing.T) {
	_, err := Compile(testSnapshot(
		Rule{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeFull, Pattern: "a.example"},
		Rule{ID: 1, Category: CategoryLogging, Action: ActionNoLog, MatchType: MatchTypeFull, Pattern: "a.example"},
	), DefaultLimits())
	if err == nil {
		t.Fatal("Compile() error = nil, want duplicate ID error")
	}
	longComment := string(make([]rune, DefaultLimits().MaxCommentRunes+1))
	_, err = Compile(testSnapshot(Rule{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeFull, Pattern: "example.com", Comment: longComment}), Limits{MaxCommentRunes: 1_000})
	if err == nil {
		t.Fatal("Compile() error = nil, want hard comment limit error")
	}
}

func TestChecksumNormalizesGeneratedAtToUTC(t *testing.T) {
	instant := time.Date(2026, 7, 16, 1, 2, 3, 0, time.FixedZone("UTC+8", 8*60*60))
	first := testSnapshot()
	first.GeneratedAt = instant
	second := testSnapshot()
	second.GeneratedAt = instant.UTC()
	compiledFirst, err := Compile(first, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	compiledSecond, err := Compile(second, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if compiledFirst.Checksum() != compiledSecond.Checksum() {
		t.Fatalf("checksums differ: %s != %s", compiledFirst.Checksum(), compiledSecond.Checksum())
	}
}

func TestStoreConcurrentMatchAndSwap(t *testing.T) {
	first, err := Compile(testSnapshot(Rule{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeDomain, Pattern: "example.com"}), DefaultLimits())
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
			for range 500 {
				snapshot := store.Load()
				if snapshot == nil {
					t.Error("Load() returned nil")
					return
				}
				if _, err := snapshot.Match("www.example.com"); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	for i := 2; i < 102; i++ {
		next, err := Compile(testSnapshot(Rule{ID: int64(i), Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeDomain, Pattern: fmt.Sprintf("%d.example.com", i)}), DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		store.Swap(next)
	}
	wg.Wait()
}
