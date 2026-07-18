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
