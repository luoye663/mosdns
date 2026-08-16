package dynamic_rule_engine

import (
	"fmt"
	"testing"
)

func BenchmarkMatchEmpty(b *testing.B) {
	benchmarkMatch(b, 0)
}

func BenchmarkMatch10KDomains(b *testing.B) {
	benchmarkMatch(b, 10_000)
}

func BenchmarkMatch100KDomains(b *testing.B) {
	benchmarkMatch(b, 100_000)
}

func BenchmarkMatch200KDomains(b *testing.B) {
	benchmarkMatch(b, 200_000)
}

func BenchmarkCompile100KDomains(b *testing.B) {
	rules := benchmarkRules(100_000)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		compiled, err := Compile(testSnapshot(rules...), DefaultLimits())
		if err != nil {
			b.Fatal(err)
		}
		if compiled.RuleCount() != len(rules) {
			b.Fatal("compiled rule count mismatch")
		}
	}
}

func BenchmarkCompile100KSubscriptionDomains(b *testing.B) {
	domains := make([]string, 100_000)
	for i := range domains {
		domains[i] = fmt.Sprintf("%d.example.test", i)
	}
	snapshot := testSnapshot()
	snapshot.SubscriptionSets = []SubscriptionSet{{SourceID: 1, SourceName: "benchmark", BindingID: 1, UpstreamGroupID: "benchmark", Category: CategoryRoute, Action: ActionUpstream, Priority: 100, Domains: domains}}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		compiled, err := Compile(snapshot, DefaultLimits())
		if err != nil {
			b.Fatal(err)
		}
		if compiled.RuleCount() != len(domains) {
			b.Fatal("compiled rule count mismatch")
		}
	}
}

func benchmarkMatch(b *testing.B, count int) {
	rules := benchmarkRules(count)
	compiled, err := Compile(testSnapshot(rules...), DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		if _, err := compiled.Match("99999.example.test"); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkRules(count int) []Rule {
	rules := make([]Rule, 0, count)
	for i := range count {
		rules = append(rules, Rule{ID: int64(i + 1), Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeDomain, Pattern: fmt.Sprintf("%d.example.test", i)})
	}
	return rules
}
