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

func benchmarkMatch(b *testing.B, count int) {
	rules := make([]Rule, 0, count)
	for i := range count {
		rules = append(rules, Rule{ID: int64(i + 1), Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeDomain, Pattern: fmt.Sprintf("%d.example.test", i)})
	}
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
