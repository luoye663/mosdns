package dynamic_rule_engine

import "testing"

func FuzzNormalizeDomain(f *testing.F) {
	for _, seed := range []string{"example.com", "BÜCHER.example.", "", "a..example", "*.example"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1024 {
			t.Skip()
		}
		_, _ = NormalizeDomain(input)
	})
}

func FuzzParseSnapshot(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"version":1,"block_rcode":3,"rules":[]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseSnapshot(input)
	})
}

func FuzzRegexpRule(f *testing.F) {
	f.Add(`^api-[0-9]+\.example\.com$`)
	f.Add(`[`)
	f.Fuzz(func(t *testing.T, pattern string) {
		if len(pattern) > DefaultLimits().MaxRegexpBytes {
			t.Skip()
		}
		_, _ = Compile(testSnapshot(Rule{ID: 1, Category: CategoryAccess, Action: ActionBlock, MatchType: MatchTypeRegexp, Pattern: pattern}), DefaultLimits())
	})
}
