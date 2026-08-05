package dynamic_forward

import (
	"fmt"
	"testing"
)

func TestCanonicalRuntimeConfigAndPriorityLevels(t *testing.T) {
	config, err := CanonicalRuntimeConfig(RuntimeConfig{Concurrent: 1, Upstreams: []Upstream{{Tag: "backup", Addr: "8.8.8.8", Priority: 200}, {Tag: "primary", Addr: "tcp://1.1.1.1", Priority: 100}}})
	if err != nil {
		t.Fatal(err)
	}
	if config.Mode != "race" || config.Upstreams[0].Addr != "udp://8.8.8.8" || config.Upstreams[0].Weight != 1 || config.Upstreams[0].TimeoutMS != defaultTimeoutMS {
		t.Fatalf("canonical config = %+v", config)
	}
	levels := priorityLevels(config.Upstreams)
	if len(levels) != 2 || levels[0][0] != "primary" || levels[1][0] != "backup" {
		t.Fatalf("priority levels = %v", levels)
	}
}

func TestCanonicalRuntimeConfigRejectsInvalidInput(t *testing.T) {
	for _, config := range []RuntimeConfig{
		{Concurrent: 0, Upstreams: []Upstream{{Tag: "one", Addr: "1.1.1.1"}}},
		{Mode: "unknown", Concurrent: 1, Upstreams: []Upstream{{Tag: "one", Addr: "1.1.1.1"}}},
		{Concurrent: 1, Upstreams: []Upstream{{Tag: "one", Addr: "ftp://1.1.1.1"}}},
		{Concurrent: 1, Upstreams: []Upstream{{Tag: "one", Addr: "1.1.1.1", TimeoutMS: 99}}},
		{Concurrent: 1, Upstreams: []Upstream{{Tag: "one", Addr: "1.1.1.1", TimeoutMS: 4001}}},
	} {
		if _, err := CanonicalRuntimeConfig(config); err == nil {
			t.Fatalf("invalid config accepted: %+v", config)
		}
	}
}

func TestCanonicalRuntimeConfigBootstrap(t *testing.T) {
	base := RuntimeConfig{Concurrent: 1, Upstreams: []Upstream{{Tag: "one", Addr: "tls://resolver.example"}}}
	for _, tc := range []struct {
		name      string
		bootstrap string
		version   int
		want      string
		wantVer   int
	}{
		{name: "default version", bootstrap: " 1.1.1.1 ", want: "1.1.1.1", wantVer: 4},
		{name: "dual stack", bootstrap: "1.1.1.1", version: 46, want: "1.1.1.1", wantVer: 46},
		{name: "ipv4 with port", bootstrap: "223.5.5.5:5353", version: 4, want: "223.5.5.5:5353", wantVer: 4},
		{name: "ipv6", bootstrap: "2400:3200::1", version: 6, want: "2400:3200::1", wantVer: 6},
		{name: "ipv6 with port", bootstrap: "[2400:3200::1]:5353", version: 6, want: "[2400:3200::1]:5353", wantVer: 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := base
			config.Bootstrap, config.BootstrapVer = tc.bootstrap, tc.version
			canonical, err := CanonicalRuntimeConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			if canonical.Bootstrap != tc.want || canonical.BootstrapVer != tc.wantVer {
				t.Fatalf("bootstrap = %q/%d, want %q/%d", canonical.Bootstrap, canonical.BootstrapVer, tc.want, tc.wantVer)
			}
		})
	}

	for _, tc := range []struct {
		bootstrap string
		version   int
	}{
		{bootstrap: "dns.example"},
		{bootstrap: "https://1.1.1.1"},
		{bootstrap: "1.1.1.1:0"},
		{bootstrap: "1.1.1.1:65536"},
		{bootstrap: "1.1.1.1", version: 5},
	} {
		config := base
		config.Bootstrap, config.BootstrapVer = tc.bootstrap, tc.version
		if _, err := CanonicalRuntimeConfig(config); err == nil {
			t.Fatalf("invalid bootstrap accepted: %q/%d", tc.bootstrap, tc.version)
		}
	}
}

func TestWeightedTagsCanOrderEveryCandidate(t *testing.T) {
	upstreams := []Upstream{{Tag: "one", Weight: 100}, {Tag: "two", Weight: 10}, {Tag: "three", Weight: 1}}
	selected := weightedTags(upstreams, len(upstreams))
	if len(selected) != len(upstreams) {
		t.Fatalf("weighted selection = %v", selected)
	}
	seen := make(map[string]bool, len(selected))
	for _, tag := range selected {
		seen[tag] = true
	}
	for _, upstream := range upstreams {
		if !seen[upstream.Tag] {
			t.Fatalf("weighted selection omitted %q: %v", upstream.Tag, selected)
		}
	}
}

func TestCanonicalRuntimeConfigBoundsUpstreamsAndConcurrencyAtSixteen(t *testing.T) {
	upstreams := make([]Upstream, 16)
	for i := range upstreams {
		upstreams[i] = Upstream{Tag: fmt.Sprintf("upstream_%d", i), Addr: "1.1.1.1", Weight: i + 1}
	}
	config, err := CanonicalRuntimeConfig(RuntimeConfig{Mode: "weighted", Concurrent: 16, Upstreams: upstreams})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Upstreams) != len(upstreams) {
		t.Fatalf("upstreams = %d, want %d", len(config.Upstreams), len(upstreams))
	}
	selected := weightedTags(config.Upstreams, config.Concurrent)
	if len(selected) != 16 {
		t.Fatalf("weighted selection = %d, want 16", len(selected))
	}
	seen := make(map[string]struct{}, len(selected))
	for _, tag := range selected {
		seen[tag] = struct{}{}
	}
	if len(seen) != len(selected) {
		t.Fatalf("weighted selection contains duplicates: %v", selected)
	}
	if _, err := CanonicalRuntimeConfig(RuntimeConfig{Mode: "weighted", Concurrent: 17, Upstreams: upstreams}); err == nil {
		t.Fatal("concurrent value above 16 was accepted")
	}
	tooMany := append(upstreams, Upstream{Tag: "upstream_16", Addr: "1.1.1.1"})
	if _, err := CanonicalRuntimeConfig(RuntimeConfig{Mode: "weighted", Concurrent: 16, Upstreams: tooMany}); err == nil {
		t.Fatal("seventeenth upstream was accepted")
	}
}
