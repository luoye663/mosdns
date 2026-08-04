package dynamic_forward

import "testing"

func TestCanonicalRuntimeConfigAndPriorityLevels(t *testing.T) {
	config, err := CanonicalRuntimeConfig(RuntimeConfig{Concurrent: 1, Upstreams: []Upstream{{Tag: "backup", Addr: "8.8.8.8", Priority: 200}, {Tag: "primary", Addr: "tcp://1.1.1.1", Priority: 100}}})
	if err != nil {
		t.Fatal(err)
	}
	if config.Mode != "race" || config.Upstreams[0].Addr != "udp://8.8.8.8" || config.Upstreams[0].Weight != 1 {
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
	} {
		if _, err := CanonicalRuntimeConfig(config); err == nil {
			t.Fatalf("invalid config accepted: %+v", config)
		}
	}
}
