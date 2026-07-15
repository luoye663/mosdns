package query_audit

import (
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
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
