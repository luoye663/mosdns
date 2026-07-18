package dynamic_ecs

import (
	"context"
	"net/netip"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/miekg/dns"
)

func TestClientSubnetUsesMaskedClientAddress(t *testing.T) {
	p := &Plugin{}
	settings := Snapshot{Version: 1, Mode: "client_subnet", Mask4: 24, Mask6: 48}
	p.snapshot.Store(&settings)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	ctx := query_context.NewContext(query)
	ctx.ServerMeta = server.QueryMeta{ClientAddr: netip.MustParseAddr("192.0.2.37")}
	if err := p.Exec(context.Background(), ctx); err != nil {
		t.Fatal(err)
	}
	option, ok := ctx.QOpt().Option[0].(*dns.EDNS0_SUBNET)
	if !ok || option.SourceNetmask != 24 || option.Address.String() != "192.0.2.0" {
		t.Fatalf("ECS option=%+v", option)
	}
}

func TestFixedSubnetRequiresCIDR(t *testing.T) {
	if _, err := canonical(Snapshot{Mode: "fixed_subnet", Preset4: "192.0.2.1"}); err == nil {
		t.Fatal("non-CIDR fixed ECS subnet was accepted")
	}
}

func TestFixedSubnetKeepsConfiguredPrefixLength(t *testing.T) {
	p := &Plugin{}
	settings, err := canonical(Snapshot{Version: 1, Mode: "fixed_subnet", Preset4: "203.0.113.23/20"})
	if err != nil {
		t.Fatal(err)
	}
	p.snapshot.Store(&settings)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	ctx := query_context.NewContext(query)
	ctx.ServerMeta = server.QueryMeta{ClientAddr: netip.MustParseAddr("192.0.2.1")}
	if err := p.Exec(context.Background(), ctx); err != nil {
		t.Fatal(err)
	}
	option := ctx.QOpt().Option[0].(*dns.EDNS0_SUBNET)
	if option.SourceNetmask != 20 || option.Address.String() != "203.0.112.0" {
		t.Fatalf("ECS option=%+v", option)
	}
}
