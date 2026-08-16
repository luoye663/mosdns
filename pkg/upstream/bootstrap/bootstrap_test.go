package bootstrap

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func startTestServer(t *testing.T, handler dns.Handler) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: conn, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	addr, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestDualStackResolvesAndRotatesAddressFamilies(t *testing.T) {
	var mu sync.Mutex
	queries := make(map[uint16]int)
	server := startTestServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		qtype := q.Question[0].Qtype
		mu.Lock()
		queries[qtype]++
		mu.Unlock()
		response := new(dns.Msg)
		response.SetReply(q)
		switch qtype {
		case dns.TypeA:
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
		case dns.TypeAAAA:
			response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")}}
		}
		_ = w.WriteMsg(response)
	}))
	resolver, err := New("resolver.example", 853, server, DualStackVersion, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	first, err := resolver.GetAddrPortStr(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolver.GetAddrPortStr(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	third, err := resolver.GetAddrPortStr(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if first != "192.0.2.1:853" || second != "[2001:db8::1]:853" || third != first {
		t.Fatalf("rotated addresses = %q, %q, %q", first, second, third)
	}
	mu.Lock()
	defer mu.Unlock()
	if queries[dns.TypeA] == 0 || queries[dns.TypeAAAA] == 0 {
		t.Fatalf("queries = %v", queries)
	}
}

func TestDualStackUsesAvailableFamilyWithoutFullTimeout(t *testing.T) {
	server := startTestServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		if q.Question[0].Qtype != dns.TypeAAAA {
			return
		}
		response := new(dns.Msg)
		response.SetReply(q)
		response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::2")}}
		_ = w.WriteMsg(response)
	}))
	resolver, err := New("ipv6-only.example", 443, server, DualStackVersion, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	addr, err := resolver.GetAddrPortStr(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "[2001:db8::2]:443" {
		t.Fatalf("address = %q", addr)
	}
}

func TestBootstrapKeepsZeroAsMinimumTTL(t *testing.T) {
	server := startTestServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600}, A: net.ParseIP("192.0.2.1")},
				&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.ParseIP("192.0.2.2")},
			}
		}
		_ = w.WriteMsg(response)
	}))
	resolver, err := New("resolver.example", 53, server, 4, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	_, ttl, _, err := resolver.updateAddr(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 0 {
		t.Fatalf("minimum TTL = %d, want 0", ttl)
	}
}

func TestBootstrapVersionQueryTypes(t *testing.T) {
	for version, want := range map[int][]uint16{
		0:                {dns.TypeA},
		4:                {dns.TypeA},
		6:                {dns.TypeAAAA},
		DualStackVersion: {dns.TypeA, dns.TypeAAAA},
	} {
		got, ok := bootstrapVer2Qts(version)
		if !ok || len(got) != len(want) {
			t.Fatalf("version %d query types = %v, ok=%t", version, got, ok)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("version %d query types = %v", version, got)
			}
		}
	}
	if _, ok := bootstrapVer2Qts(5); ok {
		t.Fatal("invalid bootstrap version accepted")
	}
}
