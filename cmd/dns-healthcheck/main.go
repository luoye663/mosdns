// dns-healthcheck 以 UDP 或 TCP 查询验证 mosdns DNS listener 是否可用。
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/miekg/dns"
)

func main() {
	server := flag.String("server", "127.0.0.1:53", "DNS server address")
	name := flag.String("name", "healthcheck.invalid", "DNS query name")
	network := flag.String("network", "udp", "DNS transport: udp or tcp")
	timeout := flag.Duration("timeout", 2*time.Second, "query timeout")
	flag.Parse()
	if *network != "udp" && *network != "tcp" {
		fmt.Fprintln(os.Stderr, "network must be udp or tcp")
		os.Exit(2)
	}
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(*name), dns.TypeA)
	response, _, err := (&dns.Client{Net: *network, Timeout: *timeout}).Exchange(query, *server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "DNS health check failed:", err)
		os.Exit(1)
	}
	if response == nil {
		fmt.Fprintln(os.Stderr, "DNS health check failed: empty response")
		os.Exit(1)
	}
	fmt.Printf("dns_healthcheck network=%s rcode=%s answers=%d\n", *network, dns.RcodeToString[response.Rcode], len(response.Answer))
}
