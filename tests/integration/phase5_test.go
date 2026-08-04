//go:build linux

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const controlToken = "phase5-integration-token"

func TestPhase5DNSRoutingAndAtomicPublishing(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 5 launches a real mosdns process")
	}
	groupA := newMockUpstream(t, netip.MustParseAddr("10.0.0.1"))
	groupB := newMockUpstream(t, netip.MustParseAddr("10.0.0.2"))
	instance := startMosdns(t, groupA.addr, groupB.addr)

	// UDP 与 TCP 均走配置默认组，并且第二次查询命中该组的专属缓存。
	assertAnswer(t, instance.query("udp", "cache.example"), "10.0.0.2")
	assertAnswer(t, instance.query("tcp", "cache.example"), "10.0.0.2")
	if got := groupB.queries.Load(); got != 1 {
		t.Fatalf("default upstream queries = %d, want 1 after cache hit", got)
	}

	// 已缓存域名发布 block 后仍必须在进入 cache 前返回 NXDOMAIN。
	instance.apply(t, 1, 0, []rule{{ID: 1, Category: "access", Action: "block", MatchType: "domain", Pattern: "cache.example"}})
	if response := instance.query("udp", "cache.example"); response.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked cached response rcode = %s, want NXDOMAIN", dns.RcodeToString[response.Rcode])
	}
	if got := groupB.queries.Load(); got != 1 {
		t.Fatalf("block unexpectedly reached default upstream: %d queries", got)
	}

	// full allow 的优先级高于 domain block，只绕过 block，不强制变更默认组。
	instance.apply(t, 2, 1, []rule{
		{ID: 2, Category: "access", Action: "block", MatchType: "domain", Pattern: "cache.example"},
		{ID: 3, Category: "access", Action: "allow", MatchType: "full", Pattern: "cache.example"},
	})
	assertAnswer(t, instance.query("udp", "cache.example"), "10.0.0.2")

	// 任意组路由命中不同 mock upstream，验证两个组缓存的物理隔离。
	instance.apply(t, 3, 2, []rule{
		{ID: 4, Category: "route", Action: "upstream", UpstreamGroupID: "group_a", MatchType: "full", Pattern: "force.a"},
		{ID: 5, Category: "route", Action: "upstream", UpstreamGroupID: "group_b", MatchType: "full", Pattern: "force.b"},
	})
	assertAnswer(t, instance.query("udp", "force.a"), "10.0.0.1")
	assertAnswer(t, instance.query("udp", "force.b"), "10.0.0.2")
	if groupA.queries.Load() != 1 || groupB.queries.Load() != 2 {
		t.Fatalf("unexpected route counts group_a=%d group_b=%d", groupA.queries.Load(), groupB.queries.Load())
	}

	// 同一域名切换组后，不能读取前一个组缓存中的旧响应。
	instance.apply(t, 4, 3, []rule{{ID: 6, Category: "route", Action: "upstream", UpstreamGroupID: "group_b", MatchType: "full", Pattern: "switch.example"}})
	assertAnswer(t, instance.query("udp", "switch.example"), "10.0.0.2")
	instance.apply(t, 5, 4, []rule{{ID: 7, Category: "route", Action: "upstream", UpstreamGroupID: "group_a", MatchType: "full", Pattern: "switch.example"}})
	assertAnswer(t, instance.query("udp", "switch.example"), "10.0.0.1")

	// cache flush 只允许共享 token；flush 后默认组查询会再次到达 upstream。
	instance.flush(t, "group_b", "", http.StatusUnauthorized)
	assertAnswer(t, instance.query("udp", "flush.example"), "10.0.0.2")
	beforeFlush := groupB.queries.Load()
	instance.flush(t, "group_b", controlToken, http.StatusOK)
	assertAnswer(t, instance.query("udp", "flush.example"), "10.0.0.2")
	if got := groupB.queries.Load(); got != beforeFlush+1 {
		t.Fatalf("default cache flush did not force new upstream query: got %d want %d", got, beforeFlush+1)
	}

	// controller/query ingest 不可用时，审计 worker 的发送失败不能影响 DNS 或重建 DNS socket。
	pid := instance.cmd.Process.Pid
	var queryFailures atomic.Int32
	stopQueries := make(chan struct{})
	var queries sync.WaitGroup
	queries.Add(1)
	go func() {
		defer queries.Done()
		for {
			select {
			case <-stopQueries:
				return
			default:
				if response, err := instance.queryResult("udp", "publish.example"); err != nil || response.Rcode != dns.RcodeSuccess {
					queryFailures.Add(1)
				}
			}
		}
	}()
	for version := uint64(6); version < 1006; version++ {
		instance.apply(t, version, version-1, nil)
	}
	close(stopQueries)
	queries.Wait()
	if queryFailures.Load() != 0 {
		t.Fatalf("continuous DNS queries failed during publishing: %d", queryFailures.Load())
	}
	if instance.cmd.Process.Pid != pid || instance.cmd.ProcessState != nil {
		t.Fatal("mosdns process changed or exited during atomic publishing")
	}
	assertAnswer(t, instance.query("tcp", "publish.example"), "10.0.0.2")
}

type mockUpstream struct {
	addr    string
	server  *dns.Server
	queries atomic.Int32
}

func newMockUpstream(t *testing.T, answer netip.Addr) *mockUpstream {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mock := &mockUpstream{addr: packetConn.LocalAddr().String()}
	mock.server = &dns.Server{PacketConn: packetConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		mock.queries.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: answer.AsSlice()})
		_ = w.WriteMsg(response)
	})}
	go func() { _ = mock.server.ActivateAndServe() }()
	t.Cleanup(func() { _ = mock.server.Shutdown() })
	return mock
}

type mosdnsInstance struct {
	t       *testing.T
	cmd     *exec.Cmd
	dnsAddr string
	apiURL  string
	client  *http.Client
}

func startMosdns(t *testing.T, groupAAddr, groupBAddr string) *mosdnsInstance {
	t.Helper()
	mosdnsRoot := filepath.Clean(filepath.Join("..", ".."))
	tempDir := t.TempDir()
	binary := filepath.Join(tempDir, "mosdns")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = mosdnsRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build mosdns: %v\n%s", err, output)
	}
	dnsPort := unusedTCPPort(t)
	apiPort := unusedTCPPort(t)
	tokenFile := filepath.Join(tempDir, "token")
	if err := os.WriteFile(tokenFile, []byte(controlToken), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(tempDir, "config.yaml")
	config := fmt.Sprintf(`log:
  level: info
api:
  http: "127.0.0.1:%d"
plugins:
  - tag: dynamic_rules
    type: dynamic_rule_engine
    args:
      snapshot_file: %q
      backup_file: %q
      auth_token_file: %q
      fail_open_on_snapshot_error: true
  - tag: query_audit
    type: query_audit
    args:
      endpoint: "http://127.0.0.1:1/internal/v1/query-events/batch"
      auth_token_file: %q
      queue_size: 32
      batch_size: 8
      flush_interval: "10ms"
      request_timeout: "20ms"
      max_retries: 0
      include_answers: false
      include_error_text: true
      max_error_text_bytes: 64
  - tag: dynamic_upstreams
    type: dynamic_upstream_registry
    args:
      snapshot_file: %q
      backup_file: %q
      auth_token_file: %q
      initial_snapshot:
        schema_version: 1
        version: 1
        default_group_id: group_b
        groups:
          - id: group_a
            name: Group A
            enabled: true
            mode: race
            concurrent: 1
            upstreams:
              - tag: group_a_upstream
                addr: "udp://%s"
            ecs:
              mode: off
            cache:
              enabled: true
              size: 32
          - id: group_b
            name: Group B
            enabled: true
            mode: race
            concurrent: 1
            upstreams:
              - tag: group_b_upstream
                addr: "udp://%s"
            ecs:
              mode: off
            cache:
              enabled: true
              size: 32
        cache:
          enabled: true
          lazy_ttl: 0
          negative:
            enabled: true
            ttl: 30
  - tag: main
    type: sequence
    args:
      - exec: $query_audit
      - exec: $dynamic_rules
      - matches:
          - mark 1001
        exec: reject 3
      - exec: $dynamic_upstreams
      - exec: accept
  - tag: udp_server
    type: udp_server
    args:
      entry: main
      listen: "127.0.0.1:%d"
  - tag: tcp_server
    type: tcp_server
    args:
      entry: main
      listen: "127.0.0.1:%d"
`, apiPort, filepath.Join(tempDir, "rules-current.json"), filepath.Join(tempDir, "rules-backup.json"), tokenFile, tokenFile, filepath.Join(tempDir, "registry-current.json"), filepath.Join(tempDir, "registry-backup.json"), tokenFile, groupAAddr, groupBAddr, dnsPort, dnsPort)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	cmd := exec.Command(binary, "start", "-c", configPath)
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	instance := &mosdnsInstance{t: t, cmd: cmd, dnsAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort)), apiURL: fmt.Sprintf("http://127.0.0.1:%d", apiPort), client: &http.Client{Timeout: time.Second}}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	lastResult := "no response"
	for time.Now().Before(deadline) {
		request, _ := http.NewRequest(http.MethodGet, instance.apiURL+"/plugins/dynamic_rules/status", nil)
		request.Header.Set("Authorization", "Bearer "+controlToken)
		response, err := instance.client.Do(request)
		if err == nil && response.StatusCode == http.StatusOK {
			response.Body.Close()
			return instance
		}
		if err != nil {
			lastResult = err.Error()
		}
		if response != nil {
			lastResult = "HTTP " + response.Status
			response.Body.Close()
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("mosdns did not become ready (%s):\n%s", lastResult, logs.String())
	return nil
}

func (m *mosdnsInstance) query(network, name string) *dns.Msg {
	m.t.Helper()
	response, err := m.queryResult(network, name)
	if err != nil {
		m.t.Fatal(err)
	}
	return response
}

func (m *mosdnsInstance) queryResult(network, name string) (*dns.Msg, error) {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), dns.TypeA)
	response, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(query, m.dnsAddr)
	return response, err
}

func (m *mosdnsInstance) apply(t *testing.T, version, expected uint64, rules []rule) {
	t.Helper()
	payload := snapshot{SchemaVersion: 4, Version: version, ExpectedCurrentVersion: expected, GeneratedAt: time.Now().UTC(), BlockRCode: dns.RcodeNameError, Rules: rules}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, m.apiURL+"/plugins/dynamic_rules/snapshot", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+controlToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := m.client.Do(request)
	if err != nil {
		t.Fatalf("apply version %d: %v", version, err)
	}
	defer response.Body.Close()
	content, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("apply version %d status=%d body=%s", version, response.StatusCode, content)
	}
}

func (m *mosdnsInstance) flush(t *testing.T, tag, token string, wantStatus int) {
	t.Helper()
	body := bytes.NewBufferString(fmt.Sprintf(`{"group_id":%q,"expected_current_version":1}`, tag))
	request, err := http.NewRequest(http.MethodPost, m.apiURL+"/plugins/dynamic_upstreams/flush", body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := m.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		t.Fatalf("flush %s status=%d want=%d", tag, response.StatusCode, wantStatus)
	}
}

type snapshot struct {
	SchemaVersion          int       `json:"schema_version"`
	Version                uint64    `json:"version"`
	ExpectedCurrentVersion uint64    `json:"expected_current_version"`
	GeneratedAt            time.Time `json:"generated_at"`
	BlockRCode             int       `json:"block_rcode"`
	Rules                  []rule    `json:"rules"`
}

type rule struct {
	ID              int64  `json:"id"`
	Category        string `json:"category"`
	Action          string `json:"action"`
	UpstreamGroupID string `json:"upstream_group_id,omitempty"`
	MatchType       string `json:"match_type"`
	Pattern         string `json:"pattern"`
	Priority        int    `json:"priority"`
	Source          string `json:"source"`
	Comment         string `json:"comment"`
}

func unusedTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func assertAnswer(t *testing.T, response *dns.Msg, want string) {
	t.Helper()
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("response rcode=%s answers=%v", dns.RcodeToString[response.Rcode], response.Answer)
	}
	answer, ok := response.Answer[0].(*dns.A)
	if !ok || answer.A.String() != want {
		t.Fatalf("answer=%v, want %s", response.Answer, want)
	}
}
