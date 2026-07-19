// Package query_audit 在 DNS 查询完成后异步发送轻量审计事件。
package query_audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_rule_engine"
	fastforward "github.com/IrineSistiana/mosdns/v5/plugin/executable/forward"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	PluginType            = "query_audit"
	eventSchemaVersion    = 1
	shutdownFlushLimit    = 2 * time.Second
	maxAnswerIPs          = 16
	maxAnswerRecords      = 32
	maxAnswerRecordBytes  = 1024
	maxAnswerRecordsBytes = 16 * 1024
)

var Version = "dev"

// Marks 统一定义审计读取的 marks，启动时会检查彼此不冲突。
type Marks struct {
	AccessBlock        uint32 `yaml:"access_block"`
	RouteLocal         uint32 `yaml:"route_local"`
	RouteRemote        uint32 `yaml:"route_remote"`
	NoLog              uint32 `yaml:"no_log"`
	SubscriptionLocal  uint32 `yaml:"subscription_local"`
	SubscriptionRemote uint32 `yaml:"subscription_remote"`
	SubscriptionBlock  uint32 `yaml:"subscription_block"`
	SubscriptionAllow  uint32 `yaml:"subscription_allow"`
	CacheHit           uint32 `yaml:"cache_hit"`
}

// Args 是 query_audit 的 YAML 配置；启用 include_answers 时携带受限的 Answer 区诊断数据。
type Args struct {
	Endpoint          string `yaml:"endpoint"`
	AuthTokenFile     string `yaml:"auth_token_file"`
	QueueSize         int    `yaml:"queue_size"`
	BatchSize         int    `yaml:"batch_size"`
	FlushInterval     string `yaml:"flush_interval"`
	RequestTimeout    string `yaml:"request_timeout"`
	MaxRetries        int    `yaml:"max_retries"`
	IncludeAnswers    bool   `yaml:"include_answers"`
	IncludeErrorText  bool   `yaml:"include_error_text"`
	MaxErrorTextBytes int    `yaml:"max_error_text_bytes"`
	Marks             Marks  `yaml:"marks"`
}

// QueryEvent 是 controller ingest 接口使用的最小隐私审计记录。
type QueryEvent struct {
	SchemaVersion          int      `json:"schema_version"`
	EventID                string   `json:"event_id"`
	TimestampUnixMS        int64    `json:"timestamp_unix_ms"`
	ProcessStartedAtUnixMS int64    `json:"process_started_at_unix_ms"`
	ClientIP               string   `json:"client_ip"`
	Protocol               string   `json:"protocol"`
	QName                  string   `json:"qname"`
	QType                  uint16   `json:"qtype"`
	QClass                 uint16   `json:"qclass"`
	RCode                  int      `json:"rcode"`
	Route                  string   `json:"route"`
	RouteSource            string   `json:"route_source"`
	UpstreamGroup          string   `json:"upstream_group"`
	UpstreamTag            string   `json:"upstream_tag"`
	CacheHit               bool     `json:"cache_hit"`
	SnapshotVersion        uint64   `json:"snapshot_version"`
	AccessRuleID           int64    `json:"access_rule_id"`
	RouteRuleID            int64    `json:"route_rule_id"`
	SubscriptionSourceID   int64    `json:"subscription_source_id"`
	SubscriptionSourceName string   `json:"subscription_source_name"`
	AnswerCount            int      `json:"answer_count"`
	AnswerMinTTLSeconds    *uint32  `json:"answer_min_ttl_seconds"`
	SubscriptionCategories []string `json:"subscription_categories,omitempty"`
	AnswerIPs              []string `json:"answer_ips,omitempty"`
	AnswerRecords          []string `json:"answer_records,omitempty"`
	LatencyUS              int64    `json:"latency_us"`
	ErrorCode              string   `json:"error_code"`
	ErrorText              string   `json:"error_text"`
}

type eventBatch struct {
	SchemaVersion int          `json:"schema_version"`
	SenderID      string       `json:"sender_id"`
	SentAtUnixMS  int64        `json:"sent_at_unix_ms"`
	Events        []QueryEvent `json:"events"`
}

type auditMetrics struct {
	enqueued    prometheus.Counter
	dropped     *prometheus.CounterVec
	sent        prometheus.Counter
	batches     *prometheus.CounterVec
	sendErrors  prometheus.Counter
	queueSize   prometheus.Gauge
	lastSuccess prometheus.Gauge
}

// Plugin 将网络发送完全隔离到单一 worker；DNS 请求只构建事件并尝试非阻塞入队。
type Plugin struct {
	closed       atomic.Bool
	once         sync.Once
	queue        chan QueryEvent
	eventCounter atomic.Uint64

	endpoint       string
	token          []byte
	batchSize      int
	flushInterval  time.Duration
	requestTimeout time.Duration
	maxRetries     int
	includeAnswers bool
	includeErrors  bool
	maxErrorBytes  int
	marks          Marks
	client         *http.Client
	processStarted time.Time
	eventPrefix    string

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	metrics auditMetrics
	dropped atomic.Uint64
}

var (
	_ sequence.RecursiveExecutable = (*Plugin)(nil)
	_ io.Closer                    = (*Plugin)(nil)
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, raw any) (any, error) {
	args, ok := raw.(*Args)
	if !ok {
		return nil, fmt.Errorf("invalid query_audit arguments %T", raw)
	}
	p, err := newPlugin(*args)
	if err != nil {
		return nil, err
	}
	if err := p.registerMetrics(bp); err != nil {
		_ = p.Close()
		return nil, err
	}
	bp.RegAPI(p.Api())
	p.startWorker()
	return p, nil
}

func newPlugin(args Args) (*Plugin, error) {
	if err := validateArgs(&args); err != nil {
		return nil, err
	}
	token, err := os.ReadFile(args.AuthTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read auth_token_file: %w", err)
	}
	token = []byte(strings.TrimSpace(string(token)))
	if len(token) == 0 {
		return nil, fmt.Errorf("auth_token_file is empty")
	}
	flushInterval, _ := time.ParseDuration(args.FlushInterval)
	requestTimeout, _ := time.ParseDuration(args.RequestTimeout)
	ctx, cancel := context.WithCancel(context.Background())
	prefix, err := newEventPrefix()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("generate query event prefix: %w", err)
	}
	p := &Plugin{
		queue: make(chan QueryEvent, args.QueueSize), endpoint: args.Endpoint, token: token,
		batchSize: args.BatchSize, flushInterval: flushInterval, requestTimeout: requestTimeout,
		maxRetries: args.MaxRetries, includeAnswers: args.IncludeAnswers, includeErrors: args.IncludeErrorText, maxErrorBytes: args.MaxErrorTextBytes,
		marks: args.Marks, client: &http.Client{}, processStarted: time.Now().UTC(), eventPrefix: prefix, ctx: ctx, cancel: cancel,
	}
	p.metrics = newAuditMetrics(nil)
	return p, nil
}

// startWorker 必须在正式指标注册后调用，避免 worker 与初始化写入共享字段。
func (p *Plugin) startWorker() {
	p.wg.Add(1)
	go p.runWorker()
}

func validateArgs(args *Args) error {
	if args.Endpoint == "" || args.AuthTokenFile == "" {
		return fmt.Errorf("endpoint and auth_token_file are required")
	}
	u, err := url.Parse(args.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("endpoint must be an absolute http(s) URL")
	}
	if args.QueueSize == 0 {
		args.QueueSize = 65_536
	}
	if args.BatchSize == 0 {
		args.BatchSize = 256
	}
	if args.FlushInterval == "" {
		args.FlushInterval = "250ms"
	}
	if args.RequestTimeout == "" {
		args.RequestTimeout = "2s"
	}
	if args.MaxErrorTextBytes == 0 {
		args.MaxErrorTextBytes = 256
	}
	if args.Marks == (Marks{}) {
		args.Marks = Marks{AccessBlock: 1001, RouteLocal: 1101, RouteRemote: 1102, NoLog: 1201, SubscriptionLocal: 1301, SubscriptionRemote: 1302, SubscriptionBlock: 1303, SubscriptionAllow: 1304, CacheHit: 2101}
	}
	if args.QueueSize < 1 || args.BatchSize < 1 {
		return fmt.Errorf("queue_size and batch_size must be greater than zero")
	}
	if args.MaxRetries < 0 || args.MaxRetries > 1 {
		return fmt.Errorf("max_retries must be within 0..1")
	}
	if args.MaxErrorTextBytes < 0 || args.MaxErrorTextBytes > 4096 {
		return fmt.Errorf("max_error_text_bytes must be within 0..4096")
	}
	if duration, err := time.ParseDuration(args.FlushInterval); err != nil || duration <= 0 {
		return fmt.Errorf("flush_interval must be a positive duration")
	}
	if duration, err := time.ParseDuration(args.RequestTimeout); err != nil || duration <= 0 {
		return fmt.Errorf("request_timeout must be a positive duration")
	}
	seen := map[uint32]string{}
	for name, value := range map[string]uint32{"access_block": args.Marks.AccessBlock, "route_local": args.Marks.RouteLocal, "route_remote": args.Marks.RouteRemote, "no_log": args.Marks.NoLog, "subscription_local": args.Marks.SubscriptionLocal, "subscription_remote": args.Marks.SubscriptionRemote, "subscription_block": args.Marks.SubscriptionBlock, "subscription_allow": args.Marks.SubscriptionAllow, "cache_hit": args.Marks.CacheHit} {
		if value == 0 {
			return fmt.Errorf("marks.%s must be greater than zero", name)
		}
		if previous, ok := seen[value]; ok {
			return fmt.Errorf("marks.%s duplicates marks.%s", name, previous)
		}
		seen[value] = name
	}
	return nil
}

// Exec 必须先让后续 sequence 执行，才能观察 goto、accept、reject 后的最终状态。
func (p *Plugin) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	started := time.Now()
	err := next.ExecNext(ctx, qCtx)
	p.enqueueNonBlocking(p.buildEvent(qCtx, started, err))
	return err
}

func (p *Plugin) buildEvent(qCtx *query_context.Context, started time.Time, execErr error) *QueryEvent {
	if len(qCtx.Q().Question) != 1 {
		p.metrics.dropped.WithLabelValues("no_question").Inc()
		return nil
	}
	if qCtx.HasMark(p.marks.NoLog) {
		p.metrics.dropped.WithLabelValues("no_log").Inc()
		return nil
	}
	question := qCtx.QQuestion()
	response := qCtx.R()
	rcode, answerCount := dns.RcodeRefused, 0
	if execErr != nil {
		rcode = dns.RcodeServerFailure
	} else if response != nil {
		rcode, answerCount = response.Rcode, len(response.Answer)
	}
	route, routeSource, upstream := p.route(qCtx)
	event := &QueryEvent{
		SchemaVersion: eventSchemaVersion, EventID: p.newEventID(), TimestampUnixMS: time.Now().UnixMilli(), ProcessStartedAtUnixMS: p.processStarted.UnixMilli(),
		ClientIP: qCtx.ServerMeta.ClientAddr.String(), Protocol: protocol(qCtx), QName: normalizeQName(question.Name), QType: question.Qtype, QClass: question.Qclass,
		RCode: rcode, Route: route, RouteSource: routeSource, UpstreamGroup: upstream, UpstreamTag: fastforward.SelectedUpstreamTag(qCtx), CacheHit: qCtx.HasMark(p.marks.CacheHit),
		AnswerCount: answerCount, LatencyUS: time.Since(started).Microseconds(),
	}
	for _, category := range []struct {
		mark uint32
		name string
	}{{p.marks.SubscriptionAllow, "allow"}, {p.marks.SubscriptionBlock, "block"}, {p.marks.SubscriptionLocal, "local"}, {p.marks.SubscriptionRemote, "remote"}} {
		if qCtx.HasMark(category.mark) {
			event.SubscriptionCategories = append(event.SubscriptionCategories, category.name)
		}
	}
	if decision, ok := dynamic_rule_engine.RuntimeDecisionFromContext(qCtx); ok {
		event.SnapshotVersion, event.AccessRuleID, event.RouteRuleID = decision.SnapshotVersion, decision.AccessRuleID, decision.RouteRuleID
		event.SubscriptionSourceID, event.SubscriptionSourceName = decision.SubscriptionSourceID, decision.SubscriptionSourceName
		if event.RouteSource == "" {
			event.RouteSource = decision.RouteSource
		}
	}
	if execErr != nil {
		event.ErrorCode = "DNS_PROCESSING_ERROR"
		if p.includeErrors {
			event.ErrorText = truncate(execErr.Error(), p.maxErrorBytes)
		}
	}
	if p.includeAnswers && response != nil {
		event.AnswerIPs = answerIPs(response)
		event.AnswerRecords = answerRecords(response)
	}
	if response != nil {
		event.AnswerMinTTLSeconds = answerMinTTLSeconds(response)
	}
	return event
}

// answerMinTTLSeconds captures the shortest final Answer lifetime clients receive.
func answerMinTTLSeconds(response *dns.Msg) *uint32 {
	if len(response.Answer) == 0 {
		return nil
	}
	minimum := response.Answer[0].Header().Ttl
	for _, record := range response.Answer[1:] {
		if ttl := record.Header().Ttl; ttl < minimum {
			minimum = ttl
		}
	}
	return &minimum
}

// answerIPs retains only A and AAAA data for the controller's bounded memory cache.
func answerIPs(response *dns.Msg) []string {
	ips := make([]string, 0, maxAnswerIPs)
	seen := make(map[string]struct{}, maxAnswerIPs)
	for _, record := range response.Answer {
		var ip string
		switch value := record.(type) {
		case *dns.A:
			ip = value.A.String()
		case *dns.AAAA:
			ip = value.AAAA.String()
		default:
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
		if len(ips) == maxAnswerIPs {
			break
		}
	}
	return ips
}

// answerRecords preserves Answer order for short-lived diagnostics without retaining a DNS packet.
func answerRecords(response *dns.Msg) []string {
	records := make([]string, 0, min(len(response.Answer), maxAnswerRecords))
	remaining := maxAnswerRecordsBytes
	for _, record := range response.Answer {
		if len(records) == maxAnswerRecords || remaining == 0 {
			break
		}
		value := truncate(record.String(), min(maxAnswerRecordBytes, remaining))
		records = append(records, value)
		remaining -= len(value)
	}
	return records
}

func (p *Plugin) route(qCtx *query_context.Context) (route, source, upstream string) {
	if qCtx.HasMark(p.marks.AccessBlock) {
		if qCtx.HasMark(p.marks.SubscriptionBlock) {
			return "block", "subscription", ""
		}
		return "block", "dynamic_rule", ""
	}
	dynamicSource := false
	if decision, ok := dynamic_rule_engine.RuntimeDecisionFromContext(qCtx); ok {
		dynamicSource = decision.RouteSource == "dynamic_rule"
	}
	if qCtx.HasMark(p.marks.RouteLocal) {
		if qCtx.HasMark(p.marks.SubscriptionLocal) {
			return "local", "subscription", "local_dns"
		}
		if dynamicSource {
			return "local", "dynamic_rule", "local_dns"
		}
		return "local", "default", "local_dns"
	}
	if qCtx.HasMark(p.marks.RouteRemote) {
		if qCtx.HasMark(p.marks.SubscriptionRemote) {
			return "remote", "subscription", "remote_dns"
		}
		if dynamicSource {
			return "remote", "dynamic_rule", "remote_dns"
		}
		return "remote", "default", "remote_dns"
	}
	return "remote", "default", "remote_dns"
}

func (p *Plugin) enqueueNonBlocking(event *QueryEvent) {
	if event == nil || p.closed.Load() {
		return
	}
	select {
	case p.queue <- *event:
		p.metrics.enqueued.Inc()
		p.metrics.queueSize.Inc()
	default:
		p.metrics.dropped.WithLabelValues("queue_full").Inc()
		p.dropped.Add(1)
	}
}

// Api exposes only non-sensitive runtime health values to the authenticated controller.
func (p *Plugin) Api() *chi.Mux {
	router := chi.NewRouter()
	router.Use(p.authorize)
	router.Get("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"queue_depth": len(p.queue), "queue_capacity": cap(p.queue), "dropped_events": p.dropped.Load()})
	})
	return router
}

func (p *Plugin) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		value := r.Header.Get("Authorization")
		provided := []byte(strings.TrimPrefix(value, prefix))
		if !strings.HasPrefix(value, prefix) || len(provided) != len(p.token) || subtle.ConstantTimeCompare(provided, p.token) != 1 {
			http.Error(w, "authorization required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Plugin) runWorker() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()
	batch := make([]QueryEvent, 0, p.batchSize)
	for {
		select {
		case event := <-p.queue:
			p.metrics.queueSize.Dec()
			batch = append(batch, event)
			if len(batch) >= p.batchSize {
				p.send(batch, p.ctx)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				p.send(batch, p.ctx)
				batch = batch[:0]
			}
		case <-p.ctx.Done():
			// 关闭时不关闭 queue，尽力拿走已经入队的事件，避免生产者 panic。
			for {
				select {
				case event := <-p.queue:
					p.metrics.queueSize.Dec()
					batch = append(batch, event)
				default:
					if len(batch) > 0 {
						shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownFlushLimit)
						p.send(batch, shutdownCtx)
						cancel()
					}
					return
				}
			}
		}
	}
}

func (p *Plugin) send(events []QueryEvent, parent context.Context) {
	if len(events) == 0 {
		return
	}
	for attempt := 0; attempt <= p.maxRetries; attempt++ {
		if err := p.sendOnce(events, parent); err == nil {
			p.metrics.sent.Add(float64(len(events)))
			p.metrics.batches.WithLabelValues("success").Inc()
			p.metrics.lastSuccess.SetToCurrentTime()
			return
		}
		p.metrics.sendErrors.Inc()
		if attempt < p.maxRetries {
			select {
			case <-time.After(50 * time.Millisecond):
			case <-parent.Done():
			}
		}
	}
	p.metrics.batches.WithLabelValues("failure").Inc()
	p.dropped.Add(uint64(len(events)))
}

func (p *Plugin) sendOnce(events []QueryEvent, parent context.Context) error {
	body, err := json.Marshal(eventBatch{SchemaVersion: eventSchemaVersion, SenderID: "mosdns", SentAtUnixMS: time.Now().UnixMilli(), Events: events})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, p.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+string(p.token))
	req.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("controller returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (p *Plugin) registerMetrics(bp *coremain.BP) error {
	p.metrics = newAuditMetrics(prometheus.Labels{"tag": bp.Tag()})
	registerer := prometheus.WrapRegistererWithPrefix(PluginType+"_", bp.M().GetMetricsReg())
	for _, collector := range []prometheus.Collector{p.metrics.enqueued, p.metrics.dropped, p.metrics.sent, p.metrics.batches, p.metrics.sendErrors, p.metrics.queueSize, p.metrics.lastSuccess} {
		if err := registerer.Register(collector); err != nil {
			return err
		}
	}
	return nil
}

func newAuditMetrics(labels prometheus.Labels) auditMetrics {
	return auditMetrics{
		enqueued:    prometheus.NewCounter(prometheus.CounterOpts{Name: "enqueued_total", Help: "Enqueued query audit events.", ConstLabels: labels}),
		dropped:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dropped_total", Help: "Dropped query audit events.", ConstLabels: labels}, []string{"reason"}),
		sent:        prometheus.NewCounter(prometheus.CounterOpts{Name: "sent_total", Help: "Sent query audit events.", ConstLabels: labels}),
		batches:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "batch_total", Help: "Query audit batch sends.", ConstLabels: labels}, []string{"result"}),
		sendErrors:  prometheus.NewCounter(prometheus.CounterOpts{Name: "send_error_total", Help: "Query audit send errors.", ConstLabels: labels}),
		queueSize:   prometheus.NewGauge(prometheus.GaugeOpts{Name: "queue_size", Help: "Current query audit queue size.", ConstLabels: labels}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{Name: "last_success_timestamp_seconds", Help: "Last successful query audit send.", ConstLabels: labels}),
	}
}

func (p *Plugin) Close() error {
	p.once.Do(func() { p.closed.Store(true); p.cancel() })
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(shutdownFlushLimit):
	}
	return nil
}

func newEventPrefix() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// newEventID 在请求路径只做原子递增，随机数仅在插件启动阶段读取一次。
func (p *Plugin) newEventID() string {
	return p.eventPrefix + "-" + strconv.FormatUint(p.eventCounter.Add(1), 10)
}

func protocol(qCtx *query_context.Context) string {
	if qCtx.ServerMeta.FromUDP {
		return "udp"
	}
	return "tcp"
}
func normalizeQName(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }
func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
