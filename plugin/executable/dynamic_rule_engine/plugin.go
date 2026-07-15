// Package dynamic_rule_engine 提供不可变 DNS 规则快照的运行时扩展点。
package dynamic_rule_engine

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
)

const PluginType = "dynamic_rule_engine"

var Version = "dev"

// runtimeDecisionKey 仅在 DNSContext 生命周期内保存不可变的规则决策。
var runtimeDecisionKey = query_context.RegKey()

// Args 是 dynamic_rule_engine 的 YAML 配置。配置错误必须在启动时拒绝。
type Args struct {
	SnapshotFile        string `yaml:"snapshot_file"`
	BackupFile          string `yaml:"backup_file"`
	AuthTokenFile       string `yaml:"auth_token_file"`
	MaxRules            int    `yaml:"max_rules"`
	MaxRegexpRules      int    `yaml:"max_regexp_rules"`
	MaxRequestBodyBytes int64  `yaml:"max_request_body_bytes"`
	FailOpen            bool   `yaml:"fail_open_on_snapshot_error"`
	Marks               Marks  `yaml:"marks"`
}

type pluginMetrics struct {
	applySuccess  prometheus.Counter
	applyFailure  prometheus.Counter
	applyConflict prometheus.Counter
	match         *prometheus.CounterVec
}

// Plugin 的写路径由 applyMu 串行化；DNS 请求只读取 Store 中的原子指针。
type Plugin struct {
	closed atomic.Bool
	store  Store

	snapshotFile        string
	backupFile          string
	maxRequestBodyBytes int64
	limits              Limits
	marks               Marks
	token               []byte
	persist             func(Snapshot) error
	applyMu             sync.Mutex

	stateValue          atomic.Value // string
	snapshotFileOK      atomic.Bool
	lastCompileDuration atomic.Int64
	metrics             pluginMetrics
}

var (
	_ sequence.Executable        = (*Plugin)(nil)
	_ interface{ Close() error } = (*Plugin)(nil)
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, raw any) (any, error) {
	args, ok := raw.(*Args)
	if !ok {
		return nil, fmt.Errorf("invalid dynamic_rule_engine arguments %T", raw)
	}
	p, err := newPlugin(*args)
	if err != nil {
		return nil, err
	}
	if err := p.registerMetrics(bp); err != nil {
		return nil, err
	}
	router := chi.NewRouter()
	router.Mount("/", p.router())
	bp.RegAPI(router)
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
	p := &Plugin{
		snapshotFile: args.SnapshotFile, backupFile: args.BackupFile,
		maxRequestBodyBytes: args.MaxRequestBodyBytes,
		limits:              Limits{MaxRules: args.MaxRules, MaxRegexpRules: args.MaxRegexpRules},
		marks:               args.Marks, token: token,
	}
	// 独立构造（如单元测试）也可安全调用 API；正式 Init 会替换为已注册指标。
	p.metrics = newPluginMetrics(nil)
	p.persist = func(snapshot Snapshot) error { return persistSnapshot(snapshot, p.snapshotFile, p.backupFile) }
	p.setState("starting")
	if err := p.loadStartupSnapshot(); err != nil {
		if !args.FailOpen {
			return nil, err
		}
		p.setState("degraded")
	}
	return p, nil
}

func validateArgs(args *Args) error {
	if args.SnapshotFile == "" || args.BackupFile == "" || args.AuthTokenFile == "" {
		return fmt.Errorf("snapshot_file, backup_file and auth_token_file are required")
	}
	if args.SnapshotFile == args.BackupFile {
		return fmt.Errorf("snapshot_file and backup_file must differ")
	}
	defaults := DefaultLimits()
	if args.MaxRules == 0 {
		args.MaxRules = defaults.MaxRules
	}
	if args.MaxRegexpRules == 0 {
		args.MaxRegexpRules = defaults.MaxRegexpRules
	}
	if args.MaxRequestBodyBytes == 0 {
		args.MaxRequestBodyBytes = maxHardRequestBodyBytes
	}
	if args.MaxRules < 1 || args.MaxRules > defaults.MaxRules {
		return fmt.Errorf("max_rules must be within 1..%d", defaults.MaxRules)
	}
	if args.MaxRegexpRules < 1 || args.MaxRegexpRules > defaults.MaxRegexpRules {
		return fmt.Errorf("max_regexp_rules must be within 1..%d", defaults.MaxRegexpRules)
	}
	if args.MaxRequestBodyBytes < 1 || args.MaxRequestBodyBytes > maxHardRequestBodyBytes {
		return fmt.Errorf("max_request_body_bytes must be within 1..%d", maxHardRequestBodyBytes)
	}
	if args.Marks == (Marks{}) {
		args.Marks = defaultMarks()
	}
	return args.Marks.validate()
}

func (p *Plugin) loadStartupSnapshot() error {
	var errors []string
	for _, filename := range []string{p.snapshotFile, p.backupFile} {
		data, err := os.ReadFile(filename)
		if err != nil {
			errors = append(errors, fmt.Sprintf("read %s: %v", filename, err))
			continue
		}
		snapshot, err := ParseSnapshot(data)
		if err != nil {
			errors = append(errors, fmt.Sprintf("parse %s: %v", filename, err))
			continue
		}
		_, compiled, err := canonicalSnapshot(snapshot, p.limits)
		if err != nil {
			errors = append(errors, fmt.Sprintf("validate %s: %v", filename, err))
			continue
		}
		p.store.Swap(compiled)
		p.snapshotFileOK.Store(filename == p.snapshotFile)
		p.setState("ready")
		return nil
	}
	return fmt.Errorf("load startup snapshot failed: %s", strings.Join(errors, "; "))
}

func (p *Plugin) registerMetrics(bp *coremain.BP) error {
	// 公共指标名称遵循规格中的 mosdns_dynamic_rules_*，不暴露内部包名。
	registerer := prometheus.WrapRegistererWithPrefix("dynamic_rules_", bp.M().GetMetricsReg())
	labels := prometheus.Labels{"tag": bp.Tag()}
	p.metrics = newPluginMetrics(labels)
	collectors := []prometheus.Collector{
		p.metrics.applySuccess, p.metrics.applyFailure, p.metrics.applyConflict, p.metrics.match,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "snapshot_version", Help: "Current dynamic snapshot version.", ConstLabels: labels}, func() float64 {
			if snapshot := p.store.Load(); snapshot != nil {
				return float64(snapshot.Version())
			}
			return 0
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "rule_count", Help: "Current dynamic snapshot rule count.", ConstLabels: labels}, func() float64 {
			if snapshot := p.store.Load(); snapshot != nil {
				return float64(snapshot.RuleCount())
			}
			return 0
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "regexp_rule_count", Help: "Current dynamic snapshot regexp rule count.", ConstLabels: labels}, func() float64 {
			if snapshot := p.store.Load(); snapshot != nil {
				return float64(snapshot.RegexpRuleCount())
			}
			return 0
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "last_compile_duration_seconds", Help: "Last snapshot compilation duration.", ConstLabels: labels}, func() float64 {
			return float64(p.lastCompileDuration.Load()) / 1000
		}),
	}
	for _, collector := range collectors {
		if err := registerer.Register(collector); err != nil {
			return err
		}
	}
	return nil
}

func newPluginMetrics(labels prometheus.Labels) pluginMetrics {
	return pluginMetrics{
		applySuccess:  prometheus.NewCounter(prometheus.CounterOpts{Name: "apply_total", Help: "Applied dynamic snapshots.", ConstLabels: mergeLabels(labels, prometheus.Labels{"result": "success"})}),
		applyFailure:  prometheus.NewCounter(prometheus.CounterOpts{Name: "apply_total", Help: "Failed dynamic snapshot applies.", ConstLabels: mergeLabels(labels, prometheus.Labels{"result": "failure"})}),
		applyConflict: prometheus.NewCounter(prometheus.CounterOpts{Name: "apply_total", Help: "Conflicting dynamic snapshot applies.", ConstLabels: mergeLabels(labels, prometheus.Labels{"result": "conflict"})}),
		match:         prometheus.NewCounterVec(prometheus.CounterOpts{Name: "match_total", Help: "Dynamic rule match decisions.", ConstLabels: labels}, []string{"access", "route"}),
	}
}

func mergeLabels(left, right prometheus.Labels) prometheus.Labels {
	result := make(prometheus.Labels, len(left)+len(right))
	for key, value := range left {
		result[key] = value
	}
	for key, value := range right {
		result[key] = value
	}
	return result
}

// Exec 不做 I/O 或锁等待，只读取已发布快照，并为后续 sequence 写入 marks 与 metadata。
func (p *Plugin) Exec(_ context.Context, qCtx *query_context.Context) error {
	snapshot := p.store.Load()
	if snapshot == nil {
		return nil
	}
	result, err := snapshot.Match(qCtx.QQuestion().Name)
	if err != nil {
		return nil
	} // 非法 QNAME 不影响 DNS 主链路。
	p.recordMatch(result)
	decision := RuntimeDecision{SnapshotVersion: result.SnapshotVersion, AccessRuleID: result.Access.RuleID, RouteRuleID: result.Route.RuleID, LoggingRuleID: result.Logging.RuleID, AccessAction: result.Access.Action, RouteAction: result.Route.Action}
	if result.Access.Action == ActionBlock {
		qCtx.SetMark(p.marks.AccessBlock)
	}
	if result.Route.Action == ActionLocal {
		qCtx.SetMark(p.marks.RouteLocal)
		decision.RouteSource = "dynamic_rule"
	}
	if result.Route.Action == ActionRemote {
		qCtx.SetMark(p.marks.RouteRemote)
		decision.RouteSource = "dynamic_rule"
	}
	if result.Logging.Action == ActionNoLog {
		qCtx.SetMark(p.marks.NoLog)
	}
	qCtx.StoreValue(runtimeDecisionKey, decision)
	return nil
}

func (p *Plugin) recordMatch(result MatchResult) {
	access, route := result.Access.Action, result.Route.Action
	if access == "" {
		access = "none"
	}
	if route == "" {
		route = "none"
	}
	p.metrics.match.WithLabelValues(access, route).Inc()
}

// RuntimeDecisionFromContext 提供 query_audit 读取统一的请求生命周期 metadata 的入口。
func RuntimeDecisionFromContext(qCtx *query_context.Context) (RuntimeDecision, bool) {
	value, ok := qCtx.GetValue(runtimeDecisionKey)
	decision, valid := value.(RuntimeDecision)
	return decision, ok && valid
}

func (p *Plugin) setState(state string) { p.stateValue.Store(state) }
func (p *Plugin) state() string {
	if state, ok := p.stateValue.Load().(string); ok {
		return state
	}
	return "starting"
}

func (p *Plugin) Close() error { p.closed.Store(true); return nil }
