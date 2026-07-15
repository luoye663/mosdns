// Package dynamic_rule_engine 提供不可变 DNS 规则快照的运行时扩展点。
// 快照编译和 HTTP API 属于后续阶段；本阶段只建立已验证的 mosdns 接口契约。
package dynamic_rule_engine

import (
	"context"
	"sync/atomic"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/prometheus/client_golang/prometheus"
)

const PluginType = "dynamic_rule_engine"

var (
	// 构建时注入版本信息，不会影响规则行为。
	Version = "dev"
)

// Args 预留 Phase 3 的配置契约。快照持久化和 HTTP API 尚未实现，校验随后加入。
type Args struct {
	SnapshotFile        string `yaml:"snapshot_file"`
	BackupFile          string `yaml:"backup_file"`
	AuthTokenFile       string `yaml:"auth_token_file"`
	MaxRules            int    `yaml:"max_rules"`
	MaxRegexpRules      int    `yaml:"max_regexp_rules"`
	MaxRequestBodyBytes int64  `yaml:"max_request_body_bytes"`
	FailOpen            bool   `yaml:"fail_open_on_snapshot_error"`
}

// Plugin 会在 Phase 2 持有不可变快照指针。
type Plugin struct {
	closed atomic.Bool
	store  Store
}

var (
	_ sequence.Executable        = (*Plugin)(nil)
	_ interface{ Close() error } = (*Plugin)(nil)
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

// Init 在本阶段只注册常量版本指标；DNS 请求路径不访问快照、磁盘或 controller。
func Init(bp *coremain.BP, _ any) (any, error) {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "plugin_info",
		Help: "Static dynamic rule engine build information.",
		ConstLabels: prometheus.Labels{
			"tag":     bp.Tag(),
			"version": Version,
		},
	})
	if err := prometheus.WrapRegistererWithPrefix(PluginType+"_", bp.M().GetMetricsReg()).Register(metric); err != nil {
		return nil, err
	}
	metric.Set(1)
	return &Plugin{}, nil
}

// Exec 在不可变编译器完成前刻意保持为空操作。
func (p *Plugin) Exec(_ context.Context, _ *query_context.Context) error {
	return nil
}

// Close 保持幂等，后续 worker 可复用这一生命周期入口。
func (p *Plugin) Close() error {
	p.closed.Store(true)
	return nil
}
