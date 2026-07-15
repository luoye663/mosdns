// Package query_audit 提供 DNS 查询事件的后置观察扩展点。
package query_audit

import (
	"context"
	"sync/atomic"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/prometheus/client_golang/prometheus"
)

const PluginType = "query_audit"

var (
	// 版本信息由构建时注入，可安全作为指标标签暴露。
	Version = "dev"
)

// Args 预留 Phase 4 审计发送器的配置契约。
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
}

// Plugin 会在 Phase 4 持有有界队列和发送 worker。
type Plugin struct {
	closed atomic.Bool
}

var (
	_ sequence.RecursiveExecutable = (*Plugin)(nil)
	_ interface{ Close() error }   = (*Plugin)(nil)
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

// Init 在 skeleton 中只注册版本指标，不启动 worker。
func Init(bp *coremain.BP, _ any) (any, error) {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "plugin_info",
		Help: "Static query audit build information.",
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

// Exec 复用 query_summary 模型：先完成 next，再由后续阶段读取最终状态。
func (p *Plugin) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	return next.ExecNext(ctx, qCtx)
}

// Close 保持幂等，为后续队列 worker 定义生命周期归属。
func (p *Plugin) Close() error {
	p.closed.Store(true)
	return nil
}
