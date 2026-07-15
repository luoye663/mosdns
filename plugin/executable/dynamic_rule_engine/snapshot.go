package dynamic_rule_engine

import "time"

const (
	SchemaVersion = 1

	CategoryAccess  = "access"
	CategoryRoute   = "route"
	CategoryLogging = "logging"

	ActionAllow  = "allow"
	ActionBlock  = "block"
	ActionLocal  = "local"
	ActionRemote = "remote"
	ActionNoLog  = "no_log"

	MatchTypeFull   = "full"
	MatchTypeDomain = "domain"
	MatchTypeRegexp = "regexp"
)

// Limits 统一约束编译输入，避免大快照或大量正则耗尽控制面资源。
type Limits struct {
	MaxRules        int
	MaxRegexpRules  int
	MaxRegexpBytes  int
	MaxDomainChars  int
	MaxCommentRunes int
}

func DefaultLimits() Limits {
	return Limits{
		MaxRules:        200_000,
		MaxRegexpRules:  500,
		MaxRegexpBytes:  512,
		MaxDomainChars:  253,
		MaxCommentRunes: 500,
	}
}

// Snapshot 是 controller 与运行时共享的完整规则版本，不支持运行时增量修改。
type Snapshot struct {
	SchemaVersion          uint32    `json:"schema_version"`
	Version                uint64    `json:"version"`
	ExpectedCurrentVersion uint64    `json:"expected_current_version"`
	GeneratedAt            time.Time `json:"generated_at"`
	Checksum               string    `json:"checksum,omitempty"`
	BlockRCode             int       `json:"block_rcode"`
	Rules                  []Rule    `json:"rules"`
}

// Rule 保留发布快照中需要审计和确定性排序的全部字段。
type Rule struct {
	ID        int64  `json:"id"`
	Category  string `json:"category"`
	Action    string `json:"action"`
	MatchType string `json:"match_type"`
	Pattern   string `json:"pattern"`
	Priority  int    `json:"priority"`
	Source    string `json:"source"`
	Comment   string `json:"comment"`
}

// MatchedRule 是请求匹配结果中可安全传递到后续审计阶段的不可变值。
type MatchedRule struct {
	RuleID    int64
	Action    string
	MatchType string
	Pattern   string
	Priority  int
}

func (m MatchedRule) Matched() bool {
	return m.RuleID != 0
}

// MatchResult 分别保存三个独立规则维度的最佳匹配。
type MatchResult struct {
	NormalizedQName string
	SnapshotVersion uint64
	Access          MatchedRule
	Route           MatchedRule
	Logging         MatchedRule
}
