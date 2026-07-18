package dynamic_rule_engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const categoryCount = 3

type compiledRegex struct {
	re       *regexp.Regexp
	match    MatchedRule
	category int
}
type compiledSubscriptionSet struct {
	match   MatchedRule
	domains []string
}

// CompiledSnapshot 的索引仅在 Compile 完成前写入；发布后只读。
type CompiledSnapshot struct {
	schemaVersion uint32
	version       uint64
	checksum      string
	blockRCode    int
	ruleCount     int
	regexpCount   int
	loadedAt      time.Time

	full          [categoryCount]map[string]MatchedRule
	domain        [categoryCount]map[string]MatchedRule
	regex         []compiledRegex
	subscriptions [categoryCount][]compiledSubscriptionSet
}

func (s *CompiledSnapshot) SchemaVersion() uint32 { return s.schemaVersion }
func (s *CompiledSnapshot) Version() uint64       { return s.version }
func (s *CompiledSnapshot) Checksum() string      { return s.checksum }
func (s *CompiledSnapshot) BlockRCode() int       { return s.blockRCode }
func (s *CompiledSnapshot) RuleCount() int        { return s.ruleCount }
func (s *CompiledSnapshot) RegexpRuleCount() int  { return s.regexpCount }
func (s *CompiledSnapshot) LoadedAt() time.Time   { return s.loadedAt }

// Compile 在 DNS 请求路径外执行全部校验和索引构建。
func Compile(snapshot Snapshot, limits Limits) (*CompiledSnapshot, error) {
	limits = normalizeLimits(limits)
	if snapshot.SchemaVersion != 1 && snapshot.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("schema_version %d is unsupported", snapshot.SchemaVersion)
	}
	if snapshot.Version == 0 {
		return nil, fmt.Errorf("version must be greater than zero")
	}
	if snapshot.BlockRCode < 0 || snapshot.BlockRCode > 0xFFF {
		return nil, fmt.Errorf("block_rcode %d is invalid", snapshot.BlockRCode)
	}
	if len(snapshot.Rules)+subscriptionDomainCount(snapshot.SubscriptionSets) > limits.MaxRules {
		return nil, fmt.Errorf("rule count exceeds %d", limits.MaxRules)
	}

	normalizedRules := make([]Rule, 0, len(snapshot.Rules))
	regexpCount := 0
	ruleIDs := make(map[int64]struct{}, len(snapshot.Rules))
	for i, rule := range snapshot.Rules {
		normalized, isRegexp, err := normalizeRule(rule, limits)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		if isRegexp {
			regexpCount++
			if regexpCount > limits.MaxRegexpRules {
				return nil, fmt.Errorf("regexp rule count exceeds %d", limits.MaxRegexpRules)
			}
		}
		if _, exists := ruleIDs[normalized.ID]; exists {
			return nil, fmt.Errorf("rule %d: duplicate id %d", i, normalized.ID)
		}
		ruleIDs[normalized.ID] = struct{}{}
		normalizedRules = append(normalizedRules, normalized)
	}
	if err := validateRouteConflicts(normalizedRules); err != nil {
		return nil, err
	}
	normalizedSets, err := normalizeSubscriptionSets(snapshot.SubscriptionSets, limits)
	if err != nil {
		return nil, err
	}
	if err := validateSubscriptionRouteConflicts(normalizedRules, normalizedSets); err != nil {
		return nil, err
	}

	checksum, canonicalRules, err := checksumSnapshot(snapshot, normalizedRules, normalizedSets)
	if err != nil {
		return nil, err
	}
	if snapshot.Checksum != "" && snapshot.Checksum != checksum {
		return nil, fmt.Errorf("checksum mismatch: got %q, want %q", snapshot.Checksum, checksum)
	}

	compiled := &CompiledSnapshot{
		schemaVersion: snapshot.SchemaVersion,
		version:       snapshot.Version,
		checksum:      checksum,
		blockRCode:    snapshot.BlockRCode,
		ruleCount:     len(canonicalRules),
		regexpCount:   regexpCount,
		loadedAt:      time.Now().UTC(),
	}
	for i := range compiled.full {
		compiled.full[i] = make(map[string]MatchedRule)
		compiled.domain[i] = make(map[string]MatchedRule)
	}
	for _, rule := range canonicalRules {
		if err := compiled.addRule(rule); err != nil {
			return nil, err
		}
	}
	if err := compiled.addSubscriptionSets(normalizedSets, limits); err != nil {
		return nil, err
	}
	compiled.ruleCount += subscriptionDomainCount(snapshot.SubscriptionSets)
	return compiled, nil
}

func normalizeSubscriptionSets(sets []SubscriptionSet, limits Limits) ([]SubscriptionSet, error) {
	result := make([]SubscriptionSet, len(sets))
	seen := make(map[int64]struct{}, len(sets))
	for i, set := range sets {
		if _, exists := seen[set.SourceID]; exists {
			return nil, fmt.Errorf("duplicate subscription set %d", set.SourceID)
		}
		seen[set.SourceID] = struct{}{}
		category, ok := categoryIndex(set.Category)
		if !ok || category < 0 || !validAction(set.Category, set.Action) || set.SourceID <= 0 || set.SourceName == "" || set.Priority < 0 || set.Priority > 1000 || len(set.Domains) == 0 {
			return nil, fmt.Errorf("invalid subscription set %d", set.SourceID)
		}
		domains := make([]string, len(set.Domains))
		for j, value := range set.Domains {
			normalized, err := NormalizeDomain(value)
			if err != nil || len(normalized) > limits.MaxDomainChars {
				return nil, fmt.Errorf("subscription set %d domain %d is invalid", set.SourceID, j)
			}
			domains[j] = normalized
		}
		sort.Strings(domains)
		for j := 1; j < len(domains); j++ {
			if domains[j] == domains[j-1] {
				return nil, fmt.Errorf("subscription set %d contains duplicate domains", set.SourceID)
			}
		}
		set.Domains = domains
		result[i] = set
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SourceID < result[j].SourceID })
	return result, nil
}

func (s *CompiledSnapshot) addSubscriptionSets(sets []SubscriptionSet, limits Limits) error {
	for _, set := range sets {
		category, _ := categoryIndex(set.Category)
		s.subscriptions[category] = append(s.subscriptions[category], compiledSubscriptionSet{match: MatchedRule{RuleID: set.SourceID, Action: set.Action, MatchType: MatchTypeDomain, Priority: set.Priority, SourceID: set.SourceID, SourceName: set.SourceName}, domains: set.Domains})
	}
	return nil
}
func subscriptionDomainCount(sets []SubscriptionSet) int {
	total := 0
	for _, set := range sets {
		total += len(set.Domains)
	}
	return total
}

func validateSubscriptionRouteConflicts(rules []Rule, sets []SubscriptionSet) error {
	seen := map[string]string{}
	for _, rule := range rules {
		if rule.Category == CategoryRoute && rule.MatchType == MatchTypeDomain {
			seen[rule.Pattern+"\x00"+fmt.Sprint(rule.Priority)] = rule.Action
		}
	}
	for _, set := range sets {
		if set.Category != CategoryRoute {
			continue
		}
		for _, domain := range set.Domains {
			key := domain + "\x00" + fmt.Sprint(set.Priority)
			if action, exists := seen[key]; exists && action != set.Action {
				return fmt.Errorf("route conflict for subscription domain %q", domain)
			}
			seen[key] = set.Action
		}
	}
	return nil
}

func (s *CompiledSnapshot) addRule(rule Rule) error {
	category, _ := categoryIndex(rule.Category)
	match := MatchedRule{
		RuleID: rule.ID, Action: rule.Action, MatchType: rule.MatchType,
		Pattern: rule.Pattern, Priority: rule.Priority,
	}
	switch rule.MatchType {
	case MatchTypeFull:
		s.full[category][rule.Pattern] = preferred(match, s.full[category][rule.Pattern], category)
	case MatchTypeDomain:
		s.domain[category][rule.Pattern] = preferred(match, s.domain[category][rule.Pattern], category)
	case MatchTypeRegexp:
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("compile regexp rule %d: %w", rule.ID, err)
		}
		s.regex = append(s.regex, compiledRegex{re: re, match: match, category: category})
	}
	return nil
}

func (s *CompiledSnapshot) Match(qname string) (MatchResult, error) {
	normalized, err := NormalizeDomain(qname)
	if err != nil {
		return MatchResult{}, err
	}
	result := MatchResult{NormalizedQName: normalized, SnapshotVersion: s.version}
	result.Access = s.matchCategory(normalized, categoryAccess)
	result.Route = s.matchCategory(normalized, categoryRoute)
	result.Logging = s.matchCategory(normalized, categoryLogging)
	return result, nil
}

func (s *CompiledSnapshot) matchCategory(qname string, category int) MatchedRule {
	if match, ok := s.full[category][qname]; ok {
		return match
	}
	var best MatchedRule
	// A flat suffix table avoids one map allocation per domain label while
	// retaining the deepest-domain-first matching semantics of the old trie.
	for suffix := qname; suffix != ""; {
		if match, ok := s.domain[category][suffix]; ok {
			best = match
			break
		}
		separator := strings.IndexByte(suffix, '.')
		if separator < 0 {
			break
		}
		suffix = suffix[separator+1:]
	}
	for _, set := range s.subscriptions[category] {
		if subscriptionMatches(set.domains, qname) {
			best = preferred(set.match, best, category)
		}
	}
	if best.Matched() {
		return best
	}
	for _, rule := range s.regex {
		if rule.category == category && rule.re.MatchString(qname) {
			best = preferred(rule.match, best, category)
		}
	}
	return best
}

func subscriptionMatches(domains []string, qname string) bool {
	for suffix := qname; suffix != ""; {
		i := sort.SearchStrings(domains, suffix)
		if i < len(domains) && domains[i] == suffix {
			return true
		}
		separator := strings.IndexByte(suffix, '.')
		if separator < 0 {
			return false
		}
		suffix = suffix[separator+1:]
	}
	return false
}

func normalizeLimits(l Limits) Limits {
	defaults := DefaultLimits()
	if l.MaxRules <= 0 || l.MaxRules > defaults.MaxRules {
		l.MaxRules = defaults.MaxRules
	}
	if l.MaxRegexpRules <= 0 || l.MaxRegexpRules > defaults.MaxRegexpRules {
		l.MaxRegexpRules = defaults.MaxRegexpRules
	}
	if l.MaxRegexpBytes <= 0 || l.MaxRegexpBytes > defaults.MaxRegexpBytes {
		l.MaxRegexpBytes = defaults.MaxRegexpBytes
	}
	if l.MaxDomainChars <= 0 || l.MaxDomainChars > defaults.MaxDomainChars {
		l.MaxDomainChars = defaults.MaxDomainChars
	}
	if l.MaxCommentRunes <= 0 || l.MaxCommentRunes > defaults.MaxCommentRunes {
		l.MaxCommentRunes = defaults.MaxCommentRunes
	}
	return l
}

func normalizeRule(rule Rule, limits Limits) (Rule, bool, error) {
	if rule.ID <= 0 {
		return Rule{}, false, fmt.Errorf("id must be greater than zero")
	}
	if _, ok := categoryIndex(rule.Category); !ok {
		return Rule{}, false, fmt.Errorf("unsupported category %q", rule.Category)
	}
	if !validAction(rule.Category, rule.Action) {
		return Rule{}, false, fmt.Errorf("action %q is invalid for category %q", rule.Action, rule.Category)
	}
	if rule.Priority < 0 || rule.Priority > 1000 {
		return Rule{}, false, fmt.Errorf("priority %d is outside 0..1000", rule.Priority)
	}
	if utf8.RuneCountInString(rule.Comment) > limits.MaxCommentRunes {
		return Rule{}, false, fmt.Errorf("comment exceeds %d characters", limits.MaxCommentRunes)
	}

	switch rule.MatchType {
	case MatchTypeFull, MatchTypeDomain:
		pattern, err := NormalizeDomain(rule.Pattern)
		if err != nil {
			return Rule{}, false, err
		}
		if len(pattern) > limits.MaxDomainChars {
			return Rule{}, false, fmt.Errorf("domain pattern exceeds %d characters", limits.MaxDomainChars)
		}
		rule.Pattern = pattern
		return rule, false, nil
	case MatchTypeRegexp:
		if len(rule.Pattern) > limits.MaxRegexpBytes {
			return Rule{}, true, fmt.Errorf("regexp exceeds %d bytes", limits.MaxRegexpBytes)
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return Rule{}, true, fmt.Errorf("invalid regexp: %w", err)
		}
		return rule, true, nil
	default:
		return Rule{}, false, fmt.Errorf("unsupported match_type %q", rule.MatchType)
	}
}

func categoryIndex(category string) (int, bool) {
	switch category {
	case CategoryAccess:
		return categoryAccess, true
	case CategoryRoute:
		return categoryRoute, true
	case CategoryLogging:
		return categoryLogging, true
	default:
		return 0, false
	}
}

const (
	categoryAccess = iota
	categoryRoute
	categoryLogging
)

func validAction(category, action string) bool {
	switch category {
	case CategoryAccess:
		return action == ActionAllow || action == ActionBlock
	case CategoryRoute:
		return action == ActionLocal || action == ActionRemote
	case CategoryLogging:
		return action == ActionNoLog
	default:
		return false
	}
}

// preferred 按 priority 和规格定义的同级语义选择唯一且确定的记录。
func preferred(candidate, current MatchedRule, category int) MatchedRule {
	if !current.Matched() || candidate.Priority > current.Priority {
		return candidate
	}
	if candidate.Priority < current.Priority {
		return current
	}
	if category == categoryAccess && candidate.Action == ActionAllow && current.Action == ActionBlock {
		return candidate
	}
	if category == categoryAccess && candidate.Action == ActionBlock && current.Action == ActionAllow {
		return current
	}
	// 相同效果的未定义并列顺序采用最小 ID，保证审计结果可重放。
	if candidate.RuleID < current.RuleID {
		return candidate
	}
	return current
}

func validateRouteConflicts(rules []Rule) error {
	seen := make(map[string]string)
	for _, rule := range rules {
		if rule.Category != CategoryRoute {
			continue
		}
		key := strings.Join([]string{rule.MatchType, rule.Pattern, fmt.Sprint(rule.Priority)}, "\x00")
		if action, ok := seen[key]; ok && action != rule.Action {
			return fmt.Errorf("route conflict for %s pattern %q at priority %d", rule.MatchType, rule.Pattern, rule.Priority)
		}
		seen[key] = rule.Action
	}
	return nil
}

func checksumSnapshot(snapshot Snapshot, rules []Rule, sets []SubscriptionSet) (string, []Rule, error) {
	// rules is already a private normalized slice. Sort it in place to avoid a
	// second full rule slice while compiling large subscription snapshots.
	sort.Slice(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.MatchType != b.MatchType {
			return a.MatchType < b.MatchType
		}
		if a.Pattern != b.Pattern {
			return a.Pattern < b.Pattern
		}
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		return a.ID < b.ID
	})
	canonical := Snapshot{SchemaVersion: snapshot.SchemaVersion, Version: snapshot.Version, ExpectedCurrentVersion: snapshot.ExpectedCurrentVersion, GeneratedAt: snapshot.GeneratedAt.UTC(), BlockRCode: snapshot.BlockRCode, Rules: rules, SubscriptionSets: sets}
	b, err := json.Marshal(canonical)
	if err != nil {
		return "", nil, fmt.Errorf("marshal canonical snapshot: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), rules, nil
}

// ParseSnapshot 使用严格 decoder，避免 API 层接受拼写错误或未定义字段。
func ParseSnapshot(data []byte) (Snapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Snapshot{}, fmt.Errorf("snapshot contains trailing JSON")
	}
	return snapshot, nil
}
