package dynamic_rule_engine

import (
	"compress/gzip"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const maxHardRequestBodyBytes int64 = 64 << 20

func (p *Plugin) router() *chi.Mux {
	router := chi.NewRouter()
	router.Use(p.authorize)
	router.Get("/status", p.handleStatus)
	router.Post("/validate", p.handleValidate)
	router.Put("/snapshot", p.handleSnapshot)
	router.Post("/match", p.handleMatch)
	return router
}

// authorize 统一保护插件全部控制面端点；token 比较使用恒定时间函数。
func (p *Plugin) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, prefix)), p.token) != 1 {
			writeError(w, http.StatusUnauthorized, "authorization required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Plugin) handleStatus(w http.ResponseWriter, _ *http.Request) {
	snapshot := p.store.Load()
	response := statusResponse{
		SchemaVersion: SchemaVersion, PluginVersion: Version, MosdnsBase: "v5.3.4",
		State: p.state(), SnapshotFileOK: p.snapshotFileOK.Load(),
		LastCompileDurationMS: p.lastCompileDuration.Load(),
		MemoryRSSBytes:        processRSSBytes(),
	}
	if snapshot != nil {
		response.SnapshotVersion = snapshot.Version()
		response.Checksum = snapshot.Checksum()
		response.RuleCount = snapshot.RuleCount()
		response.RegexpRuleCount = snapshot.RegexpRuleCount()
		response.LoadedAt = snapshot.LoadedAt()
	}
	writeJSON(w, http.StatusOK, response)
}

func (p *Plugin) handleValidate(w http.ResponseWriter, r *http.Request) {
	snapshot, err := p.decodeSnapshot(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	started := time.Now()
	_, compiled, err := canonicalSnapshot(snapshot, p.limits)
	p.lastCompileDuration.Store(time.Since(started).Milliseconds())
	if err != nil {
		p.metrics.applyFailure.Inc()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, validateResponse{Valid: true, Checksum: compiled.Checksum(), RuleCount: compiled.RuleCount(), RegexpRuleCount: compiled.RegexpRuleCount(), CompileDurationMS: p.lastCompileDuration.Load(), Warnings: []string{}})
}

func (p *Plugin) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot, err := p.decodeSnapshot(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	current := p.store.Load()
	currentVersion := uint64(0)
	if current != nil {
		currentVersion = current.Version()
	}
	if snapshot.ExpectedCurrentVersion != currentVersion {
		p.metrics.applyConflict.Inc()
		writeJSON(w, http.StatusConflict, map[string]any{"error": "expected_current_version does not match", "current_version": currentVersion})
		return
	}
	started := time.Now()
	canonical, compiled, err := canonicalSnapshot(snapshot, p.limits)
	compileDuration := time.Since(started)
	p.lastCompileDuration.Store(compileDuration.Milliseconds())
	if err != nil {
		p.metrics.applyFailure.Inc()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	persistStarted := time.Now()
	if err := p.persist(canonical); err != nil {
		p.metrics.applyFailure.Inc()
		writeError(w, http.StatusInternalServerError, "persist snapshot: "+err.Error())
		return
	}
	p.store.Swap(compiled)
	p.snapshotFileOK.Store(true)
	p.setState("ready")
	p.metrics.applySuccess.Inc()
	writeJSON(w, http.StatusOK, applyResponse{Applied: true, PreviousVersion: currentVersion, Version: compiled.Version(), Checksum: compiled.Checksum(), CompileDurationMS: compileDuration.Milliseconds(), PersistDurationMS: time.Since(persistStarted).Milliseconds(), AppliedAt: time.Now().UTC()})
}

func (p *Plugin) handleMatch(w http.ResponseWriter, r *http.Request) {
	var request matchRequest
	if err := p.decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snapshot := p.store.Load()
	if snapshot == nil {
		writeError(w, http.StatusServiceUnavailable, "no runtime snapshot loaded")
		return
	}
	result, err := snapshot.Match(request.QName)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, matchResponse{NormalizedQName: result.NormalizedQName, SnapshotVersion: result.SnapshotVersion, Access: matchEffect(result.Access, ""), Route: matchEffect(result.Route, "dynamic_rule"), Logging: matchEffect(result.Logging, ""), Answer: matchEffect(result.Answer, "dynamic_rule")})
}

func (p *Plugin) decodeSnapshot(r *http.Request) (Snapshot, error) {
	var snapshot Snapshot
	if err := p.decodeJSON(r, &snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (p *Plugin) decodeJSON(r *http.Request, target any) error {
	body := io.Reader(r.Body)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(body)
		if err != nil {
			return fmt.Errorf("open gzip request body: %w", err)
		}
		defer gzipReader.Close()
		body = io.LimitReader(gzipReader, p.maxRequestBodyBytes+1)
	}
	data, err := io.ReadAll(io.LimitReader(body, p.maxRequestBodyBytes+1))
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	if int64(len(data)) > p.maxRequestBodyBytes {
		return fmt.Errorf("request body exceeds %d bytes", p.maxRequestBodyBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("request contains trailing JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

type statusResponse struct {
	SchemaVersion         uint32    `json:"schema_version"`
	PluginVersion         string    `json:"plugin_version"`
	MosdnsBase            string    `json:"mosdns_base"`
	State                 string    `json:"state"`
	SnapshotVersion       uint64    `json:"snapshot_version"`
	Checksum              string    `json:"checksum,omitempty"`
	RuleCount             int       `json:"rule_count"`
	RegexpRuleCount       int       `json:"regexp_rule_count"`
	LoadedAt              time.Time `json:"loaded_at,omitempty"`
	LastCompileDurationMS int64     `json:"last_compile_duration_ms"`
	SnapshotFileOK        bool      `json:"snapshot_file_ok"`
	MemoryRSSBytes        int64     `json:"memory_rss_bytes"`
}

type validateResponse struct {
	Valid             bool     `json:"valid"`
	Checksum          string   `json:"checksum"`
	RuleCount         int      `json:"rule_count"`
	RegexpRuleCount   int      `json:"regexp_rule_count"`
	CompileDurationMS int64    `json:"compile_duration_ms"`
	Warnings          []string `json:"warnings"`
}

type applyResponse struct {
	Applied           bool      `json:"applied"`
	PreviousVersion   uint64    `json:"previous_version"`
	Version           uint64    `json:"version"`
	Checksum          string    `json:"checksum"`
	CompileDurationMS int64     `json:"compile_duration_ms"`
	PersistDurationMS int64     `json:"persist_duration_ms"`
	AppliedAt         time.Time `json:"applied_at"`
}

type matchRequest struct {
	QName string `json:"qname"`
}

type matchEffectResponse struct {
	Decision               string   `json:"decision"`
	RuleID                 int64    `json:"rule_id,omitempty"`
	MatchType              string   `json:"match_type,omitempty"`
	Pattern                string   `json:"pattern,omitempty"`
	Source                 string   `json:"source,omitempty"`
	SubscriptionSourceID   int64    `json:"subscription_source_id,omitempty"`
	SubscriptionSourceName string   `json:"subscription_source_name,omitempty"`
	SubscriptionBindingID  int64    `json:"subscription_binding_id,omitempty"`
	UpstreamGroupID        string   `json:"upstream_group_id,omitempty"`
	IPv4Addresses          []string `json:"ipv4_addresses,omitempty"`
	IPv6Addresses          []string `json:"ipv6_addresses,omitempty"`
	TTL                    uint32   `json:"ttl,omitempty"`
}

type matchResponse struct {
	NormalizedQName string              `json:"normalized_qname"`
	SnapshotVersion uint64              `json:"snapshot_version"`
	Access          matchEffectResponse `json:"access"`
	Route           matchEffectResponse `json:"route"`
	Logging         matchEffectResponse `json:"logging"`
	Answer          matchEffectResponse `json:"answer"`
}

func matchEffect(rule MatchedRule, source string) matchEffectResponse {
	if !rule.Matched() {
		if source == "" {
			return matchEffectResponse{Decision: "default"}
		}
		return matchEffectResponse{Decision: "none"}
	}
	if rule.SourceID != 0 {
		source = "subscription"
	}
	return matchEffectResponse{Decision: rule.Action, RuleID: rule.RuleID, MatchType: rule.MatchType, Pattern: rule.Pattern, Source: source, SubscriptionSourceID: rule.SourceID, SubscriptionSourceName: rule.SourceName, SubscriptionBindingID: rule.BindingID, UpstreamGroupID: rule.UpstreamGroupID, IPv4Addresses: rule.IPv4Addresses, IPv6Addresses: rule.IPv6Addresses, TTL: rule.TTL}
}
