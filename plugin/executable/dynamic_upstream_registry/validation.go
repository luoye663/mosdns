package dynamic_upstream_registry

import (
	"errors"
	"fmt"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_ecs"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_forward"
)

func canonicalSnapshotValues(snapshot Snapshot) (Snapshot, error) {
	if snapshot.SchemaVersion == 1 {
		snapshot.SchemaVersion = registrySchemaVersion
	}
	if snapshot.SchemaVersion != registrySchemaVersion {
		return Snapshot{}, fmt.Errorf("schema_version must be %d", registrySchemaVersion)
	}
	if snapshot.Protection.GlobalMaxInFlight == 0 {
		snapshot.Protection.GlobalMaxInFlight = 1024
	}
	if snapshot.Protection.DefaultGroupMaxInFlight == 0 {
		snapshot.Protection.DefaultGroupMaxInFlight = 256
	}
	if snapshot.Protection.DefaultGroupQueryTimeoutMS == 0 {
		snapshot.Protection.DefaultGroupQueryTimeoutMS = 5000
	}
	if snapshot.Protection.OverloadAction == "" {
		snapshot.Protection.OverloadAction = "servfail"
	}
	if snapshot.Protection.GlobalMaxInFlight < 1 || snapshot.Protection.GlobalMaxInFlight > 65535 {
		return Snapshot{}, errors.New("protection.global_max_in_flight must be within 1..65535")
	}
	if snapshot.Protection.DefaultGroupMaxInFlight < 1 || snapshot.Protection.DefaultGroupMaxInFlight > snapshot.Protection.GlobalMaxInFlight {
		return Snapshot{}, errors.New("protection.default_group_max_in_flight must be within 1..global_max_in_flight")
	}
	if snapshot.Protection.DefaultGroupQueryTimeoutMS < 1000 || snapshot.Protection.DefaultGroupQueryTimeoutMS > 30000 {
		return Snapshot{}, errors.New("protection.default_group_query_timeout_ms must be within 1000..30000")
	}
	if action := snapshot.Protection.OverloadAction; action != "servfail" && action != "refused" && action != "drop" {
		return Snapshot{}, errors.New("protection.overload_action must be servfail, refused or drop")
	}
	if len(snapshot.Groups) < 1 || len(snapshot.Groups) > 32 {
		return Snapshot{}, errors.New("groups must contain 1..32 entries")
	}
	if snapshot.Cache.LazyTTL < 0 || snapshot.Cache.LazyTTL > 604800 {
		return Snapshot{}, errors.New("cache.lazy_ttl must be within 0..604800")
	}
	if snapshot.Cache.Negative.TTL == 0 {
		snapshot.Cache.Negative.TTL = 30
	}
	if snapshot.Cache.Negative.TTL > 86400 {
		return Snapshot{}, errors.New("cache.negative.ttl must be within 1..86400")
	}
	snapshot.DefaultGroupID = strings.TrimSpace(snapshot.DefaultGroupID)
	if !groupIDPattern.MatchString(snapshot.DefaultGroupID) {
		return Snapshot{}, errors.New("default_group_id is invalid")
	}
	seen := make(map[string]struct{}, len(snapshot.Groups))
	totalCacheSize, defaultEnabled := 0, false
	for i := range snapshot.Groups {
		group := &snapshot.Groups[i]
		group.ID, group.Name, group.Socks5, group.Bootstrap = strings.TrimSpace(group.ID), strings.TrimSpace(group.Name), strings.TrimSpace(group.Socks5), strings.TrimSpace(group.Bootstrap)
		if !groupIDPattern.MatchString(group.ID) {
			return Snapshot{}, fmt.Errorf("group %d has an invalid id", i+1)
		}
		if _, exists := seen[group.ID]; exists {
			return Snapshot{}, errors.New("group ids must be unique")
		}
		seen[group.ID] = struct{}{}
		if group.Name == "" || len(group.Name) > 128 {
			return Snapshot{}, fmt.Errorf("group %s name must contain 1..128 bytes", group.ID)
		}
		if group.MaxInFlight != nil && (*group.MaxInFlight < 1 || *group.MaxInFlight > 65535) {
			return Snapshot{}, fmt.Errorf("group %s max_in_flight must be within 1..65535", group.ID)
		}
		if group.QueryTimeoutMS != nil && (*group.QueryTimeoutMS < 1000 || *group.QueryTimeoutMS > 30000) {
			return Snapshot{}, fmt.Errorf("group %s query_timeout_ms must be within 1000..30000", group.ID)
		}
		if group.Cache.Size == 0 {
			group.Cache.Size = defaultCacheSize
		}
		if group.Cache.Size < 1 || group.Cache.Size > maximumCacheEntries {
			return Snapshot{}, fmt.Errorf("group %s cache.size must be within 1..65536", group.ID)
		}
		totalCacheSize += group.Cache.Size
		if totalCacheSize > maximumCacheEntries {
			return Snapshot{}, errors.New("total group cache size must not exceed 65536")
		}
		ecs, err := dynamic_ecs.CanonicalConfig(group.ECS)
		if err != nil {
			return Snapshot{}, fmt.Errorf("group %s ECS: %w", group.ID, err)
		}
		group.ECS = ecs
		forward, err := dynamic_forward.CanonicalRuntimeConfig(dynamic_forward.RuntimeConfig{Mode: group.Mode, Concurrent: group.Concurrent, Socks5: group.Socks5, Bootstrap: group.Bootstrap, BootstrapVer: group.BootstrapVer, Upstreams: group.Upstreams})
		if err != nil {
			return Snapshot{}, fmt.Errorf("group %s forward: %w", group.ID, err)
		}
		group.Mode, group.Concurrent, group.Socks5, group.Bootstrap, group.BootstrapVer, group.Upstreams = forward.Mode, forward.Concurrent, forward.Socks5, forward.Bootstrap, forward.BootstrapVer, forward.Upstreams
		if group.ID == snapshot.DefaultGroupID {
			defaultEnabled = group.Enabled
		}
	}
	if !defaultEnabled {
		return Snapshot{}, errors.New("default group must exist and be enabled")
	}
	snapshot.ExpectedCurrentVersion = 0
	return snapshot, nil
}
