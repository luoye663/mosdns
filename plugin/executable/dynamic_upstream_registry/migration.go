package dynamic_upstream_registry

import (
	"errors"
	"fmt"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_ecs"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/dynamic_forward"
)

func migrateLegacyGroups(initial Snapshot, legacyGroups []LegacyGroup) (Snapshot, error) {
	if len(legacyGroups) == 0 {
		return initial, nil
	}
	initial.Groups = append([]Group(nil), initial.Groups...)
	groupIndexes := make(map[string]int, len(initial.Groups))
	for i, group := range initial.Groups {
		groupIndexes[group.ID] = i
	}
	seen := make(map[string]struct{}, len(legacyGroups))
	for i, legacy := range legacyGroups {
		legacy.ID = strings.TrimSpace(legacy.ID)
		if !groupIDPattern.MatchString(legacy.ID) {
			return Snapshot{}, fmt.Errorf("legacy_groups[%d].id is invalid", i)
		}
		if _, exists := seen[legacy.ID]; exists {
			return Snapshot{}, fmt.Errorf("legacy group %q is duplicated", legacy.ID)
		}
		seen[legacy.ID] = struct{}{}
		index, exists := groupIndexes[legacy.ID]
		if !exists {
			return Snapshot{}, fmt.Errorf("legacy group %q is absent from initial_snapshot", legacy.ID)
		}
		if err := validateLegacyFiles(legacy); err != nil {
			return Snapshot{}, fmt.Errorf("legacy group %q: %w", legacy.ID, err)
		}

		forward, forwardFound, err := dynamic_forward.LoadSnapshotFiles(legacy.ForwardSnapshotFile, legacy.ForwardBackupFile)
		if err != nil {
			return Snapshot{}, fmt.Errorf("legacy group %q forward: %w", legacy.ID, err)
		}
		ecs, ecsFound, err := dynamic_ecs.LoadSnapshotFiles(legacy.ECSSnapshotFile, legacy.ECSBackupFile)
		if err != nil {
			return Snapshot{}, fmt.Errorf("legacy group %q ECS: %w", legacy.ID, err)
		}
		group := &initial.Groups[index]
		if forwardFound {
			group.Mode, group.Concurrent, group.Socks5, group.Upstreams = forward.Mode, forward.Concurrent, forward.Socks5, forward.Upstreams
		}
		if ecsFound {
			group.ECS = dynamic_ecs.Config{Mode: ecs.Mode, Mask4: ecs.Mask4, Mask6: ecs.Mask6, Preset4: ecs.Preset4, Preset6: ecs.Preset6}
		}
	}
	return initial, nil
}

func validateLegacyFiles(group LegacyGroup) error {
	files := []struct {
		name  string
		value string
	}{
		{"forward_snapshot_file", group.ForwardSnapshotFile},
		{"forward_backup_file", group.ForwardBackupFile},
		{"ecs_snapshot_file", group.ECSSnapshotFile},
		{"ecs_backup_file", group.ECSBackupFile},
	}
	for _, file := range files {
		if strings.TrimSpace(file.value) == "" {
			return fmt.Errorf("%s is required", file.name)
		}
	}
	if group.ForwardSnapshotFile == group.ForwardBackupFile {
		return errors.New("forward snapshot and backup files must differ")
	}
	if group.ECSSnapshotFile == group.ECSBackupFile {
		return errors.New("ECS snapshot and backup files must differ")
	}
	return nil
}
