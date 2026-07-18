package dynamic_rule_engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// canonicalSnapshot 将已校验规则规范化和排序，确保落盘内容与 checksum 一致。
func canonicalSnapshot(snapshot Snapshot, limits Limits) (Snapshot, *CompiledSnapshot, error) {
	compiled, err := Compile(snapshot, limits)
	if err != nil {
		return Snapshot{}, nil, err
	}
	rules := make([]Rule, 0, len(snapshot.Rules))
	for _, rule := range snapshot.Rules {
		normalized, _, err := normalizeRule(rule, normalizeLimits(limits))
		if err != nil {
			return Snapshot{}, nil, err
		}
		rules = append(rules, normalized)
	}
	sets, err := normalizeSubscriptionSets(snapshot.SubscriptionSets, normalizeLimits(limits))
	if err != nil {
		return Snapshot{}, nil, err
	}
	checksum, rules, err := checksumSnapshot(snapshot, rules, sets)
	if err != nil {
		return Snapshot{}, nil, err
	}
	snapshot.GeneratedAt = snapshot.GeneratedAt.UTC()
	snapshot.Rules = rules
	snapshot.SubscriptionSets = sets
	snapshot.Checksum = checksum
	return snapshot, compiled, nil
}

// persistSnapshot 先完整写入临时文件。主快照仅由 rename 覆盖，失败时活跃内存快照不会改变。
func persistSnapshot(snapshot Snapshot, snapshotFile, backupFile string) error {
	data, err := marshalSnapshot(snapshot)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(snapshotFile), 0o750); err != nil {
		return fmt.Errorf("create snapshot directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(backupFile), 0o750); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(snapshotFile), ".dynamic-rules-*.tmp")
	if err != nil {
		return fmt.Errorf("create snapshot temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write snapshot temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod snapshot temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync snapshot temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close snapshot temp file: %w", err)
	}

	// 先复制当前文件到备份，避免在新文件落盘失败时移走 current。
	if err := backupCurrent(snapshotFile, backupFile); err != nil {
		return err
	}
	if err := os.Rename(tmpName, snapshotFile); err != nil {
		return fmt.Errorf("replace current snapshot: %w", err)
	}
	if err := syncDirectory(filepath.Dir(snapshotFile)); err != nil {
		return err
	}
	return nil
}

func marshalSnapshot(snapshot Snapshot) ([]byte, error) {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("marshal snapshot: %w", err)
	}
	return data, nil
}

func backupCurrent(snapshotFile, backupFile string) error {
	source, err := os.Open(snapshotFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open current snapshot for backup: %w", err)
	}
	defer source.Close()
	tmp, err := os.CreateTemp(filepath.Dir(backupFile), ".dynamic-rules-backup-*.tmp")
	if err != nil {
		return fmt.Errorf("create backup temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := io.Copy(tmp, source); err != nil {
		tmp.Close()
		return fmt.Errorf("copy current snapshot to backup: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod backup temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync backup temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close backup temp file: %w", err)
	}
	if err := os.Rename(tmpName, backupFile); err != nil {
		return fmt.Errorf("replace backup snapshot: %w", err)
	}
	return syncDirectory(filepath.Dir(backupFile))
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open snapshot directory: %w", err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync snapshot directory: %w", err)
	}
	return nil
}
