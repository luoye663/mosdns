package dynamic_upstream_registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func loadSnapshot(currentFile, backupFile string) (Snapshot, string, error) {
	var failures []error
	found := false
	for _, filename := range []string{currentFile, backupFile} {
		data, err := os.ReadFile(filename)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		found = true
		if err != nil {
			failures = append(failures, fmt.Errorf("read %s: %w", filename, err))
			continue
		}
		var snapshot Snapshot
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&snapshot); err != nil {
			failures = append(failures, fmt.Errorf("parse %s: %w", filename, err))
			continue
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			failures = append(failures, fmt.Errorf("parse %s: trailing JSON", filename))
			continue
		}
		if _, err := canonicalWithoutRuntime(snapshot); err != nil {
			failures = append(failures, fmt.Errorf("validate %s: %w", filename, err))
			continue
		}
		return snapshot, filename, nil
	}
	if !found {
		return Snapshot{}, "", nil
	}
	return Snapshot{}, "", errors.Join(failures...)
}

func persistSnapshot(snapshot Snapshot, currentFile, backupFile string) error {
	if data, err := os.ReadFile(currentFile); err == nil {
		if err := writeBytesAtomic(data, backupFile); err != nil {
			return fmt.Errorf("write backup: %w", err)
		}
	}
	return writeSnapshotAtomic(snapshot, currentFile)
}

func writeSnapshotAtomic(snapshot Snapshot, filename string) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return writeBytesAtomic(data, filename)
}

func writeBytesAtomic(data []byte, filename string) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".dynamic-upstream-registry-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Chmod(0o600)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmpName, filename); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
