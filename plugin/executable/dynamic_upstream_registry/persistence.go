package dynamic_upstream_registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

func (p *Plugin) dumpCaches(state *runtimeState) {
	p.writeCacheDumps(state, false)
}

func (p *Plugin) closeAndDumpCaches(state *runtimeState) {
	p.writeCacheDumps(state, true)
}

func (p *Plugin) writeCacheDumps(state *runtimeState, closeCaches bool) {
	p.cacheDumpMu.Lock()
	defer p.cacheDumpMu.Unlock()
	for id, group := range state.groups {
		filename := p.cacheDumpFile(state.snapshot.Version, id)
		if err := writeFileAtomic(filename, func(w io.Writer) error {
			var err error
			if closeCaches {
				_, err = group.cache.CloseWithDump(w)
			} else {
				_, err = group.cache.WriteDump(w)
			}
			return err
		}); err != nil {
			p.logger.Warn("write cache dump", zap.String("group", id), zap.Error(err))
		}
	}
}

func (p *Plugin) cleanupCacheDumps(state *runtimeState) {
	p.cacheDumpMu.Lock()
	defer p.cacheDumpMu.Unlock()
	entries, err := os.ReadDir(p.cacheDumpDir)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		p.logger.Warn("read cache dump directory", zap.Error(err))
		return
	}
	for _, entry := range entries {
		version, id, ok := cacheDumpIdentity(entry.Name())
		if entry.IsDir() || !ok {
			continue
		}
		if _, exists := state.groups[id]; exists && version == state.snapshot.Version {
			continue
		}
		if err := os.Remove(filepath.Join(p.cacheDumpDir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			p.logger.Warn("remove deleted group cache dump", zap.String("group", id), zap.Error(err))
		}
	}
}

func (p *Plugin) removeCacheDumps() error {
	p.cacheDumpMu.Lock()
	defer p.cacheDumpMu.Unlock()
	entries, err := os.ReadDir(p.cacheDumpDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		if _, _, ok := cacheDumpIdentity(entry.Name()); !entry.IsDir() && ok {
			if err := os.Remove(filepath.Join(p.cacheDumpDir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				failures = append(failures, fmt.Errorf("remove %s: %w", entry.Name(), err))
			}
		}
	}
	return errors.Join(failures...)
}

func (p *Plugin) removeCacheDump(version uint64, groupID string) error {
	p.cacheDumpMu.Lock()
	defer p.cacheDumpMu.Unlock()
	if err := os.Remove(p.cacheDumpFile(version, groupID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func cacheDumpIdentity(name string) (uint64, string, bool) {
	if filepath.Ext(name) != ".dump" {
		return 0, "", false
	}
	base := strings.TrimSuffix(name, ".dump")
	separator := strings.IndexByte(base, '-')
	if separator < 1 {
		return 0, "", false
	}
	version, err := strconv.ParseUint(base[:separator], 10, 64)
	id := base[separator+1:]
	return version, id, err == nil && version > 0 && groupIDPattern.MatchString(id)
}

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
	return writeFileAtomic(filename, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

func writeFileAtomic(filename string, write func(io.Writer) error) error {
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
	if err = write(tmp); err == nil {
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
