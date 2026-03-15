package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type RecentExecContext struct {
	TimestampUnixMS int64  `json:"timestamp_unix_ms"`
	NodeID          string `json:"node_id"`
	User            string `json:"user"`
	PID             int    `json:"pid"`
	ExecPath        string `json:"exec_path"`
	Comm            string `json:"comm"`
	Cmdline         string `json:"cmdline"`
	Source          string `json:"source"`
}

type RecentFileAccessContext struct {
	TimestampUnixMS int64  `json:"timestamp_unix_ms"`
	NodeID          string `json:"node_id"`
	User            string `json:"user"`
	PID             int    `json:"pid"`
	Path            string `json:"path"`
	Access          string `json:"access"`
	ExecPath        string `json:"exec_path"`
	Comm            string `json:"comm"`
	Cmdline         string `json:"cmdline"`
	Source          string `json:"source"`
}

type FileAttribution struct {
	User     string
	PID      int
	ExecPath string
	Comm     string
	Cmdline  string
	Source   string
}

type RecentContextStore struct {
	root string
}

func NewRecentContextStore(root string) *RecentContextStore {
	return &RecentContextStore{root: strings.TrimSpace(root)}
}

func (s *RecentContextStore) Enabled() bool {
	return s != nil && s.root != ""
}

func (s *RecentContextStore) RecordExec(ctx RecentExecContext, maxAge time.Duration) error {
	if !s.Enabled() {
		return nil
	}
	ctx.NodeID = strings.TrimSpace(ctx.NodeID)
	if ctx.NodeID == "" {
		return nil
	}
	if ctx.TimestampUnixMS <= 0 {
		ctx.TimestampUnixMS = time.Now().UnixMilli()
	}
	if err := s.writeEntry(filepath.Join(s.root, "exec", safeComponent(ctx.NodeID)), entryFileName(ctx.TimestampUnixMS, ctx.PID), ctx); err != nil {
		return err
	}
	return s.pruneOld(filepath.Join(s.root, "exec", safeComponent(ctx.NodeID)), maxAge)
}

func (s *RecentContextStore) RecordFileAccess(ctx RecentFileAccessContext, maxAge time.Duration) error {
	if !s.Enabled() {
		return nil
	}
	ctx.NodeID = strings.TrimSpace(ctx.NodeID)
	ctx.Path = filepath.Clean(strings.TrimSpace(ctx.Path))
	if ctx.NodeID == "" || ctx.Path == "." || ctx.Path == "" {
		return nil
	}
	if ctx.TimestampUnixMS <= 0 {
		ctx.TimestampUnixMS = time.Now().UnixMilli()
	}
	if err := s.writeEntry(filepath.Join(s.root, "file_access", safeComponent(ctx.NodeID)), entryFileName(ctx.TimestampUnixMS, ctx.PID), ctx); err != nil {
		return err
	}
	return s.pruneOld(filepath.Join(s.root, "file_access", safeComponent(ctx.NodeID)), maxAge)
}

func (s *RecentContextStore) FindFileAttribution(nodeID, path string, now time.Time, fileAccessMaxAge, execMaxAge time.Duration) (FileAttribution, bool) {
	if !s.Enabled() {
		return FileAttribution{}, false
	}
	nodeID = strings.TrimSpace(nodeID)
	path = filepath.Clean(strings.TrimSpace(path))
	if nodeID == "" || path == "" || path == "." {
		return FileAttribution{}, false
	}
	if attr, ok := s.findExactFileAccess(nodeID, path, now, fileAccessMaxAge); ok {
		return attr, true
	}
	if attr, ok := s.findParentFileAccess(nodeID, path, now, fileAccessMaxAge); ok {
		return attr, true
	}
	return s.findProcessHint(nodeID, path, now, execMaxAge)
}

func (s *RecentContextStore) findExactFileAccess(nodeID, path string, now time.Time, maxAge time.Duration) (FileAttribution, bool) {
	files, err := s.recentFiles(filepath.Join(s.root, "file_access", safeComponent(nodeID)))
	if err != nil {
		return FileAttribution{}, false
	}
	for _, entry := range files {
		var ctx RecentFileAccessContext
		if !readJSON(entry, &ctx) {
			continue
		}
		if expired(ctx.TimestampUnixMS, now, maxAge) {
			continue
		}
		if filepath.Clean(ctx.Path) != path {
			continue
		}
		if strings.TrimSpace(ctx.User) == "" || strings.EqualFold(strings.TrimSpace(ctx.User), "unknown") {
			continue
		}
		return FileAttribution{
			User:     strings.TrimSpace(ctx.User),
			PID:      ctx.PID,
			ExecPath: strings.TrimSpace(ctx.ExecPath),
			Comm:     strings.TrimSpace(ctx.Comm),
			Cmdline:  strings.TrimSpace(ctx.Cmdline),
			Source:   strings.TrimSpace(ctx.Source),
		}, true
	}
	return FileAttribution{}, false
}

func (s *RecentContextStore) findParentFileAccess(nodeID, path string, now time.Time, maxAge time.Duration) (FileAttribution, bool) {
	files, err := s.recentFiles(filepath.Join(s.root, "file_access", safeComponent(nodeID)))
	if err != nil {
		return FileAttribution{}, false
	}
	bestScore := 0
	best := FileAttribution{}
	for _, entry := range files {
		var ctx RecentFileAccessContext
		if !readJSON(entry, &ctx) {
			continue
		}
		if expired(ctx.TimestampUnixMS, now, maxAge) {
			continue
		}
		cleanPath := filepath.Clean(ctx.Path)
		user := strings.TrimSpace(ctx.User)
		if cleanPath == "" || cleanPath == "." || user == "" || strings.EqualFold(user, "unknown") {
			continue
		}
		if cleanPath == path {
			continue
		}
		if !strings.HasSuffix(path, string(os.PathSeparator)+filepath.Base(path)) {
			continue
		}
		prefix := cleanPath + string(os.PathSeparator)
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		score := len(cleanPath)
		if isLikelyFileMutator(ctx.Comm, ctx.ExecPath) {
			score += 1000
		}
		if score <= bestScore {
			continue
		}
		bestScore = score
		best = FileAttribution{
			User:     user,
			PID:      ctx.PID,
			ExecPath: strings.TrimSpace(ctx.ExecPath),
			Comm:     strings.TrimSpace(ctx.Comm),
			Cmdline:  strings.TrimSpace(ctx.Cmdline),
			Source:   strings.TrimSpace(ctx.Source),
		}
	}
	if bestScore == 0 {
		return FileAttribution{}, false
	}
	return best, true
}

func (s *RecentContextStore) findProcessHint(nodeID, path string, now time.Time, maxAge time.Duration) (FileAttribution, bool) {
	files, err := s.recentFiles(filepath.Join(s.root, "exec", safeComponent(nodeID)))
	if err != nil {
		return FileAttribution{}, false
	}
	bestScore := 0
	best := FileAttribution{}
	base := filepath.Base(path)
	for _, entry := range files {
		var ctx RecentExecContext
		if !readJSON(entry, &ctx) {
			continue
		}
		if expired(ctx.TimestampUnixMS, now, maxAge) {
			continue
		}
		user := strings.TrimSpace(ctx.User)
		if user == "" || strings.EqualFold(user, "unknown") {
			continue
		}
		score := scoreProcessHint(ctx, path, base)
		if score <= bestScore {
			continue
		}
		bestScore = score
		best = FileAttribution{
			User:     user,
			PID:      ctx.PID,
			ExecPath: strings.TrimSpace(ctx.ExecPath),
			Comm:     strings.TrimSpace(ctx.Comm),
			Cmdline:  strings.TrimSpace(ctx.Cmdline),
			Source:   strings.TrimSpace(ctx.Source),
		}
	}
	if bestScore == 0 {
		return FileAttribution{}, false
	}
	return best, true
}

func scoreProcessHint(ctx RecentExecContext, path, base string) int {
	cmdline := strings.TrimSpace(ctx.Cmdline)
	execPath := strings.TrimSpace(ctx.ExecPath)
	comm := strings.TrimSpace(ctx.Comm)
	switch {
	case cmdline != "" && strings.Contains(cmdline, path):
		return 100
	case cmdline != "" && base != "" && strings.Contains(cmdline, base) && isLikelyFileMutator(comm, execPath):
		return 70
	default:
		return 0
	}
}

func isLikelyFileMutator(comm, execPath string) bool {
	name := strings.ToLower(strings.TrimSpace(comm))
	if name == "" {
		name = strings.ToLower(filepath.Base(strings.TrimSpace(execPath)))
	}
	switch name {
	case "touch", "rm", "mv", "cp", "install", "chmod", "chown", "sed", "tee", "nano", "vi", "vim", "nvim", "perl", "python", "python3", "bash", "sh":
		return true
	default:
		return false
	}
}

func (s *RecentContextStore) writeEntry(dir, name string, payload any) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir recent context dir: %w", err)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal recent context: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create recent context temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write recent context temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close recent context temp: %w", err)
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("rename recent context temp: %w", err)
	}
	return nil
}

func (s *RecentContextStore) pruneOld(dir string, maxAge time.Duration) error {
	if maxAge <= 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	cutoff := time.Now().Add(-maxAge).UnixMilli()
	for _, entry := range entries {
		ts := fileTimestamp(entry.Name())
		if ts == 0 || ts >= cutoff {
			continue
		}
		_ = os.Remove(filepath.Join(dir, entry.Name()))
	}
	return nil
}

func (s *RecentContextStore) recentFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		return fileTimestamp(entries[i].Name()) > fileTimestamp(entries[j].Name())
	})
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	return paths, nil
}

func entryFileName(tsMS int64, pid int) string {
	return fmt.Sprintf("%013d_%d.json", tsMS, pid)
}

func fileTimestamp(name string) int64 {
	prefix := strings.SplitN(name, "_", 2)[0]
	if prefix == "" {
		return 0
	}
	n, _ := strconv.ParseInt(prefix, 10, 64)
	return n
}

func safeComponent(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", " ", "_", ":", "_")
	return replacer.Replace(value)
}

func expired(tsMS int64, now time.Time, maxAge time.Duration) bool {
	if tsMS <= 0 || maxAge <= 0 {
		return false
	}
	return time.UnixMilli(tsMS).Before(now.Add(-maxAge))
}

func readJSON(path string, target any) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(data, target) == nil
}
