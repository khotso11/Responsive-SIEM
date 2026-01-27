package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	defaultCooldownWindowMs = int64(60000)
	defaultCooldownMaxKeys  = 50000
)

// CooldownConfig controls trigger suppression.
type CooldownConfig struct {
	Enabled  bool               `yaml:"enabled"`
	WindowMs int64              `yaml:"window_ms"`
	MaxKeys  int                `yaml:"max_keys"`
	Persist  CooldownPersistCfg `yaml:"persist"`
	PerRule  []CooldownRuleCfg  `yaml:"per_rule"`
}

type CooldownPersistCfg struct {
	Enabled         bool   `yaml:"enabled"`
	Path            string `yaml:"path"`
	FlushIntervalMs int64  `yaml:"flush_interval_ms"`
}

type CooldownRuleCfg struct {
	RuleID   string `yaml:"rule_id"`
	WindowMs int64  `yaml:"window_ms"`
}

// ResolveCooldownConfig applies defaults to the provided config.
func ResolveCooldownConfig(raw *CooldownConfig) CooldownConfig {
	cfg := CooldownConfig{
		Enabled:  true,
		WindowMs: defaultCooldownWindowMs,
		MaxKeys:  defaultCooldownMaxKeys,
		Persist: CooldownPersistCfg{
			Enabled:         true,
			Path:            "tmp/cooldown.checkpoint.json",
			FlushIntervalMs: 5000,
		},
	}
	if raw == nil {
		return cfg
	}
	cfg.Enabled = raw.Enabled
	if raw.WindowMs > 0 {
		cfg.WindowMs = raw.WindowMs
	}
	if raw.MaxKeys > 0 {
		cfg.MaxKeys = raw.MaxKeys
	}
	cfg.Persist.Enabled = raw.Persist.Enabled
	if raw.Persist.Path != "" {
		cfg.Persist.Path = raw.Persist.Path
	}
	if raw.Persist.FlushIntervalMs > 0 {
		cfg.Persist.FlushIntervalMs = raw.Persist.FlushIntervalMs
	}
	if len(raw.PerRule) > 0 {
		cfg.PerRule = raw.PerRule
	}
	return cfg
}

// CooldownTracker suppresses repeated trigger publishes for the same key.
type CooldownTracker struct {
	cfg  CooldownConfig
	mu   sync.Mutex
	last map[string]int64

	dirty         bool
	lastFlushUnix int64

	perRuleWindows map[string]int64
}

// NewCooldownTracker creates a tracker with defaults applied.
func NewCooldownTracker(cfg CooldownConfig) *CooldownTracker {
	return &CooldownTracker{
		cfg:            cfg,
		last:           make(map[string]int64),
		perRuleWindows: make(map[string]int64),
	}
}

// Allow returns true if the key can publish at the given time.
func (t *CooldownTracker) Allow(key string, now int64) (bool, int64) {
	if t == nil || !t.cfg.Enabled {
		return true, 0
	}
	normalizedKey, windowMs := t.normalizeKey(key)
	key = normalizedKey
	t.mu.Lock()
	defer t.mu.Unlock()

	last, ok := t.last[key]
	if ok {
		elapsed := now - last
		if elapsed < 0 {
			elapsed = 0
		}
		if windowMs > 0 && elapsed < windowMs {
			return false, elapsed
		}
	}

	t.last[key] = now
	t.dirty = true
	if t.cfg.MaxKeys > 0 && len(t.last) > t.cfg.MaxKeys {
		t.cleanup(now)
	}
	return true, 0
}

func (t *CooldownTracker) WindowMs() int64 {
	if t == nil {
		return 0
	}
	return t.cfg.WindowMs
}

func (t *CooldownTracker) SetPerRuleWindows(windows map[string]int64) {
	if t == nil {
		return
	}
	copied := make(map[string]int64, len(windows))
	for key, value := range windows {
		copied[key] = value
	}
	t.mu.Lock()
	t.perRuleWindows = copied
	t.mu.Unlock()
}

func (t *CooldownTracker) EffectiveWindow(ruleID string) int64 {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.effectiveWindowUnlocked(ruleID)
}

func (t *CooldownTracker) cleanup(now int64) {
	if t.cfg.MaxKeys <= 0 {
		return
	}
	for key, ts := range t.last {
		normalizedKey, windowMs := t.normalizeKey(key)
		if normalizedKey != key {
			delete(t.last, key)
			if _, exists := t.last[normalizedKey]; !exists {
				t.last[normalizedKey] = ts
			}
			key = normalizedKey
		}
		if windowMs > 0 && ts <= now-windowMs {
			delete(t.last, key)
		}
	}
	if len(t.last) <= t.cfg.MaxKeys {
		return
	}
	keys := make([]string, 0, len(t.last))
	for key := range t.last {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(t.last) <= t.cfg.MaxKeys {
			break
		}
		delete(t.last, key)
	}
}

type cooldownCheckpoint struct {
	Version       int             `json:"version"`
	WindowMs      int64           `json:"window_ms"`
	SavedAtUnixMs int64           `json:"saved_at_unix_ms"`
	Entries       []cooldownEntry `json:"entries"`
}

type cooldownEntry struct {
	Key               string `json:"k"`
	LastPublishedUnix int64  `json:"last_published_unix_ms"`
}

func (t *CooldownTracker) LoadFrom(path string, now int64) (int, int, error) {
	if t == nil || path == "" {
		return 0, 0, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, err
		}
		return 0, 0, fmt.Errorf("read cooldown checkpoint: %w", err)
	}
	var checkpoint cooldownCheckpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return 0, 0, fmt.Errorf("parse cooldown checkpoint: %w", err)
	}
	loaded := len(checkpoint.Entries)
	kept := 0

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, entry := range checkpoint.Entries {
		if entry.Key == "" {
			continue
		}
		if entry.LastPublishedUnix == 0 {
			continue
		}
		key, windowMs := t.normalizeKey(entry.Key)
		if now > 0 && windowMs > 0 && now-entry.LastPublishedUnix > windowMs {
			continue
		}
		t.last[key] = entry.LastPublishedUnix
		kept++
	}
	t.cleanup(now)
	t.dirty = false
	return loaded, kept, nil
}

func (t *CooldownTracker) FlushIfDirty(path string, now int64) (int, int, error) {
	if t == nil || path == "" || !t.cfg.Persist.Enabled {
		return 0, 0, nil
	}
	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return 0, 0, nil
	}
	if t.lastFlushUnix > 0 && t.cfg.Persist.FlushIntervalMs > 0 && now-t.lastFlushUnix < t.cfg.Persist.FlushIntervalMs {
		t.mu.Unlock()
		return 0, 0, nil
	}
	t.cleanup(now)
	keys := make([]string, 0, len(t.last))
	for key := range t.last {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	entries := make([]cooldownEntry, 0, len(keys))
	for _, key := range keys {
		if t.cfg.MaxKeys > 0 && len(entries) >= t.cfg.MaxKeys {
			break
		}
		entries = append(entries, cooldownEntry{
			Key:               key,
			LastPublishedUnix: t.last[key],
		})
	}
	checkpoint := cooldownCheckpoint{
		Version:       1,
		WindowMs:      t.cfg.WindowMs,
		SavedAtUnixMs: now,
		Entries:       entries,
	}
	payload, err := json.Marshal(checkpoint)
	if err != nil {
		t.mu.Unlock()
		return 0, 0, fmt.Errorf("marshal cooldown checkpoint: %w", err)
	}
	t.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return 0, 0, fmt.Errorf("mkdir cooldown checkpoint dir: %w", err)
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0644); err != nil {
		return 0, 0, fmt.Errorf("write cooldown checkpoint tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return 0, 0, fmt.Errorf("rename cooldown checkpoint: %w", err)
	}

	t.mu.Lock()
	t.dirty = false
	t.lastFlushUnix = now
	t.mu.Unlock()

	return len(payload), len(entries), nil
}

func (t *CooldownTracker) normalizeKey(key string) (string, int64) {
	parts := strings.Split(key, "|")
	if len(parts) >= 3 {
		windowMs, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
		if err == nil && windowMs > 0 {
			return key, windowMs
		}
		return key, t.cfg.WindowMs
	}
	if len(parts) == 2 {
		windowMs := t.effectiveWindowUnlocked(parts[0])
		return fmt.Sprintf("%s|%s|%d", parts[0], parts[1], windowMs), windowMs
	}
	return key, t.cfg.WindowMs
}

func (t *CooldownTracker) effectiveWindowUnlocked(ruleID string) int64 {
	if t == nil {
		return 0
	}
	if t.perRuleWindows != nil {
		if val, ok := t.perRuleWindows[ruleID]; ok && val > 0 {
			return val
		}
	}
	return t.cfg.WindowMs
}
