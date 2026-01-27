package pipeline

import (
	"sort"
	"sync"
	"time"
)

const (
	defaultTriggerDedupeTTLMS  = int64(10 * 60 * 1000)
	defaultTriggerDedupeMaxKey = 200000
	triggerDedupeScanLimit     = 1024
)

// TriggerDedupeConfig controls trigger publish dedupe.
type TriggerDedupeConfig struct {
	Enabled bool  `yaml:"enabled"`
	TTLMS   int64 `yaml:"ttl_ms"`
	MaxKeys int   `yaml:"max_keys"`
}

// ResolveTriggerDedupeConfig applies defaults to the provided config.
func ResolveTriggerDedupeConfig(raw *TriggerDedupeConfig) TriggerDedupeConfig {
	cfg := TriggerDedupeConfig{
		Enabled: true,
		TTLMS:   defaultTriggerDedupeTTLMS,
		MaxKeys: defaultTriggerDedupeMaxKey,
	}
	if raw == nil {
		return cfg
	}
	cfg.Enabled = raw.Enabled
	if raw.TTLMS > 0 {
		cfg.TTLMS = raw.TTLMS
	}
	if raw.MaxKeys > 0 {
		cfg.MaxKeys = raw.MaxKeys
	}
	return cfg
}

// TriggerDedupe suppresses repeated trigger publishes for the same key.
type TriggerDedupe struct {
	cfg         TriggerDedupeConfig
	mu          sync.Mutex
	seen        map[string]int64
	order       []string
	scanCursor  int
	evictCursor int
	tombstones  int
	nowFn       func() int64
}

// NewTriggerDedupe creates a tracker with defaults applied.
func NewTriggerDedupe(cfg TriggerDedupeConfig, nowFn func() int64) *TriggerDedupe {
	if nowFn == nil {
		nowFn = func() int64 { return time.Now().UnixMilli() }
	}
	return &TriggerDedupe{
		cfg:   cfg,
		seen:  make(map[string]int64),
		nowFn: nowFn,
	}
}

// ShouldSuppress returns true if the key should be suppressed at the given time.
func (t *TriggerDedupe) ShouldSuppress(key string, nowMs int64) (bool, int64) {
	if t == nil || !t.cfg.Enabled || key == "" {
		return false, 0
	}
	if nowMs <= 0 {
		nowMs = t.nowFn()
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	last, ok := t.seen[key]
	if !ok {
		return false, 0
	}
	elapsed := nowMs - last
	if elapsed < 0 {
		elapsed = 0
	}
	if t.cfg.TTLMS > 0 && elapsed < t.cfg.TTLMS {
		return true, elapsed
	}
	delete(t.seen, key)
	t.tombstones++
	return false, elapsed
}

// Mark records the key at the given time.
func (t *TriggerDedupe) Mark(key string, nowMs int64) {
	if t == nil || !t.cfg.Enabled || key == "" {
		return
	}
	if nowMs <= 0 {
		nowMs = t.nowFn()
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.seen[key]; !ok {
		t.order = append(t.order, key)
	}
	t.seen[key] = nowMs
	t.cleanupLocked(nowMs)
}

// Cleanup runs a bounded cleanup and returns the number of removed keys.
func (t *TriggerDedupe) Cleanup(nowMs int64) int {
	if t == nil || !t.cfg.Enabled {
		return 0
	}
	if nowMs <= 0 {
		nowMs = t.nowFn()
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	before := len(t.seen)
	t.cleanupLocked(nowMs)
	return before - len(t.seen)
}

func (t *TriggerDedupe) TTLMS() int64 {
	if t == nil {
		return 0
	}
	return t.cfg.TTLMS
}

func (t *TriggerDedupe) cleanupLocked(nowMs int64) {
	t.cleanupExpiredLocked(nowMs)
	t.cleanupSizeLocked()
	if t.tombstones > 0 && t.tombstones*2 >= len(t.order) {
		t.compactLocked()
	}
}

func (t *TriggerDedupe) cleanupExpiredLocked(nowMs int64) {
	if t.cfg.TTLMS <= 0 || len(t.order) == 0 {
		return
	}
	for i := 0; i < triggerDedupeScanLimit && len(t.order) > 0; i++ {
		if t.scanCursor >= len(t.order) {
			t.scanCursor = 0
		}
		idx := t.scanCursor
		key := t.order[idx]
		t.scanCursor++
		if key == "" {
			continue
		}
		last, ok := t.seen[key]
		if !ok {
			t.order[idx] = ""
			t.tombstones++
			continue
		}
		if nowMs-last >= t.cfg.TTLMS {
			delete(t.seen, key)
			t.order[idx] = ""
			t.tombstones++
		}
	}
}

func (t *TriggerDedupe) cleanupSizeLocked() {
	if t.cfg.MaxKeys <= 0 {
		return
	}
	for len(t.seen) > t.cfg.MaxKeys && len(t.order) > 0 {
		if t.evictCursor >= len(t.order) {
			t.evictCursor = 0
		}
		idx := t.evictCursor
		key := t.order[idx]
		t.evictCursor++
		if key == "" {
			continue
		}
		if _, ok := t.seen[key]; !ok {
			t.order[idx] = ""
			t.tombstones++
			continue
		}
		delete(t.seen, key)
		t.order[idx] = ""
		t.tombstones++
	}
}

func (t *TriggerDedupe) compactLocked() {
	if len(t.order) == 0 {
		return
	}
	keys := make([]string, 0, len(t.seen))
	for _, key := range t.order {
		if key == "" {
			continue
		}
		if _, ok := t.seen[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	t.order = keys
	t.tombstones = 0
	t.scanCursor = 0
	t.evictCursor = 0
}
