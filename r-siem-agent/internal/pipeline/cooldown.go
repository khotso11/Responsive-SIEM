package pipeline

import (
	"sort"
	"sync"
)

const (
	defaultCooldownWindowMs = int64(60000)
	defaultCooldownMaxKeys  = 50000
)

// CooldownConfig controls trigger suppression.
type CooldownConfig struct {
	Enabled  bool  `yaml:"enabled"`
	WindowMs int64 `yaml:"window_ms"`
	MaxKeys  int   `yaml:"max_keys"`
}

// ResolveCooldownConfig applies defaults to the provided config.
func ResolveCooldownConfig(raw *CooldownConfig) CooldownConfig {
	cfg := CooldownConfig{
		Enabled:  true,
		WindowMs: defaultCooldownWindowMs,
		MaxKeys:  defaultCooldownMaxKeys,
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
	return cfg
}

// CooldownTracker suppresses repeated trigger publishes for the same key.
type CooldownTracker struct {
	cfg  CooldownConfig
	mu   sync.Mutex
	last map[string]int64
}

// NewCooldownTracker creates a tracker with defaults applied.
func NewCooldownTracker(cfg CooldownConfig) *CooldownTracker {
	return &CooldownTracker{
		cfg:  cfg,
		last: make(map[string]int64),
	}
}

// Allow returns true if the key can publish at the given time.
func (t *CooldownTracker) Allow(key string, now int64) (bool, int64) {
	if t == nil || !t.cfg.Enabled {
		return true, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	last, ok := t.last[key]
	if ok {
		elapsed := now - last
		if elapsed < 0 {
			elapsed = 0
		}
		if elapsed < t.cfg.WindowMs {
			return false, elapsed
		}
	}

	t.last[key] = now
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

func (t *CooldownTracker) cleanup(now int64) {
	if t.cfg.MaxKeys <= 0 {
		return
	}
	cutoff := now - t.cfg.WindowMs
	for key, ts := range t.last {
		if ts <= cutoff {
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
