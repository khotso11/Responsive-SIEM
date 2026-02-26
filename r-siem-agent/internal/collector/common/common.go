package common

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// ResolveNodeID returns configured node id or host fallback.
func ResolveNodeID(nodeID string) string {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID != "" {
		return nodeID
	}
	host, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "unknown"
	}
	return host
}

// EventID builds a stable idempotency key from normalized inputs.
func EventID(prefix, sourceType, nodeID, rawHash string, eventTsUnixMs int64) string {
	bucket := eventTsUnixMs / 1000
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%d", sourceType, nodeID, rawHash, prefix, bucket)))
	return fmt.Sprintf("%s%s", prefix, hex.EncodeToString(sum[:]))
}

// SHA256Hex returns hex digest for bytes.
func SHA256Hex(in []byte) string {
	s := sha256.Sum256(in)
	return hex.EncodeToString(s[:])
}

// TruncateString bounds payload size while preserving deterministic indicator.
func TruncateString(s string, max int) (string, bool) {
	if max <= 0 {
		return "", len(s) > 0
	}
	if len(s) <= max {
		return s, false
	}
	if max <= 14 {
		return s[:max], true
	}
	return s[:max-14] + "...[truncated]", true
}

// RateLimiter is a tiny global token-bucket limiter.
type RateLimiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func NewRateLimiter(ratePerSec int) *RateLimiter {
	rate := float64(ratePerSec)
	if rate <= 0 {
		rate = 1
	}
	now := time.Now()
	return &RateLimiter{
		rate:   rate,
		burst:  rate,
		tokens: rate,
		last:   now,
	}
}

func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(r.last).Seconds()
	if elapsed > 0 {
		r.tokens += elapsed * r.rate
		if r.tokens > r.burst {
			r.tokens = r.burst
		}
		r.last = now
	}
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

// ParseLogLevel normalizes and validates level value.
func ParseLogLevel(raw string) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
