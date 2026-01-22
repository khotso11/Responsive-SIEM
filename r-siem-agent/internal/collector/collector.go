package collector

import "context"

// Health reports collector state and counters.
type Health struct {
	Running    bool
	LastError  string
	Published  uint64
	Errors     uint64
	LastOffset uint64
	LastSeq    uint64
}

// Collector defines the collector lifecycle.
type Collector interface {
	Name() string
	Start(ctx context.Context) error
	Stop() error
	Health() Health
}
