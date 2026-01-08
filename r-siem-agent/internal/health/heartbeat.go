package health

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Heartbeat reports a periodic liveness message.
type Heartbeat struct {
	interval time.Duration
	logger   *slog.Logger
}

// NewHeartbeat builds a heartbeat reporter.
func NewHeartbeat(logger *slog.Logger, interval time.Duration) *Heartbeat {
	if interval <= 0 {
		interval = time.Minute
	}

	return &Heartbeat{interval: interval, logger: logger}
}

// Run emits heartbeat logs until the context is cancelled.
func (h *Heartbeat) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	h.logger.Info("heartbeat started", "interval_seconds", int(h.interval.Seconds()))

	for {
		select {
		case <-ctx.Done():
			h.logger.Info("heartbeat stopped")
			return
		case <-ticker.C:
			h.logger.Info("heartbeat", "interval_seconds", int(h.interval.Seconds()))
		}
	}
}
