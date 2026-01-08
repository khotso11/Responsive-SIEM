package pipeline

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"r-siem-agent/internal/event"
)

// Sink logs normalized events.
type Sink struct {
	logger *slog.Logger
}

// NewSink creates a new sink.
func NewSink(logger *slog.Logger) *Sink {
	return &Sink{logger: logger}
}

// Run consumes events and logs them until the context is cancelled.
func (s *Sink) Run(ctx context.Context, wg *sync.WaitGroup, in <-chan event.Event) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-in:
			if !ok {
				return
			}
			s.logEvent(evt)
		}
	}
}

func (s *Sink) logEvent(evt event.Event) {
	s.logger.Info(
		"event",
		"id", evt.ID,
		"seq", evt.Seq,
		"timestamp", evt.Timestamp.Format(time.RFC3339Nano),
		"host", evt.Host,
		"source", evt.Source,
		"type", evt.Type,
		"severity", evt.Severity,
		"message", evt.Message,
		"fields", evt.Fields,
	)
}
