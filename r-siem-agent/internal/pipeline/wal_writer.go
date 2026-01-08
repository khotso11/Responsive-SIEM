package pipeline

import (
	"context"
	"log/slog"
	"sync"

	"r-siem-agent/internal/event"
	"r-siem-agent/internal/wal"
)

// WALWriter ensures events are durably recorded before entering lane queues.
type WALWriter struct {
	logger *slog.Logger
	wal    *wal.WAL
}

// NewWALWriter wires a WALWriter.
func NewWALWriter(logger *slog.Logger, store *wal.WAL) *WALWriter {
	return &WALWriter{
		logger: logger,
		wal:    store,
	}
}

// Run appends incoming events to the WAL before forwarding them downstream.
func (w *WALWriter) Run(ctx context.Context, wg *sync.WaitGroup, in <-chan event.Event, out chan<- event.Event) {
	defer wg.Done()
	defer close(out)

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-in:
			if !ok {
				return
			}

			offset, err := w.wal.Append(evt)
			if err != nil {
				w.logger.Error("wal append failed", "error", err)
				continue
			}
			evt.WALOffset = offset

			select {
			case <-ctx.Done():
				return
			case out <- evt:
			}
		}
	}
}
