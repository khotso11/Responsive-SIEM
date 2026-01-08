package pipeline

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"r-siem-agent/internal/event"
)

// Processor normalizes raw events.
type Processor struct {
	logger      *slog.Logger
	host        string
	defaultSrc  string
	defaultType string
}

// NewProcessor builds a processor with sane defaults.
func NewProcessor(logger *slog.Logger) *Processor {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown-host"
	}

	return &Processor{
		logger:      logger,
		host:        hostname,
		defaultSrc:  "mockgen",
		defaultType: "event",
	}
}

// Run reads raw events, normalizes them, and forwards them downstream.
func (p *Processor) Run(ctx context.Context, wg *sync.WaitGroup, in <-chan event.Event, out chan<- event.Event) {
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

			outEvt := p.normalize(evt)
			select {
			case <-ctx.Done():
				return
			case out <- outEvt:
			}
		}
	}
}

func (p *Processor) normalize(evt event.Event) event.Event {
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}

	if evt.Host == "" {
		evt.Host = p.host
	}

	if evt.Source == "" {
		evt.Source = p.defaultSrc
	}

	if evt.Type == "" {
		evt.Type = p.defaultType
	}

	if evt.Severity == "" {
		evt.Severity = "INFO"
	}

	if evt.Fields == nil {
		evt.Fields = make(map[string]any)
	}

	return evt
}
