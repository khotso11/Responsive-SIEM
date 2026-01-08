package pipeline

import (
	"context"
	"log/slog"
	"sync"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/event"
)

const agentVersion = "0.1.0-dev"

// Enricher augments events with agent metadata.
type Enricher struct {
	logger          *slog.Logger
	agentName       string
	agentInstanceID string
}

// NewEnricher wires an Enricher with configuration-provided metadata.
func NewEnricher(logger *slog.Logger, cfg *config.Config) *Enricher {
	return &Enricher{
		logger:          logger,
		agentName:       cfg.AgentName(),
		agentInstanceID: cfg.AgentInstanceID(),
	}
}

// Run reads normalized events, enriches them, and pushes downstream.
func (e *Enricher) Run(ctx context.Context, wg *sync.WaitGroup, in <-chan event.Event, out chan<- event.Event) {
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

			enriched := e.enrich(evt)
			select {
			case <-ctx.Done():
				return
			case out <- enriched:
			}
		}
	}
}

func (e *Enricher) enrich(evt event.Event) event.Event {
	if evt.Fields == nil {
		evt.Fields = make(map[string]any)
	}

	e.setIfMissing(evt.Fields, "agent.name", e.agentName)
	e.setIfMissing(evt.Fields, "agent.instance_id", e.agentInstanceID)
	e.setIfMissing(evt.Fields, "agent.version", agentVersion)

	return evt
}

func (e *Enricher) setIfMissing(fields map[string]any, key string, value string) {
	if _, exists := fields[key]; exists {
		return
	}
	fields[key] = value
}
