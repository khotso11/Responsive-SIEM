package pipeline

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"r-siem-agent/internal/event"
)

// Classifier assigns lane values to events.
type Classifier struct {
	logger *slog.Logger
}

// NewClassifier creates a classifier.
func NewClassifier(logger *slog.Logger) *Classifier {
	return &Classifier{logger: logger}
}

// Run reads events, annotates them with lanes, and forwards them.
func (c *Classifier) Run(ctx context.Context, wg *sync.WaitGroup, in <-chan event.Event, out chan<- event.Event) {
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

			classified := c.classify(evt)
			select {
			case <-ctx.Done():
				return
			case out <- classified:
			}
		}
	}
}

func (c *Classifier) classify(evt event.Event) event.Event {
	severity := strings.ToUpper(evt.Severity)
	switch severity {
	case "CRITICAL", "HIGH":
		evt.Lane = event.LaneFast
	default:
		evt.Lane = event.LaneStandard
	}
	return evt
}
