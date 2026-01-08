package mock

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"r-siem-agent/internal/event"
)

// Generator emits mock events at a fixed interval.
type Generator struct {
	interval time.Duration
	seq      atomic.Uint64
}

// NewGenerator configures a mock event generator.
func NewGenerator(interval time.Duration) *Generator {
	if interval <= 0 {
		interval = time.Second
	}

	return &Generator{interval: interval}
}

// Run emits events until the context is cancelled and then closes the output channel.
func (g *Generator) Run(ctx context.Context, wg *sync.WaitGroup, out chan<- event.Event) {
	defer wg.Done()
	defer close(out)

	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			seq := g.seq.Add(1)
			severity := g.severityForSeq(seq)
			out <- event.Event{
				Seq:      seq,
				ID:       fmt.Sprintf("mock-%d", seq),
				Source:   "mockgen",
				Type:     "mock_event",
				Severity: severity,
				Message:  "mock event generated",
				Fields: map[string]any{
					"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
				},
			}
		}
	}
}

func (g *Generator) severityForSeq(seq uint64) string {
	switch {
	case seq%10 == 0:
		return "CRITICAL"
	case seq%5 == 0:
		return "HIGH"
	default:
		return "INFO"
	}
}
