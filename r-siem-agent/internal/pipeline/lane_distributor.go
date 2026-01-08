package pipeline

import (
	"context"
	"log/slog"
	"sync"

	"r-siem-agent/internal/event"
)

// LaneDistributor routes classified events into lane queues.
type LaneDistributor struct {
	logger       *slog.Logger
	fastLane     chan event.Event
	standardLane chan event.Event
}

// NewLaneDistributor builds a distributor with explicit lane channels.
func NewLaneDistributor(logger *slog.Logger, fast chan event.Event, standard chan event.Event) *LaneDistributor {
	return &LaneDistributor{
		logger:       logger,
		fastLane:     fast,
		standardLane: standard,
	}
}

// Run forwards events into their respective lane queues.
func (d *LaneDistributor) Run(ctx context.Context, wg *sync.WaitGroup, in <-chan event.Event) {
	defer wg.Done()
	defer close(d.fastLane)
	defer close(d.standardLane)

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-in:
			if !ok {
				return
			}

			if !d.dispatch(ctx, evt) {
				return
			}
		}
	}
}

func (d *LaneDistributor) dispatch(ctx context.Context, evt event.Event) bool {
	if evt.Lane == event.LaneFast {
		for {
			select {
			case <-ctx.Done():
				return false
			case d.fastLane <- evt:
				return true
			}
		}
	}

	select {
	case <-ctx.Done():
		return false
	case d.standardLane <- evt:
		return true
	default:
		d.logger.Warn(
			"standard lane full dropping event",
			"lane", event.LaneStandard,
			"id", evt.ID,
			"seq", evt.Seq,
			"severity", evt.Severity,
		)
		return true
	}
}
