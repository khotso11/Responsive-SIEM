package pipeline

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"r-siem-agent/internal/event"
)

// Batch wraps a set of events destined for the same lane.
type Batch struct {
	Lane      string
	Events    []event.Event
	MaxOffset uint64
}

// LaneBatchSettings configures batching constraints for a given lane.
type LaneBatchSettings struct {
	MaxSize    int
	MaxLatency time.Duration
}

// Scheduler drains lane queues, builds micro-batches, and forwards them downstream.
type Scheduler struct {
	logger       *slog.Logger
	fastSettings LaneBatchSettings
	stdSettings  LaneBatchSettings
}

// NewScheduler wires a Scheduler with lane-specific settings.
func NewScheduler(logger *slog.Logger, fast LaneBatchSettings, standard LaneBatchSettings) *Scheduler {
	return &Scheduler{
		logger:       logger,
		fastSettings: fast,
		stdSettings:  standard,
	}
}

// Run manages batching until the context is cancelled and channels are drained.
func (s *Scheduler) Run(ctx context.Context, wg *sync.WaitGroup, fast <-chan event.Event, standard <-chan event.Event, out chan<- Batch) {
	defer wg.Done()
	defer close(out)

	fastLane := newLaneBatch(event.LaneFast, s.fastSettings)
	standardLane := newLaneBatch(event.LaneStandard, s.stdSettings)

	fastCh := fast
	standardCh := standard

	for {
		if ctx.Err() != nil {
			s.flushLane(ctx, fastLane, out)
			s.flushLane(ctx, standardLane, out)
			return
		}

		if fastCh == nil && standardCh == nil && !fastLane.hasPending() && !standardLane.hasPending() {
			return
		}

		// Prefer FAST lane by draining it when ready.
		if fastCh != nil {
			select {
			case evt, ok := <-fastCh:
				if !ok {
					fastCh = nil
				} else if !s.handleEvent(ctx, fastLane, evt, out) {
					return
				}
				continue
			default:
			}
		}

		if fastCh == nil && fastLane.hasPending() {
			if !s.flushLane(ctx, fastLane, out) {
				return
			}
			continue
		}

		if standardCh == nil && standardLane.hasPending() {
			if !s.flushLane(ctx, standardLane, out) {
				return
			}
			continue
		}

		fastTimer := fastLane.timerChan()
		standardTimer := standardLane.timerChan()

		select {
		case <-ctx.Done():
			s.flushLane(ctx, fastLane, out)
			s.flushLane(ctx, standardLane, out)
			return
		case evt, ok := <-fastCh:
			if !ok {
				fastCh = nil
				break
			}
			if !s.handleEvent(ctx, fastLane, evt, out) {
				return
			}
		case <-fastTimer:
			if !s.flushLane(ctx, fastLane, out) {
				return
			}
		case evt, ok := <-standardCh:
			if !ok {
				standardCh = nil
				break
			}
			if !s.handleEvent(ctx, standardLane, evt, out) {
				return
			}
		case <-standardTimer:
			if !s.flushLane(ctx, standardLane, out) {
				return
			}
		}
	}
}

func (s *Scheduler) handleEvent(ctx context.Context, lane *laneBatch, evt event.Event, out chan<- Batch) bool {
	shouldFlush := lane.add(evt)
	if !shouldFlush {
		return true
	}
	return s.flushLane(ctx, lane, out)
}

func (s *Scheduler) flushLane(ctx context.Context, lane *laneBatch, out chan<- Batch) bool {
	if !lane.hasPending() {
		return true
	}

	events := lane.takeEvents()
	batch := Batch{
		Lane:      lane.lane,
		Events:    events,
		MaxOffset: maxOffset(events),
	}

	select {
	case <-ctx.Done():
		return false
	case out <- batch:
		return true
	}
}

type laneBatch struct {
	lane       string
	maxSize    int
	maxLatency time.Duration
	pending    []event.Event
	timer      *time.Timer
}

func newLaneBatch(lane string, settings LaneBatchSettings) *laneBatch {
	return &laneBatch{
		lane:       lane,
		maxSize:    settings.MaxSize,
		maxLatency: settings.MaxLatency,
	}
}

func (lb *laneBatch) add(evt event.Event) bool {
	if len(lb.pending) == 0 {
		lb.startTimer()
	}

	lb.pending = append(lb.pending, evt)
	return len(lb.pending) >= lb.maxSize
}

func (lb *laneBatch) hasPending() bool {
	return len(lb.pending) > 0
}

func (lb *laneBatch) takeEvents() []event.Event {
	events := lb.pending
	lb.pending = nil
	lb.stopTimer()
	return events
}

func (lb *laneBatch) timerChan() <-chan time.Time {
	if !lb.hasPending() || lb.timer == nil {
		return nil
	}
	return lb.timer.C
}

func (lb *laneBatch) startTimer() {
	if lb.timer == nil {
		lb.timer = time.NewTimer(lb.maxLatency)
		return
	}

	lb.resetTimer()
}

func (lb *laneBatch) stopTimer() {
	if lb.timer == nil {
		return
	}
	if !lb.timer.Stop() {
		lb.drainTimer()
	}
}

func (lb *laneBatch) resetTimer() {
	if lb.timer == nil {
		return
	}
	if !lb.timer.Stop() {
		lb.drainTimer()
	}
	lb.timer.Reset(lb.maxLatency)
}

func (lb *laneBatch) drainTimer() {
	if lb.timer == nil {
		return
	}
	select {
	case <-lb.timer.C:
	default:
	}
}

func maxOffset(events []event.Event) uint64 {
	var max uint64
	for _, evt := range events {
		if evt.WALOffset > max {
			max = evt.WALOffset
		}
	}
	return max
}
