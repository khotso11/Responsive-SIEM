package pipeline

import (
	"context"
	"log/slog"
	"sync"
)

// BatchSink logs batches, acting as a stub transport.
type BatchSink struct {
	logger *slog.Logger
}

// NewBatchSink creates a new sink instance.
func NewBatchSink(logger *slog.Logger) *BatchSink {
	return &BatchSink{logger: logger}
}

// Run consumes batches and logs concise summaries.
func (s *BatchSink) Run(ctx context.Context, wg *sync.WaitGroup, in <-chan Batch) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-in:
			if !ok {
				return
			}
			s.logBatch(batch)
		}
	}
}

func (s *BatchSink) logBatch(batch Batch) {
	if len(batch.Events) == 0 {
		return
	}

	first := batch.Events[0]
	last := batch.Events[len(batch.Events)-1]

	s.logger.Info(
		"batch",
		"lane", batch.Lane,
		"batch_size", len(batch.Events),
		"first_seq", first.Seq,
		"last_seq", last.Seq,
	)
}
