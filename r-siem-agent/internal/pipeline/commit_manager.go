package pipeline

import (
	"context"
	"log/slog"
	"sync"

	"r-siem-agent/internal/wal"
)

// CommitManager accepts ACKs and advances the WAL committed watermark.
type CommitManager struct {
	logger *slog.Logger
	wal    *wal.WAL
}

// NewCommitManager builds a CommitManager instance.
func NewCommitManager(logger *slog.Logger, store *wal.WAL) *CommitManager {
	return &CommitManager{
		logger: logger,
		wal:    store,
	}
}

// Run listens for acknowledgments and commits the WAL.
func (c *CommitManager) Run(ctx context.Context, wg *sync.WaitGroup, acks <-chan Ack) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case ack, ok := <-acks:
			if !ok {
				return
			}

			if err := c.wal.MarkCommittedUpTo(ack.MaxOffset); err != nil {
				c.logger.Error("wal commit failed", "error", err, "max_offset", ack.MaxOffset)
				continue
			}

			c.logger.Info(
				"commit",
				"lane", ack.Lane,
				"batch_size", ack.BatchSize,
				"max_offset", ack.MaxOffset,
			)
		}
	}
}
