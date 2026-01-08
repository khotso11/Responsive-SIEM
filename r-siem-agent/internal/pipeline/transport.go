package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"time"

	"r-siem-agent/internal/proto"
)

// TransportSession consumes batches and emits ACKs.
type TransportSession interface {
	Run(ctx context.Context, batches <-chan Batch, acks chan<- Ack) error
}

// Ack represents a batch acknowledgment.
type Ack struct {
	Lane      string
	MaxOffset uint64
	BatchSize int
}

// MockTransportSession is an in-memory transport stub.
type MockTransportSession struct {
	logger   *slog.Logger
	ackDelay time.Duration
	dropRate float64
	rng      *rand.Rand
}

// NewMockTransportSession creates a mock session.
func NewMockTransportSession(logger *slog.Logger, ackDelay time.Duration, dropRate float64) *MockTransportSession {
	return &MockTransportSession{
		logger:   logger,
		ackDelay: ackDelay,
		dropRate: dropRate,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Run drains batches, logging send events and emitting ACKs with delay/drop rules.
func (s *MockTransportSession) Run(ctx context.Context, batches <-chan Batch, acks chan<- Ack) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batch, ok := <-batches:
			if !ok {
				return nil
			}
			s.handleBatch(ctx, batch, acks)
		}
	}
}

func (s *MockTransportSession) handleBatch(ctx context.Context, batch Batch, acks chan<- Ack) {
	if len(batch.Events) == 0 {
		return
	}

	first := batch.Events[0]
	last := batch.Events[len(batch.Events)-1]

	s.logger.Info(
		"send_batch",
		"lane", batch.Lane,
		"batch_size", len(batch.Events),
		"first_seq", first.Seq,
		"last_seq", last.Seq,
		"max_offset", batch.MaxOffset,
	)

	if s.shouldDrop() {
		s.logger.Warn(
			"drop_batch",
			"lane", batch.Lane,
			"batch_size", len(batch.Events),
			"max_offset", batch.MaxOffset,
		)
		return
	}

	if s.ackDelay <= 0 {
		s.emitAck(ctx, batch, acks)
		return
	}

	timer := time.NewTimer(s.ackDelay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		s.emitAck(ctx, batch, acks)
	}
}

func (s *MockTransportSession) emitAck(ctx context.Context, batch Batch, acks chan<- Ack) {
	ack := Ack{
		Lane:      batch.Lane,
		MaxOffset: batch.MaxOffset,
		BatchSize: len(batch.Events),
	}

	select {
	case <-ctx.Done():
		return
	case acks <- ack:
		s.logger.Info(
			"ack_batch",
			"lane", ack.Lane,
			"batch_size", ack.BatchSize,
			"max_offset", ack.MaxOffset,
		)
	}
}

func (s *MockTransportSession) shouldDrop() bool {
	if s.dropRate <= 0 {
		return false
	}
	if s.dropRate >= 1 {
		return true
	}
	return s.rng.Float64() < s.dropRate
}

var errBatchesClosed = errors.New("batches channel closed")

// TCPTransportSession streams batches to a remote master over TCP.
type TCPTransportSession struct {
	logger *slog.Logger
	addr   string
	dialer net.Dialer
}

// NewTCPTransportSession constructs a TCP-backed transport session.
func NewTCPTransportSession(logger *slog.Logger, addr string) *TCPTransportSession {
	return &TCPTransportSession{
		logger: logger,
		addr:   addr,
		dialer: net.Dialer{Timeout: 5 * time.Second},
	}
}

// Run maintains a TCP connection, reconnecting on failures until shutdown.
func (s *TCPTransportSession) Run(ctx context.Context, batches <-chan Batch, acks chan<- Ack) error {
	backoff := time.Second

	for {
		conn, err := s.dialer.DialContext(ctx, "tcp", s.addr)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.logger.Warn("transport dial failed", "error", err, "addr", s.addr)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}

		s.logger.Info("transport connected", "addr", s.addr)
		backoff = time.Second
		err = s.handleConnection(ctx, conn, batches, acks)
		conn.Close()

		if errors.Is(err, errBatchesClosed) {
			return nil
		}
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			return nil
		}

		s.logger.Warn("transport connection lost", "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 10*time.Second {
			backoff *= 2
		}
	}
}

func (s *TCPTransportSession) handleConnection(ctx context.Context, conn net.Conn, batches <-chan Batch, acks chan<- Ack) error {
	errCh := make(chan error, 2)
	var once sync.Once
	closeConn := func() {
		once.Do(func() { _ = conn.Close() })
	}

	go func() {
		err := s.writerLoop(ctx, conn, batches)
		closeConn()
		errCh <- err
	}()

	go func() {
		err := s.readerLoop(ctx, conn, acks)
		closeConn()
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		closeConn()
		return ctx.Err()
	}
}

func (s *TCPTransportSession) writerLoop(ctx context.Context, conn net.Conn, batches <-chan Batch) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batch, ok := <-batches:
			if !ok {
				return errBatchesClosed
			}
			if len(batch.Events) == 0 {
				continue
			}

			first := batch.Events[0]
			last := batch.Events[len(batch.Events)-1]
			s.logger.Info(
				"send_batch",
				"lane", batch.Lane,
				"batch_size", len(batch.Events),
				"first_seq", first.Seq,
				"last_seq", last.Seq,
				"max_offset", batch.MaxOffset,
			)

			msg := proto.BatchMsg{
				Lane:      batch.Lane,
				BatchSize: len(batch.Events),
				MaxOffset: batch.MaxOffset,
				FirstSeq:  first.Seq,
				LastSeq:   last.Seq,
			}

			if err := proto.WriteFrame(conn, msg); err != nil {
				return err
			}
		}
	}
}

func (s *TCPTransportSession) readerLoop(ctx context.Context, conn net.Conn, acks chan<- Ack) error {
	for {
		var msg proto.AckMsg
		if err := proto.ReadFrame(conn, &msg); err != nil {
			return err
		}

		ack := Ack{
			Lane:      msg.Lane,
			MaxOffset: msg.MaxOffset,
			BatchSize: msg.BatchSize,
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case acks <- ack:
			s.logger.Info(
				"ack_batch",
				"lane", ack.Lane,
				"batch_size", ack.BatchSize,
				"max_offset", ack.MaxOffset,
			)
		}
	}
}
