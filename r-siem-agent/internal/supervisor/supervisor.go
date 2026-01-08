package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"r-siem-agent/internal/collector/mock"
	"r-siem-agent/internal/config"
	"r-siem-agent/internal/event"
	"r-siem-agent/internal/health"
	"r-siem-agent/internal/pipeline"
	"r-siem-agent/internal/wal"
)

const shutdownTimeout = 3 * time.Second

// Supervisor coordinates agent sub-systems.
type Supervisor struct {
	cfg    *config.Config
	logger *slog.Logger
}

// New creates a Supervisor instance.
func New(cfg *config.Config, logger *slog.Logger) *Supervisor {
	return &Supervisor{cfg: cfg, logger: logger}
}

// Run starts managed routines and blocks until the context is cancelled.
func (s *Supervisor) Run(ctx context.Context) error {
	s.logger.Info("supervisor starting")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	heartbeat := health.NewHeartbeat(s.logger, s.cfg.HeartbeatInterval())
	wg.Add(1)
	go heartbeat.Run(ctx, &wg)

	walStore, err := wal.Open(s.cfg.WALPath(), s.cfg.WALFsync())
	if err != nil {
		return fmt.Errorf("open wal: %w", err)
	}
	defer walStore.Close()

	rawEvents := make(chan event.Event, 1)
	normalizedEvents := make(chan event.Event, 1)
	enrichedEvents := make(chan event.Event, 1)
	classifiedEvents := make(chan event.Event, 1)
	walEvents := make(chan event.Event, 1)
	fastLane := make(chan event.Event, s.cfg.LaneFastBuffer())
	standardLane := make(chan event.Event, s.cfg.LaneStandardBuffer())
	batches := make(chan pipeline.Batch, 1)
	acks := make(chan pipeline.Ack, 1)

	mockGen := mock.NewGenerator(s.cfg.MockInterval())
	processor := pipeline.NewProcessor(s.logger)
	enricher := pipeline.NewEnricher(s.logger, s.cfg)
	classifier := pipeline.NewClassifier(s.logger)
	walWriter := pipeline.NewWALWriter(s.logger, walStore)
	distributor := pipeline.NewLaneDistributor(s.logger, fastLane, standardLane)
	scheduler := pipeline.NewScheduler(
		s.logger,
		pipeline.LaneBatchSettings{
			MaxSize:    s.cfg.BatchFastMaxSize(),
			MaxLatency: s.cfg.BatchFastMaxLatency(),
		},
		pipeline.LaneBatchSettings{
			MaxSize:    s.cfg.BatchStandardMaxSize(),
			MaxLatency: s.cfg.BatchStandardMaxLatency(),
		},
	)
	var session pipeline.TransportSession
	var sessionErr error
	switch s.cfg.TransportMode() {
	case "mock":
		session = pipeline.NewMockTransportSession(
			s.logger,
			s.cfg.TransportAckDelay(),
			s.cfg.TransportAckDropRate(),
		)
	case "tcp":
		session = pipeline.NewTCPTransportSession(
			s.logger,
			s.cfg.TransportAddr(),
		)
	case "grpc_mtls":
		session, sessionErr = pipeline.NewGRPCMTLSTransportSession(
			s.logger,
			s.cfg.TransportAddr(),
			s.cfg.TransportTLSCA(),
			s.cfg.TransportTLSCert(),
			s.cfg.TransportTLSKey(),
			s.cfg.TransportTLSServerName(),
		)
	default:
		return fmt.Errorf("unsupported transport mode: %s", s.cfg.TransportMode())
	}
	if sessionErr != nil {
		return fmt.Errorf("init transport: %w", sessionErr)
	}
	commits := pipeline.NewCommitManager(s.logger, walStore)

	wg.Add(2)
	go distributor.Run(ctx, &wg, walEvents)
	go scheduler.Run(ctx, &wg, fastLane, standardLane, batches)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(acks)
		if err := session.Run(ctx, batches, acks); err != nil && !errors.Is(err, context.Canceled) {
			s.logger.Error("transport session ended with error", "error", err)
		}
	}()
	wg.Add(1)
	go commits.Run(ctx, &wg, acks)

	if err := s.replayFromWAL(ctx, walStore, walEvents); err != nil {
		return err
	}

	wg.Add(5)
	go mockGen.Run(ctx, &wg, rawEvents)
	go processor.Run(ctx, &wg, rawEvents, normalizedEvents)
	go enricher.Run(ctx, &wg, normalizedEvents, enrichedEvents)
	go classifier.Run(ctx, &wg, enrichedEvents, classifiedEvents)
	go walWriter.Run(ctx, &wg, classifiedEvents, walEvents)

	<-ctx.Done()
	s.logger.Info("supervisor shutting down")

	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()

	select {
	case <-done:
		s.logger.Info("supervisor shutdown complete")
		return nil
	case <-time.After(shutdownTimeout):
		return errors.New("supervisor shutdown timed out")
	}
}

func (s *Supervisor) replayFromWAL(ctx context.Context, store *wal.WAL, laneInput chan<- event.Event) error {
	var total, fast, standard int

	err := store.ReplayUncommitted(func(evt event.Event) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case laneInput <- evt:
		}

		total++
		switch evt.Lane {
		case event.LaneFast:
			fast++
		case event.LaneStandard:
			standard++
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("replay wal: %w", err)
	}

	s.logger.Info(
		"wal replay complete",
		"replayed_total", total,
		"replayed_fast", fast,
		"replayed_standard", standard,
	)
	return nil
}
