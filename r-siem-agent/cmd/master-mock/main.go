package main

import (
	"context"
	"flag"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"r-siem-agent/internal/logging"
	"r-siem-agent/internal/proto"
)

type server struct {
	logger   *slog.Logger
	addr     string
	ackDelay time.Duration
	dropRate float64
	rng      *rand.Rand
}

func main() {
	addr := flag.String("addr", "127.0.0.1:7777", "listen address")
	ackDelay := flag.Int("ack-delay-ms", 150, "ack delay in milliseconds")
	dropRate := flag.Float64("ack-drop-rate", 0.0, "ack drop probability (0..1)")
	flag.Parse()

	logger, err := logging.NewLogger("INFO")
	if err != nil {
		panic(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &server{
		logger:   logger,
		addr:     *addr,
		ackDelay: time.Duration(*ackDelay) * time.Millisecond,
		dropRate: *dropRate,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	if err := srv.run(ctx); err != nil {
		logger.Error("master exited with error", "error", err)
		os.Exit(1)
	}
}

func (s *server) run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	s.logger.Info("master listening", "addr", s.addr, "ack_delay_ms", s.ackDelay.Milliseconds(), "ack_drop_rate", s.dropRate)

	var wg sync.WaitGroup
	defer func() {
		ln.Close()
		wg.Wait()
	}()

	acceptErr := make(chan error, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				acceptErr <- err
				return
			}
			wg.Add(1)
			go s.handleConn(ctx, conn, &wg)
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-acceptErr:
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
}

func (s *server) handleConn(ctx context.Context, conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()

	s.logger.Info("master accepted connection", "remote", conn.RemoteAddr().String())

	for {
		var batch proto.BatchMsg
		if err := proto.ReadFrame(conn, &batch); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Warn("master read error", "error", err)
			return
		}

		s.logger.Info(
			"master_recv_batch",
			"lane", batch.Lane,
			"batch_size", batch.BatchSize,
			"first_seq", batch.FirstSeq,
			"last_seq", batch.LastSeq,
			"max_offset", batch.MaxOffset,
		)

		if s.shouldDrop() {
			s.logger.Warn(
				"master_drop_batch",
				"lane", batch.Lane,
				"batch_size", batch.BatchSize,
				"max_offset", batch.MaxOffset,
			)
			continue
		}

		if s.ackDelay > 0 {
			timer := time.NewTimer(s.ackDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}

		ack := proto.AckMsg{
			Lane:      batch.Lane,
			MaxOffset: batch.MaxOffset,
			BatchSize: batch.BatchSize,
		}

		if err := proto.WriteFrame(conn, ack); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Warn("master write error", "error", err)
			return
		}

		s.logger.Info(
			"master_send_ack",
			"lane", ack.Lane,
			"batch_size", ack.BatchSize,
			"max_offset", ack.MaxOffset,
		)
	}
}

func (s *server) shouldDrop() bool {
	if s.dropRate <= 0 {
		return false
	}
	if s.dropRate >= 1 {
		return true
	}
	return s.rng.Float64() < s.dropRate
}
