package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"r-siem-agent/internal/logging"
	pb "r-siem-agent/internal/proto/pb"
)

type grpcServer struct {
	pb.UnimplementedAgentIngestServer

	logger   *slog.Logger
	ackDelay time.Duration
	dropRate float64
	rng      *rand.Rand
}

func main() {
	addr := flag.String("addr", "127.0.0.1:7777", "listen address")
	caPath := flag.String("ca", "configs/certs/ca.pem", "CA certificate path")
	certPath := flag.String("cert", "configs/certs/master.pem", "server certificate path")
	keyPath := flag.String("key", "configs/certs/master-key.pem", "server private key path")
	ackDelay := flag.Int("ack-delay-ms", 150, "ack delay in milliseconds")
	dropRate := flag.Float64("ack-drop-rate", 0.0, "ack drop probability (0..1)")
	flag.Parse()

	logger, err := logging.NewLogger("INFO")
	if err != nil {
		panic(err)
	}

	creds, err := loadServerCredentials(*caPath, *certPath, *keyPath)
	if err != nil {
		logger.Error("failed to load tls config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	server := &grpcServer{
		logger:   logger,
		ackDelay: time.Duration(*ackDelay) * time.Millisecond,
		dropRate: *dropRate,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	if err := server.run(ctx, *addr, creds); err != nil {
		logger.Error("master exited with error", "error", err)
		os.Exit(1)
	}
}

func (s *grpcServer) run(ctx context.Context, addr string, creds credentials.TransportCredentials) error {
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterAgentIngestServer(grpcServer, s)

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer lis.Close()

	s.logger.Info(
		"mock master (grpc) listening",
		"addr", addr,
		"ack_delay_ms", s.ackDelay.Milliseconds(),
		"ack_drop_rate", s.dropRate,
	)

	errCh := make(chan error, 1)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		stopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			grpcServer.Stop()
		}
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *grpcServer) Stream(stream pb.AgentIngest_StreamServer) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		s.logger.Info(
			"master_recv_batch",
			"lane", msg.GetLane(),
			"batch_size", msg.GetBatchSize(),
			"first_seq", msg.GetFirstSeq(),
			"last_seq", msg.GetLastSeq(),
			"max_offset", msg.GetMaxOffset(),
		)

		if s.shouldDrop() {
			s.logger.Warn(
				"master_drop_batch",
				"lane", msg.GetLane(),
				"batch_size", msg.GetBatchSize(),
				"max_offset", msg.GetMaxOffset(),
			)
			continue
		}

		if s.ackDelay > 0 {
			timer := time.NewTimer(s.ackDelay)
			select {
			case <-stream.Context().Done():
				timer.Stop()
				return stream.Context().Err()
			case <-timer.C:
			}
		}

		ack := &pb.AckMsg{
			Lane:      msg.GetLane(),
			BatchSize: msg.GetBatchSize(),
			MaxOffset: msg.GetMaxOffset(),
		}

		if err := stream.Send(ack); err != nil {
			return err
		}

		s.logger.Info(
			"master_send_ack",
			"lane", ack.GetLane(),
			"batch_size", ack.GetBatchSize(),
			"max_offset", ack.GetMaxOffset(),
		)
	}
}

func (s *grpcServer) shouldDrop() bool {
	if s.dropRate <= 0 {
		return false
	}
	if s.dropRate >= 1 {
		return true
	}
	return s.rng.Float64() < s.dropRate
}

func loadServerCredentials(caPath, certPath, keyPath string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	caData, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("invalid ca certs at %s", caPath)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	return credentials.NewTLS(cfg), nil
}
