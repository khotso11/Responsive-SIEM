package pipeline

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	pb "r-siem-agent/internal/proto/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// GRPCMTLSTransportSession implements a gRPC-based transport with mTLS.
type GRPCMTLSTransportSession struct {
	logger *slog.Logger
	addr   string
	creds  credentials.TransportCredentials
}

// NewGRPCMTLSTransportSession wires a gRPC transport session.
func NewGRPCMTLSTransportSession(logger *slog.Logger, addr, caPath, certPath, keyPath, serverName string) (*GRPCMTLSTransportSession, error) {
	creds, err := loadClientCredentials(caPath, certPath, keyPath, serverName)
	if err != nil {
		return nil, err
	}

	return &GRPCMTLSTransportSession{
		logger: logger,
		addr:   addr,
		creds:  creds,
	}, nil
}

// Run maintains the gRPC stream until cancellation.
func (s *GRPCMTLSTransportSession) Run(ctx context.Context, batches <-chan Batch, acks chan<- Ack) error {
	backoff := time.Second

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		connCtx, cancel := context.WithCancel(ctx)
		conn, err := grpc.DialContext(
			connCtx,
			s.addr,
			grpc.WithTransportCredentials(s.creds),
			grpc.WithBlock(),
		)
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.logger.Warn("grpc transport dial failed", "error", err, "addr", s.addr)
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

		s.logger.Info("transport connected", "addr", s.addr, "mode", "grpc_mtls")
		backoff = time.Second

		err = s.handleStream(connCtx, conn, batches, acks)
		cancel()
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

		s.logger.Warn("grpc transport stream ended", "error", err)
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

func (s *GRPCMTLSTransportSession) handleStream(ctx context.Context, conn *grpc.ClientConn, batches <-chan Batch, acks chan<- Ack) error {
	client := pb.NewAgentIngestClient(conn)
	stream, err := client.Stream(ctx)
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)
	var once sync.Once
	closeStream := func() {
		once.Do(func() {
			_ = stream.CloseSend()
		})
	}

	go func() {
		defer closeStream()
		errCh <- s.writerLoop(ctx, stream, batches)
	}()

	go func() {
		defer closeStream()
		errCh <- s.readerLoop(ctx, stream, acks)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (s *GRPCMTLSTransportSession) writerLoop(ctx context.Context, stream pb.AgentIngest_StreamClient, batches <-chan Batch) error {
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

			msg := &pb.BatchMsg{
				Lane:      batch.Lane,
				BatchSize: int32(len(batch.Events)),
				FirstSeq:  first.Seq,
				LastSeq:   last.Seq,
				MaxOffset: batch.MaxOffset,
			}

			s.logger.Info(
				"send_batch",
				"lane", batch.Lane,
				"batch_size", len(batch.Events),
				"first_seq", first.Seq,
				"last_seq", last.Seq,
				"max_offset", batch.MaxOffset,
			)

			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

func (s *GRPCMTLSTransportSession) readerLoop(ctx context.Context, stream pb.AgentIngest_StreamClient, acks chan<- Ack) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		ack := Ack{
			Lane:      msg.GetLane(),
			MaxOffset: msg.GetMaxOffset(),
			BatchSize: int(msg.GetBatchSize()),
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

func loadClientCredentials(caPath, certPath, keyPath, serverName string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client certs: %w", err)
	}

	caData, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("invalid ca certs at %s", caPath)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   serverName,
	}

	return credentials.NewTLS(tlsConfig), nil
}
