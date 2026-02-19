package pipeline

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	pb "r-siem-agent/internal/proto/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// GRPCMTLSTransportSession implements a gRPC-based transport with mTLS.
type GRPCMTLSTransportSession struct {
	logger  *slog.Logger
	addr    string
	creds   credentials.TransportCredentials
	agentID string
}

// NewGRPCMTLSTransportSession wires a gRPC transport session.
func NewGRPCMTLSTransportSession(logger *slog.Logger, addr, caPath, certPath, keyPath, serverName, serverCertPin, agentID string) (*GRPCMTLSTransportSession, error) {
	creds, err := loadClientCredentials(logger, caPath, certPath, keyPath, serverName, serverCertPin)
	if err != nil {
		return nil, err
	}

	return &GRPCMTLSTransportSession{
		logger:  logger,
		addr:    addr,
		creds:   creds,
		agentID: strings.TrimSpace(agentID),
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
			s.logger.LogAttrs(context.Background(), slog.LevelWarn, "grpc_mtls_handshake_failed",
				slog.String("reason", classifyClientDialError(err)),
				slog.String("error", err.Error()),
				slog.String("addr", s.addr),
			)
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
	streamCtx := ctx
	if s.agentID != "" {
		streamCtx = metadata.AppendToOutgoingContext(ctx, "x-rsiem-agent-id", s.agentID)
	}
	stream, err := client.Stream(streamCtx)
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

func loadClientCredentials(logger *slog.Logger, caPath, certPath, keyPath, serverName, serverCertPin string) (credentials.TransportCredentials, error) {
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

	normalizedPin, err := normalizeFingerprint(serverCertPin)
	if err != nil {
		return nil, fmt.Errorf("invalid transport.tls.server_cert_pin_sha256: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   serverName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("server certificate missing")
			}
			serverFP := certFingerprintSHA256(cs.PeerCertificates[0])
			if normalizedPin != "" && !strings.EqualFold(serverFP, normalizedPin) {
				return fmt.Errorf("server fingerprint mismatch")
			}
			logger.LogAttrs(context.Background(), slog.LevelInfo, "grpc_mtls_client_connected",
				slog.String("server_name", serverName),
				slog.String("server_fingerprint_sha256", serverFP),
				slog.Bool("pinning_enabled", normalizedPin != ""),
			)
			return nil
		},
	}

	return credentials.NewTLS(tlsConfig), nil
}

func certFingerprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

func normalizeFingerprint(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, ":", "")
	if s == "" {
		return "", nil
	}
	if len(s) != 64 {
		return "", fmt.Errorf("must be 64 hex chars")
	}
	for _, ch := range s {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return "", fmt.Errorf("must be hexadecimal")
		}
	}
	return s, nil
}

func classifyClientDialError(err error) string {
	if err == nil {
		return "unknown"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "certificate required"), strings.Contains(msg, "no certificates"):
		return "no_client_certificate"
	case strings.Contains(msg, "unknown authority"), strings.Contains(msg, "unknown ca"):
		return "unknown_ca"
	case strings.Contains(msg, "identity mismatch"):
		return "identity_mismatch"
	case strings.Contains(msg, "fingerprint mismatch"):
		return "fingerprint_mismatch"
	case strings.Contains(msg, "expired"), strings.Contains(msg, "not yet valid"):
		return "certificate_validity"
	default:
		return "handshake_error"
	}
}
