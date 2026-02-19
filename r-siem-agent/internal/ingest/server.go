package ingest

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"r-siem-agent/internal/buffer"
	"r-siem-agent/internal/proto/pb"
)

// Server implements the Ingest gRPC service.
type Server struct {
	pb.UnimplementedIngestServer
	logger         *slog.Logger
	publisher      *buffer.JetStreamPublisher
	ackDelay       time.Duration
	ackDropRate    float64
	rand           *rand.Rand
	peerCertLookup func(addr string) (*x509.Certificate, bool)
	idSourcePolicy string
}

// NewServer constructs a streaming ingest server.
func NewServer(logger *slog.Logger, publisher *buffer.JetStreamPublisher, ackDelay time.Duration, ackDropRate float64, peerCertLookup func(addr string) (*x509.Certificate, bool), idSourcePolicy string) *Server {
	idSourcePolicy = strings.ToLower(strings.TrimSpace(idSourcePolicy))
	switch idSourcePolicy {
	case "cert_only", "cert_prefer", "metadata_only":
	default:
		idSourcePolicy = "cert_prefer"
	}
	return &Server{
		logger:         logger,
		publisher:      publisher,
		ackDelay:       ackDelay,
		ackDropRate:    ackDropRate,
		rand:           rand.New(rand.NewSource(time.Now().UnixNano())),
		peerCertLookup: peerCertLookup,
		idSourcePolicy: idSourcePolicy,
	}
}

// Stream handles bidirectional batch ingest.
func (s *Server) Stream(stream pb.Ingest_StreamServer) error {
	if err := s.logAuthenticatedPeer(stream.Context()); err != nil {
		return err
	}

	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Internal, "recv batch: %v", err)
		}

		lane := strings.ToUpper(batch.GetLane())
		if err := validateBatch(lane, batch); err != nil {
			s.logger.Error("batch_invalid", slog.String("lane", lane), slog.String("reason", err.Error()))
			return status.Error(codes.InvalidArgument, err.Error())
		}

		payloadLen := len(batch.GetPayload())
		s.logger.Info("master_recv_batch",
			slog.String("lane", lane),
			slog.Uint64("seq_start", batch.SeqStart),
			slog.Uint64("seq_end", batch.SeqEnd),
			slog.Int("payload_len", payloadLen),
		)

		idemKey := fmt.Sprintf("batch.%s.%d.%d", lane, batch.SeqStart, batch.SeqEnd)

		if jsSeqStr, ok, err := s.publisher.IdemGet(idemKey); err != nil {
			s.logger.Error("idempotency_get_failed", slog.String("key", idemKey), slog.String("error", err.Error()))
			return status.Errorf(codes.Internal, "idempotency get: %v", err)
		} else if ok {
			jsSeq, err := strconv.ParseUint(jsSeqStr, 10, 64)
			if err != nil {
				s.logger.Error("idempotency_parse_failed", slog.String("key", idemKey), slog.String("error", err.Error()))
				return status.Errorf(codes.Internal, "idempotency parse: %v", err)
			}

			s.logger.Info("duplicate_batch",
				slog.String("lane", lane),
				slog.Uint64("seq_start", batch.SeqStart),
				slog.Uint64("seq_end", batch.SeqEnd),
				slog.String("idem_key", idemKey),
				slog.Uint64("js_seq", jsSeq),
			)

			if err := s.sendAck(stream, lane, batch.SeqEnd, jsSeq); err != nil {
				return err
			}

			continue
		}

		data, err := proto.Marshal(batch)
		if err != nil {
			s.logger.Error("batch_marshal_failed", slog.String("lane", lane), slog.String("error", err.Error()))
			return status.Errorf(codes.Internal, "marshal batch: %v", err)
		}

		jsSeq, err := s.publisher.PublishBatch(stream.Context(), lane, data)
		if err != nil {
			s.logger.Error("jetstream_publish_failed", slog.String("lane", lane), slog.String("error", err.Error()))
			return status.Errorf(codes.Internal, "publish batch: %v", err)
		}

		if err := s.publisher.IdemPut(idemKey, fmt.Sprintf("%d", jsSeq)); err != nil {
			s.logger.Error("idempotency_put_failed", slog.String("key", idemKey), slog.String("error", err.Error()))
		}

		if err := s.sendAck(stream, lane, batch.SeqEnd, jsSeq); err != nil {
			return err
		}
	}
}

func (s *Server) logAuthenticatedPeer(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return nil
	}
	cert := peerCertificate(ctx, p, s.peerCertLookup)

	certID, certSource := extractAgentIDFromCert(cert)
	metadataID := extractAgentIDFromMetadata(ctx)
	agentID := "unknown"
	agentIDSource := "unknown"
	switch s.idSourcePolicy {
	case "cert_only":
		if certID == "unknown" {
			s.logger.Warn("grpc_mtls_client_rejected",
				slog.String("reason", "client_identity_missing_in_cert"),
			)
			return status.Error(codes.Unauthenticated, "client identity missing in cert")
		}
		agentID = certID
		agentIDSource = certSource
	case "metadata_only":
		if metadataID != "" {
			agentID = metadataID
			agentIDSource = "grpc_metadata"
		}
	default:
		if certID != "unknown" {
			agentID = certID
			agentIDSource = certSource
		} else if metadataID != "" {
			agentID = metadataID
			agentIDSource = "grpc_metadata"
		}
	}

	peerSubject := ""
	peerSAN := ""
	peerFingerprint := ""
	if cert != nil {
		peerSubject = cert.Subject.String()
		peerSAN = certSANSummary(cert)
		peerFingerprint = certFingerprintSHA256(cert)
	}
	s.logger.Info("grpc_mtls_client_authenticated",
		slog.String("peer_subject", peerSubject),
		slog.String("peer_san", peerSAN),
		slog.String("peer_fingerprint_sha256", peerFingerprint),
		slog.String("agent_instance_id", agentID),
		slog.String("agent_id_source", agentIDSource),
	)
	return nil
}

func peerCertificate(ctx context.Context, p *peer.Peer, lookup func(addr string) (*x509.Certificate, bool)) *x509.Certificate {
	if lookup != nil && p != nil && p.Addr != nil {
		if cert, ok := lookup(p.Addr.String()); ok && cert != nil {
			return cert
		}
	}
	if p != nil && p.AuthInfo != nil {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			if len(tlsInfo.State.PeerCertificates) > 0 {
				return tlsInfo.State.PeerCertificates[0]
			}
		}
		if tlsInfo, ok := p.AuthInfo.(*credentials.TLSInfo); ok {
			if len(tlsInfo.State.PeerCertificates) > 0 {
				return tlsInfo.State.PeerCertificates[0]
			}
		}
	}
	return nil
}

func extractAgentIDFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get("x-rsiem-agent-id")
	if len(vals) == 0 {
		return ""
	}
	return strings.TrimSpace(vals[0])
}

func extractAgentIDFromCert(cert *x509.Certificate) (string, string) {
	if cert == nil {
		return "unknown", "unknown"
	}
	for _, dns := range cert.DNSNames {
		dns = strings.TrimSpace(dns)
		if dns != "" {
			return dns, "cert_san"
		}
	}
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		raw := strings.TrimSpace(uri.String())
		if raw != "" {
			return raw, "cert_san"
		}
	}
	cn := strings.TrimSpace(cert.Subject.CommonName)
	if cn != "" {
		return cn, "cert_cn"
	}
	return "unknown", "unknown"
}

func certFingerprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

func certSANSummary(cert *x509.Certificate) string {
	parts := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.URIs))
	for _, dns := range cert.DNSNames {
		dns = strings.TrimSpace(dns)
		if dns != "" {
			parts = append(parts, "DNS:"+dns)
		}
	}
	for _, ip := range cert.IPAddresses {
		parts = append(parts, "IP:"+ip.String())
	}
	for _, uri := range cert.URIs {
		if uri != nil {
			parts = append(parts, "URI:"+uri.String())
		}
	}
	if len(parts) == 0 && strings.TrimSpace(cert.Subject.CommonName) != "" {
		parts = append(parts, "CN:"+cert.Subject.CommonName)
	}
	return strings.Join(parts, ",")
}

func (s *Server) sendAck(stream pb.Ingest_StreamServer, lane string, seqEnd uint64, jsSeq uint64) error {
	if err := s.maybeDelayAck(stream.Context()); err != nil {
		return err
	}

	if s.shouldDropAck() {
		s.logger.Info("master_ack_dropped",
			slog.String("lane", lane),
			slog.Uint64("seq_end", seqEnd),
			slog.Uint64("js_seq", jsSeq),
		)
		return nil
	}

	ack := &pb.Ack{
		Lane:   lane,
		SeqEnd: seqEnd,
		JsSeq:  jsSeq,
	}

	if err := stream.Send(ack); err != nil {
		return status.Errorf(codes.Unavailable, "send ack: %v", err)
	}

	s.logger.Info("master_send_ack",
		slog.String("lane", lane),
		slog.Uint64("seq_end", seqEnd),
		slog.Uint64("js_seq", jsSeq),
	)

	return nil
}

func (s *Server) maybeDelayAck(ctx context.Context) error {
	if s.ackDelay <= 0 {
		return nil
	}

	timer := time.NewTimer(s.ackDelay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return status.Error(codes.Canceled, "context canceled before ack")
	case <-timer.C:
		return nil
	}
}

func (s *Server) shouldDropAck() bool {
	if s.ackDropRate <= 0 {
		return false
	}

	return s.rand.Float64() < s.ackDropRate
}

func validateBatch(lane string, batch *pb.Batch) error {
	if lane != "FAST" && lane != "STANDARD" {
		return fmt.Errorf("invalid lane: %s", lane)
	}

	if batch.SeqEnd < batch.SeqStart {
		return fmt.Errorf("seq_end must be >= seq_start")
	}

	return nil
}
