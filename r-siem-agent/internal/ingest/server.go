package ingest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"r-siem-agent/internal/buffer"
	"r-siem-agent/internal/proto/pb"
)

// Server implements the Ingest gRPC service.
type Server struct {
	pb.UnimplementedIngestServer
	logger      *slog.Logger
	publisher   *buffer.JetStreamPublisher
	ackDelay    time.Duration
	ackDropRate float64
	rand        *rand.Rand
}

// NewServer constructs a streaming ingest server.
func NewServer(logger *slog.Logger, publisher *buffer.JetStreamPublisher, ackDelay time.Duration, ackDropRate float64) *Server {
	return &Server{
		logger:      logger,
		publisher:   publisher,
		ackDelay:    ackDelay,
		ackDropRate: ackDropRate,
		rand:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Stream handles bidirectional batch ingest.
func (s *Server) Stream(stream pb.Ingest_StreamServer) error {
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
