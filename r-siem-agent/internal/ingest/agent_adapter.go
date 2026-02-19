package ingest

import (
	"io"
	"log/slog"
	"strings"
	"time"

	pb "r-siem-agent/internal/proto/pb"
)

// AgentIngestAdapter serves agent.v1.AgentIngest for FR-02 mTLS transport compatibility.
// It intentionally keeps behavior minimal: validate lane, optionally delay/drop, and ack.
type AgentIngestAdapter struct {
	pb.UnimplementedAgentIngestServer
	core *Server
}

// NewAgentIngestAdapter returns an AgentIngest gRPC adapter backed by the core ingest server settings.
func NewAgentIngestAdapter(core *Server) *AgentIngestAdapter {
	return &AgentIngestAdapter{core: core}
}

// Stream handles bidirectional streaming batches from agent.v1.AgentIngest.
func (a *AgentIngestAdapter) Stream(stream pb.AgentIngest_StreamServer) error {
	if a.core == nil {
		return io.EOF
	}
	if err := a.core.logAuthenticatedPeer(stream.Context()); err != nil {
		return err
	}

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		lane := strings.ToUpper(msg.GetLane())
		if lane != "FAST" && lane != "STANDARD" {
			a.core.logger.Warn("batch_invalid", "lane", lane, "reason", "invalid lane")
			return nil
		}

		a.core.logger.Info("master_recv_batch",
			slog.String("lane", lane),
			slog.Int("batch_size", int(msg.GetBatchSize())),
			slog.Uint64("first_seq", msg.GetFirstSeq()),
			slog.Uint64("last_seq", msg.GetLastSeq()),
			slog.Uint64("max_offset", msg.GetMaxOffset()),
		)

		if a.core.ackDelay > 0 {
			timer := time.NewTimer(a.core.ackDelay)
			select {
			case <-stream.Context().Done():
				timer.Stop()
				return stream.Context().Err()
			case <-timer.C:
			}
		}

		if a.core.shouldDropAck() {
			a.core.logger.Info("master_ack_dropped",
				slog.String("lane", lane),
				slog.Int("batch_size", int(msg.GetBatchSize())),
				slog.Uint64("max_offset", msg.GetMaxOffset()),
			)
			continue
		}

		ack := &pb.AckMsg{
			Lane:      lane,
			BatchSize: msg.GetBatchSize(),
			MaxOffset: msg.GetMaxOffset(),
		}
		if err := stream.Send(ack); err != nil {
			return err
		}
		a.core.logger.Info("master_send_ack",
			slog.String("lane", ack.GetLane()),
			slog.Int("batch_size", int(ack.GetBatchSize())),
			slog.Uint64("max_offset", ack.GetMaxOffset()),
		)
	}
}
