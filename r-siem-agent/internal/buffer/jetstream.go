package buffer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/nats-io/nats.go"

	"r-siem-agent/internal/config"
)

const idemBucket = "RSIEM_IDEMP"

// JetStreamPublisher wraps JetStream publish operations for master ingress.
type JetStreamPublisher struct {
	nc              *nats.Conn
	js              nats.JetStreamContext
	kv              nats.KeyValue
	stream          string
	subjectFast     string
	subjectStandard string
	logger          *slog.Logger
}

// NewJetStreamPublisher connects to NATS, ensures the target stream, and returns a publisher.
func NewJetStreamPublisher(ctx context.Context, cfg config.JetStreamConfig, logger *slog.Logger) (*JetStreamPublisher, error) {
	nc, err := nats.Connect(cfg.URL, nats.Name("r-siem-master"))
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream context: %w", err)
	}

	p := &JetStreamPublisher{
		nc:              nc,
		js:              js,
		stream:          cfg.Stream,
		subjectFast:     cfg.SubjectFast,
		subjectStandard: cfg.SubjectStandard,
		logger:          logger,
	}

	if err := p.ensureStream(ctx, cfg); err != nil {
		nc.Close()
		return nil, err
	}

	if err := p.ensureKV(); err != nil {
		nc.Close()
		return nil, err
	}

	return p, nil
}

func (p *JetStreamPublisher) ensureStream(ctx context.Context, cfg config.JetStreamConfig) error {
	if _, err := p.js.StreamInfo(cfg.Stream); err == nil {
		return nil
	}

	_, err := p.js.AddStream(&nats.StreamConfig{
		Name:     cfg.Stream,
		Subjects: []string{cfg.SubjectFast, cfg.SubjectStandard},
	}, nats.Context(ctx))
	if err != nil {
		return fmt.Errorf("ensure stream: %w", err)
	}

	p.logger.Info("jetstream_stream_ready",
		slog.String("stream", cfg.Stream),
		slog.String("subject_fast", cfg.SubjectFast),
		slog.String("subject_standard", cfg.SubjectStandard),
	)

	return nil
}

func (p *JetStreamPublisher) ensureKV() error {
	kv, err := p.js.KeyValue(idemBucket)
	if err != nil {
		if !errors.Is(err, nats.ErrBucketNotFound) {
			return fmt.Errorf("open kv bucket: %w", err)
		}

		kv, err = p.js.CreateKeyValue(&nats.KeyValueConfig{Bucket: idemBucket})
		if err != nil {
			return fmt.Errorf("create kv bucket: %w", err)
		}

		p.logger.Info("jetstream_kv_ready", slog.String("bucket", idemBucket))
	}

	p.kv = kv
	return nil
}

// PublishBatch publishes a marshaled Batch to the subject for the lane and returns the JetStream sequence.
func (p *JetStreamPublisher) PublishBatch(ctx context.Context, lane string, batchBytes []byte) (uint64, error) {
	subject, err := p.subjectForLane(lane)
	if err != nil {
		return 0, err
	}

	ack, err := p.js.PublishMsg(&nats.Msg{
		Subject: subject,
		Data:    batchBytes,
	}, nats.Context(ctx))
	if err != nil {
		return 0, fmt.Errorf("publish: %w", err)
	}

	return ack.Sequence, nil
}

// Close closes the NATS connection.
func (p *JetStreamPublisher) Close() {
	p.nc.Close()
}

func (p *JetStreamPublisher) subjectForLane(lane string) (string, error) {
	switch lane {
	case "FAST":
		return p.subjectFast, nil
	case "STANDARD":
		return p.subjectStandard, nil
	default:
		return "", fmt.Errorf("invalid lane: %s", lane)
	}
}

// IdemGet returns the stored JetStream sequence for a batch idempotency key.
func (p *JetStreamPublisher) IdemGet(key string) (string, bool, error) {
	if p.kv == nil {
		return "", false, fmt.Errorf("kv bucket not initialized")
	}

	entry, err := p.kv.Get(key)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("kv get: %w", err)
	}

	return string(entry.Value()), true, nil
}

// IdemPut stores the JetStream sequence for a batch idempotency key.
func (p *JetStreamPublisher) IdemPut(key, val string) error {
	if p.kv == nil {
		return fmt.Errorf("kv bucket not initialized")
	}

	if _, err := p.kv.Put(key, []byte(val)); err != nil {
		return fmt.Errorf("kv put: %w", err)
	}

	return nil
}
