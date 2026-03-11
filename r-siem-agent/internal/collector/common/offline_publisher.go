package common

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

const defaultPublisherRetry = 2 * time.Second

type OfflinePublisherConfig struct {
	Name          string
	URL           string
	Stream        string
	Subject       string
	SpoolPath     string
	SpoolFsync    bool
	RetryInterval time.Duration
}

type OfflinePublisher struct {
	cfg    OfflinePublisherConfig
	logger *slog.Logger
	spool  *messageSpool

	mu sync.RWMutex
	nc *nats.Conn
	js nats.JetStreamContext
}

func NewOfflinePublisher(cfg OfflinePublisherConfig, logger *slog.Logger) (*OfflinePublisher, error) {
	cfg.Name = strings.TrimSpace(cfg.Name)
	cfg.URL = strings.TrimSpace(cfg.URL)
	cfg.Stream = strings.TrimSpace(cfg.Stream)
	cfg.Subject = strings.TrimSpace(cfg.Subject)
	if cfg.Name == "" {
		cfg.Name = "collector"
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = defaultPublisherRetry
	}
	if logger == nil {
		logger = slog.Default()
	}
	spoolPath, err := resolveSpoolPath(cfg.Name, strings.TrimSpace(cfg.SpoolPath))
	if err != nil {
		return nil, err
	}
	spool, err := openMessageSpool(spoolPath, cfg.SpoolFsync)
	if err != nil {
		return nil, err
	}
	return &OfflinePublisher{cfg: cfg, logger: logger, spool: spool}, nil
}

func resolveSpoolPath(name, configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	preferred := filepath.Join("/var/lib/rsiem", fmt.Sprintf("%s.spool.jsonl", name))
	if dir := filepath.Dir(preferred); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err == nil {
			return preferred, nil
		}
	}
	fallback := filepath.Join("/tmp", fmt.Sprintf("%s.spool.jsonl", name))
	if err := os.MkdirAll(filepath.Dir(fallback), 0o755); err != nil {
		return "", fmt.Errorf("create fallback spool directory: %w", err)
	}
	return fallback, nil
}

func (p *OfflinePublisher) Start(ctx context.Context) {
	go p.run(ctx)
}

func (p *OfflinePublisher) run(ctx context.Context) {
	ticker := time.NewTicker(p.cfg.RetryInterval)
	defer ticker.Stop()
	for {
		if err := p.ensureConnected(); err == nil {
			if err := p.flushPending(ctx); err != nil && !errors.Is(err, context.Canceled) {
				p.logger.Warn("collector_offline_flush_failed", slog.String("collector", p.cfg.Name), slog.String("error", err.Error()))
				p.disconnect()
			}
		}
		select {
		case <-ctx.Done():
			p.disconnect()
			return
		case <-ticker.C:
		}
	}
}

func (p *OfflinePublisher) Publish(ctx context.Context, eventID string, data []byte) (bool, error) {
	if strings.TrimSpace(eventID) == "" {
		return false, fmt.Errorf("event id required")
	}
	if p.spool.HasPending() {
		if _, err := p.spool.Append(eventID, data); err != nil {
			return false, err
		}
		p.logger.Warn("collector_event_spooled", slog.String("collector", p.cfg.Name), slog.String("event_idem_key", eventID), slog.String("reason", "pending_backlog"))
		return true, nil
	}
	if err := p.publishNow(ctx, eventID, data); err == nil {
		return false, nil
	}
	if _, err := p.spool.Append(eventID, data); err != nil {
		return false, err
	}
	p.logger.Warn("collector_event_spooled", slog.String("collector", p.cfg.Name), slog.String("event_idem_key", eventID), slog.String("reason", "publish_failed"))
	return true, nil
}

func (p *OfflinePublisher) publishNow(ctx context.Context, eventID string, data []byte) error {
	if err := p.ensureConnected(); err != nil {
		return err
	}
	p.mu.RLock()
	js := p.js
	p.mu.RUnlock()
	if js == nil {
		return fmt.Errorf("jetstream unavailable")
	}
	_, err := js.Publish(p.cfg.Subject, data, nats.MsgId(eventID), nats.Context(ctx))
	if err != nil {
		p.disconnect()
		return err
	}
	return nil
}

func (p *OfflinePublisher) flushPending(ctx context.Context) error {
	var committed uint64
	if err := p.spool.ReplayUncommitted(func(seq uint64, eventID string, data []byte) error {
		if err := p.publishNow(ctx, eventID, data); err != nil {
			return err
		}
		committed = seq
		return nil
	}); err != nil {
		if committed > 0 {
			_ = p.spool.MarkCommittedUpTo(committed)
		}
		return err
	}
	if committed > 0 {
		if err := p.spool.MarkCommittedUpTo(committed); err != nil {
			return err
		}
		p.logger.Info("collector_offline_flush_committed", slog.String("collector", p.cfg.Name), slog.Uint64("max_seq", committed))
	}
	return nil
}

func (p *OfflinePublisher) ensureConnected() error {
	p.mu.RLock()
	nc := p.nc
	js := p.js
	p.mu.RUnlock()
	if nc != nil && js != nil && nc.Status() == nats.CONNECTED {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nc != nil && p.js != nil && p.nc.Status() == nats.CONNECTED {
		return nil
	}
	nc, err := nats.Connect(p.cfg.URL, nats.Name(p.cfg.Name), nats.RetryOnFailedConnect(true), nats.MaxReconnects(-1), nats.ReconnectWait(p.cfg.RetryInterval))
	if err != nil {
		return err
	}
	js, err = nc.JetStream()
	if err != nil {
		nc.Close()
		return err
	}
	if err := ensureEventsStream(js, p.cfg.Stream, p.cfg.Subject); err != nil {
		nc.Close()
		return err
	}
	p.nc = nc
	p.js = js
	p.logger.Info("collector_nats_connected", slog.String("collector", p.cfg.Name), slog.String("url", p.cfg.URL), slog.String("spool_path", p.spool.path))
	return nil
}

func (p *OfflinePublisher) disconnect() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nc != nil {
		p.nc.Close()
	}
	p.nc = nil
	p.js = nil
}

func (p *OfflinePublisher) Close() error {
	p.disconnect()
	if p.spool != nil {
		return p.spool.Close()
	}
	return nil
}

func ensureEventsStream(js nats.JetStreamContext, stream, subject string) error {
	_, err := js.AddStream(&nats.StreamConfig{Name: stream, Subjects: []string{subject}})
	if err != nil && !errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return err
	}
	return nil
}
