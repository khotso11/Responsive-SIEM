package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nats-io/nats.go"
	"gopkg.in/yaml.v3"

	"r-siem-agent/internal/collector/common"
	"r-siem-agent/internal/collector/syslog"
	"r-siem-agent/internal/logging"
)

type configFile struct {
	LogLevel  string `yaml:"log_level"`
	JetStream struct {
		URL     string `yaml:"url"`
		Stream  string `yaml:"stream"`
		Subject string `yaml:"subject"`
	} `yaml:"jetstream"`
	Collector struct {
		BindAddr       string `yaml:"bind_addr"`
		Port           int    `yaml:"port"`
		MaxPacketBytes int    `yaml:"max_packet_bytes"`
		QueueSize      int    `yaml:"queue_size"`
		RateLimitPPS   int    `yaml:"rate_limit_pps"`
		RawSubject     string `yaml:"raw_subject"`
		NodeID         string `yaml:"node_id"`
		SourceType     string `yaml:"source_type"`
		MaxMessageLen  int    `yaml:"max_message_len"`
	} `yaml:"collector"`
}

func main() {
	configPath := flag.String("config", "configs/collector-syslog.yaml", "Path to collector config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}
	logger, err := logging.NewLogger(strings.ToUpper(strings.TrimSpace(cfg.LogLevel)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	logger.LogAttrs(context.Background(), common.ParseLogLevel(cfg.LogLevel), "collector_config_loaded",
		slog.String("config_path", *configPath),
		slog.String("bind_addr", cfg.Collector.BindAddr),
		slog.Int("port", cfg.Collector.Port),
	)

	nc, err := nats.Connect(cfg.JetStream.URL, nats.Name("r-siem-collector-syslog"))
	if err != nil {
		logger.Error("nats_connect_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		logger.Error("jetstream_context_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := ensureEventsStream(js, cfg.JetStream.Stream, cfg.JetStream.Subject); err != nil {
		logger.Error("ensure_events_stream_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	collector := syslog.New(syslog.Config{
		BindAddr:       cfg.Collector.BindAddr,
		Port:           cfg.Collector.Port,
		MaxPacketBytes: cfg.Collector.MaxPacketBytes,
		QueueSize:      cfg.Collector.QueueSize,
		RateLimitPPS:   cfg.Collector.RateLimitPPS,
		RawSubject:     cfg.Collector.RawSubject,
		NodeID:         cfg.Collector.NodeID,
		SourceType:     cfg.Collector.SourceType,
		MaxMessageLen:  cfg.Collector.MaxMessageLen,
	}, logger, js)

	ctx, cancel := signalContext()
	defer cancel()
	if err := collector.Start(ctx); err != nil {
		logger.Error("collector_start_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	<-ctx.Done()
	collector.Stop()
}

func loadConfig(path string) (*configFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg configFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if strings.TrimSpace(cfg.LogLevel) == "" {
		cfg.LogLevel = "INFO"
	}
	if strings.TrimSpace(cfg.JetStream.URL) == "" {
		cfg.JetStream.URL = "nats://127.0.0.1:4222"
	}
	if strings.TrimSpace(cfg.JetStream.Stream) == "" {
		cfg.JetStream.Stream = "RSIEM_EVENTS"
	}
	if strings.TrimSpace(cfg.JetStream.Subject) == "" {
		cfg.JetStream.Subject = "rsiem.events.raw"
	}
	if strings.TrimSpace(cfg.Collector.RawSubject) == "" {
		cfg.Collector.RawSubject = cfg.JetStream.Subject
	}
	if strings.TrimSpace(cfg.Collector.SourceType) == "" {
		cfg.Collector.SourceType = "syslog"
	}
	if strings.TrimSpace(cfg.Collector.BindAddr) == "" {
		cfg.Collector.BindAddr = "127.0.0.1"
	}
	if cfg.Collector.Port <= 0 {
		cfg.Collector.Port = 5140
	}
	return &cfg, nil
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

func ensureEventsStream(js nats.JetStreamContext, stream, subject string) error {
	_, err := js.AddStream(&nats.StreamConfig{
		Name:     stream,
		Subjects: []string{subject},
	})
	if err != nil && !errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return err
	}
	return nil
}
