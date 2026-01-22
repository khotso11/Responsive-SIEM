package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"r-siem-agent/internal/buffer"
	"r-siem-agent/internal/collector/tail"
	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
)

type tailConfigWrapper struct {
	Collectors struct {
		Tail struct {
			Enabled          bool   `yaml:"enabled"`
			Path             string `yaml:"path"`
			CheckpointPath   string `yaml:"checkpoint_path"`
			PollMs           int    `yaml:"poll_ms"`
			FingerprintBytes int    `yaml:"fingerprint_bytes"`
		} `yaml:"tail"`
	} `yaml:"collectors"`
}

func main() {
	configPath := flag.String("config", "configs/master.yaml", "Path to master config")
	flag.Parse()

	cfg, err := config.LoadMaster(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}
	logger, err := logging.NewLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}

	collectorCfg, err := loadTailConfig(*configPath)
	if err != nil {
		logger.Error("collector_tail_config_load_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if collectorCfg == nil || !collectorCfg.Enabled {
		logger.Info("collector_tail_disabled")
		return
	}

	publisher, err := buffer.NewJetStreamPublisher(context.Background(), cfg.JetStream, logger)
	if err != nil {
		logger.Error("collector_tail_publisher_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer publisher.Close()

	collector := tail.New(*collectorCfg, logger, publisher)
	ctx, cancel := signalContext()
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		logger.Error("collector_tail_start_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	<-ctx.Done()
	_ = collector.Stop()
}

func loadTailConfig(path string) (*tail.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var wrapper tailConfigWrapper
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse collectors config: %w", err)
	}
	raw := wrapper.Collectors.Tail
	cfg := &tail.Config{
		Enabled:          raw.Enabled,
		Path:             raw.Path,
		CheckpointPath:   raw.CheckpointPath,
		PollInterval:     time.Duration(raw.PollMs) * time.Millisecond,
		FingerprintBytes: raw.FingerprintBytes,
	}
	return cfg, nil
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
