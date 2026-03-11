package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"r-siem-agent/internal/collector/common"
	"r-siem-agent/internal/collector/tail"
	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
)

func main() {
	configPath := flag.String("config", "configs/collector.yaml", "Path to collector config")
	flag.Parse()

	cfg, err := config.LoadCollector(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}
	logger, err := logging.NewLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}

	publisher, err := common.NewOfflinePublisher(common.OfflinePublisherConfig{
		Name:          "r-siem-collector-tail",
		URL:           cfg.JetStream.URL,
		Stream:        cfg.JetStream.Stream,
		Subject:       cfg.JetStream.Subject,
		SpoolPath:     cfg.JetStream.OfflineSpoolPath,
		RetryInterval: time.Duration(cfg.JetStream.RetryMs) * time.Millisecond,
		SpoolFsync:    cfg.JetStream.OfflineSpoolFsync != nil && *cfg.JetStream.OfflineSpoolFsync,
	}, logger)
	if err != nil {
		logger.Error("offline_publisher_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer publisher.Close()

	tailPath := cfg.Tail.Path
	pathSource := "config"
	if strings.TrimSpace(cfg.Tail.Path) == "tmp/demo.log" {
		pathSource = "default"
	}
	if overridePath := strings.TrimSpace(os.Getenv("RSIEM_COLLECTOR_TAIL_PATH")); overridePath != "" {
		tailPath = overridePath
		pathSource = "env_override"
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_tail_input_path_resolved",
		slog.String("path", tailPath),
		slog.String("source", pathSource),
		slog.Bool("override_enabled", pathSource == "env_override"),
	)

	collector := tail.New(tail.Config{
		Path:           tailPath,
		CheckpointPath: cfg.Tail.CheckpointPath,
		PollInterval:   time.Duration(cfg.Tail.PollMs) * time.Millisecond,
		Stream:         cfg.JetStream.Stream,
		Subject:        cfg.JetStream.Subject,
	}, logger, publisher)
	ctx, cancel := signalContext()
	defer cancel()
	publisher.Start(ctx)

	if err := collector.Start(ctx); err != nil {
		logger.Error("collector_tail_start_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	<-ctx.Done()
	_ = collector.Stop()
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
