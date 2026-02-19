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
	"time"

	"github.com/nats-io/nats.go"

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

	nc, err := nats.Connect(cfg.JetStream.URL, nats.Name("r-siem-collector-tail"))
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
	}, logger, js)
	ctx, cancel := signalContext()
	defer cancel()

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
