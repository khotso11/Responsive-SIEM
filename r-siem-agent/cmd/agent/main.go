package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
	"r-siem-agent/internal/supervisor"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/agent.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := logging.NewLogger(cfg.LogLevel())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to configure logger: %v\n", err)
		os.Exit(1)
	}

	logger.Info("r-siem-agent starting")
	logger.Info(
		"config summary",
		"log_level", cfg.LogLevel(),
		"heartbeat_interval_seconds", cfg.HeartbeatIntervalSeconds(),
		"mock_interval_seconds", cfg.MockIntervalSeconds(),
		"agent_name", cfg.AgentName(),
		"agent_instance_id", cfg.AgentInstanceID(),
		"fast_lane_buffer", cfg.LaneFastBuffer(),
		"standard_lane_buffer", cfg.LaneStandardBuffer(),
		"wal_path", cfg.WALPath(),
		"wal_fsync", cfg.WALFsync(),
		"fast_batch_max_size", cfg.BatchFastMaxSize(),
		"fast_batch_max_latency_ms", cfg.BatchFastMaxLatencyMillis(),
		"standard_batch_max_size", cfg.BatchStandardMaxSize(),
		"standard_batch_max_latency_ms", cfg.BatchStandardMaxLatencyMillis(),
		"transport_ack_delay_ms", cfg.TransportAckDelayMillis(),
		"transport_ack_drop_rate", cfg.TransportAckDropRate(),
		"transport_mode", cfg.TransportMode(),
		"transport_addr", cfg.TransportAddr(),
		"transport_tls_ca", cfg.TransportTLSCA(),
		"transport_tls_cert", cfg.TransportTLSCert(),
		"transport_tls_server_name", cfg.TransportTLSServerName(),
	)

	baseCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(baseCtx)
	defer cancel()

	listenerErrs := make(chan error, 1)
	go func() {
		listenerErrs <- runCommandListener(ctx, logger, commandNatsURL())
	}()
	go func() {
		if err := <-listenerErrs; err != nil {
			logger.Error("agent_command_listener_failed", "error", err)
			cancel()
		}
	}()

	sup := supervisor.New(cfg, logger)
	if err := sup.Run(ctx); err != nil {
		logger.Error("agent exited with error", "error", err)
		os.Exit(1)
	}

	logger.Info("agent shutdown complete")
}
