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
	"r-siem-agent/internal/collector/syslogudp"
	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
)

type syslogUDPConfigWrapper struct {
	Collectors struct {
		SyslogUDP struct {
			Enabled          bool   `yaml:"enabled"`
			ListenAddr       string `yaml:"listen_addr"`
			MaxDatagramBytes int    `yaml:"max_datagram_bytes"`
			QueueSize        int    `yaml:"queue_size"`
			ReadTimeoutMs    int    `yaml:"read_timeout_ms"`
		} `yaml:"syslog_udp"`
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

	collectorCfg, err := loadSyslogUDPConfig(*configPath)
	if err != nil {
		logger.Error("collector_syslog_config_load_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if collectorCfg == nil || !collectorCfg.Enabled {
		logger.Info("collector_syslog_disabled")
		return
	}

	publisher, err := buffer.NewJetStreamPublisher(context.Background(), cfg.JetStream, logger)
	if err != nil {
		logger.Error("collector_syslog_publisher_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer publisher.Close()

	collector := syslogudp.New(*collectorCfg, logger, publisher)
	ctx, cancel := signalContext()
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		logger.Error("collector_syslog_start_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	<-ctx.Done()
	_ = collector.Stop()
}

func loadSyslogUDPConfig(path string) (*syslogudp.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var wrapper syslogUDPConfigWrapper
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse collectors config: %w", err)
	}
	raw := wrapper.Collectors.SyslogUDP
	cfg := &syslogudp.Config{
		Enabled:          raw.Enabled,
		ListenAddr:       raw.ListenAddr,
		MaxDatagramBytes: raw.MaxDatagramBytes,
		QueueSize:        raw.QueueSize,
		ReadTimeout:      time.Duration(raw.ReadTimeoutMs) * time.Millisecond,
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
