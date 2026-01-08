package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"r-siem-agent/internal/buffer"
	"r-siem-agent/internal/config"
	"r-siem-agent/internal/ingest"
	"r-siem-agent/internal/logging"
	"r-siem-agent/internal/proto/pb"
)

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

	logger.Info("master_starting")
	logger.Info("config_summary", slog.Any("config", cfg.Summary()))

	tlsConfig, err := buildServerTLS(cfg)
	if err != nil {
		logger.Error("tls_setup_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	publisher, err := buffer.NewJetStreamPublisher(context.Background(), cfg.JetStream, logger)
	if err != nil {
		logger.Error("jetstream_setup_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer publisher.Close()

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	pb.RegisterIngestServer(grpcServer, ingest.NewServer(logger, publisher, time.Duration(cfg.AckDelayMs)*time.Millisecond, cfg.AckDropRate))

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		logger.Error("listen_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.Info("master_listening", slog.String("addr", cfg.ListenAddr))

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("grpc_serve_error", slog.String("error", err.Error()))
		}
	}()

	waitForSignal(logger)
	logger.Info("master_shutting_down")
	grpcServer.GracefulStop()
	publisher.Close()
}

func buildServerTLS(cfg *config.MasterConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Transport.TLS.Cert, cfg.Transport.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.Transport.TLS.CA)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("append ca cert failed")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, nil
}

func waitForSignal(logger *slog.Logger) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	logger.Info("signal_received")
}
