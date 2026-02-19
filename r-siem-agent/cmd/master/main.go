package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"

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

	tlsConfig, err := buildServerTLS(cfg, logger)
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

	peerCerts := newPeerCertStore()
	grpcServer := grpc.NewServer()
	coreIngest := ingest.NewServer(
		logger,
		publisher,
		time.Duration(cfg.AckDelayMs)*time.Millisecond,
		cfg.AckDropRate,
		peerCerts.Get,
		cfg.Transport.TLS.ClientIdentitySource,
	)
	pb.RegisterIngestServer(grpcServer, coreIngest)
	pb.RegisterAgentIngestServer(grpcServer, ingest.NewAgentIngestAdapter(coreIngest))

	baseLis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		logger.Error("listen_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	lis := &mtlsLoggingListener{
		Listener:  baseLis,
		tlsConfig: tlsConfig,
		logger:    logger,
		peerCerts: peerCerts,
		idPolicy:  strings.ToLower(strings.TrimSpace(cfg.Transport.TLS.ClientIdentitySource)),
	}

	logger.LogAttrs(context.Background(), slog.LevelInfo, "grpc_mtls_server_started",
		slog.String("listen_addr", cfg.ListenAddr),
		slog.String("ca_path", cfg.Transport.TLS.CA),
		slog.String("cert_path", cfg.Transport.TLS.Cert),
		slog.Bool("require_client_cert", true),
	)

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

func buildServerTLS(cfg *config.MasterConfig, logger *slog.Logger) (*tls.Config, error) {
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

	allowlist, err := loadClientFingerprintAllowlist(
		cfg.Transport.TLS.ClientFingerprintAllowlist,
		cfg.Transport.TLS.ClientFingerprintAllowlistPath,
		os.Getenv("RSIEM_MTLS_CLIENT_FINGERPRINT_ALLOWLIST"),
	)
	if err != nil {
		return nil, fmt.Errorf("load client fingerprint allowlist: %w", err)
	}
	expectedIdentity := strings.TrimSpace(cfg.Transport.TLS.ClientIdentity)
	if envIdentity := strings.TrimSpace(os.Getenv("RSIEM_MTLS_CLIENT_IDENTITY")); envIdentity != "" {
		expectedIdentity = envIdentity
	}
	identitySource := strings.ToLower(strings.TrimSpace(cfg.Transport.TLS.ClientIdentitySource))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no client certificate")
			}
			leaf := cs.PeerCertificates[0]
			if err := verifyClientIdentity(leaf, expectedIdentity); err != nil {
				return err
			}
			if len(allowlist) > 0 {
				fp := certFingerprintSHA256(leaf)
				if _, ok := allowlist[fp]; !ok {
					logger.LogAttrs(context.Background(), slog.LevelWarn, "grpc_mtls_client_rejected",
						slog.String("reason", "fingerprint_not_allowlisted"),
						slog.String("peer_fingerprint_sha256", fp),
					)
					return fmt.Errorf("fingerprint_not_allowlisted")
				}
			}
			return nil
		},
	}

	logger.LogAttrs(context.Background(), slog.LevelInfo, "grpc_mtls_server_identity_policy",
		slog.String("expected_client_identity", expectedIdentity),
		slog.String("client_identity_source", identitySource),
		slog.Int("client_fingerprint_allowlist_len", len(allowlist)),
	)

	return tlsConfig, nil
}

type mtlsLoggingListener struct {
	net.Listener
	tlsConfig *tls.Config
	logger    *slog.Logger
	peerCerts *peerCertStore
	idPolicy  string
}

func (l *mtlsLoggingListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		tlsConn := tls.Server(conn, l.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			l.logger.LogAttrs(context.Background(), slog.LevelWarn, "grpc_mtls_handshake_failed",
				slog.String("reason", classifyServerHandshakeError(err)),
				slog.String("error", err.Error()),
			)
			_ = tlsConn.Close()
			continue
		}

		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			l.logger.LogAttrs(context.Background(), slog.LevelWarn, "grpc_mtls_handshake_failed",
				slog.String("reason", "no client certificate"),
				slog.String("error", "peer certificates missing"),
			)
			_ = tlsConn.Close()
			continue
		}

		leaf := state.PeerCertificates[0]
		agentID, agentIDSource := extractAgentInstanceID(leaf)
		if l.idPolicy == "cert_only" && agentID == "unknown" {
			l.logger.LogAttrs(context.Background(), slog.LevelWarn, "grpc_mtls_client_rejected",
				slog.String("reason", "client_identity_missing_in_cert"),
			)
			_ = tlsConn.Close()
			continue
		}
		remoteAddr := tlsConn.RemoteAddr().String()
		if l.peerCerts != nil {
			l.peerCerts.Set(remoteAddr, leaf)
		}
		l.logger.LogAttrs(context.Background(), slog.LevelInfo, "grpc_mtls_client_authenticated",
			slog.String("peer_subject", leaf.Subject.String()),
			slog.String("peer_san", certSANSummary(leaf)),
			slog.String("peer_fingerprint_sha256", certFingerprintSHA256(leaf)),
			slog.String("agent_instance_id", agentID),
			slog.String("agent_id_source", agentIDSource),
		)
		return &trackedTLSConn{
			Conn: tlsConn,
			onClose: func() {
				if l.peerCerts != nil {
					l.peerCerts.Delete(remoteAddr)
				}
			},
		}, nil
	}
}

type trackedTLSConn struct {
	net.Conn
	onClose func()
}

func (c *trackedTLSConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return c.Conn.Close()
}

type peerCertStore struct {
	mu sync.RWMutex
	m  map[string]*x509.Certificate
}

func newPeerCertStore() *peerCertStore {
	return &peerCertStore{m: make(map[string]*x509.Certificate)}
}

func (s *peerCertStore) Set(addr string, cert *x509.Certificate) {
	if s == nil || cert == nil {
		return
	}
	s.mu.Lock()
	s.m[addr] = cert
	s.mu.Unlock()
}

func (s *peerCertStore) Get(addr string) (*x509.Certificate, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	cert, ok := s.m[addr]
	s.mu.RUnlock()
	return cert, ok
}

func (s *peerCertStore) Delete(addr string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.m, addr)
	s.mu.Unlock()
}

func certFingerprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

func certSANSummary(cert *x509.Certificate) string {
	parts := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	for _, dns := range cert.DNSNames {
		if strings.TrimSpace(dns) != "" {
			parts = append(parts, "DNS:"+dns)
		}
	}
	for _, ip := range cert.IPAddresses {
		parts = append(parts, "IP:"+ip.String())
	}
	if len(parts) == 0 && strings.TrimSpace(cert.Subject.CommonName) != "" {
		parts = append(parts, "CN:"+cert.Subject.CommonName)
	}
	return strings.Join(parts, ",")
}

func extractAgentInstanceID(cert *x509.Certificate) (string, string) {
	if cert == nil {
		return "unknown", "unknown"
	}
	for _, dns := range cert.DNSNames {
		dns = strings.TrimSpace(dns)
		if dns != "" {
			return dns, "cert_san"
		}
	}
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		raw := strings.TrimSpace(uri.String())
		if raw != "" {
			return raw, "cert_san"
		}
	}
	cn := strings.TrimSpace(cert.Subject.CommonName)
	if cn != "" {
		return cn, "cert_cn"
	}
	return "unknown", "unknown"
}

func verifyClientIdentity(cert *x509.Certificate, expected string) error {
	ids := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+1)
	for _, dns := range cert.DNSNames {
		if strings.TrimSpace(dns) != "" {
			ids = append(ids, strings.TrimSpace(dns))
		}
	}
	for _, ip := range cert.IPAddresses {
		ids = append(ids, ip.String())
	}
	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		ids = append(ids, cn)
	}
	if len(ids) == 0 {
		return fmt.Errorf("identity missing")
	}
	if strings.TrimSpace(expected) == "" {
		return nil
	}
	for _, id := range ids {
		if strings.EqualFold(id, expected) {
			return nil
		}
	}
	return fmt.Errorf("identity mismatch")
}

func normalizeFingerprint(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, ":", "")
	if s == "" {
		return "", nil
	}
	if len(s) != 64 {
		return "", fmt.Errorf("must be 64 hex chars")
	}
	for _, ch := range s {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return "", fmt.Errorf("must be hexadecimal")
		}
	}
	return s, nil
}

func loadClientFingerprintAllowlist(inline []string, path string, envRaw string) (map[string]struct{}, error) {
	allow := make(map[string]struct{})
	add := func(raw string) error {
		normalized, err := normalizeFingerprint(raw)
		if err != nil {
			return err
		}
		if normalized != "" {
			allow[normalized] = struct{}{}
		}
		return nil
	}

	for _, raw := range inline {
		if err := add(raw); err != nil {
			return nil, err
		}
	}

	if strings.TrimSpace(path) != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if err := add(line); err != nil {
				return nil, err
			}
		}
	}

	if strings.TrimSpace(envRaw) != "" {
		for _, raw := range strings.Split(envRaw, ",") {
			if err := add(raw); err != nil {
				return nil, err
			}
		}
	}
	return allow, nil
}

func classifyServerHandshakeError(err error) string {
	if err == nil {
		return "unknown"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no client certificate"), strings.Contains(msg, "client didn't provide a certificate"), strings.Contains(msg, "certificate required"):
		return "no_client_certificate"
	case strings.Contains(msg, "unknown authority"), strings.Contains(msg, "unknown ca"):
		return "unknown_ca"
	case strings.Contains(msg, "identity mismatch"):
		return "identity_mismatch"
	case strings.Contains(msg, "fingerprint_not_allowlisted"):
		return "fingerprint_not_allowlisted"
	case strings.Contains(msg, "expired"), strings.Contains(msg, "not yet valid"):
		return "certificate_validity"
	default:
		return "handshake_error"
	}
}

func waitForSignal(logger *slog.Logger) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	logger.Info("signal_received")
}
