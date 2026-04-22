package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"r-siem-agent/internal/collector/common"
	"r-siem-agent/internal/logging"
)

const (
	defaultJetStreamURL     = "nats://127.0.0.1:4222"
	defaultJetStreamStream  = "RSIEM_EVENTS"
	defaultJetStreamSubject = "rsiem.events.raw"
	defaultRetryInterval    = 2 * time.Second
	defaultReadTimeout      = 2500 * time.Millisecond
	defaultWriteTimeout     = 2500 * time.Millisecond
	defaultMaxPayloadBytes  = 2048
	defaultMaxConcurrent    = 64
	protocolHTTP            = "http"
	protocolSSHBanner       = "ssh_banner"
	protocolTelnetBanner    = "telnet_banner"
	protocolTCPBanner       = "tcp_banner"
	defaultHTTPListen       = "127.0.0.1:18081"
	defaultSSHListen        = "127.0.0.1:2222"
	defaultTelnetListen     = "127.0.0.1:2323"
	defaultHTTPTitle        = "Restricted Administration Portal"
	defaultHTTPRealm        = "Operations Console"
	defaultSSHBanner        = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
	defaultTelnetBanner     = "R-SIEM operations gateway"
	defaultGenericTCPBanner = "Restricted service\r\n"
	deceptionRuleMarker     = "attack=deception_tripwire"
	deceptionEventType      = "auth_failed"
	deceptionSourceType     = "deception"
)

type configFile struct {
	LogLevel              string          `yaml:"log_level"`
	NodeID                string          `yaml:"node_id"`
	Host                  string          `yaml:"host"`
	ResponseTargetAgentID string          `yaml:"response_target_agent_id"`
	JetStream             jetStreamConfig `yaml:"jetstream"`
	Limits                limitConfig     `yaml:"limits"`
	Services              []serviceConfig `yaml:"services"`
}

type jetStreamConfig struct {
	URL             string `yaml:"url"`
	Stream          string `yaml:"stream"`
	Subject         string `yaml:"subject"`
	SpoolPath       string `yaml:"spool_path"`
	SpoolFsync      bool   `yaml:"spool_fsync"`
	RetryIntervalMs int    `yaml:"retry_interval_ms"`
}

type limitConfig struct {
	ReadTimeoutMs   int `yaml:"read_timeout_ms"`
	WriteTimeoutMs  int `yaml:"write_timeout_ms"`
	MaxPayloadBytes int `yaml:"max_payload_bytes"`
	MaxConcurrent   int `yaml:"max_concurrent"`
}

type serviceConfig struct {
	ID        string `yaml:"id"`
	Enabled   bool   `yaml:"enabled"`
	Protocol  string `yaml:"protocol"`
	Listen    string `yaml:"listen"`
	Banner    string `yaml:"banner"`
	HTTPTitle string `yaml:"http_title"`
	Realm     string `yaml:"realm"`
}

type honeypot struct {
	logger          *slog.Logger
	publisher       *common.OfflinePublisher
	nodeID          string
	host            string
	targetAgentID   string
	readTimeout     time.Duration
	writeTimeout    time.Duration
	maxPayloadBytes int
	serviceByID     map[string]serviceConfig
	sessionSeq      atomic.Uint64
}

type interaction struct {
	ServiceID     string
	Protocol      string
	SrcIP         string
	SrcPort       int
	DstIP         string
	DstPort       int
	AttemptedUser string
	Method        string
	Path          string
	Payload       string
	SessionKey    string
}

func main() {
	configPath := flag.String("config", "configs/honeypot.yaml", "Path to honeypot config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load honeypot config: %v\n", err)
		os.Exit(1)
	}

	logger, err := logging.NewLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}

	publisher, err := common.NewOfflinePublisher(common.OfflinePublisherConfig{
		Name:          "honeypot",
		URL:           cfg.JetStream.URL,
		Stream:        cfg.JetStream.Stream,
		Subject:       cfg.JetStream.Subject,
		SpoolPath:     cfg.JetStream.SpoolPath,
		SpoolFsync:    cfg.JetStream.SpoolFsync,
		RetryInterval: retryInterval(cfg.JetStream.RetryIntervalMs),
	}, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init publisher: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	publisher.Start(ctx)

	hp := &honeypot{
		logger:          logger,
		publisher:       publisher,
		nodeID:          firstNonEmpty(strings.TrimSpace(cfg.NodeID), hostName()),
		host:            firstNonEmpty(strings.TrimSpace(cfg.Host), hostName()),
		targetAgentID:   firstNonEmpty(strings.TrimSpace(cfg.ResponseTargetAgentID), strings.TrimSpace(cfg.NodeID), hostName()),
		readTimeout:     durationOrDefault(cfg.Limits.ReadTimeoutMs, defaultReadTimeout),
		writeTimeout:    durationOrDefault(cfg.Limits.WriteTimeoutMs, defaultWriteTimeout),
		maxPayloadBytes: intOrDefault(cfg.Limits.MaxPayloadBytes, defaultMaxPayloadBytes),
		serviceByID:     make(map[string]serviceConfig),
	}
	if hp.maxPayloadBytes <= 0 {
		hp.maxPayloadBytes = defaultMaxPayloadBytes
	}

	for _, service := range cfg.Services {
		if !service.Enabled {
			continue
		}
		hp.serviceByID[service.ID] = service
	}

	if len(hp.serviceByID) == 0 {
		logger.Error("honeypot_no_services_enabled")
		os.Exit(1)
	}

	logger.Info("honeypot_starting",
		slog.String("node_id", hp.nodeID),
		slog.String("host", hp.host),
		slog.String("target_agent_id", hp.targetAgentID),
		slog.Int("services", len(hp.serviceByID)),
		slog.String("subject", cfg.JetStream.Subject),
		slog.String("stream", cfg.JetStream.Stream),
	)

	var wg sync.WaitGroup
	sem := make(chan struct{}, intOrDefault(cfg.Limits.MaxConcurrent, defaultMaxConcurrent))
	errCh := make(chan error, len(hp.serviceByID))

	for _, service := range cfg.Services {
		if !service.Enabled {
			continue
		}
		service := normalizeService(service)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := hp.serve(ctx, service, sem); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s: %w", service.ID, err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		wg.Wait()
	case err := <-errCh:
		logger.Error("honeypot_service_failed", slog.String("error", err.Error()))
		cancel()
		wg.Wait()
		os.Exit(1)
	}
}

func loadConfig(path string) (configFile, error) {
	cfg := configFile{}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	cfg.LogLevel = firstNonEmpty(strings.TrimSpace(cfg.LogLevel), "info")
	cfg.JetStream.URL = firstNonEmpty(strings.TrimSpace(cfg.JetStream.URL), envOr("RSIEM_HONEYPOT_NATS_URL", defaultJetStreamURL))
	cfg.JetStream.Stream = firstNonEmpty(strings.TrimSpace(cfg.JetStream.Stream), defaultJetStreamStream)
	cfg.JetStream.Subject = firstNonEmpty(strings.TrimSpace(cfg.JetStream.Subject), defaultJetStreamSubject)
	cfg.NodeID = firstNonEmpty(strings.TrimSpace(os.Getenv("RSIEM_HONEYPOT_NODE_ID")), strings.TrimSpace(cfg.NodeID))
	cfg.Host = firstNonEmpty(strings.TrimSpace(os.Getenv("RSIEM_HONEYPOT_HOST")), strings.TrimSpace(cfg.Host))
	cfg.ResponseTargetAgentID = firstNonEmpty(strings.TrimSpace(os.Getenv("RSIEM_HONEYPOT_TARGET_AGENT_ID")), strings.TrimSpace(cfg.ResponseTargetAgentID))
	if len(cfg.Services) == 0 {
		cfg.Services = defaultServices()
	}
	for idx := range cfg.Services {
		cfg.Services[idx] = normalizeService(cfg.Services[idx])
	}
	return cfg, nil
}

func defaultServices() []serviceConfig {
	return []serviceConfig{
		{ID: "decoy-admin-http", Enabled: true, Protocol: protocolHTTP, Listen: defaultHTTPListen, HTTPTitle: defaultHTTPTitle, Realm: defaultHTTPRealm},
		{ID: "decoy-ssh", Enabled: true, Protocol: protocolSSHBanner, Listen: defaultSSHListen, Banner: defaultSSHBanner},
		{ID: "decoy-telnet", Enabled: true, Protocol: protocolTelnetBanner, Listen: defaultTelnetListen, Banner: defaultTelnetBanner},
	}
}

func normalizeService(service serviceConfig) serviceConfig {
	service.ID = strings.TrimSpace(service.ID)
	service.Protocol = strings.ToLower(strings.TrimSpace(service.Protocol))
	service.Listen = strings.TrimSpace(service.Listen)
	service.Banner = strings.TrimSpace(service.Banner)
	service.HTTPTitle = strings.TrimSpace(service.HTTPTitle)
	service.Realm = strings.TrimSpace(service.Realm)
	if service.ID == "" {
		service.ID = fmt.Sprintf("service-%s", service.Protocol)
	}
	if service.Listen == "" {
		switch service.Protocol {
		case protocolHTTP:
			service.Listen = defaultHTTPListen
		case protocolSSHBanner:
			service.Listen = defaultSSHListen
		case protocolTelnetBanner:
			service.Listen = defaultTelnetListen
		default:
			service.Listen = defaultHTTPListen
		}
	}
	if service.Protocol == "" {
		service.Protocol = protocolHTTP
	}
	if service.Protocol == protocolHTTP {
		if service.HTTPTitle == "" {
			service.HTTPTitle = defaultHTTPTitle
		}
		if service.Realm == "" {
			service.Realm = defaultHTTPRealm
		}
	}
	if service.Banner == "" {
		switch service.Protocol {
		case protocolSSHBanner:
			service.Banner = defaultSSHBanner
		case protocolTelnetBanner:
			service.Banner = defaultTelnetBanner
		case protocolTCPBanner:
			service.Banner = defaultGenericTCPBanner
		}
	}
	return service
}

func (hp *honeypot) serve(ctx context.Context, service serviceConfig, sem chan struct{}) error {
	switch service.Protocol {
	case protocolHTTP:
		return hp.serveHTTP(ctx, service)
	case protocolSSHBanner, protocolTelnetBanner, protocolTCPBanner:
		return hp.serveTCP(ctx, service, sem)
	default:
		return fmt.Errorf("unsupported protocol %q", service.Protocol)
	}
}

func (hp *honeypot) serveHTTP(ctx context.Context, service serviceConfig) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		interaction := hp.httpInteraction(service, r)
		if err := hp.publishInteraction(r.Context(), interaction); err != nil {
			hp.logger.Error("honeypot_publish_failed", slog.String("service_id", service.ID), slog.String("protocol", service.Protocol), slog.String("error", err.Error()))
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if strings.EqualFold(interaction.Path, "/admin") {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", service.Realm))
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_, _ = io.WriteString(w, renderHTTPResponse(service.HTTPTitle))
	})

	server := &http.Server{
		Addr:              service.Listen,
		Handler:           mux,
		ReadHeaderTimeout: hp.readTimeout,
		ReadTimeout:       hp.readTimeout,
		WriteTimeout:      hp.writeTimeout,
		IdleTimeout:       hp.writeTimeout,
	}

	hp.logger.Info("honeypot_service_listening", slog.String("service_id", service.ID), slog.String("protocol", service.Protocol), slog.String("listen", service.Listen))

	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func (hp *honeypot) serveTCP(ctx context.Context, service serviceConfig, sem chan struct{}) error {
	listener, err := net.Listen("tcp", service.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()

	hp.logger.Info("honeypot_service_listening", slog.String("service_id", service.ID), slog.String("protocol", service.Protocol), slog.String("listen", service.Listen))

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			return ctx.Err()
		}
		go func() {
			defer func() { <-sem }()
			if err := hp.handleTCPConn(ctx, service, conn); err != nil && !errors.Is(err, net.ErrClosed) {
				hp.logger.Warn("honeypot_tcp_session_failed", slog.String("service_id", service.ID), slog.String("protocol", service.Protocol), slog.String("error", err.Error()))
			}
		}()
	}
}

func (hp *honeypot) handleTCPConn(ctx context.Context, service serviceConfig, conn net.Conn) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(hp.readTimeout))
	if service.Banner != "" {
		_, _ = io.WriteString(conn, ensureCRLF(service.Banner))
	}
	remoteHost, remotePort := splitAddr(conn.RemoteAddr())
	localHost, localPort := splitAddr(conn.LocalAddr())
	user := "unknown"
	payload := ""

	switch service.Protocol {
	case protocolSSHBanner, protocolTCPBanner:
		payload = sanitizeText(readLimitedPayload(conn, hp.maxPayloadBytes))
	case protocolTelnetBanner:
		_, _ = io.WriteString(conn, "login: ")
		user = normalizeCandidateUser(readLine(conn, 128))
		_, _ = io.WriteString(conn, "Password: ")
		_ = readLine(conn, 128)
		payload = fmt.Sprintf("login=%s password=<redacted>", user)
		_, _ = io.WriteString(conn, "\r\nAccess denied\r\n")
	}

	interaction := interaction{
		ServiceID:     service.ID,
		Protocol:      service.Protocol,
		SrcIP:         remoteHost,
		SrcPort:       remotePort,
		DstIP:         localHost,
		DstPort:       localPort,
		AttemptedUser: user,
		Payload:       payload,
		SessionKey:    sessionKey(service.ID, remoteHost, remotePort, localPort, hp.sessionSeq.Add(1)),
	}
	return hp.publishInteraction(ctx, interaction)
}

func (hp *honeypot) httpInteraction(service serviceConfig, r *http.Request) interaction {
	remoteHost, remotePort := splitRemoteHostPort(r.RemoteAddr)
	if forwarded := forwardedIP(r); forwarded != "" {
		remoteHost = forwarded
	}
	localHost, localPort := localAddrFromRequest(r, service.Listen)
	body := readHTTPBody(r.Body, hp.maxPayloadBytes)
	values := parsedValues(r.URL.Query(), r.Header.Get("Content-Type"), body)
	user := firstNonEmpty(
		normalizeCandidateUser(httpBasicUser(r)),
		normalizeCandidateUser(values.Get("username")),
		normalizeCandidateUser(values.Get("user")),
		normalizeCandidateUser(values.Get("login")),
		"unknown",
	)
	payload := sanitizeText(buildHTTPPayload(r, body, user))
	return interaction{
		ServiceID:     service.ID,
		Protocol:      service.Protocol,
		SrcIP:         remoteHost,
		SrcPort:       remotePort,
		DstIP:         localHost,
		DstPort:       localPort,
		AttemptedUser: user,
		Method:        r.Method,
		Path:          requestPath(r),
		Payload:       payload,
		SessionKey:    sessionKey(service.ID, remoteHost, remotePort, localPort, hp.sessionSeq.Add(1)),
	}
}

func (hp *honeypot) publishInteraction(ctx context.Context, in interaction) error {
	now := time.Now().UTC()
	tsUnixMs := now.UnixMilli()
	message := buildMessage(in)
	eventID := eventIDForInteraction(in, tsUnixMs)
	payload := map[string]any{
		"event_idem_key":      eventID,
		"observed_at_unix_ms": tsUnixMs,
		"event_ts_unix_ms":    tsUnixMs,
		"recv_ts_unix_ms":     tsUnixMs,
		"ts":                  tsUnixMs,
		"message":             message,
		"raw_line":            message,
		"line":                message,
		"host":                hp.host,
		"node_id":             hp.nodeID,
		"source":              fmt.Sprintf("honeypot:%s", in.ServiceID),
		"source_type":         deceptionSourceType,
		"event_type":          deceptionEventType,
		"group_key":           firstNonEmpty(strings.TrimSpace(in.SrcIP), hp.nodeID),
		"src_ip":              strings.TrimSpace(in.SrcIP),
		"dst_ip":              strings.TrimSpace(in.DstIP),
		"dst_port":            in.DstPort,
		"protocol_family":     protocolFamily(in.Protocol),
		"user":                firstNonEmpty(strings.TrimSpace(in.AttemptedUser), "unknown"),
		"session_id":          numericSessionID(in.SessionKey),
	}
	if hp.targetAgentID != "" {
		payload["target_agent_id"] = hp.targetAgentID
	}
	if trimmed := strings.TrimSpace(in.Payload); trimmed != "" {
		payload["cmdline"] = trimmed
	}
	if trimmed := strings.TrimSpace(in.Path); trimmed != "" {
		payload["file_path"] = trimmed
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	spooled, err := hp.publisher.Publish(ctx, eventID, data)
	if err != nil {
		return err
	}
	hp.logger.Info("honeypot_event_published",
		slog.String("event_idem_key", eventID),
		slog.String("service_id", in.ServiceID),
		slog.String("protocol", in.Protocol),
		slog.String("src_ip", in.SrcIP),
		slog.Int("dst_port", in.DstPort),
		slog.String("user", firstNonEmpty(strings.TrimSpace(in.AttemptedUser), "unknown")),
		slog.String("target_agent_id", hp.targetAgentID),
		slog.Bool("spooled", spooled),
	)
	return nil
}

func buildMessage(in interaction) string {
	parts := []string{
		"ALERT",
		fmt.Sprintf("invalid user=%s", firstNonEmpty(strings.TrimSpace(in.AttemptedUser), "honeypot")),
		fmt.Sprintf("src=%s", firstNonEmpty(strings.TrimSpace(in.SrcIP), "unknown")),
		deceptionRuleMarker,
		fmt.Sprintf("service=%s", in.ServiceID),
		fmt.Sprintf("protocol=%s", in.Protocol),
	}
	if in.DstPort > 0 {
		parts = append(parts, fmt.Sprintf("dst_port=%d", in.DstPort))
	}
	if strings.TrimSpace(in.Method) != "" {
		parts = append(parts, fmt.Sprintf("method=%s", strings.ToUpper(strings.TrimSpace(in.Method))))
	}
	if strings.TrimSpace(in.Path) != "" {
		parts = append(parts, fmt.Sprintf("path=%s", strings.TrimSpace(in.Path)))
	}
	if strings.TrimSpace(in.Payload) != "" {
		parts = append(parts, fmt.Sprintf("detail=%s", compactForMessage(in.Payload, 180)))
	}
	parts = append(parts, fmt.Sprintf("session=%s", in.SessionKey))
	return strings.Join(parts, " ")
}

func buildHTTPPayload(r *http.Request, body []byte, user string) string {
	segments := []string{fmt.Sprintf("method=%s", strings.ToUpper(r.Method)), fmt.Sprintf("path=%s", requestPath(r))}
	if user != "" && user != "unknown" {
		segments = append(segments, fmt.Sprintf("login=%s", user))
	}
	if ua := sanitizeText(r.UserAgent()); ua != "" {
		segments = append(segments, fmt.Sprintf("user_agent=%s", ua))
	}
	if len(body) > 0 {
		segments = append(segments, fmt.Sprintf("body=%s", redactSecrets(string(body))))
	}
	return strings.Join(segments, " ")
}

func parsedValues(query url.Values, contentType string, body []byte) url.Values {
	combined := url.Values{}
	for key, values := range query {
		for _, value := range values {
			combined.Add(key, value)
		}
	}
	if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") && len(body) > 0 {
		if parsed, err := url.ParseQuery(string(body)); err == nil {
			for key, values := range parsed {
				for _, value := range values {
					combined.Add(key, value)
				}
			}
		}
	}
	return combined
}

func requestPath(r *http.Request) string {
	if r.URL == nil {
		return "/"
	}
	if raw := strings.TrimSpace(r.URL.RequestURI()); raw != "" {
		return raw
	}
	if path := strings.TrimSpace(r.URL.Path); path != "" {
		return path
	}
	return "/"
}

func httpBasicUser(r *http.Request) string {
	user, _, ok := r.BasicAuth()
	if !ok {
		return ""
	}
	return user
}

func forwardedIP(r *http.Request) string {
	for _, header := range []string{"X-RSIEM-Source-IP", "X-Forwarded-For"} {
		value := strings.TrimSpace(r.Header.Get(header))
		if value == "" {
			continue
		}
		for _, part := range strings.Split(value, ",") {
			candidate := strings.TrimSpace(part)
			if net.ParseIP(candidate) != nil {
				return candidate
			}
		}
	}
	return ""
}

func renderHTTPResponse(title string) string {
	return fmt.Sprintf("<!doctype html><html><head><title>%s</title></head><body><h1>%s</h1><p>Authentication required.</p></body></html>", title, title)
}

func protocolFamily(protocol string) string {
	switch protocol {
	case protocolHTTP:
		return "http"
	default:
		return "tcp"
	}
}

func sessionKey(serviceID, srcIP string, srcPort, dstPort int, seq uint64) string {
	return fmt.Sprintf("%s-%s-%d-%d-%d", serviceID, normalizeToken(srcIP), srcPort, dstPort, seq)
}

func eventIDForInteraction(in interaction, tsUnixMs int64) string {
	base := fmt.Sprintf("honeypot|%s|%s|%d|%d|%s|%d", in.ServiceID, in.SrcIP, in.SrcPort, in.DstPort, in.SessionKey, tsUnixMs)
	sum := sha256.Sum256([]byte(base))
	return "evt.honeypot." + hex.EncodeToString(sum[:])
}

func numericSessionID(sessionKey string) int {
	sum := sha256.Sum256([]byte(sessionKey))
	value := int(sum[0])<<24 | int(sum[1])<<16 | int(sum[2])<<8 | int(sum[3])
	if value < 0 {
		return -value
	}
	if value == 0 {
		return 1
	}
	return value
}

func splitRemoteHostPort(addr string) (string, int) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return strings.TrimSpace(addr), 0
	}
	portNum, _ := strconv.Atoi(port)
	return host, portNum
}

func splitAddr(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	return splitRemoteHostPort(addr.String())
}

func localAddrFromRequest(r *http.Request, listen string) (string, int) {
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return splitAddr(addr)
	}
	return splitRemoteHostPort(listen)
}

func readLimitedPayload(reader io.Reader, maxBytes int) string {
	if reader == nil {
		return ""
	}
	data, _ := io.ReadAll(io.LimitReader(reader, int64(maxBytes)))
	return string(data)
}

func readHTTPBody(body io.ReadCloser, maxBytes int) []byte {
	if body == nil {
		return nil
	}
	defer body.Close()
	data, _ := io.ReadAll(io.LimitReader(body, int64(maxBytes)))
	return data
}

func readLine(conn net.Conn, maxBytes int) string {
	if conn == nil {
		return ""
	}
	reader := bufio.NewReader(io.LimitReader(conn, int64(maxBytes)))
	line, _ := reader.ReadString('\n')
	if line == "" {
		line, _ = reader.ReadString('\r')
	}
	return sanitizeText(line)
}

func ensureCRLF(value string) string {
	if value == "" {
		return ""
	}
	if strings.HasSuffix(value, "\r\n") {
		return value
	}
	if strings.HasSuffix(value, "\n") {
		return strings.TrimSuffix(value, "\n") + "\r\n"
	}
	return value + "\r\n"
}

func sanitizeText(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.TrimSpace(value)
	return redactSecrets(value)
}

func redactSecrets(value string) string {
	if value == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"password=", "password=<redacted>",
		"passwd=", "passwd=<redacted>",
		"pass=", "pass=<redacted>",
		"pwd=", "pwd=<redacted>",
	)
	value = replacer.Replace(value)
	for _, key := range []string{"password", "passwd", "pass", "pwd"} {
		value = redactQueryKey(value, key)
	}
	return strings.Join(strings.Fields(value), " ")
}

func redactQueryKey(value, key string) string {
	needle := key + "="
	start := strings.Index(strings.ToLower(value), needle)
	if start < 0 {
		return value
	}
	prefix := value[:start] + needle + "<redacted>"
	rest := value[start+len(needle):]
	if idx := strings.IndexAny(rest, " &"); idx >= 0 {
		return prefix + rest[idx:]
	}
	return prefix
}

func compactForMessage(value string, limit int) string {
	trimmed := sanitizeText(value)
	if limit > 0 && len(trimmed) > limit {
		return trimmed[:limit] + "..."
	}
	return trimmed
}

func normalizeCandidateUser(value string) string {
	value = sanitizeText(value)
	if value == "" {
		return ""
	}
	return normalizeToken(value)
}

func normalizeToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.', r == '@':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return strings.Trim(strings.Join(strings.Fields(strings.TrimSpace(b.String())), "_"), "_")
}

func retryInterval(ms int) time.Duration {
	if ms <= 0 {
		return defaultRetryInterval
	}
	return time.Duration(ms) * time.Millisecond
}

func durationOrDefault(ms int, fallback time.Duration) time.Duration {
	if ms <= 0 {
		return fallback
	}
	return time.Duration(ms) * time.Millisecond
}

func intOrDefault(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func hostName() string {
	host, err := os.Hostname()
	if err != nil {
		return "honeypot"
	}
	return strings.TrimSpace(host)
}
