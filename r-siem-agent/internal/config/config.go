package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultLogLevel                   = "INFO"
	defaultHeartbeatInterval          = 60
	defaultMockInterval               = 1
	defaultAgentName                  = "r-siem-agent"
	defaultAgentInstanceID            = "local-instance"
	defaultFastLaneBuffer             = 1000
	defaultStandardLaneBuffer         = 5000
	defaultWALPath                    = "./data/agent.wal"
	defaultWALFsync                   = true
	defaultFastBatchSize              = 50
	defaultFastBatchLatencyMillis     = 200
	defaultStandardBatchSize          = 200
	defaultStandardBatchLatencyMillis = 500
	defaultTransportAckDelayMillis    = 150
	defaultTransportAckDropRate       = 0.0
	defaultTransportMode              = "mock"
	defaultTransportAddr              = "127.0.0.1:7777"
	defaultMasterLogLevel             = "INFO"
	defaultMasterListenAddr           = "0.0.0.0:7777"
	defaultMasterTransportMode        = "grpc_mtls"
	defaultMasterAckDelayMillis       = 0
	defaultMasterAckDropRate          = 0.0
	defaultMasterJetStreamURL         = "nats://127.0.0.1:4222"
	defaultMasterJetStreamStream      = "RSIEM"
	defaultMasterSubjectFast          = "rsiem.fast"
	defaultMasterSubjectStandard      = "rsiem.standard"
	defaultMasterDurableFast          = "master-fast"
	defaultMasterDurableStandard      = "master-standard"
	defaultMasterServerName           = "master.local"
	defaultMasterClientIdentitySource = "cert_prefer"
	defaultConsumerFastWorkers        = 1
	defaultConsumerStandardWorkers    = 1
	defaultConsumerPullBatch          = 10
	defaultConsumerPullTimeoutMillis  = 500
)

// Config represents the agent configuration file.
type Config struct {
	Log       LogConfig       `yaml:"log"`
	Heartbeat HeartbeatConfig `yaml:"heartbeat"`
	Mock      MockConfig      `yaml:"mock"`
	Agent     AgentConfig     `yaml:"agent"`
	Lanes     LanesConfig     `yaml:"lanes"`
	WAL       WALConfig       `yaml:"wal"`
	Batch     BatchConfig     `yaml:"batch"`
	Transport TransportConfig `yaml:"transport"`
}

// LogConfig controls structured logging.
type LogConfig struct {
	Level string `yaml:"level"`
}

// HeartbeatConfig configures the supervisor heartbeat.
type HeartbeatConfig struct {
	IntervalSeconds int `yaml:"interval_seconds"`
}

// MockConfig tunes the mock event generator.
type MockConfig struct {
	IntervalSeconds int `yaml:"interval_seconds"`
}

// AgentConfig contains metadata about the running agent instance.
type AgentConfig struct {
	Name                         string   `yaml:"name"`
	InstanceID                   string   `yaml:"instance_id"`
	QuarantineRoot               string   `yaml:"quarantine_root"`
	QuarantineAllowedSourceRoots []string `yaml:"quarantine_allowed_source_roots"`
}

// LanesConfig exposes buffer sizing knobs for lane queues.
type LanesConfig struct {
	FastBuffer     int `yaml:"fast_buffer"`
	StandardBuffer int `yaml:"standard_buffer"`
}

// WALConfig controls write-ahead logging behavior.
type WALConfig struct {
	Path  string `yaml:"path"`
	Fsync *bool  `yaml:"fsync"`
}

// BatchConfig describes per-lane batching parameters.
type BatchConfig struct {
	Fast     BatchLaneConfig `yaml:"fast"`
	Standard BatchLaneConfig `yaml:"standard"`
}

// BatchLaneConfig tunes micro-batching knobs for a lane.
type BatchLaneConfig struct {
	MaxSize      int `yaml:"max_size"`
	MaxLatencyMs int `yaml:"max_latency_ms"`
}

// TransportConfig controls the transport session behavior.
type TransportConfig struct {
	Mode        string             `yaml:"mode"`
	Addr        string             `yaml:"addr"`
	AckDelayMs  int                `yaml:"ack_delay_ms"`
	AckDropRate float64            `yaml:"ack_drop_rate"`
	TLS         TransportTLSConfig `yaml:"tls"`
}

// TransportTLSConfig carries TLS certificate settings.
type TransportTLSConfig struct {
	CA                  string `yaml:"ca"`
	Cert                string `yaml:"cert"`
	Key                 string `yaml:"key"`
	ServerName          string `yaml:"server_name"`
	ServerCertPinSHA256 string `yaml:"server_cert_pin_sha256"`
}

// Load reads and validates the configuration from disk.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Log.Level == "" {
		c.Log.Level = defaultLogLevel
	}

	c.Log.Level = strings.ToUpper(c.Log.Level)

	if c.Heartbeat.IntervalSeconds <= 0 {
		c.Heartbeat.IntervalSeconds = defaultHeartbeatInterval
	}

	if c.Mock.IntervalSeconds <= 0 {
		c.Mock.IntervalSeconds = defaultMockInterval
	}

	if strings.TrimSpace(c.Agent.Name) == "" {
		c.Agent.Name = defaultAgentName
	}

	if strings.TrimSpace(c.Agent.InstanceID) == "" {
		c.Agent.InstanceID = defaultAgentInstanceID
	}

	if strings.TrimSpace(c.Agent.QuarantineRoot) == "" {
		c.Agent.QuarantineRoot = "tmp/quarantine"
	}
	if len(c.Agent.QuarantineAllowedSourceRoots) == 0 {
		c.Agent.QuarantineAllowedSourceRoots = []string{"tmp"}
	}

	if c.Lanes.FastBuffer <= 0 {
		c.Lanes.FastBuffer = defaultFastLaneBuffer
	}

	if c.Lanes.StandardBuffer <= 0 {
		c.Lanes.StandardBuffer = defaultStandardLaneBuffer
	}

	if strings.TrimSpace(c.WAL.Path) == "" {
		c.WAL.Path = defaultWALPath
	}

	if c.WAL.Fsync == nil {
		val := defaultWALFsync
		c.WAL.Fsync = &val
	}

	if strings.TrimSpace(c.Transport.Mode) == "" {
		c.Transport.Mode = defaultTransportMode
	}

	if strings.TrimSpace(c.Transport.Addr) == "" {
		c.Transport.Addr = defaultTransportAddr
	}

	if c.Transport.AckDelayMs <= 0 {
		c.Transport.AckDelayMs = defaultTransportAckDelayMillis
	}

	if c.Transport.AckDropRate < 0 {
		c.Transport.AckDropRate = defaultTransportAckDropRate
	}

	if c.Batch.Fast.MaxSize <= 0 {
		c.Batch.Fast.MaxSize = defaultFastBatchSize
	}

	if c.Batch.Fast.MaxLatencyMs <= 0 {
		c.Batch.Fast.MaxLatencyMs = defaultFastBatchLatencyMillis
	}

	if c.Batch.Standard.MaxSize <= 0 {
		c.Batch.Standard.MaxSize = defaultStandardBatchSize
	}

	if c.Batch.Standard.MaxLatencyMs <= 0 {
		c.Batch.Standard.MaxLatencyMs = defaultStandardBatchLatencyMillis
	}
}

func (c *Config) validate() error {
	switch c.Log.Level {
	case "DEBUG", "INFO", "WARN", "ERROR":
	default:
		return fmt.Errorf("invalid log level: %s", c.Log.Level)
	}

	if c.Heartbeat.IntervalSeconds <= 0 {
		return fmt.Errorf("heartbeat interval must be > 0")
	}

	if c.Mock.IntervalSeconds <= 0 {
		return fmt.Errorf("mock interval must be > 0")
	}

	if c.Lanes.FastBuffer <= 0 {
		return fmt.Errorf("fast lane buffer must be > 0")
	}

	if c.Lanes.StandardBuffer <= 0 {
		return fmt.Errorf("standard lane buffer must be > 0")
	}

	if strings.TrimSpace(c.WAL.Path) == "" {
		return fmt.Errorf("wal path must be set")
	}

	if c.Transport.AckDelayMs < 0 {
		return fmt.Errorf("transport ack delay must be >= 0")
	}

	if c.Transport.AckDropRate < 0 || c.Transport.AckDropRate > 1 {
		return fmt.Errorf("transport ack drop rate must be between 0 and 1")
	}

	switch strings.ToLower(c.Transport.Mode) {
	case "mock", "tcp", "grpc_mtls":
	default:
		return fmt.Errorf("invalid transport mode: %s", c.Transport.Mode)
	}

	if strings.TrimSpace(c.Transport.Addr) == "" {
		return fmt.Errorf("transport addr must be set")
	}

	if strings.ToLower(c.Transport.Mode) == "grpc_mtls" {
		if strings.TrimSpace(c.Transport.TLS.CA) == "" {
			return fmt.Errorf("transport.tls.ca must be set for grpc_mtls mode")
		}
		if strings.TrimSpace(c.Transport.TLS.Cert) == "" {
			return fmt.Errorf("transport.tls.cert must be set for grpc_mtls mode")
		}
		if strings.TrimSpace(c.Transport.TLS.Key) == "" {
			return fmt.Errorf("transport.tls.key must be set for grpc_mtls mode")
		}
		if strings.TrimSpace(c.Transport.TLS.ServerName) == "" {
			return fmt.Errorf("transport.tls.server_name must be set for grpc_mtls mode")
		}
	}

	if c.Batch.Fast.MaxSize <= 0 {
		return fmt.Errorf("fast batch max size must be > 0")
	}

	if c.Batch.Fast.MaxLatencyMs <= 0 {
		return fmt.Errorf("fast batch max latency must be > 0")
	}

	if c.Batch.Standard.MaxSize <= 0 {
		return fmt.Errorf("standard batch max size must be > 0")
	}

	if c.Batch.Standard.MaxLatencyMs <= 0 {
		return fmt.Errorf("standard batch max latency must be > 0")
	}

	if strings.TrimSpace(c.Agent.QuarantineRoot) == "" {
		return fmt.Errorf("agent.quarantine_root must be set")
	}
	if len(c.Agent.QuarantineAllowedSourceRoots) == 0 {
		return fmt.Errorf("agent.quarantine_allowed_source_roots must contain at least one entry")
	}

	return nil
}

// LogLevel returns the configured log level.
func (c *Config) LogLevel() string {
	return c.Log.Level
}

// HeartbeatInterval returns the configured heartbeat interval as a duration.
func (c *Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.Heartbeat.IntervalSeconds) * time.Second
}

// HeartbeatIntervalSeconds exposes the interval in seconds for logging summaries.
func (c *Config) HeartbeatIntervalSeconds() int {
	return c.Heartbeat.IntervalSeconds
}

// MockInterval returns the configured mock collector interval.
func (c *Config) MockInterval() time.Duration {
	return time.Duration(c.Mock.IntervalSeconds) * time.Second
}

// MockIntervalSeconds exposes the mock interval for logging summaries.
func (c *Config) MockIntervalSeconds() int {
	return c.Mock.IntervalSeconds
}

// AgentName returns the configured agent name.
func (c *Config) AgentName() string {
	return c.Agent.Name
}

// AgentInstanceID returns the configured agent instance identifier.
func (c *Config) AgentInstanceID() string {
	return c.Agent.InstanceID
}

// AgentQuarantineRoot returns the configured quarantine root directory.
func (c *Config) AgentQuarantineRoot() string {
	return strings.TrimSpace(c.Agent.QuarantineRoot)
}

// AgentQuarantineAllowedSourceRoots returns allowed source root directories.
func (c *Config) AgentQuarantineAllowedSourceRoots() []string {
	if len(c.Agent.QuarantineAllowedSourceRoots) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.Agent.QuarantineAllowedSourceRoots))
	for _, root := range c.Agent.QuarantineAllowedSourceRoots {
		root = strings.TrimSpace(root)
		if root != "" {
			out = append(out, root)
		}
	}
	return out
}

// LaneFastBuffer returns the configured FAST lane buffer size.
func (c *Config) LaneFastBuffer() int {
	return c.Lanes.FastBuffer
}

// LaneStandardBuffer returns the configured STANDARD lane buffer size.
func (c *Config) LaneStandardBuffer() int {
	return c.Lanes.StandardBuffer
}

// WALPath returns the configured WAL path.
func (c *Config) WALPath() string {
	return c.WAL.Path
}

// WALFsync indicates whether to fsync on every append.
func (c *Config) WALFsync() bool {
	if c.WAL.Fsync == nil {
		return defaultWALFsync
	}
	return *c.WAL.Fsync
}

// TransportAckDelay returns the configured ACK delay.
func (c *Config) TransportAckDelay() time.Duration {
	return time.Duration(c.Transport.AckDelayMs) * time.Millisecond
}

// TransportAckDelayMillis exposes the ACK delay value as milliseconds.
func (c *Config) TransportAckDelayMillis() int {
	return c.Transport.AckDelayMs
}

// TransportAckDropRate returns the probability that an ACK is dropped.
func (c *Config) TransportAckDropRate() float64 {
	return c.Transport.AckDropRate
}

// TransportMode returns the configured transport mode.
func (c *Config) TransportMode() string {
	return strings.ToLower(c.Transport.Mode)
}

// TransportAddr returns the configured transport address.
func (c *Config) TransportAddr() string {
	return c.Transport.Addr
}

// TransportTLSCA returns the CA certificate path.
func (c *Config) TransportTLSCA() string {
	return c.Transport.TLS.CA
}

// TransportTLSCert returns the client certificate path.
func (c *Config) TransportTLSCert() string {
	return c.Transport.TLS.Cert
}

// TransportTLSKey returns the client private key path.
func (c *Config) TransportTLSKey() string {
	return c.Transport.TLS.Key
}

// TransportTLSServerName returns the mTLS server name.
func (c *Config) TransportTLSServerName() string {
	return c.Transport.TLS.ServerName
}

// TransportTLSServerCertPinSHA256 returns optional server leaf certificate pin.
func (c *Config) TransportTLSServerCertPinSHA256() string {
	return c.Transport.TLS.ServerCertPinSHA256
}

// BatchFastMaxSize returns the FAST lane batch max size.
func (c *Config) BatchFastMaxSize() int {
	return c.Batch.Fast.MaxSize
}

// BatchFastMaxLatency returns the FAST lane max latency.
func (c *Config) BatchFastMaxLatency() time.Duration {
	return time.Duration(c.Batch.Fast.MaxLatencyMs) * time.Millisecond
}

// BatchFastMaxLatencyMillis exposes the configured FAST max latency in ms.
func (c *Config) BatchFastMaxLatencyMillis() int {
	return c.Batch.Fast.MaxLatencyMs
}

// BatchStandardMaxSize returns the STANDARD lane batch max size.
func (c *Config) BatchStandardMaxSize() int {
	return c.Batch.Standard.MaxSize
}

// BatchStandardMaxLatency returns the STANDARD lane latency.
func (c *Config) BatchStandardMaxLatency() time.Duration {
	return time.Duration(c.Batch.Standard.MaxLatencyMs) * time.Millisecond
}

// BatchStandardMaxLatencyMillis exposes the STANDARD max latency.
func (c *Config) BatchStandardMaxLatencyMillis() int {
	return c.Batch.Standard.MaxLatencyMs
}

// MasterConfig holds configuration for the master service.
type MasterConfig struct {
	LogLevel    string                `yaml:"log_level"`
	ListenAddr  string                `yaml:"listen_addr"`
	Transport   MasterTransportConfig `yaml:"transport"`
	JetStream   JetStreamConfig       `yaml:"jetstream"`
	Consumer    ConsumerConfig        `yaml:"consumer"`
	AckDelayMs  int                   `yaml:"ack_delay_ms"`
	AckDropRate float64               `yaml:"ack_drop_rate"`
}

// MasterTransportConfig controls inbound transport settings for the master.
type MasterTransportConfig struct {
	Mode       string          `yaml:"mode"`
	TLS        MasterTLSConfig `yaml:"tls"`
	ServerName string          `yaml:"server_name"`
}

// MasterTLSConfig captures TLS cert paths for the master transport.
type MasterTLSConfig struct {
	CA                             string   `yaml:"ca"`
	Cert                           string   `yaml:"cert"`
	Key                            string   `yaml:"key"`
	ClientIdentity                 string   `yaml:"client_identity"`
	ClientIdentitySource           string   `yaml:"client_identity_source"`
	ClientFingerprintAllowlist     []string `yaml:"client_fingerprint_allowlist"`
	ClientFingerprintAllowlistPath string   `yaml:"client_fingerprint_allowlist_path"`
}

// JetStreamConfig configures the JetStream publisher boundary.
type JetStreamConfig struct {
	URL                 string `yaml:"url"`
	Stream              string `yaml:"stream"`
	SubjectFast         string `yaml:"subject_fast"`
	SubjectStandard     string `yaml:"subject_standard"`
	DurableNameFast     string `yaml:"durable_name_fast"`
	DurableNameStandard string `yaml:"durable_name_standard"`
}

// ConsumerConfig configures JetStream consumers.
type ConsumerConfig struct {
	FastWorkers     int `yaml:"fast_workers"`
	StandardWorkers int `yaml:"standard_workers"`
	PullBatch       int `yaml:"pull_batch"`
	PullTimeoutMs   int `yaml:"pull_timeout_ms"`
}

// LoadMaster reads and validates the master configuration from disk.
func LoadMaster(path string) (*MasterConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg MasterConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *MasterConfig) applyDefaults() {
	if strings.TrimSpace(c.LogLevel) == "" {
		c.LogLevel = defaultMasterLogLevel
	}
	c.LogLevel = strings.ToUpper(c.LogLevel)

	if strings.TrimSpace(c.ListenAddr) == "" {
		c.ListenAddr = defaultMasterListenAddr
	}

	if strings.TrimSpace(c.Transport.Mode) == "" {
		c.Transport.Mode = defaultMasterTransportMode
	}

	if strings.TrimSpace(c.Transport.ServerName) == "" {
		c.Transport.ServerName = defaultMasterServerName
	}
	if strings.TrimSpace(c.Transport.TLS.ClientIdentitySource) == "" {
		c.Transport.TLS.ClientIdentitySource = defaultMasterClientIdentitySource
	}
	c.Transport.TLS.ClientIdentitySource = strings.ToLower(strings.TrimSpace(c.Transport.TLS.ClientIdentitySource))

	if c.Consumer.FastWorkers <= 0 {
		c.Consumer.FastWorkers = defaultConsumerFastWorkers
	}
	if c.Consumer.StandardWorkers <= 0 {
		c.Consumer.StandardWorkers = defaultConsumerStandardWorkers
	}
	if c.Consumer.PullBatch <= 0 {
		c.Consumer.PullBatch = defaultConsumerPullBatch
	}
	if c.Consumer.PullTimeoutMs <= 0 {
		c.Consumer.PullTimeoutMs = defaultConsumerPullTimeoutMillis
	}

	if strings.TrimSpace(c.JetStream.URL) == "" {
		c.JetStream.URL = defaultMasterJetStreamURL
	}

	if strings.TrimSpace(c.JetStream.Stream) == "" {
		c.JetStream.Stream = defaultMasterJetStreamStream
	}

	if strings.TrimSpace(c.JetStream.SubjectFast) == "" {
		c.JetStream.SubjectFast = defaultMasterSubjectFast
	}

	if strings.TrimSpace(c.JetStream.SubjectStandard) == "" {
		c.JetStream.SubjectStandard = defaultMasterSubjectStandard
	}

	if strings.TrimSpace(c.JetStream.DurableNameFast) == "" {
		c.JetStream.DurableNameFast = defaultMasterDurableFast
	}

	if strings.TrimSpace(c.JetStream.DurableNameStandard) == "" {
		c.JetStream.DurableNameStandard = defaultMasterDurableStandard
	}

	if c.AckDelayMs < 0 {
		c.AckDelayMs = defaultMasterAckDelayMillis
	}

	if c.AckDropRate < 0 {
		c.AckDropRate = defaultMasterAckDropRate
	}
}

func (c *MasterConfig) validate() error {
	switch c.LogLevel {
	case "DEBUG", "INFO", "WARN", "ERROR":
	default:
		return fmt.Errorf("invalid log level: %s", c.LogLevel)
	}

	if strings.TrimSpace(c.ListenAddr) == "" {
		return fmt.Errorf("listen_addr must be set")
	}

	if c.AckDelayMs < 0 {
		return fmt.Errorf("ack_delay_ms must be >= 0")
	}

	if c.AckDropRate < 0 || c.AckDropRate > 1 {
		return fmt.Errorf("ack_drop_rate must be between 0 and 1")
	}

	if strings.ToLower(c.Transport.Mode) != "grpc_mtls" {
		return fmt.Errorf("unsupported transport mode: %s", c.Transport.Mode)
	}
	switch strings.ToLower(strings.TrimSpace(c.Transport.TLS.ClientIdentitySource)) {
	case "cert_only", "cert_prefer", "metadata_only":
	default:
		return fmt.Errorf("transport.tls.client_identity_source must be one of cert_only, cert_prefer, metadata_only")
	}

	if err := requireFile(c.Transport.TLS.CA, "transport.tls.ca"); err != nil {
		return err
	}
	if err := requireFile(c.Transport.TLS.Cert, "transport.tls.cert"); err != nil {
		return err
	}
	if err := requireFile(c.Transport.TLS.Key, "transport.tls.key"); err != nil {
		return err
	}
	if strings.TrimSpace(c.Transport.TLS.ClientFingerprintAllowlistPath) != "" {
		if err := requireFile(c.Transport.TLS.ClientFingerprintAllowlistPath, "transport.tls.client_fingerprint_allowlist_path"); err != nil {
			return err
		}
	}

	if strings.TrimSpace(c.JetStream.URL) == "" {
		return fmt.Errorf("jetstream.url must be set")
	}
	if strings.TrimSpace(c.JetStream.Stream) == "" {
		return fmt.Errorf("jetstream.stream must be set")
	}
	if strings.TrimSpace(c.JetStream.SubjectFast) == "" {
		return fmt.Errorf("jetstream.subject_fast must be set")
	}
	if strings.TrimSpace(c.JetStream.SubjectStandard) == "" {
		return fmt.Errorf("jetstream.subject_standard must be set")
	}
	if strings.TrimSpace(c.JetStream.DurableNameFast) == "" {
		return fmt.Errorf("jetstream.durable_name_fast must be set")
	}
	if strings.TrimSpace(c.JetStream.DurableNameStandard) == "" {
		return fmt.Errorf("jetstream.durable_name_standard must be set")
	}

	if c.Consumer.FastWorkers <= 0 {
		return fmt.Errorf("consumer.fast_workers must be > 0")
	}
	if c.Consumer.StandardWorkers <= 0 {
		return fmt.Errorf("consumer.standard_workers must be > 0")
	}
	if c.Consumer.PullBatch <= 0 {
		return fmt.Errorf("consumer.pull_batch must be > 0")
	}
	if c.Consumer.PullTimeoutMs <= 0 {
		return fmt.Errorf("consumer.pull_timeout_ms must be > 0")
	}

	return nil
}

func requireFile(path string, field string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s must be set", field)
	}

	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}

	return nil
}

// Summary returns a concise, log-safe view of the master config.
func (c *MasterConfig) Summary() map[string]any {
	return map[string]any{
		"log_level":   c.LogLevel,
		"listen_addr": c.ListenAddr,
		"transport": map[string]any{
			"mode": c.Transport.Mode,
			"tls": map[string]any{
				"ca":                                c.Transport.TLS.CA,
				"cert":                              c.Transport.TLS.Cert,
				"key":                               c.Transport.TLS.Key,
				"client_identity":                   c.Transport.TLS.ClientIdentity,
				"client_identity_source":            c.Transport.TLS.ClientIdentitySource,
				"client_fingerprint_allowlist_len":  len(c.Transport.TLS.ClientFingerprintAllowlist),
				"client_fingerprint_allowlist_path": c.Transport.TLS.ClientFingerprintAllowlistPath,
			},
			"server_name": c.Transport.ServerName,
		},
		"jetstream": map[string]string{
			"url":                   c.JetStream.URL,
			"stream":                c.JetStream.Stream,
			"subject_fast":          c.JetStream.SubjectFast,
			"subject_standard":      c.JetStream.SubjectStandard,
			"durable_name_fast":     c.JetStream.DurableNameFast,
			"durable_name_standard": c.JetStream.DurableNameStandard,
		},
		"consumer": map[string]int{
			"fast_workers":     c.Consumer.FastWorkers,
			"standard_workers": c.Consumer.StandardWorkers,
			"pull_batch":       c.Consumer.PullBatch,
			"pull_timeout_ms":  c.Consumer.PullTimeoutMs,
		},
		"ack_delay_ms":  c.AckDelayMs,
		"ack_drop_rate": c.AckDropRate,
	}
}
