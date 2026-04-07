package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultEventsStream       = "RSIEM_EVENTS"
	defaultEventsSubject      = "rsiem.events.raw"
	defaultDetectorKV         = "RSIEM_DETECT_DEDUPE"
	defaultDetectorCDKV       = "RSIEM_DETECT_COOLDOWN"
	defaultDetectorDur        = "detector-v0"
	defaultDetectorCooldownMs = 60000
)

// CollectorConfig configures collector-tail.
type CollectorConfig struct {
	LogLevel  string                   `yaml:"log_level"`
	JetStream CollectorJetStreamConfig `yaml:"jetstream"`
	Tail      CollectorTailConfig      `yaml:"tail"`
}

// CollectorJetStreamConfig configures JetStream for collector-tail.
type CollectorJetStreamConfig struct {
	URL               string `yaml:"url"`
	Stream            string `yaml:"stream"`
	Subject           string `yaml:"subject"`
	OfflineSpoolPath  string `yaml:"offline_spool_path"`
	OfflineSpoolFsync *bool  `yaml:"offline_spool_fsync"`
	RetryMs           int    `yaml:"retry_ms"`
}

// CollectorTailConfig configures tailing behavior.
type CollectorTailConfig struct {
	Path           string `yaml:"path"`
	CheckpointPath string `yaml:"checkpoint_path"`
	PollMs         int    `yaml:"poll_ms"`
}

// DetectorConfig configures detector-v0.
type DetectorConfig struct {
	LogLevel       string                       `yaml:"log_level"`
	JetStream      DetectorJetStreamConfig      `yaml:"jetstream"`
	Dedupe         DetectorDedupeConfig         `yaml:"dedupe"`
	Cooldown       DetectorCooldownConfig       `yaml:"cooldown"`
	CooldownMs     int                          `yaml:"cooldown_ms"`
	Baseline       DetectorBaselineConfig       `yaml:"baseline"`
	Network        DetectorNetworkConfig        `yaml:"network"`
	DNS            DetectorDNSConfig            `yaml:"dns"`
	InternalScan   DetectorInternalScanConfig   `yaml:"internal_scan"`
	Infrastructure DetectorInfrastructureConfig `yaml:"infrastructure"`
}

// DetectorJetStreamConfig configures JetStream for detector-v0.
type DetectorJetStreamConfig struct {
	URL     string `yaml:"url"`
	Stream  string `yaml:"stream"`
	Subject string `yaml:"subject"`
	Durable string `yaml:"durable"`
}

// DetectorDedupeConfig configures detector dedupe KV.
type DetectorDedupeConfig struct {
	Bucket string `yaml:"bucket"`
}

// DetectorCooldownConfig configures detector cooldown KV.
type DetectorCooldownConfig struct {
	Bucket string `yaml:"bucket"`
}

// DetectorNetworkConfig tunes network-connection alert selectivity.
type DetectorNetworkConfig struct {
	BenignDestinationIPs   []string `yaml:"benign_destination_ips"`
	KnownBadDestinationIPs []string `yaml:"known_bad_destination_ips"`
	RiskyPorts             []int    `yaml:"risky_ports"`
	RepeatThreshold        int      `yaml:"repeat_threshold"`
	RepeatWindowMs         int      `yaml:"repeat_window_ms"`
}

type DetectorProtocolScanConfig struct {
	Ports                  []int `yaml:"ports"`
	UniqueTargetsThreshold int   `yaml:"unique_targets_threshold"`
	ConfidenceScore        int   `yaml:"confidence_score"`
}

type DetectorInternalScanAllowlistConfig struct {
	Users            []string `yaml:"users"`
	Nodes            []string `yaml:"nodes"`
	ExecPathPrefixes []string `yaml:"exec_path_prefixes"`
	CommPrefixes     []string `yaml:"comm_prefixes"`
}

type DetectorInternalScanConfig struct {
	Enabled       bool                                `yaml:"enabled"`
	WindowMs      int                                 `yaml:"window_ms"`
	InternalCIDRs []string                            `yaml:"internal_cidrs"`
	Allowlist     DetectorInternalScanAllowlistConfig `yaml:"allowlist"`
	SMB           DetectorProtocolScanConfig          `yaml:"smb"`
	RPC           DetectorProtocolScanConfig          `yaml:"rpc"`
	LDAP          DetectorProtocolScanConfig          `yaml:"ldap"`
	DNS           DetectorProtocolScanConfig          `yaml:"dns"`
	FTP           DetectorProtocolScanConfig          `yaml:"ftp"`
	RDP           DetectorProtocolScanConfig          `yaml:"rdp"`
	WinRM         DetectorProtocolScanConfig          `yaml:"winrm"`
	SSH           DetectorProtocolScanConfig          `yaml:"ssh"`
}

// DetectorBaselineConfig tunes in-memory first-seen tracking.
type DetectorBaselineConfig struct {
	ProcessFirstSeenTTLms int `yaml:"process_first_seen_ttl_ms"`
	NetworkFirstSeenTTLms int `yaml:"network_first_seen_ttl_ms"`
}

// DetectorDNSConfig tunes DNS detection selectivity.
type DetectorDNSConfig struct {
	KnownBadDomains []string `yaml:"known_bad_domains"`
	SuspiciousTLDs  []string `yaml:"suspicious_tlds"`
}

type DetectorInfrastructurePatternBurstConfig struct {
	Threshold       int      `yaml:"threshold"`
	WindowMs        int      `yaml:"window_ms"`
	Keywords        []string `yaml:"keywords"`
	ContextKeywords []string `yaml:"context_keywords"`
}

type DetectorInfrastructureAdminLoginConfig struct {
	SuccessKeywords []string `yaml:"success_keywords"`
	AdminUsers      []string `yaml:"admin_users"`
}

type DetectorInfrastructureLinkFlapConfig struct {
	Threshold    int      `yaml:"threshold"`
	WindowMs     int      `yaml:"window_ms"`
	DownKeywords []string `yaml:"down_keywords"`
	UpKeywords   []string `yaml:"up_keywords"`
}

type DetectorInfrastructureConfig struct {
	FirewallDeny      DetectorInfrastructurePatternBurstConfig `yaml:"firewall_deny"`
	NetworkAdminLogin DetectorInfrastructureAdminLoginConfig   `yaml:"network_admin_login"`
	LinkFlap          DetectorInfrastructureLinkFlapConfig     `yaml:"link_flap"`
}

// LoadCollector reads and validates the collector configuration from disk.
func LoadCollector(path string) (*CollectorConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg CollectorConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyCollectorDefaults(&cfg)
	if err := validateCollector(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// LoadDetector reads and validates the detector configuration from disk.
func LoadDetector(path string) (*DetectorConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg DetectorConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyDetectorDefaults(&cfg)
	if err := validateDetector(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func applyCollectorDefaults(c *CollectorConfig) {
	if strings.TrimSpace(c.LogLevel) == "" {
		c.LogLevel = defaultMasterLogLevel
	}
	c.LogLevel = strings.ToUpper(c.LogLevel)

	if strings.TrimSpace(c.JetStream.URL) == "" {
		c.JetStream.URL = defaultMasterJetStreamURL
	}
	if strings.TrimSpace(c.JetStream.Stream) == "" {
		c.JetStream.Stream = defaultEventsStream
	}
	if strings.TrimSpace(c.JetStream.Subject) == "" {
		c.JetStream.Subject = defaultEventsSubject
	}
	if c.JetStream.RetryMs <= 0 {
		c.JetStream.RetryMs = 2000
	}

	if strings.TrimSpace(c.Tail.Path) == "" {
		c.Tail.Path = "tmp/demo.log"
	}
	if strings.TrimSpace(c.Tail.CheckpointPath) == "" {
		c.Tail.CheckpointPath = "tmp/tail.checkpoint.json"
	}
	if c.Tail.PollMs <= 0 {
		c.Tail.PollMs = 200
	}
}

func validateCollector(c *CollectorConfig) error {
	if strings.TrimSpace(c.JetStream.URL) == "" {
		return fmt.Errorf("jetstream.url required")
	}
	if strings.TrimSpace(c.JetStream.Stream) == "" {
		return fmt.Errorf("jetstream.stream required")
	}
	if strings.TrimSpace(c.JetStream.Subject) == "" {
		return fmt.Errorf("jetstream.subject required")
	}
	if strings.TrimSpace(c.Tail.Path) == "" {
		return fmt.Errorf("tail.path required")
	}
	return nil
}

func applyDetectorDefaults(c *DetectorConfig) {
	if strings.TrimSpace(c.LogLevel) == "" {
		c.LogLevel = defaultMasterLogLevel
	}
	c.LogLevel = strings.ToUpper(c.LogLevel)

	if strings.TrimSpace(c.JetStream.URL) == "" {
		c.JetStream.URL = defaultMasterJetStreamURL
	}
	if strings.TrimSpace(c.JetStream.Stream) == "" {
		c.JetStream.Stream = defaultEventsStream
	}
	if strings.TrimSpace(c.JetStream.Subject) == "" {
		c.JetStream.Subject = defaultEventsSubject
	}
	if strings.TrimSpace(c.JetStream.Durable) == "" {
		c.JetStream.Durable = defaultDetectorDur
	}
	if strings.TrimSpace(c.Dedupe.Bucket) == "" {
		c.Dedupe.Bucket = defaultDetectorKV
	}
	if strings.TrimSpace(c.Cooldown.Bucket) == "" {
		c.Cooldown.Bucket = defaultDetectorCDKV
	}
	if c.CooldownMs <= 0 {
		c.CooldownMs = defaultDetectorCooldownMs
	}
	if len(c.Network.RiskyPorts) == 0 {
		c.Network.RiskyPorts = []int{22, 23, 3389, 4444, 5555}
	}
	if c.Network.RepeatThreshold <= 0 {
		c.Network.RepeatThreshold = 3
	}
	if c.Network.RepeatWindowMs <= 0 {
		c.Network.RepeatWindowMs = 30000
	}
	if c.Baseline.ProcessFirstSeenTTLms <= 0 {
		c.Baseline.ProcessFirstSeenTTLms = 7 * 24 * 60 * 60 * 1000
	}
	if c.Baseline.NetworkFirstSeenTTLms <= 0 {
		c.Baseline.NetworkFirstSeenTTLms = 7 * 24 * 60 * 60 * 1000
	}
	if len(c.DNS.SuspiciousTLDs) == 0 {
		c.DNS.SuspiciousTLDs = []string{".top", ".xyz", ".zip", ".mov", ".cam"}
	}
	if c.Infrastructure.FirewallDeny.Threshold <= 0 {
		c.Infrastructure.FirewallDeny.Threshold = 5
	}
	if c.Infrastructure.FirewallDeny.WindowMs <= 0 {
		c.Infrastructure.FirewallDeny.WindowMs = 60000
	}
	if len(c.Infrastructure.FirewallDeny.Keywords) == 0 {
		c.Infrastructure.FirewallDeny.Keywords = []string{" deny ", " denied ", " blocked ", " reject ", " rejected ", " drop ", " dropped "}
	}
	if len(c.Infrastructure.FirewallDeny.ContextKeywords) == 0 {
		c.Infrastructure.FirewallDeny.ContextKeywords = []string{"firewall", "policy", "acl", "iptables", "nft", "pf", "src=", "dst=", "src ", "dst "}
	}
	if len(c.Infrastructure.NetworkAdminLogin.SuccessKeywords) == 0 {
		c.Infrastructure.NetworkAdminLogin.SuccessKeywords = []string{"accepted password", "login successful", "logged in", "authentication succeeded", "ssh login", "user login"}
	}
	if len(c.Infrastructure.NetworkAdminLogin.AdminUsers) == 0 {
		c.Infrastructure.NetworkAdminLogin.AdminUsers = []string{"admin", "administrator", "root", "netadmin", "fwadmin"}
	}
	if c.Infrastructure.LinkFlap.Threshold <= 0 {
		c.Infrastructure.LinkFlap.Threshold = 3
	}
	if c.Infrastructure.LinkFlap.WindowMs <= 0 {
		c.Infrastructure.LinkFlap.WindowMs = 300000
	}
	if len(c.Infrastructure.LinkFlap.DownKeywords) == 0 {
		c.Infrastructure.LinkFlap.DownKeywords = []string{"link down", "interface down", "changed state to down", "line protocol down", "port down"}
	}
	if len(c.Infrastructure.LinkFlap.UpKeywords) == 0 {
		c.Infrastructure.LinkFlap.UpKeywords = []string{"link up", "interface up", "changed state to up", "line protocol up", "port up", "flapping"}
	}
	if c.InternalScan.WindowMs <= 0 {
		c.InternalScan.WindowMs = 60000
	}
	if len(c.InternalScan.InternalCIDRs) == 0 {
		c.InternalScan.InternalCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	}
	applyProtocolScanDefaults(&c.InternalScan.SMB, []int{445}, 5, 90)
	applyProtocolScanDefaults(&c.InternalScan.RPC, []int{135}, 5, 88)
	applyProtocolScanDefaults(&c.InternalScan.LDAP, []int{389, 636, 3268, 3269}, 5, 88)
	applyProtocolScanDefaults(&c.InternalScan.DNS, []int{53}, 8, 82)
	applyProtocolScanDefaults(&c.InternalScan.FTP, []int{21}, 4, 86)
	applyProtocolScanDefaults(&c.InternalScan.RDP, []int{3389}, 4, 90)
	applyProtocolScanDefaults(&c.InternalScan.WinRM, []int{5985, 5986}, 4, 88)
	applyProtocolScanDefaults(&c.InternalScan.SSH, []int{22}, 5, 86)
}

func validateDetector(c *DetectorConfig) error {
	if strings.TrimSpace(c.JetStream.URL) == "" {
		return fmt.Errorf("jetstream.url required")
	}
	if strings.TrimSpace(c.JetStream.Stream) == "" {
		return fmt.Errorf("jetstream.stream required")
	}
	if strings.TrimSpace(c.JetStream.Subject) == "" {
		return fmt.Errorf("jetstream.subject required")
	}
	if strings.TrimSpace(c.JetStream.Durable) == "" {
		return fmt.Errorf("jetstream.durable required")
	}
	if strings.TrimSpace(c.Dedupe.Bucket) == "" {
		return fmt.Errorf("dedupe.bucket required")
	}
	if strings.TrimSpace(c.Cooldown.Bucket) == "" {
		return fmt.Errorf("cooldown.bucket required")
	}
	if c.CooldownMs <= 0 {
		return fmt.Errorf("cooldown_ms must be > 0")
	}
	for _, cidr := range c.InternalScan.InternalCIDRs {
		if strings.TrimSpace(cidr) == "" {
			return fmt.Errorf("internal_scan.internal_cidrs contains empty value")
		}
	}
	return nil
}

func applyProtocolScanDefaults(c *DetectorProtocolScanConfig, ports []int, threshold int, confidence int) {
	if len(c.Ports) == 0 {
		c.Ports = append([]int(nil), ports...)
	}
	if c.UniqueTargetsThreshold <= 0 {
		c.UniqueTargetsThreshold = threshold
	}
	if c.ConfidenceScore <= 0 {
		c.ConfidenceScore = confidence
	}
}
