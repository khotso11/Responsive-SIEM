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
	URL     string `yaml:"url"`
	Stream  string `yaml:"stream"`
	Subject string `yaml:"subject"`
}

// CollectorTailConfig configures tailing behavior.
type CollectorTailConfig struct {
	Path           string `yaml:"path"`
	CheckpointPath string `yaml:"checkpoint_path"`
	PollMs         int    `yaml:"poll_ms"`
}

// DetectorConfig configures detector-v0.
type DetectorConfig struct {
	LogLevel   string                  `yaml:"log_level"`
	JetStream  DetectorJetStreamConfig `yaml:"jetstream"`
	Dedupe     DetectorDedupeConfig    `yaml:"dedupe"`
	Cooldown   DetectorCooldownConfig  `yaml:"cooldown"`
	CooldownMs int                     `yaml:"cooldown_ms"`
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
	return nil
}
