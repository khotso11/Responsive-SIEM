package netflowv5

import "strings"

// Config contains runtime parameters for netflow v5 collector.
type Config struct {
	BindAddr       string
	Port           int
	MaxPacketBytes int
	QueueSize      int
	RateLimitPPS   int
	RawSubject     string
	NodeID         string
	SourceType     string
}

func (c *Config) applyDefaults() {
	if strings.TrimSpace(c.BindAddr) == "" {
		c.BindAddr = "127.0.0.1"
	}
	if c.Port <= 0 {
		c.Port = 2055
	}
	if c.MaxPacketBytes <= 0 {
		c.MaxPacketBytes = 4096
	}
	if c.QueueSize <= 0 {
		c.QueueSize = 1024
	}
	if c.RateLimitPPS <= 0 {
		c.RateLimitPPS = 500
	}
	if strings.TrimSpace(c.RawSubject) == "" {
		c.RawSubject = "rsiem.events.raw"
	}
	if strings.TrimSpace(c.SourceType) == "" {
		c.SourceType = "netflow_v5"
	}
}
