package syslogudp

import "time"

// Config configures the syslog UDP collector.
type Config struct {
	Enabled          bool
	ListenAddr       string
	MaxDatagramBytes int
	QueueSize        int
	ReadTimeout      time.Duration
}

func (c *Config) applyDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0:5514"
	}
	if c.MaxDatagramBytes <= 0 {
		c.MaxDatagramBytes = 2048
	}
	if c.QueueSize <= 0 {
		c.QueueSize = 1024
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 500 * time.Millisecond
	}
}
