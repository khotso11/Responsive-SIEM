package tail

import "time"

// Config configures the tail collector.
type Config struct {
	Enabled        bool
	Path           string
	CheckpointPath string
	PollInterval   time.Duration
}

func (c *Config) applyDefaults() {
	if c.PollInterval <= 0 {
		c.PollInterval = 200 * time.Millisecond
	}
}
