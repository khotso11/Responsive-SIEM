package tail

import "time"

// Config configures the tail collector.
type Config struct {
	Path           string
	CheckpointPath string
	PollInterval   time.Duration
	Stream         string
	Subject        string
}

func (c *Config) applyDefaults() {
	if c.PollInterval <= 0 {
		c.PollInterval = 200 * time.Millisecond
	}
}
