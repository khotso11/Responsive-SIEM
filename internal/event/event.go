package event

import "time"

// Event represents a normalized telemetry record passed through the agent pipeline.
type Event struct {
	ID        string                 `json:"id"`
	Seq       uint64                 `json:"seq"`
	Timestamp time.Time              `json:"timestamp"`
	Host      string                 `json:"host"`
	Source    string                 `json:"source"`
	Type      string                 `json:"type"`
	Severity  string                 `json:"severity"`
	Message   string                 `json:"message"`
	Fields    map[string]any         `json:"fields,omitempty"`
}
