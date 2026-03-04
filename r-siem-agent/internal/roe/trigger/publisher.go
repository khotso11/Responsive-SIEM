package trigger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	ResponseStream      = "RSIEM_RESPONSE"
	ResponseTriggerFast = "rsiem.response.triggers.fast"
	ResponseTriggerStd  = "rsiem.response.triggers.standard"
	ResponseStepsFast   = "rsiem.response.steps.fast"
	ResponseStepsStd    = "rsiem.response.steps.standard"
)

// Alert describes a response trigger alert payload.
type Alert struct {
	AlertKey         string
	RuleID           string
	Severity         string
	Lane             string
	GroupBy          string
	GroupKey         string
	ObservedAtUnixMs int64
	EventTsUnixMs    int64
	AlertTsUnixMs    int64
	LatencyMs        int64
	NodeID           string
	SourceType       string
	EventType        string
	SrcIP            string
	User             string
	EventIdemKey     string
	AgentID          string
	TargetAgentID    string
}

// Publisher publishes ROE triggers using the pubtrigger schema.
type Publisher struct {
	logger *slog.Logger
	js     nats.JetStreamContext
}

// NewPublisher ensures the response stream and returns a publisher.
func NewPublisher(logger *slog.Logger, js nats.JetStreamContext) (*Publisher, error) {
	if err := ensureResponseStream(js); err != nil {
		return nil, err
	}
	return &Publisher{logger: logger, js: js}, nil
}

// PublishAlert sends a response trigger alert and returns the subject and trigger id.
func (p *Publisher) PublishAlert(alert Alert) (string, string, error) {
	lane := strings.ToUpper(strings.TrimSpace(alert.Lane))
	if lane != "FAST" && lane != "STANDARD" {
		return "", "", fmt.Errorf("invalid lane: %s", lane)
	}
	subject := ResponseTriggerStd
	if lane == "FAST" {
		subject = ResponseTriggerFast
	}
	triggerID := fmt.Sprintf("trig.alert.%s", strings.TrimSpace(alert.AlertKey))
	observedAt := alert.ObservedAtUnixMs
	if observedAt == 0 {
		observedAt = time.Now().UnixMilli()
	}
	eventTs := alert.EventTsUnixMs
	if eventTs <= 0 {
		eventTs = observedAt
	}
	alertTs := alert.AlertTsUnixMs
	if alertTs <= 0 {
		alertTs = observedAt
	}
	latencyMs := alert.LatencyMs
	if latencyMs < 0 {
		latencyMs = 0
	}
	if latencyMs == 0 && alertTs >= eventTs {
		latencyMs = alertTs - eventTs
	}
	payload := map[string]any{
		"msg":                 "response_trigger",
		"trigger_kind":        "alert",
		"trigger_idem_key":    triggerID,
		"alert_key":           strings.TrimSpace(alert.AlertKey),
		"rule_id":             strings.TrimSpace(alert.RuleID),
		"severity":            strings.TrimSpace(alert.Severity),
		"lane":                lane,
		"observed_at_unix_ms": observedAt,
		"event_ts_unix_ms":    eventTs,
		"alert_ts_unix_ms":    alertTs,
		"latency_ms":          latencyMs,
	}
	if strings.TrimSpace(alert.GroupBy) != "" {
		payload["group_by"] = strings.TrimSpace(alert.GroupBy)
	}
	if strings.TrimSpace(alert.GroupKey) != "" {
		payload["group_key"] = strings.TrimSpace(alert.GroupKey)
	}
	if strings.TrimSpace(alert.NodeID) != "" {
		payload["node_id"] = strings.TrimSpace(alert.NodeID)
	}
	if strings.TrimSpace(alert.SourceType) != "" {
		payload["source_type"] = strings.TrimSpace(alert.SourceType)
	}
	if strings.TrimSpace(alert.EventType) != "" {
		payload["event_type"] = strings.TrimSpace(alert.EventType)
	}
	if strings.TrimSpace(alert.SrcIP) != "" {
		payload["src_ip"] = strings.TrimSpace(alert.SrcIP)
	}
	if strings.TrimSpace(alert.User) != "" {
		payload["user"] = strings.TrimSpace(alert.User)
	}
	if strings.TrimSpace(alert.EventIdemKey) != "" {
		payload["event_idem_key"] = strings.TrimSpace(alert.EventIdemKey)
	}
	if strings.TrimSpace(alert.AgentID) != "" {
		payload["agent_id"] = strings.TrimSpace(alert.AgentID)
	}
	if strings.TrimSpace(alert.TargetAgentID) != "" {
		payload["target_agent_id"] = strings.TrimSpace(alert.TargetAgentID)
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	if _, err := p.js.Publish(subject, data); err != nil {
		return "", "", err
	}
	if p.logger != nil {
		p.logger.LogAttrs(context.Background(), slog.LevelInfo, "pubtrigger_published",
			slog.String("subject", subject),
			slog.String("trigger_idem_key", triggerID),
		)
	}
	return subject, triggerID, nil
}

func ensureResponseStream(js nats.JetStreamContext) error {
	_, err := js.AddStream(&nats.StreamConfig{
		Name: ResponseStream,
		Subjects: []string{
			ResponseTriggerFast,
			ResponseTriggerStd,
			ResponseStepsFast,
			ResponseStepsStd,
		},
	})
	if err != nil && !errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return err
	}
	return nil
}
