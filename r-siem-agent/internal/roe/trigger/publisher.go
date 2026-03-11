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
	ConfidenceScore  int
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
	DstIP            string
	User             string
	ExecPath         string
	Comm             string
	Cmdline          string
	FilePath         string
	FileSHA256       string
	ExecSHA256       string
	SignerHint       string
	DNSName          string
	DNSType          string
	EventIdemKey     string
	AgentID          string
	TargetAgentID    string
}

func normalizeConfidence(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func defaultConfidenceForSeverity(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 70
	case "high":
		return 58
	case "medium":
		return 46
	case "low":
		return 32
	case "info":
		return 20
	default:
		return 40
	}
}

func deriveConfidence(alert Alert) int {
	score := defaultConfidenceForSeverity(alert.Severity)
	if strings.EqualFold(strings.TrimSpace(alert.Lane), "FAST") {
		score += 6
	}
	switch strings.ToLower(strings.TrimSpace(alert.SourceType)) {
	case "auditd_exec":
		score += 8
	case "inotify":
		score += 7
	case "dns_packet":
		score += 6
	case "proc_net":
		score += 4
	case "host", "tail":
		score += 3
	}
	user := strings.ToLower(strings.TrimSpace(alert.User))
	if user != "" && user != "unknown" {
		score += 6
	}
	if strings.TrimSpace(alert.ExecPath) != "" {
		score += 6
	}
	if strings.TrimSpace(alert.Comm) != "" {
		score += 4
	}
	if strings.TrimSpace(alert.Cmdline) != "" {
		score += 4
	}
	if strings.TrimSpace(alert.DstIP) != "" {
		score += 3
	}
	if strings.TrimSpace(alert.DNSName) != "" {
		score += 6
	}
	if strings.TrimSpace(alert.FileSHA256) != "" {
		score += 6
	}
	if strings.TrimSpace(alert.ExecSHA256) != "" {
		score += 6
	}
	if strings.TrimSpace(alert.SignerHint) != "" {
		score += 2
	}
	return normalizeConfidence(score)
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
	confidence := normalizeConfidence(alert.ConfidenceScore)
	if confidence == 0 {
		confidence = deriveConfidence(alert)
	}
	payload["confidence_score"] = confidence
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
	if strings.TrimSpace(alert.DstIP) != "" {
		payload["dst_ip"] = strings.TrimSpace(alert.DstIP)
	}
	if strings.TrimSpace(alert.ExecPath) != "" {
		payload["exec_path"] = strings.TrimSpace(alert.ExecPath)
	}
	if strings.TrimSpace(alert.Comm) != "" {
		payload["comm"] = strings.TrimSpace(alert.Comm)
	}
	if strings.TrimSpace(alert.Cmdline) != "" {
		payload["cmdline"] = strings.TrimSpace(alert.Cmdline)
	}
	if strings.TrimSpace(alert.FilePath) != "" {
		payload["file_path"] = strings.TrimSpace(alert.FilePath)
	}
	if strings.TrimSpace(alert.FileSHA256) != "" {
		payload["file_sha256"] = strings.TrimSpace(alert.FileSHA256)
	}
	if strings.TrimSpace(alert.ExecSHA256) != "" {
		payload["exec_sha256"] = strings.TrimSpace(alert.ExecSHA256)
	}
	if strings.TrimSpace(alert.SignerHint) != "" {
		payload["signer_hint"] = strings.TrimSpace(alert.SignerHint)
	}
	if strings.TrimSpace(alert.DNSName) != "" {
		payload["dns_name"] = strings.TrimSpace(alert.DNSName)
	}
	if strings.TrimSpace(alert.DNSType) != "" {
		payload["dns_type"] = strings.TrimSpace(alert.DNSType)
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
