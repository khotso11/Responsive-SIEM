package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
)

const (
	responseStream      = "RSIEM_RESPONSE"
	responseTriggerFast = "rsiem.response.triggers.fast"
	responseTriggerStd  = "rsiem.response.triggers.standard"
	responseStepsFast   = "rsiem.response.steps.fast"
	responseStepsStd    = "rsiem.response.steps.standard"
)

func main() {
	configPath := flag.String("config", "configs/master.yaml", "Path to master config")
	lane := flag.String("lane", "STANDARD", "FAST or STANDARD")
	alertKey := flag.String("alert-key", "", "Alert key")
	ruleID := flag.String("rule-id", "", "Rule id")
	severity := flag.String("severity", "", "Severity (low|medium|high)")
	groupBy := flag.String("group-by", "", "Group by (optional)")
	groupKey := flag.String("group-key", "", "Group key (optional)")
	flag.Parse()

	if strings.TrimSpace(*alertKey) == "" || strings.TrimSpace(*ruleID) == "" || strings.TrimSpace(*severity) == "" {
		fmt.Fprintf(os.Stderr, "alert-key, rule-id, and severity are required\n")
		os.Exit(1)
	}

	cfg, err := config.LoadMaster(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}
	logger, err := logging.NewLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}

	nc, err := nats.Connect(cfg.JetStream.URL, nats.Name("r-siem-master-roe-pubtrigger"))
	if err != nil {
		logger.Error("nats_connect_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		logger.Error("jetstream_context_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if err := ensureResponseStream(js); err != nil {
		logger.Error("ensure_response_stream_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	laneValue := strings.ToUpper(strings.TrimSpace(*lane))
	if laneValue != "FAST" && laneValue != "STANDARD" {
		fmt.Fprintf(os.Stderr, "lane must be FAST or STANDARD\n")
		os.Exit(1)
	}
	subject := responseTriggerStd
	if laneValue == "FAST" {
		subject = responseTriggerFast
	}

	triggerID := fmt.Sprintf("trig.alert.%s", strings.TrimSpace(*alertKey))
	payload := map[string]any{
		"msg":                 "response_trigger",
		"trigger_kind":        "alert",
		"trigger_idem_key":    triggerID,
		"alert_key":           strings.TrimSpace(*alertKey),
		"rule_id":             strings.TrimSpace(*ruleID),
		"severity":            strings.TrimSpace(*severity),
		"lane":                laneValue,
		"observed_at_unix_ms": time.Now().UnixMilli(),
	}
	if strings.TrimSpace(*groupBy) != "" {
		payload["group_by"] = strings.TrimSpace(*groupBy)
	}
	if strings.TrimSpace(*groupKey) != "" {
		payload["group_key"] = strings.TrimSpace(*groupKey)
	}

	data, err := json.Marshal(payload)
	if err != nil {
		logger.Error("pubtrigger_encode_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if _, err := js.Publish(subject, data); err != nil {
		logger.Error("pubtrigger_publish_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "pubtrigger_published",
		slog.String("subject", subject),
		slog.String("trigger_idem_key", triggerID),
	)
}

func ensureResponseStream(js nats.JetStreamContext) error {
	_, err := js.AddStream(&nats.StreamConfig{
		Name: responseStream,
		Subjects: []string{
			responseTriggerFast,
			responseTriggerStd,
			responseStepsFast,
			responseStepsStd,
		},
	})
	if err != nil && !errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return err
	}
	return nil
}
