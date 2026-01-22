package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
	"r-siem-agent/internal/roe/trigger"
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

	publisher, err := trigger.NewPublisher(logger, js)
	if err != nil {
		logger.Error("ensure_response_stream_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	laneValue := strings.ToUpper(strings.TrimSpace(*lane))
	if laneValue != "FAST" && laneValue != "STANDARD" {
		fmt.Fprintf(os.Stderr, "lane must be FAST or STANDARD\n")
		os.Exit(1)
	}
	alert := trigger.Alert{
		AlertKey:         strings.TrimSpace(*alertKey),
		RuleID:           strings.TrimSpace(*ruleID),
		Severity:         strings.TrimSpace(*severity),
		Lane:             laneValue,
		GroupBy:          strings.TrimSpace(*groupBy),
		GroupKey:         strings.TrimSpace(*groupKey),
		ObservedAtUnixMs: time.Now().UnixMilli(),
	}
	if _, _, err := publisher.PublishAlert(alert); err != nil {
		logger.Error("pubtrigger_publish_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
