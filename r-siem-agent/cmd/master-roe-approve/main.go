package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"gopkg.in/yaml.v3"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
)

type roeApproveConfig struct {
	ROE struct {
		Jetstream struct {
			SubjectApprovals string `yaml:"subject_approvals"`
		} `yaml:"jetstream"`
	} `yaml:"roe"`
}

const defaultApprovalsSubject = "rsiem.response.approvals"

func main() {
	configPath := flag.String("config", "configs/master.yaml", "Path to master config")
	runID := flag.String("run_id", "", "Run ID to approve/deny")
	decision := flag.String("decision", "", "approve|deny")
	actor := flag.String("actor", "", "Actor making the decision")
	reason := flag.String("reason", "", "Reason for decision")
	flag.Parse()

	if strings.TrimSpace(*runID) == "" {
		fmt.Fprintln(os.Stderr, "run_id is required")
		os.Exit(2)
	}
	dec := strings.ToLower(strings.TrimSpace(*decision))
	if dec != "approve" && dec != "deny" {
		fmt.Fprintln(os.Stderr, "decision must be approve or deny")
		os.Exit(2)
	}

	baseCfg, err := config.LoadMaster(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := logging.NewLogger(baseCfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}

	subject, err := loadApprovalsSubject(*configPath)
	if err != nil {
		logger.Error("approval_config_load_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	nc, err := nats.Connect(baseCfg.JetStream.URL, nats.Name("r-siem-master-roe-approve"))
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

	payload := map[string]any{
		"run_id":     strings.TrimSpace(*runID),
		"decision":   dec,
		"actor":      strings.TrimSpace(*actor),
		"reason":     strings.TrimSpace(*reason),
		"ts_unix_ms": time.Now().UnixMilli(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		logger.Error("approval_payload_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if _, err := js.Publish(subject, data); err != nil {
		logger.Error("approval_publish_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "approval_published",
		slog.String("run_id", *runID),
		slog.String("decision", dec),
		slog.String("subject", subject),
	)
}

func loadApprovalsSubject(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var cfg roeApproveConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", err
	}
	subject := strings.TrimSpace(cfg.ROE.Jetstream.SubjectApprovals)
	if subject == "" {
		subject = defaultApprovalsSubject
	}
	return subject, nil
}
