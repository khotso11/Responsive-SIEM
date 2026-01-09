package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/nats-io/nats.go"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
)

const (
	responseStream    = "RSIEM_RESPONSE"
	responseStepsFast = "rsiem.response.steps.fast"
	responseStepsStd  = "rsiem.response.steps.standard"
)

type stepMessage struct {
	RunID       string `json:"run_id"`
	StepID      string `json:"step_id"`
	StepIndex   int    `json:"step_index"`
	ActionType  string `json:"action_type"`
	Lane        string `json:"lane"`
	StepIdemKey string `json:"step_idem_key,omitempty"`
	Attempt     int    `json:"attempt"`
}

func main() {
	configPath := flag.String("config", "configs/master.yaml", "Path to master config")
	lane := flag.String("lane", "STANDARD", "FAST or STANDARD")
	runID := flag.String("run-id", "", "Run id")
	stepID := flag.String("step-id", "", "Step id")
	stepIndex := flag.Int("step-index", 0, "Step index")
	actionType := flag.String("action-type", "", "Action type")
	stepIdemKey := flag.String("step-idem-key", "", "Step idempotency key (optional)")
	attempt := flag.Int("attempt", 0, "Attempt")
	flag.Parse()

	if strings.TrimSpace(*runID) == "" || strings.TrimSpace(*stepID) == "" || strings.TrimSpace(*actionType) == "" {
		fmt.Fprintf(os.Stderr, "run-id, step-id, and action-type are required\n")
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

	nc, err := nats.Connect(cfg.JetStream.URL, nats.Name("r-siem-master-roe-pubstep"))
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
	subject := responseStepsStd
	if laneValue == "FAST" {
		subject = responseStepsFast
	}

	idemKey := strings.TrimSpace(*stepIdemKey)
	if idemKey == "" {
		idemKey = fmt.Sprintf("step.%s", shortHash(fmt.Sprintf("%s|%d|%s", strings.TrimSpace(*runID), *stepIndex, strings.TrimSpace(*actionType))))
	}

	msg := stepMessage{
		RunID:       strings.TrimSpace(*runID),
		StepID:      strings.TrimSpace(*stepID),
		StepIndex:   *stepIndex,
		ActionType:  strings.TrimSpace(*actionType),
		Lane:        laneValue,
		StepIdemKey: idemKey,
		Attempt:     *attempt,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		logger.Error("pubstep_encode_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if _, err := js.Publish(subject, data); err != nil {
		logger.Error("pubstep_publish_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "pubstep_published",
		slog.String("subject", subject),
		slog.String("run_id", msg.RunID),
		slog.String("step_id", msg.StepID),
		slog.String("step_idem_key", idemKey),
	)
}

func ensureResponseStream(js nats.JetStreamContext) error {
	_, err := js.AddStream(&nats.StreamConfig{
		Name: responseStream,
		Subjects: []string{
			responseStepsFast,
			responseStepsStd,
		},
	})
	if err != nil && !errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return err
	}
	return nil
}

func shortHash(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:16]
}
