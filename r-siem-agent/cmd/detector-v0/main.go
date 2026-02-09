package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
	"r-siem-agent/internal/roe/trigger"
)

const (
	ruleID             = "R-COLLECT-INVALID-USER"
	detectorLane       = "FAST"
	detectorSeverity   = "high"
	defaultPullBatch   = 10
	defaultPullTimeout = 500 * time.Millisecond
)

var (
	invalidUserPattern = "invalid user"
	ipv4FromPattern    = regexp.MustCompile(`(?i)\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b`)
)

type rawEvent struct {
	EventIdemKey string `json:"event_idem_key"`
	Line         string `json:"line"`
}

func main() {
	configPath := flag.String("config", "configs/detector.yaml", "Path to detector config")
	flag.Parse()

	cfg, err := config.LoadDetector(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}
	logger, err := logging.NewLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}

	nc, err := nats.Connect(cfg.JetStream.URL, nats.Name("r-siem-detector-v0"))
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
	if err := ensureEventsStream(js, cfg.JetStream.Stream, cfg.JetStream.Subject); err != nil {
		logger.Error("ensure_events_stream_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := ensureConsumer(js, cfg.JetStream.Stream, cfg.JetStream.Subject, cfg.JetStream.Durable); err != nil {
		logger.Error("ensure_consumer_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	kv, err := ensureKV(js, cfg.Dedupe.Bucket)
	if err != nil {
		logger.Error("ensure_dedupe_kv_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	cooldownKV, err := ensureKV(js, cfg.Cooldown.Bucket)
	if err != nil {
		logger.Error("ensure_cooldown_kv_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	publisher, err := trigger.NewPublisher(logger, js)
	if err != nil {
		logger.Error("ensure_response_stream_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	sub, err := js.PullSubscribe(cfg.JetStream.Subject, cfg.JetStream.Durable, nats.BindStream(cfg.JetStream.Stream))
	if err != nil {
		logger.Error("subscribe_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.Info("detector_started",
		slog.String("subject", cfg.JetStream.Subject),
		slog.String("durable", cfg.JetStream.Durable),
		slog.String("kv_bucket", cfg.Dedupe.Bucket),
		slog.String("cooldown_bucket", cfg.Cooldown.Bucket),
		slog.Int("cooldown_ms", cfg.CooldownMs),
	)

	ctx, cancel := signalContext()
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			logger.Info("detector_stopped")
			return
		default:
		}

		msgs, err := sub.Fetch(defaultPullBatch, nats.MaxWait(defaultPullTimeout))
		if err != nil {
			if err == nats.ErrTimeout {
				continue
			}
			logger.Error("fetch_failed", slog.String("error", err.Error()))
			continue
		}
		for _, msg := range msgs {
			handleMessage(ctx, logger, kv, cooldownKV, publisher, cfg.CooldownMs, msg)
		}
	}
}

func handleMessage(ctx context.Context, logger *slog.Logger, kv nats.KeyValue, cooldownKV nats.KeyValue, publisher *trigger.Publisher, cooldownMs int, msg *nats.Msg) {
	var evt rawEvent
	if err := json.Unmarshal(msg.Data, &evt); err != nil {
		logger.Error("event_decode_failed", slog.String("error", err.Error()))
		_ = msg.Ack()
		return
	}
	if strings.TrimSpace(evt.EventIdemKey) == "" {
		logger.Warn("event_missing_idem_key")
		_ = msg.Ack()
		return
	}

	logger.Info("event_received", slog.String("event_idem_key", evt.EventIdemKey))

	if !matchesRule(evt.Line) {
		_ = msg.Ack()
		return
	}

	groupKey := extractIPv4(evt.Line)
	if groupKey == "" {
		logger.Info("missing_group_key", slog.String("event_idem_key", evt.EventIdemKey))
		_ = msg.Ack()
		return
	}
	logger.Info("rule_matched",
		slog.String("event_idem_key", evt.EventIdemKey),
		slog.String("group_key", groupKey),
	)

	entry, err := kv.Get(evt.EventIdemKey)
	if err == nil && entry != nil {
		logger.Info("detect_dedup_hit", slog.String("event_idem_key", evt.EventIdemKey))
		_ = msg.Ack()
		return
	}
	if err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
		logger.Error("detect_dedup_get_failed", slog.String("error", err.Error()))
		return
	}

	if _, err := kv.Put(evt.EventIdemKey, []byte("1")); err != nil {
		logger.Error("detect_dedup_put_failed", slog.String("error", err.Error()))
		return
	}

	cooldownKey := fmt.Sprintf("cd.%s.%s", ruleID, groupKey)
	if remaining, hit, err := checkCooldown(cooldownKV, cooldownKey, cooldownMs); err != nil {
		logger.Error("cooldown_check_failed", slog.String("error", err.Error()))
		_ = kv.Delete(evt.EventIdemKey)
		return
	} else if hit {
		logger.Info("cooldown_hit",
			slog.String("rule_id", ruleID),
			slog.String("group_key", groupKey),
			slog.Int64("remaining_ms", remaining),
		)
		_ = msg.Ack()
		return
	}

	nowMs := time.Now().UnixMilli()
	if _, err := cooldownKV.Put(cooldownKey, []byte(strconv.FormatInt(nowMs, 10))); err != nil {
		logger.Error("cooldown_put_failed", slog.String("error", err.Error()))
		_ = kv.Delete(evt.EventIdemKey)
		return
	}

	alertKey := "A-COLLECT-INVALID-USER-" + evt.EventIdemKey
	alert := trigger.Alert{
		AlertKey:         alertKey,
		RuleID:           ruleID,
		Severity:         detectorSeverity,
		Lane:             detectorLane,
		GroupKey:         groupKey,
		ObservedAtUnixMs: time.Now().UnixMilli(),
	}
	_, triggerID, err := publisher.PublishAlert(alert)
	if err != nil {
		_ = cooldownKV.Delete(cooldownKey)
		_ = kv.Delete(evt.EventIdemKey)
		logger.Error("trigger_publish_failed", slog.String("error", err.Error()))
		return
	}
	logger.Info("trigger_published",
		slog.String("alert_key", alertKey),
		slog.String("trigger_idem_key", triggerID),
	)

	_ = msg.Ack()
}

func matchesRule(line string) bool {
	return strings.Contains(strings.ToLower(line), invalidUserPattern)
}

func extractIPv4(line string) string {
	match := ipv4FromPattern.FindStringSubmatch(line)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func checkCooldown(kv nats.KeyValue, key string, cooldownMs int) (int64, bool, error) {
	entry, err := kv.Get(key)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return 0, false, nil
		}
		return 0, false, err
	}
	lastMs, err := strconv.ParseInt(string(entry.Value()), 10, 64)
	if err != nil {
		return 0, false, nil
	}
	now := time.Now().UnixMilli()
	elapsed := now - lastMs
	remaining := int64(cooldownMs) - elapsed
	if remaining > 0 {
		return remaining, true, nil
	}
	return 0, false, nil
}

func ensureEventsStream(js nats.JetStreamContext, stream, subject string) error {
	_, err := js.AddStream(&nats.StreamConfig{
		Name:     stream,
		Subjects: []string{subject},
	})
	if err != nil && !errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return err
	}
	return nil
}

func ensureConsumer(js nats.JetStreamContext, stream, subject, durable string) error {
	_, err := js.AddConsumer(stream, &nats.ConsumerConfig{
		Durable:       durable,
		FilterSubject: subject,
		AckPolicy:     nats.AckExplicitPolicy,
	})
	if err != nil && !errors.Is(err, nats.ErrConsumerNameAlreadyInUse) {
		return err
	}
	return nil
}

func ensureKV(js nats.JetStreamContext, bucket string) (nats.KeyValue, error) {
	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: bucket})
	if err == nil {
		return kv, nil
	}
	existing, existingErr := js.KeyValue(bucket)
	if existingErr == nil {
		return existing, nil
	}
	return nil, err
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}
