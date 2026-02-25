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
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
	"r-siem-agent/internal/roe/trigger"
)

const (
	invalidUserRuleID        = "R-COLLECT-INVALID-USER"
	processCountRuleID       = "R-COUNT-PROCESS-HOST"
	fr03HostRuleID           = "R-FR03-HOST-BRUTEFORCE-BURST"
	fr03NetworkRuleID        = "R-FR03-NETWORK-C2-BEACON"
	fr03DeceptionRuleID      = "R-FR03-DECEPTION-TRIPWIRE"
	invalidUserLane          = "FAST"
	processCountLane         = "STANDARD"
	fr03Lane                 = "FAST"
	detectorSeverityHigh     = "high"
	detectorSeverityCritical = "critical"
	processCountThreshold    = 3
	fr03HostBurstThreshold   = 3
	fr03HostBurstWindowMs    = 5000
	defaultPullBatch         = 10
	defaultPullTimeout       = 500 * time.Millisecond
)

var (
	invalidUserPattern       = "invalid user"
	ipv4FromPattern          = regexp.MustCompile(`(?i)\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b`)
	processCountPattern      = regexp.MustCompile(`(?i)\bprocess_count=(\d+)\b`)
	explicitTSPattern        = regexp.MustCompile(`\bts=([0-9]{9,13})\b`)
	fr03HostMarkerPattern    = regexp.MustCompile(`(?i)\battack=host_bruteforce\b`)
	fr03NetworkMarkerPattern = regexp.MustCompile(`(?i)\battack=(network_scan|c2_beacon)\b`)
	fr03DeceptionPattern     = regexp.MustCompile(`(?i)\battack=deception_tripwire\b`)
	fr03HostBurstTracker     = newBurstTracker(fr03HostBurstWindowMs, fr03HostBurstThreshold)
)

type rawEvent struct {
	EventIdemKey     string `json:"event_idem_key"`
	ObservedAtUnixMs int64  `json:"observed_at_unix_ms"`
	Message          string `json:"message"`
	Host             string `json:"host"`
	User             string `json:"user,omitempty"`
	SrcIP            string `json:"src_ip,omitempty"`
	EventType        string `json:"event_type,omitempty"`
	Ts               int64  `json:"ts,omitempty"`
	GroupKey         string `json:"group_key"`
	Source           string `json:"source"`
	Line             string `json:"line"`
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

	message := eventMessage(evt)
	match, ok := matchRule(message, evt)
	if !ok {
		_ = msg.Ack()
		return
	}
	if strings.TrimSpace(match.GroupKey) == "" {
		logger.Info("missing_group_key",
			slog.String("event_idem_key", evt.EventIdemKey),
			slog.String("rule_id", match.RuleID),
		)
		_ = msg.Ack()
		return
	}
	logger.Info("rule_matched",
		slog.String("event_idem_key", evt.EventIdemKey),
		slog.String("rule_id", match.RuleID),
		slog.String("group_key", match.GroupKey),
	)
	eventTsUnixMs := extractEventTSUnixMs(evt, message)
	alertTsUnixMs := time.Now().UnixMilli()
	latencyMs := alertTsUnixMs - eventTsUnixMs
	if latencyMs < 0 {
		latencyMs = 0
	}
	logger.Info("detector_rule_matched",
		slog.String("rule_id", match.RuleID),
		slog.String("severity", match.Severity),
		slog.String("event_idem_key", evt.EventIdemKey),
		slog.String("event_type", evt.EventType),
		slog.String("src_ip", evt.SrcIP),
		slog.String("user", evt.User),
		slog.Int64("event_ts_unix_ms", eventTsUnixMs),
		slog.Int64("alert_ts_unix_ms", alertTsUnixMs),
		slog.Int64("latency_ms", latencyMs),
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

	cooldownKey := fmt.Sprintf("cd.%s.%s", match.RuleID, match.GroupKey)
	if remaining, hit, err := checkCooldown(cooldownKV, cooldownKey, cooldownMs); err != nil {
		logger.Error("cooldown_check_failed", slog.String("error", err.Error()))
		_ = kv.Delete(evt.EventIdemKey)
		return
	} else if hit {
		logger.Info("cooldown_hit",
			slog.String("rule_id", match.RuleID),
			slog.String("group_key", match.GroupKey),
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

	alertKey := alertKeyForRule(match.RuleID, evt.EventIdemKey)
	alert := trigger.Alert{
		AlertKey:         alertKey,
		RuleID:           match.RuleID,
		Severity:         match.Severity,
		Lane:             match.Lane,
		GroupKey:         match.GroupKey,
		ObservedAtUnixMs: alertTsUnixMs,
		EventTsUnixMs:    eventTsUnixMs,
		AlertTsUnixMs:    alertTsUnixMs,
		LatencyMs:        latencyMs,
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
	logger.Info("detector_alert_published",
		slog.String("rule_id", match.RuleID),
		slog.String("severity", match.Severity),
		slog.String("event_idem_key", evt.EventIdemKey),
		slog.Int64("event_ts_unix_ms", eventTsUnixMs),
		slog.Int64("alert_ts_unix_ms", alertTsUnixMs),
		slog.Int64("latency_ms", latencyMs),
	)

	_ = msg.Ack()
}

type ruleMatch struct {
	RuleID   string
	Lane     string
	Severity string
	GroupKey string
}

func eventMessage(evt rawEvent) string {
	msg := strings.TrimSpace(evt.Message)
	if msg != "" {
		return msg
	}
	return strings.TrimSpace(evt.Line)
}

func matchRule(message string, evt rawEvent) (ruleMatch, bool) {
	lower := strings.ToLower(strings.TrimSpace(message))
	if fr03DeceptionPattern.MatchString(lower) {
		groupKey := strings.TrimSpace(evt.SrcIP)
		if groupKey == "" {
			groupKey = extractIPv4(message)
		}
		return ruleMatch{
			RuleID:   fr03DeceptionRuleID,
			Lane:     fr03Lane,
			Severity: detectorSeverityCritical,
			GroupKey: groupKey,
		}, true
	}

	if fr03NetworkMarkerPattern.MatchString(lower) {
		groupKey := strings.TrimSpace(evt.SrcIP)
		if groupKey == "" {
			groupKey = extractIPv4(message)
		}
		return ruleMatch{
			RuleID:   fr03NetworkRuleID,
			Lane:     fr03Lane,
			Severity: detectorSeverityHigh,
			GroupKey: groupKey,
		}, true
	}

	if fr03HostMarkerPattern.MatchString(lower) {
		groupKey := strings.TrimSpace(evt.SrcIP)
		if groupKey == "" {
			groupKey = extractIPv4(message)
		}
		if groupKey == "" {
			return ruleMatch{}, false
		}
		if !fr03HostBurstTracker.Observe(groupKey, evt.ObservedAtUnixMs) {
			return ruleMatch{}, false
		}
		return ruleMatch{
			RuleID:   fr03HostRuleID,
			Lane:     fr03Lane,
			Severity: detectorSeverityHigh,
			GroupKey: groupKey,
		}, true
	}

	if strings.EqualFold(strings.TrimSpace(evt.EventType), "auth_failed") {
		groupKey := strings.TrimSpace(evt.SrcIP)
		if groupKey == "" {
			groupKey = extractIPv4(message)
		}
		return ruleMatch{
			RuleID:   invalidUserRuleID,
			Lane:     invalidUserLane,
			Severity: detectorSeverityHigh,
			GroupKey: groupKey,
		}, true
	}
	if strings.Contains(strings.ToLower(message), invalidUserPattern) {
		groupKey := extractIPv4(message)
		return ruleMatch{
			RuleID:   invalidUserRuleID,
			Lane:     invalidUserLane,
			Severity: detectorSeverityHigh,
			GroupKey: groupKey,
		}, true
	}

	if count, ok := parseProcessCount(message); ok && count >= processCountThreshold {
		groupKey := strings.TrimSpace(evt.Host)
		if groupKey == "" {
			groupKey = strings.TrimSpace(evt.GroupKey)
		}
		return ruleMatch{
			RuleID:   processCountRuleID,
			Lane:     processCountLane,
			Severity: detectorSeverityHigh,
			GroupKey: groupKey,
		}, true
	}
	return ruleMatch{}, false
}

func extractIPv4(line string) string {
	match := ipv4FromPattern.FindStringSubmatch(line)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func parseProcessCount(message string) (int, bool) {
	match := processCountPattern.FindStringSubmatch(message)
	if len(match) < 2 {
		return 0, false
	}
	parsed, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func alertKeyForRule(ruleID, eventID string) string {
	switch ruleID {
	case invalidUserRuleID:
		return "A-COLLECT-INVALID-USER-" + eventID
	case processCountRuleID:
		return "A-COUNT-PROCESS-HOST-" + eventID
	case fr03HostRuleID:
		return "A-FR03-HOST-BRUTEFORCE-BURST-" + eventID
	case fr03NetworkRuleID:
		return "A-FR03-NETWORK-C2-BEACON-" + eventID
	case fr03DeceptionRuleID:
		return "A-FR03-DECEPTION-TRIPWIRE-" + eventID
	default:
		return "A-UNKNOWN-" + eventID
	}
}

func extractEventTSUnixMs(evt rawEvent, message string) int64 {
	if m := explicitTSPattern.FindStringSubmatch(message); len(m) == 2 {
		if parsed, ok := parseUnixTSMillis(m[1]); ok && parsed > 0 {
			return parsed
		}
	}
	if evt.Ts > 0 {
		if evt.Ts >= 1_000_000_000_000 {
			return evt.Ts
		}
		return evt.Ts * 1000
	}
	if evt.ObservedAtUnixMs > 0 {
		return evt.ObservedAtUnixMs
	}
	return time.Now().UnixMilli()
}

func parseUnixTSMillis(raw string) (int64, bool) {
	ts, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, false
	}
	if ts <= 0 {
		return 0, false
	}
	if ts >= 1_000_000_000_000 {
		return ts, true
	}
	return ts * 1000, true
}

type burstTracker struct {
	mu        sync.Mutex
	windowMs  int64
	threshold int
	hitsByKey map[string][]int64
}

func newBurstTracker(windowMs int64, threshold int) *burstTracker {
	return &burstTracker{
		windowMs:  windowMs,
		threshold: threshold,
		hitsByKey: make(map[string][]int64, 64),
	}
}

func (b *burstTracker) Observe(key string, observedAtUnixMs int64) bool {
	if strings.TrimSpace(key) == "" {
		return false
	}
	if observedAtUnixMs <= 0 {
		observedAtUnixMs = time.Now().UnixMilli()
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	raw := b.hitsByKey[key]
	kept := raw[:0]
	cutoff := observedAtUnixMs - b.windowMs
	for _, ts := range raw {
		if ts >= cutoff {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, observedAtUnixMs)
	b.hitsByKey[key] = kept
	return len(kept) == b.threshold
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
