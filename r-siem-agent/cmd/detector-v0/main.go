package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
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
	statProcessRuleID        = "R-STAT-PROCESS-MED"
	processCountRuleID       = "R-COUNT-PROCESS-HOST"
	fileSensitiveRuleID      = "R-FILE-SENSITIVE-CHANGE"
	networkObserveRuleID     = "R-NET-OUTBOUND-CONNECTION"
	authProcFileRuleID       = "R-AUTH-PROC-FILE-CHAIN"
	processFirstSeenRuleID   = "R-PROC-FIRST-SEEN-SUSPICIOUS"
	networkFirstSeenRuleID   = "R-NET-FIRST-SEEN-RISKY"
	dnsSuspiciousRuleID      = "R-DNS-SUSPICIOUS-QUERY"
	fr03HostRuleID           = "R-FR03-HOST-BRUTEFORCE-BURST"
	fr03NetworkRuleID        = "R-FR03-NETWORK-C2-BEACON"
	fr03DeceptionRuleID      = "R-FR03-DECEPTION-TRIPWIRE"
	invalidUserLane          = "FAST"
	statProcessLane          = "STANDARD"
	processCountLane         = "STANDARD"
	fileSensitiveLane        = "FAST"
	networkObserveLane       = "STANDARD"
	fr03Lane                 = "FAST"
	detectorSeverityMedium   = "medium"
	detectorSeverityHigh     = "high"
	detectorSeverityCritical = "critical"
	processCountThreshold    = 3
	processBurstWindowMs     = 60000
	fr03HostBurstThreshold   = 3
	fr03HostBurstWindowMs    = 5000
	defaultPullBatch         = 10
	defaultPullTimeout       = 500 * time.Millisecond
)

var (
	invalidUserPattern          = "invalid user"
	ipv4FromPattern             = regexp.MustCompile(`(?i)\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b`)
	processCountPattern         = regexp.MustCompile(`(?i)\bprocess_count=(\d+)\b`)
	explicitTSPattern           = regexp.MustCompile(`\bts=([0-9]{9,13})\b`)
	fr03HostMarkerPattern       = regexp.MustCompile(`(?i)\battack=host_bruteforce\b`)
	fr03NetworkMarkerPattern    = regexp.MustCompile(`(?i)\battack=(network_scan|c2_beacon)\b`)
	fr03DeceptionPattern        = regexp.MustCompile(`(?i)\battack=deception_tripwire\b`)
	suspiciousProcPattern       = regexp.MustCompile(`(?i)\b(exec=)?("?)(/usr/bin/(nmap|nc|curl|wget)|/bin/(bash|sh)|/usr/bin/python3?)\b`)
	sensitiveFilePattern        = regexp.MustCompile(`(?i)(/etc/(sudoers|passwd|shadow)\b|authorized_keys\b|/root/\.ssh/)`)
	dstIPPattern                = regexp.MustCompile(`(?i)\bdst_ip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b`)
	dstPortPattern              = regexp.MustCompile(`(?i)\bdst_port=(\d{1,5})\b`)
	dnsNamePattern              = regexp.MustCompile(`(?i)\bqname=([A-Za-z0-9._-]+)\b`)
	dnsTypePattern              = regexp.MustCompile(`(?i)\bqtype=([A-Za-z0-9]+)\b`)
	fr03HostBurstTracker        = newBurstTracker(fr03HostBurstWindowMs, fr03HostBurstThreshold)
	processBurstTracker         = newBurstTracker(processBurstWindowMs, processCountThreshold)
	networkBurstTracker         *burstTracker
	knownBadNetworkDestinations map[string]struct{}
	benignNetworkDestinations   map[string]struct{}
	knownBadDomains             map[string]struct{}
	suspiciousDNSTLDs           []string
	riskyNetworkPorts           map[int]struct{}
	recentAuthByNode            = newLastSeenTracker(5 * time.Minute)
	recentSuspiciousProcByNode  = newLastSeenTracker(2 * time.Minute)
	recentSuspiciousProcContext = newRecentProcessContextTracker(2 * time.Minute)
	recentAuthProcByNode        = newLastSeenTracker(5 * time.Minute)
	processFirstSeenTracker     *firstSeenTracker
	networkFirstSeenTracker     *firstSeenTracker
)

type rawEvent struct {
	EventIdemKey     string `json:"event_idem_key"`
	ObservedAtUnixMs int64  `json:"observed_at_unix_ms"`
	Message          string `json:"message"`
	Host             string `json:"host"`
	User             string `json:"user,omitempty"`
	SrcIP            string `json:"src_ip,omitempty"`
	EventType        string `json:"event_type,omitempty"`
	NodeID           string `json:"node_id,omitempty"`
	SourceType       string `json:"source_type,omitempty"`
	DstIP            string `json:"dst_ip,omitempty"`
	DstPort          int    `json:"dst_port,omitempty"`
	DNSName          string `json:"dns_name,omitempty"`
	DNSType          string `json:"dns_type,omitempty"`
	ExecPath         string `json:"exec_path,omitempty"`
	Comm             string `json:"comm,omitempty"`
	Cmdline          string `json:"cmdline,omitempty"`
	PID              int    `json:"pid,omitempty"`
	PPID             int    `json:"ppid,omitempty"`
	SessionID        int    `json:"session_id,omitempty"`
	TTY              string `json:"tty,omitempty"`
	FilePath         string `json:"file_path,omitempty"`
	FileSHA256       string `json:"file_sha256,omitempty"`
	ExecSHA256       string `json:"exec_sha256,omitempty"`
	SignerHint       string `json:"signer_hint,omitempty"`
	EventTsUnixMs    int64  `json:"event_ts_unix_ms,omitempty"`
	RecvTsUnixMs     int64  `json:"recv_ts_unix_ms,omitempty"`
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
	initNetworkPolicy(cfg)
	initBaselinePolicy(cfg)

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
	evt = enrichNetworkEventIdentity(evt)
	match, ok := matchRule(message, evt)
	if !ok {
		_ = msg.Ack()
		return
	}
	recordSuspiciousProcessContext(match, evt)
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
		slog.String("source_type", evt.SourceType),
		slog.String("node_id", detectorNodeID(evt)),
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
		NodeID:           detectorNodeID(evt),
		SourceType:       strings.TrimSpace(evt.SourceType),
		EventType:        strings.TrimSpace(evt.EventType),
		SrcIP:            strings.TrimSpace(evt.SrcIP),
		DstIP:            strings.TrimSpace(evt.DstIP),
		User:             strings.TrimSpace(evt.User),
		ExecPath:         strings.TrimSpace(evt.ExecPath),
		Comm:             strings.TrimSpace(evt.Comm),
		Cmdline:          strings.TrimSpace(evt.Cmdline),
		FilePath:         strings.TrimSpace(evt.FilePath),
		FileSHA256:       strings.TrimSpace(evt.FileSHA256),
		ExecSHA256:       strings.TrimSpace(evt.ExecSHA256),
		SignerHint:       strings.TrimSpace(evt.SignerHint),
		DNSName:          strings.TrimSpace(evt.DNSName),
		DNSType:          strings.TrimSpace(evt.DNSType),
		EventIdemKey:     strings.TrimSpace(evt.EventIdemKey),
		AgentID:          detectorNodeID(evt),
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
		slog.String("source_type", evt.SourceType),
		slog.String("node_id", detectorNodeID(evt)),
		slog.Int64("event_ts_unix_ms", eventTsUnixMs),
		slog.Int64("alert_ts_unix_ms", alertTsUnixMs),
		slog.Int64("latency_ms", latencyMs),
	)

	_ = msg.Ack()
}

func enrichNetworkEventIdentity(evt rawEvent) rawEvent {
	if !eventTypeIs(evt.EventType, "network", "network_connection") {
		return evt
	}
	user := strings.ToLower(strings.TrimSpace(evt.User))
	if user != "" && user != "unknown" {
		return evt
	}
	if strings.TrimSpace(evt.ExecPath) != "" || strings.TrimSpace(evt.Comm) != "" || strings.TrimSpace(evt.Cmdline) != "" {
		return evt
	}
	nodeKey := detectorNodeID(evt)
	if nodeKey == "" {
		nodeKey = strings.TrimSpace(evt.GroupKey)
	}
	if nodeKey == "" {
		return evt
	}
	ctx, ok := recentSuspiciousProcContext.Recent(nodeKey, evt.ObservedAtUnixMs)
	if !ok {
		return evt
	}
	if strings.TrimSpace(evt.User) == "" || strings.EqualFold(strings.TrimSpace(evt.User), "unknown") {
		evt.User = ctx.User
	}
	if strings.TrimSpace(evt.ExecPath) == "" {
		evt.ExecPath = ctx.ExecPath
	}
	if strings.TrimSpace(evt.Comm) == "" {
		evt.Comm = ctx.Comm
	}
	if strings.TrimSpace(evt.Cmdline) == "" {
		evt.Cmdline = ctx.Cmdline
	}
	return evt
}

func recordSuspiciousProcessContext(match ruleMatch, evt rawEvent) {
	if match.RuleID != processFirstSeenRuleID && match.RuleID != statProcessRuleID {
		return
	}
	nodeKey := detectorNodeID(evt)
	if nodeKey == "" {
		nodeKey = strings.TrimSpace(evt.GroupKey)
	}
	if nodeKey == "" {
		return
	}
	recentSuspiciousProcContext.Observe(nodeKey, recentProcessContext{
		User:       strings.TrimSpace(evt.User),
		ExecPath:   strings.TrimSpace(evt.ExecPath),
		Comm:       strings.TrimSpace(evt.Comm),
		Cmdline:    strings.TrimSpace(evt.Cmdline),
		ObservedAt: evt.ObservedAtUnixMs,
	})
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
	if eventTypeIs(evt.EventType, "dns", "dns_query") {
		qname := strings.TrimSpace(evt.DNSName)
		if qname == "" {
			qname = matchString(dnsNamePattern, message)
		}
		qname = strings.ToLower(strings.TrimSpace(qname))
		if qname != "" && (isKnownBadDomain(qname) || hasSuspiciousDNSTLD(qname)) {
			groupKey := qname
			return ruleMatch{
				RuleID:   dnsSuspiciousRuleID,
				Lane:     fr03Lane,
				Severity: detectorSeverityHigh,
				GroupKey: groupKey,
			}, true
		}
	}

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

	if eventTypeIs(evt.EventType, "file", "file_change") && sensitiveFilePattern.MatchString(message) {
		groupKey := strings.TrimSpace(evt.Host)
		if groupKey == "" {
			groupKey = detectorNodeID(evt)
		}
		if groupKey == "" {
			groupKey = strings.TrimSpace(evt.GroupKey)
		}
		if recentAuthProcByNode.SeenWithin(groupKey, evt.ObservedAtUnixMs) {
			return ruleMatch{
				RuleID:   authProcFileRuleID,
				Lane:     fr03Lane,
				Severity: detectorSeverityCritical,
				GroupKey: groupKey,
			}, true
		}
		return ruleMatch{
			RuleID:   fileSensitiveRuleID,
			Lane:     fileSensitiveLane,
			Severity: detectorSeverityHigh,
			GroupKey: groupKey,
		}, true
	}

	if isProcessEvent(evt, message) {
		groupKey := strings.TrimSpace(evt.Host)
		if groupKey == "" {
			groupKey = detectorNodeID(evt)
		}
		if groupKey == "" {
			groupKey = strings.TrimSpace(evt.GroupKey)
		}
		suspicious := suspiciousProcPattern.MatchString(processEvidenceText(evt, message))
		if suspicious {
			recentSuspiciousProcByNode.Observe(groupKey, evt.ObservedAtUnixMs)
			if recentAuthByNode.SeenWithin(groupKey, evt.ObservedAtUnixMs) {
				recentAuthProcByNode.Observe(groupKey, evt.ObservedAtUnixMs)
			}
			firstSeenKey := strings.TrimSpace(groupKey) + "|" + strings.TrimSpace(evt.User) + "|" + strings.TrimSpace(evt.ExecPath)
			if processFirstSeenTracker != nil && processFirstSeenTracker.Observe(firstSeenKey, evt.ObservedAtUnixMs) {
				return ruleMatch{
					RuleID:   processFirstSeenRuleID,
					Lane:     fr03Lane,
					Severity: detectorSeverityHigh,
					GroupKey: groupKey,
				}, true
			}
			return ruleMatch{
				RuleID:   statProcessRuleID,
				Lane:     statProcessLane,
				Severity: detectorSeverityMedium,
				GroupKey: groupKey,
			}, true
		}
		if groupKey != "" && processBurstTracker.Observe(groupKey, evt.ObservedAtUnixMs) {
			return ruleMatch{
				RuleID:   processCountRuleID,
				Lane:     processCountLane,
				Severity: detectorSeverityHigh,
				GroupKey: groupKey,
			}, true
		}
	}

	if eventTypeIs(evt.EventType, "network", "network_connection") {
		dstIP := strings.TrimSpace(evt.DstIP)
		if dstIP == "" {
			dstIP = extractDstIP(message)
		}
		if dstIP == "" || !isPublicIPv4(dstIP) || isBenignNetworkDestination(dstIP) {
			return ruleMatch{}, false
		}
		dstPort := evt.DstPort
		if dstPort == 0 {
			dstPort = extractDstPort(message)
		}
		groupKey := strings.TrimSpace(evt.Host)
		if groupKey == "" {
			groupKey = detectorNodeID(evt)
		}
		if groupKey == "" {
			groupKey = strings.TrimSpace(evt.GroupKey)
		}
		repeated := networkBurstTracker != nil && networkBurstTracker.Observe(dstIP, evt.ObservedAtUnixMs)
		if groupKey != "" && recentSuspiciousProcByNode.SeenWithin(groupKey, evt.ObservedAtUnixMs) && (isRiskyNetworkPort(dstPort) || repeated || isKnownBadNetworkDestination(dstIP)) {
			return ruleMatch{
				RuleID:   "R-SEQ-PROCESS-TO-NET",
				Lane:     fr03Lane,
				Severity: detectorSeverityHigh,
				GroupKey: groupKey,
			}, true
		}
		firstSeenKey := strings.TrimSpace(groupKey) + "|" + dstIP + ":" + strconv.Itoa(dstPort)
		if networkFirstSeenTracker != nil && networkFirstSeenTracker.Observe(firstSeenKey, evt.ObservedAtUnixMs) && (isKnownBadNetworkDestination(dstIP) || isRiskyNetworkPort(dstPort)) {
			return ruleMatch{
				RuleID:   networkFirstSeenRuleID,
				Lane:     fr03Lane,
				Severity: detectorSeverityHigh,
				GroupKey: dstIP,
			}, true
		}
		if isKnownBadNetworkDestination(dstIP) || isRiskyNetworkPort(dstPort) || repeated {
			return ruleMatch{
				RuleID:   networkObserveRuleID,
				Lane:     networkObserveLane,
				Severity: detectorSeverityHigh,
				GroupKey: dstIP,
			}, true
		}
	}

	if strings.EqualFold(strings.TrimSpace(evt.EventType), "auth_failed") {
		groupKey := strings.TrimSpace(evt.SrcIP)
		if groupKey == "" {
			groupKey = extractIPv4(message)
		}
		nodeKey := strings.TrimSpace(evt.Host)
		if nodeKey == "" {
			nodeKey = detectorNodeID(evt)
		}
		if nodeKey == "" {
			nodeKey = strings.TrimSpace(evt.GroupKey)
		}
		recentAuthByNode.Observe(nodeKey, evt.ObservedAtUnixMs)
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

func extractDstIP(line string) string {
	match := dstIPPattern.FindStringSubmatch(line)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractDstPort(line string) int {
	match := dstPortPattern.FindStringSubmatch(line)
	if len(match) < 2 {
		return 0
	}
	parsed, err := strconv.Atoi(match[1])
	if err != nil || parsed <= 0 || parsed > 65535 {
		return 0
	}
	return parsed
}

func matchString(pattern *regexp.Regexp, line string) string {
	match := pattern.FindStringSubmatch(line)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func initNetworkPolicy(cfg *config.DetectorConfig) {
	benignNetworkDestinations = make(map[string]struct{}, len(cfg.Network.BenignDestinationIPs))
	for _, raw := range cfg.Network.BenignDestinationIPs {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		benignNetworkDestinations[ip] = struct{}{}
	}
	knownBadNetworkDestinations = make(map[string]struct{}, len(cfg.Network.KnownBadDestinationIPs))
	for _, raw := range cfg.Network.KnownBadDestinationIPs {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		knownBadNetworkDestinations[ip] = struct{}{}
	}
	knownBadDomains = make(map[string]struct{}, len(cfg.DNS.KnownBadDomains))
	for _, raw := range cfg.DNS.KnownBadDomains {
		domain := strings.ToLower(strings.TrimSpace(raw))
		if domain == "" {
			continue
		}
		knownBadDomains[domain] = struct{}{}
	}
	suspiciousDNSTLDs = make([]string, 0, len(cfg.DNS.SuspiciousTLDs))
	for _, raw := range cfg.DNS.SuspiciousTLDs {
		tld := strings.ToLower(strings.TrimSpace(raw))
		if tld == "" {
			continue
		}
		suspiciousDNSTLDs = append(suspiciousDNSTLDs, tld)
	}
	riskyNetworkPorts = make(map[int]struct{}, len(cfg.Network.RiskyPorts))
	for _, port := range cfg.Network.RiskyPorts {
		if port <= 0 || port > 65535 {
			continue
		}
		riskyNetworkPorts[port] = struct{}{}
	}
	networkBurstTracker = newBurstTracker(int64(cfg.Network.RepeatWindowMs), cfg.Network.RepeatThreshold)
}

func initBaselinePolicy(cfg *config.DetectorConfig) {
	processFirstSeenTracker = newFirstSeenTracker(time.Duration(cfg.Baseline.ProcessFirstSeenTTLms) * time.Millisecond)
	networkFirstSeenTracker = newFirstSeenTracker(time.Duration(cfg.Baseline.NetworkFirstSeenTTLms) * time.Millisecond)
}

func isBenignNetworkDestination(raw string) bool {
	_, ok := benignNetworkDestinations[strings.TrimSpace(raw)]
	return ok
}

func isKnownBadNetworkDestination(raw string) bool {
	_, ok := knownBadNetworkDestinations[strings.TrimSpace(raw)]
	return ok
}

func isRiskyNetworkPort(port int) bool {
	_, ok := riskyNetworkPorts[port]
	return ok
}

func isKnownBadDomain(raw string) bool {
	_, ok := knownBadDomains[strings.ToLower(strings.TrimSpace(raw))]
	return ok
}

func hasSuspiciousDNSTLD(qname string) bool {
	qname = strings.ToLower(strings.TrimSpace(qname))
	for _, tld := range suspiciousDNSTLDs {
		if strings.HasSuffix(qname, tld) {
			return true
		}
	}
	return false
}

func isPublicIPv4(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	for _, cidr := range []string{
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"172.17.0.0/16",
		"192.168.0.0/16",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip4) {
			return false
		}
	}
	return true
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
	case statProcessRuleID:
		return "A-STAT-PROCESS-MED-" + eventID
	case processCountRuleID:
		return "A-COUNT-PROCESS-HOST-" + eventID
	case fileSensitiveRuleID:
		return "A-FILE-SENSITIVE-CHANGE-" + eventID
	case networkObserveRuleID:
		return "A-NET-OUTBOUND-CONNECTION-" + eventID
	case networkFirstSeenRuleID:
		return "A-NET-FIRST-SEEN-RISKY-" + eventID
	case processFirstSeenRuleID:
		return "A-PROC-FIRST-SEEN-SUSPICIOUS-" + eventID
	case dnsSuspiciousRuleID:
		return "A-DNS-SUSPICIOUS-QUERY-" + eventID
	case authProcFileRuleID:
		return "A-AUTH-PROC-FILE-CHAIN-" + eventID
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

func eventTypeIs(raw string, values ...string) bool {
	trimmed := strings.TrimSpace(raw)
	for _, value := range values {
		if strings.EqualFold(trimmed, value) {
			return true
		}
	}
	return false
}

func isProcessEvent(evt rawEvent, message string) bool {
	if eventTypeIs(evt.EventType, "process", "process_exec") {
		return true
	}
	if strings.TrimSpace(evt.ExecPath) != "" || strings.TrimSpace(evt.Comm) != "" || strings.TrimSpace(evt.Cmdline) != "" {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(message))
	return strings.Contains(lower, "exec=") || strings.Contains(lower, "cmdline=") || strings.Contains(lower, "comm=")
}

func processEvidenceText(evt rawEvent, message string) string {
	parts := []string{
		strings.TrimSpace(message),
		strings.TrimSpace(evt.ExecPath),
		strings.TrimSpace(evt.Comm),
		strings.TrimSpace(evt.Cmdline),
	}
	var kept []string
	for _, part := range parts {
		if part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " ")
}

func extractEventTSUnixMs(evt rawEvent, message string) int64 {
	if m := explicitTSPattern.FindStringSubmatch(message); len(m) == 2 {
		if parsed, ok := parseUnixTSMillis(m[1]); ok && parsed > 0 {
			return parsed
		}
	}
	if evt.EventTsUnixMs > 0 {
		return evt.EventTsUnixMs
	}
	if evt.Ts > 0 {
		if evt.Ts >= 1_000_000_000_000 {
			return evt.Ts
		}
		return evt.Ts * 1000
	}
	if evt.RecvTsUnixMs > 0 {
		return evt.RecvTsUnixMs
	}
	if evt.ObservedAtUnixMs > 0 {
		return evt.ObservedAtUnixMs
	}
	return time.Now().UnixMilli()
}

func detectorNodeID(evt rawEvent) string {
	if trimmed := strings.TrimSpace(evt.NodeID); trimmed != "" {
		return trimmed
	}
	if trimmed := strings.TrimSpace(evt.Host); trimmed != "" {
		return trimmed
	}
	return ""
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

type lastSeenTracker struct {
	mu     sync.Mutex
	window int64
	state  map[string]int64
}

type firstSeenTracker struct {
	mu    sync.Mutex
	ttlMs int64
	state map[string]int64
}

type recentProcessContext struct {
	User       string
	ExecPath   string
	Comm       string
	Cmdline    string
	ObservedAt int64
}

type recentProcessContextTracker struct {
	mu     sync.Mutex
	window int64
	state  map[string]recentProcessContext
}

func newFirstSeenTracker(ttl time.Duration) *firstSeenTracker {
	return &firstSeenTracker{ttlMs: int64(ttl / time.Millisecond), state: make(map[string]int64)}
}

func (t *firstSeenTracker) Observe(key string, observedAt int64) bool {
	if strings.TrimSpace(key) == "" {
		return false
	}
	if observedAt <= 0 {
		observedAt = time.Now().UnixMilli()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := observedAt - t.ttlMs
	for existingKey, first := range t.state {
		if first < cutoff {
			delete(t.state, existingKey)
		}
	}
	if _, ok := t.state[key]; ok {
		return false
	}
	t.state[key] = observedAt
	return true
}

func newLastSeenTracker(window time.Duration) *lastSeenTracker {
	return &lastSeenTracker{window: int64(window / time.Millisecond), state: make(map[string]int64)}
}

func newRecentProcessContextTracker(window time.Duration) *recentProcessContextTracker {
	return &recentProcessContextTracker{window: int64(window / time.Millisecond), state: make(map[string]recentProcessContext)}
}

func (t *lastSeenTracker) Observe(key string, observedAt int64) {
	if strings.TrimSpace(key) == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state[key] = observedAt
}

func (t *recentProcessContextTracker) Observe(key string, ctx recentProcessContext) {
	if strings.TrimSpace(key) == "" {
		return
	}
	if ctx.ObservedAt <= 0 {
		ctx.ObservedAt = time.Now().UnixMilli()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state[key] = ctx
}

func (t *recentProcessContextTracker) Recent(key string, observedAt int64) (recentProcessContext, bool) {
	if strings.TrimSpace(key) == "" {
		return recentProcessContext{}, false
	}
	if observedAt <= 0 {
		observedAt = time.Now().UnixMilli()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	ctx, ok := t.state[key]
	if !ok {
		return recentProcessContext{}, false
	}
	if ctx.ObservedAt+t.window < observedAt {
		delete(t.state, key)
		return recentProcessContext{}, false
	}
	if strings.TrimSpace(ctx.User) == "" && strings.TrimSpace(ctx.ExecPath) == "" && strings.TrimSpace(ctx.Comm) == "" && strings.TrimSpace(ctx.Cmdline) == "" {
		return recentProcessContext{}, false
	}
	return ctx, true
}

func (t *lastSeenTracker) SeenWithin(key string, observedAt int64) bool {
	if strings.TrimSpace(key) == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	last, ok := t.state[key]
	if !ok {
		return false
	}
	if observedAt-last > t.window {
		delete(t.state, key)
		return false
	}
	return observedAt >= last
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
