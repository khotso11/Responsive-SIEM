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
	"sort"
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
	invalidUserRuleID          = "R-COLLECT-INVALID-USER"
	collectFailedPwRuleID      = "R-COLLECT-FAILED-PW"
	countFailedPwSrcRuleID     = "R-COUNT-FAILED-PW-SRCIP"
	authBurstUserRuleID        = "R-AUTH-FAILED-PW-BURST-USER"
	authBurstSrcRuleID         = "R-AUTH-FAILED-PW-BURST-SRCIP"
	statProcessRuleID          = "R-STAT-PROCESS-MED"
	processCountRuleID         = "R-COUNT-PROCESS-HOST"
	fileSensitiveRuleID        = "R-FILE-SENSITIVE-CHANGE"
	networkObserveRuleID       = "R-NET-OUTBOUND-CONNECTION"
	internalSMBScanRuleID      = "R-NET-INTERNAL-SMB-SCAN"
	internalRPCScanRuleID      = "R-NET-INTERNAL-RPC-SCAN"
	internalLDAPScanRuleID     = "R-NET-INTERNAL-LDAP-SCAN"
	internalDNSScanRuleID      = "R-NET-INTERNAL-DNS-SWEEP"
	internalFTPScanRuleID      = "R-NET-INTERNAL-FTP-SCAN"
	internalRDPScanRuleID      = "R-NET-INTERNAL-RDP-SCAN"
	internalWinRMScanRuleID    = "R-NET-INTERNAL-WINRM-SCAN"
	internalSSHScanRuleID      = "R-NET-INTERNAL-SSH-SCAN"
	internalApprovedScanRuleID = "R-NET-INTERNAL-APPROVED-SCAN"
	infraFirewallDenyRuleID    = "R-INFRA-FIREWALL-DENY-BURST"
	infraNetworkAdminRuleID    = "R-INFRA-NETWORK-ADMIN-LOGIN"
	infraLinkFlapRuleID        = "R-INFRA-LINK-FLAP-BURST"
	infraEastWestFlowRuleID    = "R-INFRA-EAST-WEST-FLOW-SCAN"
	infraConfigChangeRuleID    = "R-INFRA-FIREWALL-CONFIG-CHANGE-OOW"
	infraPostContainmentRuleID = "R-INFRA-POST-CONTAINMENT-BLOCK-VERIFY"
	authProcFileRuleID         = "R-AUTH-PROC-FILE-CHAIN"
	processFirstSeenRuleID     = "R-PROC-FIRST-SEEN-SUSPICIOUS"
	networkFirstSeenRuleID     = "R-NET-FIRST-SEEN-RISKY"
	dnsSuspiciousRuleID        = "R-DNS-SUSPICIOUS-QUERY"
	fr03HostRuleID             = "R-FR03-HOST-BRUTEFORCE-BURST"
	fr03NetworkRuleID          = "R-FR03-NETWORK-C2-BEACON"
	fr03DeceptionRuleID        = "R-FR03-DECEPTION-TRIPWIRE"
	invalidUserLane            = "FAST"
	statProcessLane            = "STANDARD"
	processCountLane           = "STANDARD"
	fileSensitiveLane          = "FAST"
	networkObserveLane         = "STANDARD"
	internalScanLane           = "FAST"
	fr03Lane                   = "FAST"
	detectorSeverityMedium     = "medium"
	detectorSeverityHigh       = "high"
	detectorSeverityCritical   = "critical"
	processCountThreshold      = 3
	processBurstWindowMs       = 60000
	countFailedPwThreshold     = 5
	countFailedPwWindowMs      = 60000
	authBurstUserThreshold     = 5
	authBurstUserWindowMs      = 300000
	authBurstSrcThreshold      = 8
	authBurstSrcWindowMs       = 300000
	fr03HostBurstThreshold     = 3
	fr03HostBurstWindowMs      = 5000
	defaultPullBatch           = 10
	defaultPullTimeout         = 500 * time.Millisecond
)

var (
	invalidUserPattern                    = "invalid user"
	ipv4FromPattern                       = regexp.MustCompile(`(?i)\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b`)
	responseActionIDPattern               = regexp.MustCompile(`(?i)\bresponse_action_id=([A-Za-z0-9._:-]+)\b`)
	processCountPattern                   = regexp.MustCompile(`(?i)\bprocess_count=(\d+)\b`)
	explicitTSPattern                     = regexp.MustCompile(`\bts=([0-9]{9,13})\b`)
	fr03HostMarkerPattern                 = regexp.MustCompile(`(?i)\battack=host_bruteforce\b`)
	fr03NetworkMarkerPattern              = regexp.MustCompile(`(?i)\battack=(network_scan|c2_beacon)\b`)
	fr03DeceptionPattern                  = regexp.MustCompile(`(?i)\battack=deception_tripwire\b`)
	suspiciousProcPattern                 = regexp.MustCompile(`(?i)\b(exec=)?("?)(/usr/bin/(nmap|nc|curl|wget)|/bin/(bash|sh)|/usr/bin/python3?)\b`)
	highValueSensitiveFilePattern         = regexp.MustCompile(`(?i)(/etc/sudoers(\.d(/[^[:space:]]+)?)?\b|authorized_keys\b|/root/\.ssh/)`)
	chainSensitiveFilePattern             = regexp.MustCompile(`(?i)(/etc/(sudoers(\.d(/[^[:space:]]+)?)?|passwd|shadow|group|gshadow)\b|authorized_keys\b|/root/\.ssh/)`)
	noisyStandaloneFilePattern            = regexp.MustCompile(`(?i)(/etc/(passwd|group|shadow|gshadow)(\.[^/[:space:]]+)?\b|/etc/[^[:space:]]+\.lock\b|/etc/\.pwd\.lock\b)`)
	dstIPPattern                          = regexp.MustCompile(`(?i)\bdst_ip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b`)
	dstPortPattern                        = regexp.MustCompile(`(?i)\bdst_port=(\d{1,5})\b`)
	dnsNamePattern                        = regexp.MustCompile(`(?i)\bqname=([A-Za-z0-9._-]+)\b`)
	dnsTypePattern                        = regexp.MustCompile(`(?i)\bqtype=([A-Za-z0-9]+)\b`)
	acceptedPasswordUserPattern           = regexp.MustCompile(`(?i)accepted password for\s+([a-z0-9._-]+)`)
	loggedInAsUserPattern                 = regexp.MustCompile(`(?i)logged in as\s+([a-z0-9._-]+)`)
	keyValueUserPattern                   = regexp.MustCompile(`(?i)\b(?:user|username|account)[=: ]+([a-z0-9._-]+)\b`)
	fr03HostBurstTracker                  = newBurstTracker(fr03HostBurstWindowMs, fr03HostBurstThreshold)
	processBurstTracker                   = newBurstTracker(processBurstWindowMs, processCountThreshold)
	countFailedPwSrcTracker               = newBurstTracker(countFailedPwWindowMs, countFailedPwThreshold)
	authFailedPwBurstUserTracker          = newBurstTracker(authBurstUserWindowMs, authBurstUserThreshold)
	authFailedPwBurstSrcTracker           = newBurstTracker(authBurstSrcWindowMs, authBurstSrcThreshold)
	infrastructureFirewallDenyTracker     *burstTracker
	infrastructureLinkFlapTracker         *burstTracker
	infrastructureEastWestFlowTracker     *uniqueDestTracker
	networkBurstTracker                   *burstTracker
	knownBadNetworkDestinations           map[string]struct{}
	benignNetworkDestinations             map[string]struct{}
	knownBadDomains                       map[string]struct{}
	suspiciousDNSTLDs                     []string
	riskyNetworkPorts                     map[int]struct{}
	internalScanCIDRs                     []*net.IPNet
	internalProtocolDetections            []*protocolScanDetection
	internalScanAllowedUsers              map[string]struct{}
	internalScanAllowedNodes              map[string]struct{}
	internalScanAllowedExecPrefix         []string
	internalScanAllowedCommPrefix         []string
	infrastructureFirewallDenyKeywords    []string
	infrastructureFirewallContextKeywords []string
	infrastructureAdminLoginKeywords      []string
	infrastructureAdminUsers              map[string]struct{}
	infrastructureLinkDownKeywords        []string
	infrastructureLinkUpKeywords          []string
	infrastructureEastWestCIDRs           []*net.IPNet
	infrastructureEastWestPorts           map[int]struct{}
	infrastructureConfigChangeKeywords    []string
	infrastructureConfigContextKeywords   []string
	infrastructureOutsideWindowKeywords   []string
	infrastructureAllowedChangeStartHour  int
	infrastructureAllowedChangeEndHour    int
	infrastructurePostContainmentKeywords []string
	infrastructurePostContainmentContext  []string
	recentAuthByNode                      = newLastSeenTracker(5 * time.Minute)
	recentLocalAdminByNode                = newLastSeenTracker(2 * time.Minute)
	recentSuspiciousProcByNode            = newLastSeenTracker(2 * time.Minute)
	recentSuspiciousProcContext           = newRecentProcessContextTracker(2 * time.Minute)
	recentAuthProcByNode                  = newLastSeenTracker(5 * time.Minute)
	recentFileAlertByPath                 = newLastSeenTracker(15 * time.Second)
	recentInfrastructureTrapBySource      = newLastSeenTracker(2 * time.Minute)
	processFirstSeenTracker               *firstSeenTracker
	networkFirstSeenTracker               *firstSeenTracker
)

type protocolScanDetection struct {
	Label      string
	RuleID     string
	Severity   string
	Confidence int
	Ports      map[int]struct{}
	Tracker    *uniqueDestTracker
}

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
	initInfrastructurePolicy(cfg)
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
	evt = enrichExtractedNetworkFields(evt, message)
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
			slog.String("source_type", evt.SourceType),
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
		ConfidenceScore:  match.ConfidenceScore,
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
		DstPort:          match.DstPort,
		ProtocolFamily:   match.ProtocolFamily,
		ScanFanout:       match.ScanFanout,
		TopDestinations:  append([]string(nil), match.TopDestinations...),
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
	missingUser := false
	user := strings.ToLower(strings.TrimSpace(evt.User))
	if user == "" || user == "unknown" {
		missingUser = true
	}
	missingExecContext := strings.TrimSpace(evt.ExecPath) == "" || strings.TrimSpace(evt.Comm) == "" || strings.TrimSpace(evt.Cmdline) == ""
	if !missingUser && !missingExecContext {
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
	if missingUser {
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
	RuleID          string
	Lane            string
	Severity        string
	GroupKey        string
	ConfidenceScore int
	ProtocolFamily  string
	DstPort         int
	ScanFanout      int
	TopDestinations []string
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
	if eventTypeIs(evt.EventType, "snmp_trap") {
		for _, sourceKey := range infrastructureSourceKeys(evt) {
			recentInfrastructureTrapBySource.Observe(sourceKey, evt.ObservedAtUnixMs)
		}
		return ruleMatch{}, false
	}
	if strings.EqualFold(strings.TrimSpace(evt.SourceType), "syslog") && eventTypeIs(evt.EventType, "syslog") {
		sourceKey := infrastructureSourceKey(evt)
		if sourceKey != "" {
			if isInfrastructureNetworkAdminLogin(evt, message, lower) {
				groupKey := extractIPv4(message)
				if groupKey == "" {
					groupKey = strings.TrimSpace(evt.SrcIP)
				}
				if groupKey == "" {
					groupKey = sourceKey
				}
				return ruleMatch{
					RuleID:          infraNetworkAdminRuleID,
					Lane:            invalidUserLane,
					Severity:        detectorSeverityHigh,
					GroupKey:        groupKey,
					ConfidenceScore: 84,
				}, true
			}
			if isInfrastructureLinkEvent(lower) {
				confidence := 76
				if seenRecentInfrastructureTrap(evt) {
					confidence = 84
				}
				if infrastructureLinkFlapTracker != nil && infrastructureLinkFlapTracker.Observe(sourceKey, evt.ObservedAtUnixMs) {
					return ruleMatch{
						RuleID:          infraLinkFlapRuleID,
						Lane:            invalidUserLane,
						Severity:        detectorSeverityHigh,
						GroupKey:        sourceKey,
						ConfidenceScore: confidence,
					}, true
				}
			}
			if isInfrastructureFirewallDeny(lower) {
				if infrastructureFirewallDenyTracker != nil && infrastructureFirewallDenyTracker.Observe(sourceKey, evt.ObservedAtUnixMs) {
					return ruleMatch{
						RuleID:          infraFirewallDenyRuleID,
						Lane:            invalidUserLane,
						Severity:        detectorSeverityHigh,
						GroupKey:        sourceKey,
						ConfidenceScore: 82,
					}, true
				}
			}
			if isInfrastructureConfigChangeOutsideWindow(evt, lower) {
				return ruleMatch{
					RuleID:          infraConfigChangeRuleID,
					Lane:            invalidUserLane,
					Severity:        detectorSeverityHigh,
					GroupKey:        sourceKey,
					ConfidenceScore: 86,
				}, true
			}
			if isInfrastructurePostContainmentBlockVerification(lower) {
				groupKey := extractResponseActionID(message)
				if groupKey == "" {
					groupKey = sourceKey
				}
				return ruleMatch{
					RuleID:          infraPostContainmentRuleID,
					Lane:            networkObserveLane,
					Severity:        detectorSeverityMedium,
					GroupKey:        groupKey,
					ConfidenceScore: 88,
				}, true
			}
		}
	}
	if strings.EqualFold(strings.TrimSpace(evt.SourceType), "netflow_v5") && eventTypeIs(evt.EventType, "netflow_flow") {
		srcIP := strings.TrimSpace(evt.SrcIP)
		dstIP := strings.TrimSpace(evt.DstIP)
		dstPort := evt.DstPort
		if srcIP != "" && dstIP != "" && dstPort > 0 && isInfrastructureEastWestCandidate(srcIP, dstIP, dstPort) {
			if infrastructureEastWestFlowTracker != nil {
				matched, fanout, topDestinations := infrastructureEastWestFlowTracker.Observe(srcIP, dstIP, evt.ObservedAtUnixMs)
				if matched {
					protocolFamily := ""
					if detection := matchInternalProtocolDetection(dstPort); detection != nil {
						protocolFamily = detection.Label
					}
					return ruleMatch{
						RuleID:          infraEastWestFlowRuleID,
						Lane:            invalidUserLane,
						Severity:        detectorSeverityHigh,
						GroupKey:        srcIP,
						ConfidenceScore: 86,
						ProtocolFamily:  protocolFamily,
						DstPort:         dstPort,
						ScanFanout:      fanout,
						TopDestinations: topDestinations,
					}, true
				}
			}
		}
	}
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

	if eventTypeIs(evt.EventType, "file", "file_change") {
		fileEvidence := strings.TrimSpace(evt.FilePath)
		if fileEvidence == "" {
			fileEvidence = message
		}
		if !chainSensitiveFilePattern.MatchString(fileEvidence) {
			return ruleMatch{}, false
		}
		groupKey := strings.TrimSpace(evt.Host)
		if groupKey == "" {
			groupKey = detectorNodeID(evt)
		}
		if groupKey == "" {
			groupKey = strings.TrimSpace(evt.GroupKey)
		}
		if recentAuthProcByNode.SeenWithin(groupKey, evt.ObservedAtUnixMs) {
			if fileAlertKey := normalizedFileAlertKey(groupKey, evt, fileEvidence); fileAlertKey != "" {
				if recentFileAlertByPath.SeenWithin(fileAlertKey, evt.ObservedAtUnixMs) {
					return ruleMatch{}, false
				}
				recentFileAlertByPath.Observe(fileAlertKey, evt.ObservedAtUnixMs)
			}
			return ruleMatch{
				RuleID:   authProcFileRuleID,
				Lane:     fr03Lane,
				Severity: detectorSeverityCritical,
				GroupKey: groupKey,
			}, true
		}
		if !highValueSensitiveFilePattern.MatchString(fileEvidence) {
			return ruleMatch{}, false
		}
		if isLocalAdminChurnFileNoise(groupKey, evt, fileEvidence) {
			return ruleMatch{}, false
		}
		if fileAlertKey := normalizedFileAlertKey(groupKey, evt, fileEvidence); fileAlertKey != "" {
			if recentFileAlertByPath.SeenWithin(fileAlertKey, evt.ObservedAtUnixMs) {
				return ruleMatch{}, false
			}
			recentFileAlertByPath.Observe(fileAlertKey, evt.ObservedAtUnixMs)
		}
		if noisyStandaloneFilePattern.MatchString(fileEvidence) && strings.EqualFold(strings.TrimSpace(evt.User), "unknown") {
			return ruleMatch{}, false
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
		if isLocalAdminProcess(evt) {
			recentLocalAdminByNode.Observe(groupKey, evt.ObservedAtUnixMs)
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
		if dstIP == "" {
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
		if isInternalIPv4(dstIP) {
			if detection := matchInternalProtocolDetection(dstPort); detection != nil {
				sourceKey := internalScanSourceKey(groupKey, evt, detection.Label)
				if detection.Tracker != nil {
					matched, fanout, topDestinations := detection.Tracker.Observe(sourceKey, dstIP, evt.ObservedAtUnixMs)
					if matched {
						ruleID := detection.RuleID
						lane := internalScanLane
						severity := detection.Severity
						confidence := detection.Confidence
						if isInternalScanApprovedSource(evt) {
							ruleID = internalApprovedScanRuleID
							lane = networkObserveLane
							severity = detectorSeverityMedium
							if confidence > 72 {
								confidence = 72
							}
						}
						return ruleMatch{
							RuleID:          ruleID,
							Lane:            lane,
							Severity:        severity,
							GroupKey:        groupKey,
							ConfidenceScore: confidence,
							ProtocolFamily:  detection.Label,
							DstPort:         dstPort,
							ScanFanout:      fanout,
							TopDestinations: topDestinations,
						}, true
					}
				}
			}
			return ruleMatch{}, false
		}
		if !isPublicIPv4(dstIP) || isBenignNetworkDestination(dstIP) {
			return ruleMatch{}, false
		}
		repeated := networkBurstTracker != nil && networkBurstTracker.Observe(dstIP, evt.ObservedAtUnixMs)
		if groupKey != "" && recentSuspiciousProcByNode.SeenWithin(groupKey, evt.ObservedAtUnixMs) && (isRiskyNetworkPort(dstPort) || repeated || isKnownBadNetworkDestination(dstIP)) {
			protocolFamily := ""
			if detection := matchInternalProtocolDetection(dstPort); detection != nil {
				protocolFamily = detection.Label
			}
			return ruleMatch{
				RuleID:         "R-SEQ-PROCESS-TO-NET",
				Lane:           fr03Lane,
				Severity:       detectorSeverityHigh,
				GroupKey:       groupKey,
				DstPort:        dstPort,
				ProtocolFamily: protocolFamily,
			}, true
		}
		firstSeenKey := strings.TrimSpace(groupKey) + "|" + dstIP + ":" + strconv.Itoa(dstPort)
		if networkFirstSeenTracker != nil && networkFirstSeenTracker.Observe(firstSeenKey, evt.ObservedAtUnixMs) && (isKnownBadNetworkDestination(dstIP) || isRiskyNetworkPort(dstPort)) {
			protocolFamily := ""
			if detection := matchInternalProtocolDetection(dstPort); detection != nil {
				protocolFamily = detection.Label
			}
			return ruleMatch{
				RuleID:         networkFirstSeenRuleID,
				Lane:           fr03Lane,
				Severity:       detectorSeverityHigh,
				GroupKey:       dstIP,
				DstPort:        dstPort,
				ProtocolFamily: protocolFamily,
			}, true
		}
		if isKnownBadNetworkDestination(dstIP) || isRiskyNetworkPort(dstPort) || repeated {
			protocolFamily := ""
			if detection := matchInternalProtocolDetection(dstPort); detection != nil {
				protocolFamily = detection.Label
			}
			return ruleMatch{
				RuleID:          networkObserveRuleID,
				Lane:            networkObserveLane,
				Severity:        detectorSeverityHigh,
				GroupKey:        dstIP,
				DstPort:         dstPort,
				ProtocolFamily:  protocolFamily,
				ScanFanout:      0,
				TopDestinations: nil,
			}, true
		}
	}

	if strings.EqualFold(strings.TrimSpace(evt.EventType), "auth_failed") {
		failedPassword := strings.Contains(lower, "failed password")
		invalidUser := strings.Contains(lower, invalidUserPattern)
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
		userKey := strings.TrimSpace(evt.User)

		if failedPassword {
			if groupKey != "" && authFailedPwBurstSrcTracker.Observe(groupKey, evt.ObservedAtUnixMs) {
				return ruleMatch{
					RuleID:   authBurstSrcRuleID,
					Lane:     invalidUserLane,
					Severity: detectorSeverityHigh,
					GroupKey: groupKey,
				}, true
			}
			if userKey != "" && authFailedPwBurstUserTracker.Observe(userKey, evt.ObservedAtUnixMs) {
				return ruleMatch{
					RuleID:   authBurstUserRuleID,
					Lane:     invalidUserLane,
					Severity: detectorSeverityHigh,
					GroupKey: userKey,
				}, true
			}
			if groupKey != "" && countFailedPwSrcTracker.Observe(groupKey, evt.ObservedAtUnixMs) {
				return ruleMatch{
					RuleID:   countFailedPwSrcRuleID,
					Lane:     invalidUserLane,
					Severity: detectorSeverityHigh,
					GroupKey: groupKey,
				}, true
			}
			if invalidUser {
				return ruleMatch{
					RuleID:   invalidUserRuleID,
					Lane:     invalidUserLane,
					Severity: detectorSeverityHigh,
					GroupKey: groupKey,
				}, true
			}
			return ruleMatch{
				RuleID:   collectFailedPwRuleID,
				Lane:     invalidUserLane,
				Severity: detectorSeverityHigh,
				GroupKey: groupKey,
			}, true
		}
		if invalidUser {
			return ruleMatch{
				RuleID:   invalidUserRuleID,
				Lane:     invalidUserLane,
				Severity: detectorSeverityHigh,
				GroupKey: groupKey,
			}, true
		}
		return ruleMatch{}, false
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

func extractResponseActionID(line string) string {
	match := responseActionIDPattern.FindStringSubmatch(line)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
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

func enrichExtractedNetworkFields(evt rawEvent, message string) rawEvent {
	if !eventTypeIs(evt.EventType, "network", "network_connection") {
		return evt
	}
	if strings.TrimSpace(evt.DstIP) == "" {
		evt.DstIP = extractDstIP(message)
	}
	if evt.DstPort == 0 {
		evt.DstPort = extractDstPort(message)
	}
	return evt
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
	internalScanCIDRs = make([]*net.IPNet, 0, len(cfg.InternalScan.InternalCIDRs))
	for _, raw := range cfg.InternalScan.InternalCIDRs {
		_, block, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil || block == nil {
			continue
		}
		internalScanCIDRs = append(internalScanCIDRs, block)
	}
	internalProtocolDetections = buildInternalProtocolDetections(cfg)
	internalScanAllowedUsers = make(map[string]struct{}, len(cfg.InternalScan.Allowlist.Users))
	for _, raw := range cfg.InternalScan.Allowlist.Users {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value != "" {
			internalScanAllowedUsers[value] = struct{}{}
		}
	}
	internalScanAllowedNodes = make(map[string]struct{}, len(cfg.InternalScan.Allowlist.Nodes))
	for _, raw := range cfg.InternalScan.Allowlist.Nodes {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value != "" {
			internalScanAllowedNodes[value] = struct{}{}
		}
	}
	internalScanAllowedExecPrefix = normalizeLowerTrimmed(cfg.InternalScan.Allowlist.ExecPathPrefixes)
	internalScanAllowedCommPrefix = normalizeLowerTrimmed(cfg.InternalScan.Allowlist.CommPrefixes)
}

func initInfrastructurePolicy(cfg *config.DetectorConfig) {
	infrastructureFirewallDenyTracker = newBurstTracker(int64(cfg.Infrastructure.FirewallDeny.WindowMs), cfg.Infrastructure.FirewallDeny.Threshold)
	infrastructureLinkFlapTracker = newBurstTracker(int64(cfg.Infrastructure.LinkFlap.WindowMs), cfg.Infrastructure.LinkFlap.Threshold)
	infrastructureEastWestFlowTracker = newUniqueDestTracker(int64(cfg.Infrastructure.EastWestFlowScan.WindowMs), cfg.Infrastructure.EastWestFlowScan.Threshold)
	infrastructureFirewallDenyKeywords = normalizeLowerTrimmed(cfg.Infrastructure.FirewallDeny.Keywords)
	infrastructureFirewallContextKeywords = normalizeLowerTrimmed(cfg.Infrastructure.FirewallDeny.ContextKeywords)
	infrastructureAdminLoginKeywords = normalizeLowerTrimmed(cfg.Infrastructure.NetworkAdminLogin.SuccessKeywords)
	infrastructureAdminUsers = make(map[string]struct{}, len(cfg.Infrastructure.NetworkAdminLogin.AdminUsers))
	for _, raw := range cfg.Infrastructure.NetworkAdminLogin.AdminUsers {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value != "" {
			infrastructureAdminUsers[value] = struct{}{}
		}
	}
	infrastructureLinkDownKeywords = normalizeLowerTrimmed(cfg.Infrastructure.LinkFlap.DownKeywords)
	infrastructureLinkUpKeywords = normalizeLowerTrimmed(cfg.Infrastructure.LinkFlap.UpKeywords)
	infrastructureEastWestCIDRs = make([]*net.IPNet, 0, len(cfg.Infrastructure.EastWestFlowScan.InternalCIDRs))
	for _, raw := range cfg.Infrastructure.EastWestFlowScan.InternalCIDRs {
		_, block, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil || block == nil {
			continue
		}
		infrastructureEastWestCIDRs = append(infrastructureEastWestCIDRs, block)
	}
	infrastructureEastWestPorts = make(map[int]struct{}, len(cfg.Infrastructure.EastWestFlowScan.RiskyPorts))
	for _, port := range cfg.Infrastructure.EastWestFlowScan.RiskyPorts {
		if port > 0 && port <= 65535 {
			infrastructureEastWestPorts[port] = struct{}{}
		}
	}
	infrastructureConfigChangeKeywords = normalizeLowerTrimmed(cfg.Infrastructure.ConfigChangeOutsideWindow.ChangeKeywords)
	infrastructureConfigContextKeywords = normalizeLowerTrimmed(cfg.Infrastructure.ConfigChangeOutsideWindow.ContextKeywords)
	infrastructureOutsideWindowKeywords = normalizeLowerTrimmed(cfg.Infrastructure.ConfigChangeOutsideWindow.OutsideWindowKeywords)
	infrastructureAllowedChangeStartHour = cfg.Infrastructure.ConfigChangeOutsideWindow.AllowedStartHourLocal
	infrastructureAllowedChangeEndHour = cfg.Infrastructure.ConfigChangeOutsideWindow.AllowedEndHourLocal
	infrastructurePostContainmentKeywords = normalizeLowerTrimmed(cfg.Infrastructure.PostContainmentBlockVerify.Keywords)
	infrastructurePostContainmentContext = normalizeLowerTrimmed(cfg.Infrastructure.PostContainmentBlockVerify.ContextKeywords)
}

func initBaselinePolicy(cfg *config.DetectorConfig) {
	processFirstSeenTracker = newFirstSeenTracker(time.Duration(cfg.Baseline.ProcessFirstSeenTTLms) * time.Millisecond)
	networkFirstSeenTracker = newFirstSeenTracker(time.Duration(cfg.Baseline.NetworkFirstSeenTTLms) * time.Millisecond)
}

func infrastructureSourceKeys(evt rawEvent) []string {
	keys := make([]string, 0, 3)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range keys {
			if existing == value {
				return
			}
		}
		keys = append(keys, value)
	}

	if eventTypeIs(evt.EventType, "snmp_trap") {
		add(evt.SrcIP)
		add(evt.Host)
		add(detectorNodeID(evt))
		return keys
	}

	add(evt.Host)
	add(evt.SrcIP)
	add(detectorNodeID(evt))
	return keys
}

func infrastructureSourceKey(evt rawEvent) string {
	keys := infrastructureSourceKeys(evt)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func seenRecentInfrastructureTrap(evt rawEvent) bool {
	for _, key := range infrastructureSourceKeys(evt) {
		if recentInfrastructureTrapBySource.SeenWithin(key, evt.ObservedAtUnixMs) {
			return true
		}
	}
	return false
}

func containsAnyKeyword(lower string, keywords []string) bool {
	for _, keyword := range keywords {
		if keyword != "" && strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func isInfrastructureFirewallDeny(lower string) bool {
	if !containsAnyKeyword(lower, infrastructureFirewallDenyKeywords) {
		return false
	}
	if len(infrastructureFirewallContextKeywords) == 0 {
		return true
	}
	return containsAnyKeyword(lower, infrastructureFirewallContextKeywords)
}

func extractInfrastructureAdminUser(evt rawEvent, message string) string {
	if user := strings.ToLower(strings.TrimSpace(evt.User)); user != "" {
		return user
	}
	for _, pattern := range []*regexp.Regexp{
		acceptedPasswordUserPattern,
		loggedInAsUserPattern,
		keyValueUserPattern,
	} {
		if value := strings.ToLower(matchString(pattern, message)); value != "" {
			return value
		}
	}
	return ""
}

func isInfrastructureNetworkAdminLogin(evt rawEvent, message, lower string) bool {
	if !containsAnyKeyword(lower, infrastructureAdminLoginKeywords) {
		return false
	}
	if strings.Contains(lower, "failed password") || strings.Contains(lower, "invalid user") || strings.Contains(lower, "authentication failure") {
		return false
	}
	user := extractInfrastructureAdminUser(evt, message)
	if user == "" {
		return false
	}
	_, ok := infrastructureAdminUsers[user]
	return ok
}

func isInfrastructureLinkEvent(lower string) bool {
	return containsAnyKeyword(lower, infrastructureLinkDownKeywords) || containsAnyKeyword(lower, infrastructureLinkUpKeywords)
}

func isInfrastructureEastWestCandidate(srcIP, dstIP string, dstPort int) bool {
	if strings.TrimSpace(srcIP) == "" || strings.TrimSpace(dstIP) == "" || dstPort <= 0 {
		return false
	}
	if !isInfrastructureInternalIPv4(srcIP) || !isInfrastructureInternalIPv4(dstIP) {
		return false
	}
	if strings.TrimSpace(srcIP) == strings.TrimSpace(dstIP) {
		return false
	}
	_, ok := infrastructureEastWestPorts[dstPort]
	return ok
}

func isInfrastructureConfigChangeOutsideWindow(evt rawEvent, lower string) bool {
	if !containsAnyKeyword(lower, infrastructureConfigChangeKeywords) {
		return false
	}
	if len(infrastructureConfigContextKeywords) > 0 && !containsAnyKeyword(lower, infrastructureConfigContextKeywords) {
		return false
	}
	if containsAnyKeyword(lower, infrastructureOutsideWindowKeywords) {
		return true
	}
	if evt.ObservedAtUnixMs <= 0 {
		return false
	}
	hour := time.UnixMilli(evt.ObservedAtUnixMs).Local().Hour()
	start := infrastructureAllowedChangeStartHour
	end := infrastructureAllowedChangeEndHour
	if start == end {
		return false
	}
	if start < end {
		return hour < start || hour >= end
	}
	return hour >= end && hour < start
}

func isInfrastructurePostContainmentBlockVerification(lower string) bool {
	if !containsAnyKeyword(lower, infrastructurePostContainmentKeywords) {
		return false
	}
	if len(infrastructurePostContainmentContext) == 0 {
		return true
	}
	return containsAnyKeyword(lower, infrastructurePostContainmentContext)
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

func isInternalIPv4(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	for _, block := range internalScanCIDRs {
		if block.Contains(ip4) {
			return true
		}
	}
	return false
}

func isInfrastructureInternalIPv4(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	for _, block := range infrastructureEastWestCIDRs {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func normalizeLowerTrimmed(values []string) []string {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func isInternalScanApprovedSource(evt rawEvent) bool {
	if _, ok := internalScanAllowedUsers[strings.ToLower(strings.TrimSpace(evt.User))]; ok {
		return true
	}
	node := strings.ToLower(strings.TrimSpace(detectorNodeID(evt)))
	if _, ok := internalScanAllowedNodes[node]; ok {
		return true
	}
	return false
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
	case collectFailedPwRuleID:
		return "A-COLLECT-FAILED-PW-" + eventID
	case countFailedPwSrcRuleID:
		return "A-COUNT-FAILED-PW-SRCIP-" + eventID
	case authBurstUserRuleID:
		return "A-AUTH-FAILED-PW-BURST-USER-" + eventID
	case authBurstSrcRuleID:
		return "A-AUTH-FAILED-PW-BURST-SRCIP-" + eventID
	case statProcessRuleID:
		return "A-STAT-PROCESS-MED-" + eventID
	case processCountRuleID:
		return "A-COUNT-PROCESS-HOST-" + eventID
	case fileSensitiveRuleID:
		return "A-FILE-SENSITIVE-CHANGE-" + eventID
	case networkObserveRuleID:
		return "A-NET-OUTBOUND-CONNECTION-" + eventID
	case internalSMBScanRuleID:
		return "A-NET-INTERNAL-SMB-SCAN-" + eventID
	case internalRPCScanRuleID:
		return "A-NET-INTERNAL-RPC-SCAN-" + eventID
	case internalLDAPScanRuleID:
		return "A-NET-INTERNAL-LDAP-SCAN-" + eventID
	case internalDNSScanRuleID:
		return "A-NET-INTERNAL-DNS-SWEEP-" + eventID
	case internalFTPScanRuleID:
		return "A-NET-INTERNAL-FTP-SCAN-" + eventID
	case internalRDPScanRuleID:
		return "A-NET-INTERNAL-RDP-SCAN-" + eventID
	case internalWinRMScanRuleID:
		return "A-NET-INTERNAL-WINRM-SCAN-" + eventID
	case internalSSHScanRuleID:
		return "A-NET-INTERNAL-SSH-SCAN-" + eventID
	case internalApprovedScanRuleID:
		return "A-NET-INTERNAL-APPROVED-SCAN-" + eventID
	case infraFirewallDenyRuleID:
		return "A-INFRA-FIREWALL-DENY-BURST-" + eventID
	case infraNetworkAdminRuleID:
		return "A-INFRA-NETWORK-ADMIN-LOGIN-" + eventID
	case infraLinkFlapRuleID:
		return "A-INFRA-LINK-FLAP-BURST-" + eventID
	case infraEastWestFlowRuleID:
		return "A-INFRA-EAST-WEST-FLOW-SCAN-" + eventID
	case infraConfigChangeRuleID:
		return "A-INFRA-FIREWALL-CONFIG-CHANGE-OOW-" + eventID
	case infraPostContainmentRuleID:
		return "A-INFRA-POST-CONTAINMENT-BLOCK-VERIFY-" + eventID
	case networkFirstSeenRuleID:
		return "A-NET-FIRST-SEEN-RISKY-" + eventID
	case "R-SEQ-PROCESS-TO-NET":
		return "A-SEQ-PROCESS-TO-NET-" + eventID
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
	if eventTypeIs(evt.EventType, "network", "network_connection") {
		return false
	}
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

func isLocalAdminProcess(evt rawEvent) bool {
	text := strings.ToLower(strings.TrimSpace(processEvidenceText(evt, "")))
	if text == "" {
		return false
	}
	for _, needle := range []string{
		"/usr/bin/sudo",
		" comm=sudo",
		" sudo ",
		"/usr/bin/su",
		" comm=su",
		"/usr/bin/passwd",
		"/usr/sbin/useradd",
		"/usr/sbin/usermod",
		"/usr/sbin/userdel",
		"/usr/bin/chsh",
		"/usr/bin/chfn",
		"/usr/sbin/visudo",
		"/usr/bin/systemctl",
		"/usr/bin/loginctl",
		"/usr/bin/apt",
		"/usr/bin/apt-get",
		"/usr/bin/dpkg",
	} {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func isLocalAdminChurnFileNoise(groupKey string, evt rawEvent, fileEvidence string) bool {
	if strings.TrimSpace(groupKey) == "" {
		return false
	}
	if !recentLocalAdminByNode.SeenWithin(groupKey, evt.ObservedAtUnixMs) {
		return false
	}
	normalized := strings.ToLower(strings.TrimSpace(fileEvidence))
	if normalized == "" {
		return false
	}
	for _, needle := range []string{
		"/etc/passwd",
		"/etc/group",
		"/etc/shadow",
		"/etc/gshadow",
		"/etc/passwd.",
		"/etc/group.",
		"/etc/shadow.",
		"/etc/gshadow.",
		"/etc/passwd.lock",
		"/etc/group.lock",
		"/etc/shadow.lock",
		"/etc/gshadow.lock",
		"/etc/.pwd.lock",
	} {
		if strings.Contains(normalized, needle) {
			return true
		}
	}
	return false
}

func normalizedFileAlertKey(groupKey string, evt rawEvent, fileEvidence string) string {
	nodeKey := strings.TrimSpace(groupKey)
	if nodeKey == "" {
		nodeKey = detectorNodeID(evt)
	}
	pathKey := strings.TrimSpace(evt.FilePath)
	if pathKey == "" {
		pathKey = strings.TrimSpace(fileEvidence)
	}
	pathKey = strings.ToLower(pathKey)
	if pathKey == "" {
		return ""
	}
	for _, prefix := range []string{
		"deleted ",
		"modified ",
		"attrib ",
		"created ",
		"action=",
		"path=",
	} {
		pathKey = strings.TrimPrefix(pathKey, prefix)
	}
	return nodeKey + "|" + pathKey
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

type uniqueDestTracker struct {
	mu        sync.Mutex
	windowMs  int64
	threshold int
	state     map[string]map[string]int64
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

func newUniqueDestTracker(windowMs int64, threshold int) *uniqueDestTracker {
	return &uniqueDestTracker{
		windowMs:  windowMs,
		threshold: threshold,
		state:     make(map[string]map[string]int64, 32),
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

func (t *uniqueDestTracker) Observe(key, destination string, observedAtUnixMs int64) (bool, int, []string) {
	if strings.TrimSpace(key) == "" || strings.TrimSpace(destination) == "" {
		return false, 0, nil
	}
	if observedAtUnixMs <= 0 {
		observedAtUnixMs = time.Now().UnixMilli()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := observedAtUnixMs - t.windowMs
	for existingKey, destinations := range t.state {
		for dst, ts := range destinations {
			if ts < cutoff {
				delete(destinations, dst)
			}
		}
		if len(destinations) == 0 {
			delete(t.state, existingKey)
		}
	}
	destinations := t.state[key]
	if destinations == nil {
		destinations = make(map[string]int64, t.threshold+2)
		t.state[key] = destinations
	}
	destinations[destination] = observedAtUnixMs
	fanout := len(destinations)
	type rankedDestination struct {
		dst string
		ts  int64
	}
	ranked := make([]rankedDestination, 0, fanout)
	for dst, ts := range destinations {
		ranked = append(ranked, rankedDestination{dst: dst, ts: ts})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].ts == ranked[j].ts {
			return ranked[i].dst < ranked[j].dst
		}
		return ranked[i].ts > ranked[j].ts
	})
	topDestinations := make([]string, 0, min(5, len(ranked)))
	for idx, item := range ranked {
		if idx >= 5 {
			break
		}
		topDestinations = append(topDestinations, item.dst)
	}
	return fanout == t.threshold, fanout, topDestinations
}

func buildInternalProtocolDetections(cfg *config.DetectorConfig) []*protocolScanDetection {
	if !cfg.InternalScan.Enabled {
		return nil
	}
	windowMs := int64(cfg.InternalScan.WindowMs)
	build := func(label, ruleID, severity string, protocolCfg config.DetectorProtocolScanConfig) *protocolScanDetection {
		if len(protocolCfg.Ports) == 0 || protocolCfg.UniqueTargetsThreshold <= 0 {
			return nil
		}
		ports := make(map[int]struct{}, len(protocolCfg.Ports))
		for _, port := range protocolCfg.Ports {
			if port > 0 && port <= 65535 {
				ports[port] = struct{}{}
			}
		}
		if len(ports) == 0 {
			return nil
		}
		return &protocolScanDetection{
			Label:      label,
			RuleID:     ruleID,
			Severity:   severity,
			Confidence: protocolCfg.ConfidenceScore,
			Ports:      ports,
			Tracker:    newUniqueDestTracker(windowMs, protocolCfg.UniqueTargetsThreshold),
		}
	}
	var detections []*protocolScanDetection
	for _, detection := range []*protocolScanDetection{
		build("smb", internalSMBScanRuleID, detectorSeverityHigh, cfg.InternalScan.SMB),
		build("rpc", internalRPCScanRuleID, detectorSeverityHigh, cfg.InternalScan.RPC),
		build("ldap", internalLDAPScanRuleID, detectorSeverityHigh, cfg.InternalScan.LDAP),
		build("dns", internalDNSScanRuleID, detectorSeverityHigh, cfg.InternalScan.DNS),
		build("ftp", internalFTPScanRuleID, detectorSeverityHigh, cfg.InternalScan.FTP),
		build("rdp", internalRDPScanRuleID, detectorSeverityHigh, cfg.InternalScan.RDP),
		build("winrm", internalWinRMScanRuleID, detectorSeverityHigh, cfg.InternalScan.WinRM),
		build("ssh", internalSSHScanRuleID, detectorSeverityHigh, cfg.InternalScan.SSH),
	} {
		if detection != nil {
			detections = append(detections, detection)
		}
	}
	return detections
}

func matchInternalProtocolDetection(dstPort int) *protocolScanDetection {
	if dstPort <= 0 {
		return nil
	}
	for _, detection := range internalProtocolDetections {
		if detection == nil {
			continue
		}
		if _, ok := detection.Ports[dstPort]; ok {
			return detection
		}
	}
	return nil
}

func internalScanSourceKey(groupKey string, evt rawEvent, protocol string) string {
	nodeKey := strings.TrimSpace(groupKey)
	if nodeKey == "" {
		nodeKey = detectorNodeID(evt)
	}
	if nodeKey == "" {
		nodeKey = strings.TrimSpace(evt.SrcIP)
	}
	userKey := strings.ToLower(strings.TrimSpace(evt.User))
	return strings.Join([]string{nodeKey, userKey, protocol}, "|")
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
