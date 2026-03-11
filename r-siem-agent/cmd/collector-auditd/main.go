package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"gopkg.in/yaml.v3"

	"r-siem-agent/internal/collector/common"
	"r-siem-agent/internal/logging"
)

type configFile struct {
	LogLevel  string `yaml:"log_level"`
	JetStream struct {
		URL               string `yaml:"url"`
		Stream            string `yaml:"stream"`
		Subject           string `yaml:"subject"`
		OfflineSpoolPath  string `yaml:"offline_spool_path"`
		OfflineSpoolFsync *bool  `yaml:"offline_spool_fsync"`
		RetryMs           int    `yaml:"retry_ms"`
	} `yaml:"jetstream"`
	Collector struct {
		Path           string `yaml:"path"`
		CheckpointPath string `yaml:"checkpoint_path"`
		PollMs         int    `yaml:"poll_ms"`
		NodeID         string `yaml:"node_id"`
		SourceType     string `yaml:"source_type"`
	} `yaml:"collector"`
}

var (
	auditMsgPattern = regexp.MustCompile(`msg=audit\(([0-9]+(?:\.[0-9]+)?):([0-9]+)\)`)
	syscallPattern  = regexp.MustCompile(`\bsyscall=([0-9]+)\b`)
	successPattern  = regexp.MustCompile(`\bsuccess=([a-z]+)\b`)
	exePattern      = regexp.MustCompile(`\bexe="([^"]+)"`)
	commPattern     = regexp.MustCompile(`\bcomm="([^"]+)"`)
	pidPattern      = regexp.MustCompile(`\bpid=([0-9]+)\b`)
	ppidPattern     = regexp.MustCompile(`\bppid=([0-9]+)\b`)
	sessionPattern  = regexp.MustCompile(`\bses=([0-9]+)\b`)
	ttyPattern      = regexp.MustCompile(`\btty=([[:graph:]]+)`)
	execArgPattern  = regexp.MustCompile(`\ba\d+="([^"]*)"`)
	uidPattern      = regexp.MustCompile(`\bauid=([0-9]+)\b`)
	uidFallbackPat  = regexp.MustCompile(`\buid=([0-9]+)\b`)
)

type pendingAuditEvent struct {
	syscallLine string
	execveLine  string
	eventTs     int64
	lastSeen    time.Time
}

func main() {
	configPath := flag.String("config", "configs/collector-auditd.yaml", "Path to collector config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}
	logger, err := logging.NewLogger(strings.ToUpper(strings.TrimSpace(cfg.LogLevel)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}

	publisher, err := common.NewOfflinePublisher(common.OfflinePublisherConfig{
		Name:          "r-siem-collector-auditd",
		URL:           cfg.JetStream.URL,
		Stream:        cfg.JetStream.Stream,
		Subject:       cfg.JetStream.Subject,
		SpoolPath:     cfg.JetStream.OfflineSpoolPath,
		RetryInterval: time.Duration(cfg.JetStream.RetryMs) * time.Millisecond,
		SpoolFsync:    cfg.JetStream.OfflineSpoolFsync != nil && *cfg.JetStream.OfflineSpoolFsync,
	}, logger)
	if err != nil {
		logger.Error("offline_publisher_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer publisher.Close()

	ctx, cancel := signalContext()
	defer cancel()
	publisher.Start(ctx)
	if err := run(ctx, cfg, logger, publisher); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("collector_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *configFile, logger *slog.Logger, publisher *common.OfflinePublisher) error {
	offset := loadCheckpoint(cfg.Collector.CheckpointPath)
	logger.Info("collector_started",
		slog.String("collector", "auditd"),
		slog.String("path", cfg.Collector.Path),
		slog.Uint64("offset", offset),
	)

	file, err := os.Open(cfg.Collector.Path)
	if err != nil {
		return err
	}
	defer file.Close()

	nodeID := common.ResolveNodeID(cfg.Collector.NodeID)
	pending := map[string]pendingAuditEvent{}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
			return err
		}
		reader := bufio.NewReader(file)
		progress := false
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				offset += uint64(len(line))
				progress = true
				trimmed := strings.TrimRight(line, "\r\n")
				if key, kind, eventTs, ok := parseAuditKey(trimmed); ok {
					item := pending[key]
					item.lastSeen = time.Now()
					if eventTs > 0 {
						item.eventTs = eventTs
					}
					switch kind {
					case "syscall":
						item.syscallLine = trimmed
					case "execve":
						item.execveLine = trimmed
					}
					pending[key] = item
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return err
			}
		}
		if progress {
			flushPendingAuditEvents(pending, nodeID, cfg.Collector.SourceType, publisher, logger)
		}
		if progress {
			writeCheckpoint(cfg.Collector.CheckpointPath, offset)
		}
		time.Sleep(time.Duration(cfg.Collector.PollMs) * time.Millisecond)
	}
}

func flushPendingAuditEvents(pending map[string]pendingAuditEvent, nodeID, sourceType string, publisher *common.OfflinePublisher, logger *slog.Logger) {
	for key, item := range pending {
		if strings.TrimSpace(item.syscallLine) == "" {
			if time.Since(item.lastSeen) > 5*time.Second {
				delete(pending, key)
			}
			continue
		}
		if payload, ok := buildAuditExecPayload(item, nodeID, sourceType); ok {
			data, _ := json.Marshal(payload)
			eventID := payload["event_idem_key"].(string)
			if queued, err := publisher.Publish(context.Background(), eventID, data); err == nil {
				if queued {
					logger.Warn("collector_event_spooled",
						slog.String("collector", "auditd"),
						slog.String("event_idem_key", eventID),
						slog.String("event_type", payload["event_type"].(string)),
						slog.String("user", payload["user"].(string)),
						slog.String("exec_path", payload["exec_path"].(string)),
					)
				}
				logger.Info("collector_event_published",
					slog.String("collector", "auditd"),
					slog.String("event_idem_key", eventID),
					slog.String("event_type", payload["event_type"].(string)),
					slog.String("user", payload["user"].(string)),
					slog.String("exec_path", payload["exec_path"].(string)),
				)
			}
		}
		delete(pending, key)
	}
}

func parseAuditKey(line string) (string, string, int64, bool) {
	m := auditMsgPattern.FindStringSubmatch(line)
	if len(m) != 3 {
		return "", "", 0, false
	}
	eventTs := int64(0)
	if sec, err := strconv.ParseFloat(m[1], 64); err == nil {
		eventTs = int64(sec * 1000)
	}
	switch {
	case strings.Contains(line, "type=SYSCALL"):
		return m[1] + ":" + m[2], "syscall", eventTs, true
	case strings.Contains(line, "type=EXECVE"):
		return m[1] + ":" + m[2], "execve", eventTs, true
	default:
		return "", "", 0, false
	}
}

func buildAuditExecPayload(item pendingAuditEvent, nodeID, sourceType string) (map[string]any, bool) {
	line := item.syscallLine
	syscallMatch := syscallPattern.FindStringSubmatch(line)
	if len(syscallMatch) != 2 {
		return nil, false
	}
	if syscallMatch[1] != "59" && syscallMatch[1] != "322" {
		return nil, false
	}
	if m := successPattern.FindStringSubmatch(line); len(m) == 2 && !strings.EqualFold(m[1], "yes") {
		return nil, false
	}
	exeMatch := exePattern.FindStringSubmatch(line)
	if len(exeMatch) != 2 {
		return nil, false
	}
	eventTs := item.eventTs
	if eventTs <= 0 {
		eventTs = time.Now().UnixMilli()
	}
	username := lookupUID(line)
	if username == "" {
		username = "unknown"
	}
	comm := matchString(commPattern, line)
	execPath := exeMatch[1]
	pid := matchInt(pidPattern, line)
	ppid := matchInt(ppidPattern, line)
	sessionID := matchInt(sessionPattern, line)
	tty := strings.TrimSpace(matchString(ttyPattern, line))
	cmdline := extractExecArgs(item.execveLine)
	execSHA256, execSize, signerHint := common.FileMetadata(execPath)
	message := fmt.Sprintf("PROC exec=\"%s\" comm=\"%s\" cmdline=%q pid=%d ppid=%d session=%d tty=%s user=%s src=127.0.0.1 ts=%d node=%s",
		execPath, comm, cmdline, pid, ppid, sessionID, tty, username, eventTs, nodeID)
	rawHash := common.SHA256Hex([]byte(item.syscallLine + "\n" + item.execveLine))
	eventID := common.EventID("evt.auditd.", sourceType, nodeID, rawHash, eventTs)
	payload := map[string]any{
		"event_idem_key":      eventID,
		"observed_at_unix_ms": time.Now().UnixMilli(),
		"event_ts_unix_ms":    eventTs,
		"recv_ts_unix_ms":     time.Now().UnixMilli(),
		"message":             message,
		"raw_line":            line,
		"host":                nodeID,
		"node_id":             nodeID,
		"group_key":           nodeID,
		"source":              "collector-auditd",
		"source_type":         sourceType,
		"user":                username,
		"src_ip":              "127.0.0.1",
		"event_type":          "process_exec",
		"exec_path":           execPath,
		"comm":                comm,
		"cmdline":             cmdline,
		"pid":                 pid,
		"ppid":                ppid,
		"session_id":          sessionID,
		"tty":                 tty,
		"ts":                  eventTs,
	}
	if execSHA256 != "" {
		payload["exec_sha256"] = execSHA256
	}
	if execSize > 0 {
		payload["exec_size_bytes"] = execSize
	}
	if signerHint != "" {
		payload["signer_hint"] = signerHint
	}
	return payload, true
}

func matchString(pattern *regexp.Regexp, line string) string {
	m := pattern.FindStringSubmatch(line)
	if len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func matchInt(pattern *regexp.Regexp, line string) int {
	m := pattern.FindStringSubmatch(line)
	if len(m) != 2 {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func extractExecArgs(line string) string {
	if strings.TrimSpace(line) == "" {
		return ""
	}
	matches := execArgPattern.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return ""
	}
	args := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) == 2 && strings.TrimSpace(m[1]) != "" {
			args = append(args, m[1])
		}
	}
	return strings.Join(args, " ")
}

func lookupUID(line string) string {
	for _, pattern := range []*regexp.Regexp{uidPattern, uidFallbackPat} {
		if m := pattern.FindStringSubmatch(line); len(m) == 2 {
			if usr, err := user.LookupId(m[1]); err == nil && strings.TrimSpace(usr.Username) != "" {
				return strings.TrimSpace(usr.Username)
			}
			return m[1]
		}
	}
	return ""
}

func loadConfig(path string) (*configFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg configFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if strings.TrimSpace(cfg.LogLevel) == "" {
		cfg.LogLevel = "INFO"
	}
	if strings.TrimSpace(cfg.JetStream.URL) == "" {
		cfg.JetStream.URL = "nats://127.0.0.1:4222"
	}
	if strings.TrimSpace(cfg.JetStream.Stream) == "" {
		cfg.JetStream.Stream = "RSIEM_EVENTS"
	}
	if strings.TrimSpace(cfg.JetStream.Subject) == "" {
		cfg.JetStream.Subject = "rsiem.events.raw"
	}
	if cfg.JetStream.RetryMs <= 0 {
		cfg.JetStream.RetryMs = 2000
	}
	if strings.TrimSpace(cfg.Collector.Path) == "" {
		cfg.Collector.Path = "/var/log/audit/audit.log"
	}
	if strings.TrimSpace(cfg.Collector.CheckpointPath) == "" {
		cfg.Collector.CheckpointPath = "/var/lib/rsiem/auditd.checkpoint"
	}
	if cfg.Collector.PollMs <= 0 {
		cfg.Collector.PollMs = 500
	}
	if strings.TrimSpace(cfg.Collector.SourceType) == "" {
		cfg.Collector.SourceType = "auditd_exec"
	}
	return &cfg, nil
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

func ensureEventsStream(js nats.JetStreamContext, stream, subject string) error {
	_, err := js.AddStream(&nats.StreamConfig{Name: stream, Subjects: []string{subject}})
	if err != nil && !errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return err
	}
	return nil
}

func loadCheckpoint(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return n
}

func writeCheckpoint(path string, offset uint64) {
	_ = os.WriteFile(path, []byte(strconv.FormatUint(offset, 10)), 0644)
}
