package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
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
		Path                      string `yaml:"path"`
		CheckpointPath            string `yaml:"checkpoint_path"`
		PollMs                    int    `yaml:"poll_ms"`
		NodeID                    string `yaml:"node_id"`
		SourceType                string `yaml:"source_type"`
		ConnectSourceType         string `yaml:"connect_source_type"`
		RecentContextRoot         string `yaml:"recent_context_root"`
		ExecContextMaxAgeMS       int    `yaml:"exec_context_max_age_ms"`
		FileAccessContextMaxAgeMS int    `yaml:"file_access_context_max_age_ms"`
	} `yaml:"collector"`
}

var (
	auditMsgPattern = regexp.MustCompile(`msg=audit\(([0-9]+(?:\.[0-9]+)?):([0-9]+)\)`)
	syscallPattern  = regexp.MustCompile(`\bsyscall=([0-9]+)\b`)
	successPattern  = regexp.MustCompile(`\bsuccess=([a-z]+)\b`)
	exitPattern     = regexp.MustCompile(`\bexit=([-0-9]+)\b`)
	exePattern      = regexp.MustCompile(`\bexe="([^"]+)"`)
	commPattern     = regexp.MustCompile(`\bcomm="([^"]+)"`)
	pidPattern      = regexp.MustCompile(`\bpid=([0-9]+)\b`)
	ppidPattern     = regexp.MustCompile(`\bppid=([0-9]+)\b`)
	sessionPattern  = regexp.MustCompile(`\bses=([0-9]+)\b`)
	ttyPattern      = regexp.MustCompile(`\btty=([[:graph:]]+)`)
	execArgPattern  = regexp.MustCompile(`\ba\d+="([^"]*)"`)
	uidPattern      = regexp.MustCompile(`\bauid=([0-9]+)\b`)
	uidFallbackPat  = regexp.MustCompile(`\buid=([0-9]+)\b`)
	pathNamePattern = regexp.MustCompile(`\bname="([^"]+)"`)
	saddrPattern    = regexp.MustCompile(`\bsaddr=([0-9A-Fa-f]+)\b`)
	laddrPattern    = regexp.MustCompile(`\bladdr=([0-9A-Fa-f:.]+)\b`)
	lportPattern    = regexp.MustCompile(`\blport=([0-9]+)\b`)
)

var noisyCorrelationPaths = []string{
	"/etc/passwd",
	"/etc/group",
	"/etc/gshadow",
	"/etc/shadow",
	"/etc/login.defs",
	"/etc/nsswitch.conf",
	"/etc/hosts",
	"/etc/environment",
	"/etc/default/locale",
	"/etc/ld.so.cache",
	"/etc/sudo.conf",
}

type pendingAuditEvent struct {
	syscallLine   string
	execveLine    string
	pathLines     []string
	sockaddrLines []string
	eventTs       int64
	lastSeen      time.Time
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
	file, err := os.Open(cfg.Collector.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	offset = normalizeCheckpointOffset(file, cfg.Collector.CheckpointPath, offset, logger)
	logger.Info("collector_started",
		slog.String("collector", "auditd"),
		slog.String("path", cfg.Collector.Path),
		slog.Uint64("offset", offset),
	)

	nodeID := common.ResolveNodeID(cfg.Collector.NodeID)
	contextStore := common.NewRecentContextStore(cfg.Collector.RecentContextRoot)
	execContextMaxAge := time.Duration(cfg.Collector.ExecContextMaxAgeMS) * time.Millisecond
	fileAccessContextMaxAge := time.Duration(cfg.Collector.FileAccessContextMaxAgeMS) * time.Millisecond
	pending := map[string]pendingAuditEvent{}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		file, offset, err = reopenAuditFileIfRotated(file, cfg.Collector.Path, cfg.Collector.CheckpointPath, offset, logger)
		if err != nil {
			return err
		}
		offset = normalizeCheckpointOffset(file, cfg.Collector.CheckpointPath, offset, logger)
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
					case "path":
						item.pathLines = append(item.pathLines, trimmed)
					case "sockaddr":
						item.sockaddrLines = append(item.sockaddrLines, trimmed)
					}
					pending[key] = item
					if kind == "sockaddr" || (kind == "syscall" && len(item.sockaddrLines) > 0) {
						publishPendingAuditConnectEvent(pending, key, nodeID, cfg.Collector.ConnectSourceType, publisher, logger)
					}
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
			flushPendingAuditEvents(pending, nodeID, cfg.Collector.SourceType, cfg.Collector.ConnectSourceType, publisher, logger, contextStore, execContextMaxAge, fileAccessContextMaxAge)
		}
		if progress {
			writeCheckpoint(cfg.Collector.CheckpointPath, offset)
		}
		time.Sleep(time.Duration(cfg.Collector.PollMs) * time.Millisecond)
	}
}

func reopenAuditFileIfRotated(file *os.File, path, checkpointPath string, offset uint64, logger *slog.Logger) (*os.File, uint64, error) {
	currentInfo, err := os.Stat(path)
	if err != nil {
		return file, offset, err
	}
	openInfo, err := file.Stat()
	if err != nil {
		return file, offset, err
	}
	if os.SameFile(openInfo, currentInfo) {
		return file, offset, nil
	}

	reopened, err := os.Open(path)
	if err != nil {
		return file, offset, err
	}
	if err := file.Close(); err != nil {
		_ = reopened.Close()
		return nil, offset, err
	}

	logger.Warn("audit_log_reopened_after_rotation",
		slog.String("collector", "auditd"),
		slog.String("path", path),
		slog.Uint64("stale_offset", offset),
		slog.Int64("old_size", openInfo.Size()),
		slog.Int64("new_size", currentInfo.Size()),
	)
	writeCheckpoint(checkpointPath, 0)
	return reopened, 0, nil
}

func flushPendingAuditEvents(pending map[string]pendingAuditEvent, nodeID, sourceType, connectSourceType string, publisher *common.OfflinePublisher, logger *slog.Logger, contextStore *common.RecentContextStore, execContextMaxAge, fileAccessContextMaxAge time.Duration) {
	for key, item := range pending {
		if strings.TrimSpace(item.syscallLine) == "" {
			if time.Since(item.lastSeen) > 5*time.Second {
				delete(pending, key)
			}
			continue
		}

		handled := false
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
				handled = true
			}
			if contextStore.Enabled() {
				if err := contextStore.RecordExec(common.RecentExecContext{
					TimestampUnixMS: payload["event_ts_unix_ms"].(int64),
					NodeID:          nodeID,
					User:            payload["user"].(string),
					PID:             payload["pid"].(int),
					ExecPath:        payload["exec_path"].(string),
					Comm:            payload["comm"].(string),
					Cmdline:         payload["cmdline"].(string),
					Source:          "auditd_exec",
				}, execContextMaxAge); err != nil {
					logger.Error("recent_exec_context_record_failed",
						slog.String("node_id", nodeID),
						slog.String("user", payload["user"].(string)),
						slog.String("exec_path", payload["exec_path"].(string)),
						slog.String("error", err.Error()),
					)
				}
			}
		}
		if contextStore.Enabled() {
			for _, access := range buildAuditFileAccessContexts(item, nodeID) {
				if err := contextStore.RecordFileAccess(access, fileAccessContextMaxAge); err != nil {
					logger.Error("recent_file_access_record_failed",
						slog.String("node_id", access.NodeID),
						slog.String("user", access.User),
						slog.String("path", access.Path),
						slog.String("exec_path", access.ExecPath),
						slog.String("comm", access.Comm),
						slog.String("error", err.Error()),
					)
					continue
				}
				logger.Info("recent_file_access_recorded",
					slog.String("node_id", access.NodeID),
					slog.String("user", access.User),
					slog.String("path", access.Path),
					slog.String("exec_path", access.ExecPath),
					slog.String("comm", access.Comm),
				)
			}
		}
		if publishAuditConnectPayload(item, nodeID, connectSourceType, publisher, logger) {
			handled = true
		}

		if handled || !shouldRetainPendingAuditEvent(item) {
			delete(pending, key)
		}
	}
}

func publishPendingAuditConnectEvent(pending map[string]pendingAuditEvent, key, nodeID, connectSourceType string, publisher *common.OfflinePublisher, logger *slog.Logger) {
	item, ok := pending[key]
	if !ok {
		return
	}
	if publishAuditConnectPayload(item, nodeID, connectSourceType, publisher, logger) {
		delete(pending, key)
	}
}

func publishAuditConnectPayload(item pendingAuditEvent, nodeID, connectSourceType string, publisher *common.OfflinePublisher, logger *slog.Logger) bool {
	payload, ok := buildAuditConnectPayload(item, nodeID, connectSourceType)
	if !ok {
		return false
	}
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
				slog.String("dst_ip", payload["dst_ip"].(string)),
				slog.Int("dst_port", payload["dst_port"].(int)),
			)
		}
		logger.Info("collector_event_published",
			slog.String("collector", "auditd"),
			slog.String("event_idem_key", eventID),
			slog.String("event_type", payload["event_type"].(string)),
			slog.String("user", payload["user"].(string)),
			slog.String("exec_path", payload["exec_path"].(string)),
			slog.String("dst_ip", payload["dst_ip"].(string)),
			slog.Int("dst_port", payload["dst_port"].(int)),
		)
		return true
	}
	logger.Error("collector_event_publish_failed",
		slog.String("collector", "auditd"),
		slog.String("event_idem_key", eventID),
		slog.String("event_type", payload["event_type"].(string)),
		slog.String("user", payload["user"].(string)),
		slog.String("exec_path", payload["exec_path"].(string)),
		slog.String("dst_ip", payload["dst_ip"].(string)),
		slog.Int("dst_port", payload["dst_port"].(int)),
	)
	return false
}

func shouldRetainPendingAuditEvent(item pendingAuditEvent) bool {
	line := strings.TrimSpace(item.syscallLine)
	if line == "" {
		return false
	}
	syscallMatch := syscallPattern.FindStringSubmatch(line)
	if len(syscallMatch) != 2 {
		return false
	}
	if isConnectSyscall(syscallMatch[1]) && len(item.sockaddrLines) == 0 {
		return time.Since(item.lastSeen) <= 5*time.Second
	}
	return false
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
	case strings.Contains(line, "type=PATH"):
		return m[1] + ":" + m[2], "path", eventTs, true
	case strings.Contains(line, "type=SOCKADDR"):
		return m[1] + ":" + m[2], "sockaddr", eventTs, true
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
	if isSelfAuditNoise(execPath, comm) {
		return nil, false
	}
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

func buildAuditConnectPayload(item pendingAuditEvent, nodeID, sourceType string) (map[string]any, bool) {
	line := item.syscallLine
	syscallMatch := syscallPattern.FindStringSubmatch(line)
	if len(syscallMatch) != 2 || !isConnectSyscall(syscallMatch[1]) {
		return nil, false
	}
	dstIP, dstPort, ok := parseAuditSockaddrLines(item.sockaddrLines)
	if !ok || strings.TrimSpace(dstIP) == "" || dstPort <= 0 {
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
	execPath := matchString(exePattern, line)
	if isSelfAuditNoise(execPath, comm) {
		return nil, false
	}
	pid := matchInt(pidPattern, line)
	ppid := matchInt(ppidPattern, line)
	sessionID := matchInt(sessionPattern, line)
	tty := strings.TrimSpace(matchString(ttyPattern, line))
	cmdline := extractExecArgs(item.execveLine)
	execSHA256, execSize, signerHint := common.FileMetadata(execPath)
	connectSuccess := true
	if m := successPattern.FindStringSubmatch(line); len(m) == 2 {
		connectSuccess = strings.EqualFold(m[1], "yes")
	}
	exitCode := matchInt(exitPattern, line)
	message := fmt.Sprintf("NET_CONNECT dst_ip=%s dst_port=%d success=%t exit=%d exec=%q comm=%q cmdline=%q pid=%d ppid=%d session=%d tty=%s user=%s ts=%d node=%s",
		dstIP, dstPort, connectSuccess, exitCode, execPath, comm, cmdline, pid, ppid, sessionID, tty, username, eventTs, nodeID)
	rawHash := common.SHA256Hex([]byte(item.syscallLine + "\n" + item.execveLine + "\n" + strings.Join(item.sockaddrLines, "\n")))
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
		"event_type":          "network_connection",
		"dst_ip":              dstIP,
		"dst_port":            dstPort,
		"exec_path":           execPath,
		"comm":                comm,
		"cmdline":             cmdline,
		"pid":                 pid,
		"ppid":                ppid,
		"session_id":          sessionID,
		"tty":                 tty,
		"ts":                  eventTs,
		"connect_success":     connectSuccess,
		"exit_code":           exitCode,
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

func buildAuditFileAccessContexts(item pendingAuditEvent, nodeID string) []common.RecentFileAccessContext {
	line := item.syscallLine
	syscallMatch := syscallPattern.FindStringSubmatch(line)
	if len(syscallMatch) != 2 || !isFileAccessSyscall(syscallMatch[1]) {
		return nil
	}
	if m := successPattern.FindStringSubmatch(line); len(m) == 2 && !strings.EqualFold(m[1], "yes") {
		return nil
	}
	if len(item.pathLines) == 0 {
		return nil
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
	execPath := matchString(exePattern, line)
	if isSelfAuditNoise(execPath, comm) {
		return nil
	}
	pid := matchInt(pidPattern, line)
	cmdline := extractExecArgs(item.execveLine)
	selectedPaths := selectRelevantAuditPaths(item.syscallLine, item.pathLines, cmdline, execPath, comm)
	contexts := make([]common.RecentFileAccessContext, 0, len(selectedPaths))
	for _, path := range selectedPaths {
		contexts = append(contexts, common.RecentFileAccessContext{
			TimestampUnixMS: eventTs,
			NodeID:          nodeID,
			User:            username,
			PID:             pid,
			Path:            path,
			Access:          "open",
			ExecPath:        execPath,
			Comm:            comm,
			Cmdline:         cmdline,
			Source:          "auditd_file_access",
		})
	}
	return contexts
}

func selectRelevantAuditPaths(syscallLine string, pathLines []string, cmdline, execPath, comm string) []string {
	candidates := make([]string, 0, len(pathLines))
	seen := make(map[string]struct{})
	addCandidate := func(path string) {
		path = filepath.Clean(strings.TrimSpace(path))
		if path == "" || path == "." || !strings.HasPrefix(path, "/") {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		candidates = append(candidates, path)
	}
	addCandidate(matchString(pathNamePattern, syscallLine))
	for _, pathLine := range pathLines {
		addCandidate(matchString(pathNamePattern, pathLine))
	}
	if len(candidates) == 0 {
		return nil
	}

	hints := absoluteCmdlinePaths(cmdline)
	selected := make([]string, 0, 4)
	selectedSet := make(map[string]struct{})
	add := func(path string) {
		if path == "" {
			return
		}
		if _, ok := selectedSet[path]; ok {
			return
		}
		selectedSet[path] = struct{}{}
		selected = append(selected, path)
	}

	if len(hints) > 0 {
		for _, hint := range hints {
			for _, candidate := range candidates {
				if candidate == hint {
					add(candidate)
				}
			}
		}
		if isLikelyFileMutator(comm, execPath) {
			for _, hint := range hints {
				for _, candidate := range candidates {
					if candidate == filepath.Dir(hint) {
						add(candidate)
					}
				}
			}
		}
	}

	if len(selected) > 0 {
		return selected
	}

	for _, candidate := range rankCorrelationCandidates(candidates, comm, execPath) {
		if !isNoisyCorrelationPath(candidate) {
			add(candidate)
		}
	}
	if len(selected) > 0 {
		return selected
	}
	for _, candidate := range rankCorrelationCandidates(candidates, comm, execPath) {
		add(candidate)
	}
	return selected
}

func rankCorrelationCandidates(candidates []string, comm, execPath string) []string {
	type ranked struct {
		path  string
		score int
	}
	rankedPaths := make([]ranked, 0, len(candidates))
	mutator := isLikelyFileMutator(comm, execPath)
	for _, candidate := range candidates {
		score := len(candidate)
		base := filepath.Base(candidate)
		if base != "" && strings.Contains(base, ".") {
			score += 200
		}
		if mutator {
			score += 100
			if strings.Contains(candidate, "/sudoers.d") || strings.Contains(candidate, "/ssh/") {
				score += 150
			}
		}
		if isNoisyCorrelationPath(candidate) {
			score -= 500
		}
		rankedPaths = append(rankedPaths, ranked{path: candidate, score: score})
	}
	sort.SliceStable(rankedPaths, func(i, j int) bool {
		if rankedPaths[i].score == rankedPaths[j].score {
			return rankedPaths[i].path < rankedPaths[j].path
		}
		return rankedPaths[i].score > rankedPaths[j].score
	})
	out := make([]string, 0, len(rankedPaths))
	for _, item := range rankedPaths {
		out = append(out, item.path)
	}
	return out
}

func absoluteCmdlinePaths(cmdline string) []string {
	fields := strings.Fields(strings.TrimSpace(cmdline))
	if len(fields) == 0 {
		return nil
	}
	out := make([]string, 0, len(fields))
	seen := make(map[string]struct{})
	for _, field := range fields {
		clean := filepath.Clean(strings.Trim(field, `"'`))
		if !strings.HasPrefix(clean, "/") || clean == "/" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	return out
}

func isLikelyFileMutator(comm, execPath string) bool {
	name := strings.ToLower(strings.TrimSpace(comm))
	if name == "" && execPath != "" {
		name = strings.ToLower(filepath.Base(execPath))
	}
	switch name {
	case "touch", "rm", "mv", "cp", "install", "tee", "sed", "perl", "python", "python3", "bash", "sh", "sudo", "vim", "vi", "nano", "systemctl":
		return true
	default:
		return false
	}
}

func isNoisyCorrelationPath(path string) bool {
	for _, noisy := range noisyCorrelationPaths {
		if path == noisy {
			return true
		}
	}
	if strings.HasPrefix(path, "/etc/pam.d/") {
		return true
	}
	return false
}

func isFileAccessSyscall(syscallID string) bool {
	switch syscallID {
	case "2", "76", "77", "85", "257", "437":
		return true
	default:
		return false
	}
}

func isConnectSyscall(syscallID string) bool {
	switch syscallID {
	case "42", "203", "362":
		return true
	default:
		return false
	}
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

func parseAuditSockaddrLines(lines []string) (string, int, bool) {
	for _, line := range lines {
		raw := matchString(saddrPattern, line)
		if raw != "" {
			if dstIP, dstPort, ok := parseAuditSockaddrHex(raw); ok {
				return dstIP, dstPort, true
			}
		}
		if dstIP, dstPort, ok := parseAuditSockaddrDecoded(line); ok {
			return dstIP, dstPort, true
		}
	}
	return "", 0, false
}

func parseAuditSockaddrDecoded(line string) (string, int, bool) {
	dstIP := matchString(laddrPattern, line)
	if strings.TrimSpace(dstIP) == "" {
		return "", 0, false
	}
	portStr := matchString(lportPattern, line)
	if strings.TrimSpace(portStr) == "" {
		return "", 0, false
	}
	dstPort, err := strconv.Atoi(portStr)
	if err != nil || dstPort <= 0 || dstPort > 65535 {
		return "", 0, false
	}
	return dstIP, dstPort, true
}

func parseAuditSockaddrHex(raw string) (string, int, bool) {
	decoded, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(decoded) < 8 {
		return "", 0, false
	}
	family := binary.LittleEndian.Uint16(decoded[0:2])
	port := int(binary.BigEndian.Uint16(decoded[2:4]))
	if port <= 0 || port > 65535 {
		return "", 0, false
	}
	switch family {
	case 2:
		if len(decoded) < 8 {
			return "", 0, false
		}
		return net.IPv4(decoded[4], decoded[5], decoded[6], decoded[7]).String(), port, true
	case 10:
		if len(decoded) < 24 {
			return "", 0, false
		}
		return net.IP(decoded[8:24]).String(), port, true
	default:
		return "", 0, false
	}
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
			if m[1] == "4294967295" || m[1] == "-1" {
				continue
			}
			if usr, err := user.LookupId(m[1]); err == nil && strings.TrimSpace(usr.Username) != "" {
				return strings.TrimSpace(usr.Username)
			}
			return m[1]
		}
	}
	return ""
}

func isSelfAuditNoise(execPath, comm string) bool {
	execPath = strings.TrimSpace(execPath)
	comm = strings.TrimSpace(comm)
	if strings.Contains(execPath, "/opt/rsiem/bin/collector-") {
		return true
	}
	if strings.HasPrefix(comm, "collector-") || comm == "collector-audit" || comm == "collector-auditd" {
		return true
	}
	return false
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
	if strings.TrimSpace(cfg.Collector.ConnectSourceType) == "" {
		cfg.Collector.ConnectSourceType = "auditd_connect"
	}
	if strings.TrimSpace(cfg.Collector.RecentContextRoot) == "" {
		cfg.Collector.RecentContextRoot = "/var/lib/rsiem/recent_context"
	}
	if cfg.Collector.ExecContextMaxAgeMS <= 0 {
		cfg.Collector.ExecContextMaxAgeMS = 120000
	}
	if cfg.Collector.FileAccessContextMaxAgeMS <= 0 {
		cfg.Collector.FileAccessContextMaxAgeMS = 30000
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

func normalizeCheckpointOffset(file *os.File, checkpointPath string, offset uint64, logger *slog.Logger) uint64 {
	info, err := file.Stat()
	if err != nil {
		return offset
	}
	size := uint64(info.Size())
	if offset <= size {
		return offset
	}
	logger.Warn("checkpoint_reset_after_truncation",
		slog.String("collector", "auditd"),
		slog.String("path", file.Name()),
		slog.Uint64("stale_offset", offset),
		slog.Uint64("current_size", size),
	)
	writeCheckpoint(checkpointPath, 0)
	return 0
}

func writeCheckpoint(path string, offset uint64) {
	_ = os.WriteFile(path, []byte(strconv.FormatUint(offset, 10)), 0644)
}
