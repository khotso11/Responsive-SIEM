package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

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
		PollMs          int    `yaml:"poll_ms"`
		NodeID          string `yaml:"node_id"`
		SourceType      string `yaml:"source_type"`
		IncludeLoopback bool   `yaml:"include_loopback"`
	} `yaml:"collector"`
}

type connEntry struct {
	SrcIP    string
	SrcPort  int
	DstIP    string
	DstPort  int
	Inode    string
	UID      int
	User     string
	PID      int
	ExecPath string
	Comm     string
	Cmdline  string
}

type procMeta struct {
	PID      int
	UID      int
	User     string
	ExecPath string
	Comm     string
	Cmdline  string
}

var observedTCPStates = map[string]struct{}{
	"01": {}, // ESTABLISHED
	"02": {}, // SYN_SENT
}

func (e connEntry) key() string {
	return fmt.Sprintf("%s:%d>%s:%d", e.SrcIP, e.SrcPort, e.DstIP, e.DstPort)
}

func main() {
	configPath := flag.String("config", "configs/collector-procnet.yaml", "Path to collector config")
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
		Name:          "r-siem-collector-procnet",
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
	seen := map[string]struct{}{}
	nodeID := common.ResolveNodeID(cfg.Collector.NodeID)
	ticker := time.NewTicker(time.Duration(cfg.Collector.PollMs) * time.Millisecond)
	defer ticker.Stop()

	logger.Info("collector_started", slog.String("collector", "procnet"))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			current, err := readTCP("/proc", cfg.Collector.IncludeLoopback)
			if err != nil {
				logger.Warn("procnet_read_failed", slog.String("error", err.Error()))
				continue
			}
			next := make(map[string]struct{}, len(current))
			for _, entry := range current {
				key := entry.key()
				next[key] = struct{}{}
				if _, ok := seen[key]; ok {
					continue
				}
				publishConn(publisher, cfg.Collector.SourceType, nodeID, entry, logger)
			}
			seen = next
		}
	}
}

func publishConn(publisher *common.OfflinePublisher, sourceType, nodeID string, entry connEntry, logger *slog.Logger) {
	ts := time.Now().UnixMilli()
	username := strings.TrimSpace(entry.User)
	if username == "" {
		username = "unknown"
	}
	message := fmt.Sprintf("NET src_ip=%s src_port=%d dst_ip=%s dst_port=%d user=%s pid=%d exec=%q comm=%q ts=%d node=%s",
		entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort, username, entry.PID, entry.ExecPath, entry.Comm, ts, nodeID)
	eventID := common.EventID("evt.procnet.", sourceType, nodeID, common.SHA256Hex([]byte(message)), ts)
	payload := map[string]any{
		"event_idem_key":      eventID,
		"observed_at_unix_ms": ts,
		"event_ts_unix_ms":    ts,
		"recv_ts_unix_ms":     ts,
		"message":             message,
		"raw_line":            message,
		"host":                nodeID,
		"node_id":             nodeID,
		"group_key":           entry.SrcIP,
		"source":              "collector-procnet",
		"source_type":         sourceType,
		"user":                username,
		"src_ip":              entry.SrcIP,
		"dst_ip":              entry.DstIP,
		"dst_port":            entry.DstPort,
		"pid":                 entry.PID,
		"exec_path":           strings.TrimSpace(entry.ExecPath),
		"comm":                strings.TrimSpace(entry.Comm),
		"cmdline":             strings.TrimSpace(entry.Cmdline),
		"event_type":          "network_connection",
	}
	data, _ := json.Marshal(payload)
	if queued, err := publisher.Publish(context.Background(), eventID, data); err == nil {
		if queued {
			logger.Warn("collector_event_spooled",
				slog.String("collector", "procnet"),
				slog.String("event_idem_key", eventID),
				slog.String("src_ip", entry.SrcIP),
				slog.String("dst_ip", entry.DstIP),
				slog.String("user", username),
				slog.Int("dst_port", entry.DstPort),
			)
		}
		logger.Info("collector_event_published",
			slog.String("collector", "procnet"),
			slog.String("event_idem_key", eventID),
			slog.String("src_ip", entry.SrcIP),
			slog.String("dst_ip", entry.DstIP),
			slog.String("user", username),
			slog.Int("dst_port", entry.DstPort),
		)
	}
}

func readTCP(procRoot string, includeLoopback bool) ([]connEntry, error) {
	var out []connEntry
	for _, relPath := range []string{"net/tcp", "net/tcp6"} {
		entries, err := readTCPTable(filepath.Join(procRoot, relPath), includeLoopback)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		out = append(out, entries...)
	}
	if len(out) == 0 {
		return out, nil
	}
	wanted := make(map[string]struct{}, len(out))
	for i := range out {
		if strings.TrimSpace(out[i].Inode) != "" {
			wanted[out[i].Inode] = struct{}{}
		}
	}
	owners := scanProcSocketOwners(procRoot, wanted)
	uidCache := map[int]string{}
	for i := range out {
		if meta, ok := owners[out[i].Inode]; ok {
			out[i].PID = meta.PID
			out[i].UID = meta.UID
			out[i].User = meta.User
			out[i].ExecPath = meta.ExecPath
			out[i].Comm = meta.Comm
			out[i].Cmdline = meta.Cmdline
			continue
		}
		if out[i].UID >= 0 {
			out[i].User = lookupUsername(out[i].UID, uidCache)
		}
		if strings.TrimSpace(out[i].User) == "" {
			out[i].User = "unknown"
		}
	}
	return out, nil
}

func readTCPTable(path string, includeLoopback bool) ([]connEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []connEntry
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if _, ok := observedTCPStates[fields[3]]; !ok {
			continue
		}
		srcIP, srcPort, ok := parseHexAddr(fields[1])
		if !ok {
			continue
		}
		dstIP, dstPort, ok := parseHexAddr(fields[2])
		if !ok || dstIP == "0.0.0.0" || dstIP == "::" {
			continue
		}
		if !includeLoopback && (isLoopbackIP(srcIP) || isLoopbackIP(dstIP)) {
			continue
		}
		uid, _ := strconv.Atoi(fields[7])
		out = append(out, connEntry{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
			Inode:   strings.TrimSpace(fields[9]),
			UID:     uid,
		})
	}
	return out, scanner.Err()
}

func parseHexAddr(raw string) (string, int, bool) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return "", 0, false
	}
	portVal, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, false
	}
	ip, ok := parseHexIP(parts[0])
	if !ok {
		return "", 0, false
	}
	return ip, int(portVal), true
}

func parseHexIP(raw string) (string, bool) {
	switch len(raw) {
	case 8:
		addrVal, err := strconv.ParseUint(raw, 16, 32)
		if err != nil {
			return "", false
		}
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(addrVal))
		return net.IP(buf).String(), true
	case 32:
		decoded, err := hexStringToBytes(raw)
		if err != nil {
			return "", false
		}
		for i := 0; i < len(decoded); i += 4 {
			decoded[i], decoded[i+1], decoded[i+2], decoded[i+3] = decoded[i+3], decoded[i+2], decoded[i+1], decoded[i]
		}
		return net.IP(decoded).String(), true
	default:
		return "", false
	}
}

func hexStringToBytes(raw string) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("odd hex length")
	}
	out := make([]byte, len(raw)/2)
	for i := 0; i < len(out); i++ {
		v, err := strconv.ParseUint(raw[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}

func scanProcSocketOwners(procRoot string, wanted map[string]struct{}) map[string]procMeta {
	if len(wanted) == 0 {
		return map[string]procMeta{}
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return map[string]procMeta{}
	}
	out := make(map[string]procMeta, len(wanted))
	uidCache := map[int]string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join(procRoot, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var meta *procMeta
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if _, ok := wanted[inode]; !ok {
				continue
			}
			if _, exists := out[inode]; exists {
				continue
			}
			if meta == nil {
				loaded := loadProcMeta(procRoot, pid, uidCache)
				meta = &loaded
			}
			out[inode] = *meta
		}
	}
	return out
}

func loadProcMeta(procRoot string, pid int, uidCache map[int]string) procMeta {
	meta := procMeta{PID: pid, UID: -1, User: "unknown"}
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		meta.ExecPath = exe
	}
	if comm, err := os.ReadFile(filepath.Join(base, "comm")); err == nil {
		meta.Comm = strings.TrimSpace(string(comm))
	}
	if cmdline, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		meta.Cmdline = normalizeCmdline(cmdline)
	}
	if status, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
		meta.UID = parseStatusUID(status)
	}
	if meta.UID >= 0 {
		meta.User = lookupUsername(meta.UID, uidCache)
	}
	return meta
}

func normalizeCmdline(data []byte) string {
	parts := strings.Split(strings.Trim(string(data), "\x00"), "\x00")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, " ")
}

func parseStatusUID(data []byte) int {
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return -1
		}
		uid, err := strconv.Atoi(fields[1])
		if err != nil {
			return -1
		}
		return uid
	}
	return -1
}

func lookupUsername(uid int, cache map[int]string) string {
	if uid < 0 {
		return "unknown"
	}
	if name, ok := cache[uid]; ok {
		return name
	}
	record, err := user.LookupId(strconv.Itoa(uid))
	if err != nil || strings.TrimSpace(record.Username) == "" {
		cache[uid] = "unknown"
		return "unknown"
	}
	cache[uid] = record.Username
	return record.Username
}

func isLoopbackIP(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	return ip != nil && ip.IsLoopback()
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
	if cfg.Collector.PollMs <= 0 {
		cfg.Collector.PollMs = 1000
	}
	if strings.TrimSpace(cfg.Collector.SourceType) == "" {
		cfg.Collector.SourceType = "proc_net"
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
