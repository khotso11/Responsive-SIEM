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
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

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
		Paths                    []string `yaml:"paths"`
		Recursive                bool     `yaml:"recursive"`
		NodeID                   string   `yaml:"node_id"`
		SourceType               string   `yaml:"source_type"`
		CoalesceWindowMS         int      `yaml:"coalesce_window_ms"`
		AttributionWaitMS        int      `yaml:"attribution_wait_ms"`
		RecentContextRoot        string   `yaml:"recent_context_root"`
		RecentExecMaxAgeMS       int      `yaml:"recent_exec_max_age_ms"`
		RecentFileAccessMaxAgeMS int      `yaml:"recent_file_access_max_age_ms"`
		IgnorePrefixes           []string `yaml:"ignore_prefixes"`
	} `yaml:"collector"`
}

const watchMask = syscall.IN_CREATE | syscall.IN_MODIFY | syscall.IN_DELETE | syscall.IN_ATTRIB | syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO | syscall.IN_CLOSE_WRITE | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF

type pendingFileEvent struct {
	path      string
	action    string
	deadline  time.Time
	firstSeen time.Time
}

type eventPublisher interface {
	Publish(context.Context, string, []byte) (bool, error)
}

func main() {
	configPath := flag.String("config", "configs/collector-inotify.yaml", "Path to collector config")
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
		Name:          "r-siem-collector-inotify",
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

func run(ctx context.Context, cfg *configFile, logger *slog.Logger, publisher eventPublisher) error {
	fd, err := syscall.InotifyInit()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.SetNonblock(fd, true); err != nil {
		return err
	}

	nodeID := common.ResolveNodeID(cfg.Collector.NodeID)
	coalesceWindow := time.Duration(cfg.Collector.CoalesceWindowMS) * time.Millisecond
	contextStore := common.NewRecentContextStore(cfg.Collector.RecentContextRoot)
	execMaxAge := time.Duration(cfg.Collector.RecentExecMaxAgeMS) * time.Millisecond
	fileAccessMaxAge := time.Duration(cfg.Collector.RecentFileAccessMaxAgeMS) * time.Millisecond
	attributionWait := time.Duration(cfg.Collector.AttributionWaitMS) * time.Millisecond
	watches := map[int]string{}
	for _, root := range cfg.Collector.Paths {
		if cfg.Collector.Recursive {
			filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil || !info.IsDir() {
					return nil
				}
				wd, addErr := syscall.InotifyAddWatch(fd, path, watchMask)
				if addErr == nil {
					watches[wd] = path
				}
				return nil
			})
			continue
		}
		wd, addErr := syscall.InotifyAddWatch(fd, root, watchMask)
		if addErr == nil {
			watches[wd] = root
		}
	}
	logger.Info("collector_started",
		slog.String("collector", "inotify"),
		slog.Any("paths", cfg.Collector.Paths),
		slog.Int("coalesce_window_ms", cfg.Collector.CoalesceWindowMS),
		slog.Int("attribution_wait_ms", cfg.Collector.AttributionWaitMS),
	)

	buf := make([]byte, 4096)
	pending := map[string]pendingFileEvent{}
	flushTicker := time.NewTicker(200 * time.Millisecond)
	defer flushTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			flushPending(time.Now(), pending, publisher, cfg.Collector.SourceType, nodeID, logger, contextStore, execMaxAge, fileAccessMaxAge, attributionWait)
			return ctx.Err()
		case <-flushTicker.C:
			flushPending(time.Now(), pending, publisher, cfg.Collector.SourceType, nodeID, logger, contextStore, execMaxAge, fileAccessMaxAge, attributionWait)
		default:
		}
		n, err := syscall.Read(fd, buf)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		if n <= 0 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		offset := 0
		for offset < n {
			event := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameBytes := buf[offset+syscall.SizeofInotifyEvent : offset+syscall.SizeofInotifyEvent+int(event.Len)]
			name := strings.TrimRight(string(nameBytes), "\x00")
			base := watches[int(event.Wd)]
			path := base
			if name != "" {
				path = filepath.Join(base, name)
			}
			if cfg.Collector.Recursive && event.Mask&syscall.IN_ISDIR != 0 && event.Mask&syscall.IN_CREATE != 0 {
				if wd, addErr := syscall.InotifyAddWatch(fd, path, watchMask); addErr == nil {
					watches[wd] = path
				}
			}
			action := maskToAction(event.Mask)
			if action != "" {
				if shouldIgnorePath(path, cfg.Collector.IgnorePrefixes) {
					offset += syscall.SizeofInotifyEvent + int(event.Len)
					continue
				}
				existing := pending[path]
				firstSeen := existing.firstSeen
				if firstSeen.IsZero() {
					firstSeen = time.Now()
				}
				pending[path] = pendingFileEvent{
					path:      path,
					action:    mergeFileAction(pending[path].action, action),
					deadline:  time.Now().Add(coalesceWindow),
					firstSeen: firstSeen,
				}
			}
			offset += syscall.SizeofInotifyEvent + int(event.Len)
		}
	}
}

func flushPending(now time.Time, pending map[string]pendingFileEvent, publisher eventPublisher, sourceType, nodeID string, logger *slog.Logger, contextStore *common.RecentContextStore, execMaxAge, fileAccessMaxAge, attributionWait time.Duration) {
	for path, item := range pending {
		if item.deadline.After(now) {
			continue
		}
		attributed, eventID, data, metadata := buildFileEvent(sourceType, nodeID, item.path, item.action, contextStore, execMaxAge, fileAccessMaxAge)
		if !attributed && attributionWait > 0 && now.Sub(item.firstSeen) < attributionWait {
			logger.Info("collector_event_attribution_delayed",
				slog.String("collector", "inotify"),
				slog.String("path", item.path),
				slog.String("action", item.action),
				slog.Int64("age_ms", now.Sub(item.firstSeen).Milliseconds()),
				slog.Int64("wait_budget_ms", attributionWait.Milliseconds()),
			)
			item.deadline = now.Add(300 * time.Millisecond)
			pending[path] = item
			continue
		}
		if !publishFileEvent(publisher, logger, eventID, data, metadata) {
			continue
		}
		if !attributed {
			logger.Warn("collector_event_published_without_attribution",
				slog.String("collector", "inotify"),
				slog.String("path", item.path),
				slog.String("action", item.action),
				slog.Int64("age_ms", now.Sub(item.firstSeen).Milliseconds()),
			)
		}
		delete(pending, path)
	}
}

func mergeFileAction(current, next string) string {
	if current == "" {
		return next
	}
	if next == "" {
		return current
	}
	score := map[string]int{
		"attrib":   1,
		"created":  2,
		"modified": 3,
		"moved":    4,
		"deleted":  5,
	}
	if score[next] >= score[current] {
		return next
	}
	return current
}

type fileEventMetadata struct {
	path              string
	action            string
	user              string
	attributionSource string
}

func buildFileEvent(sourceType, nodeID, path, action string, contextStore *common.RecentContextStore, execMaxAge, fileAccessMaxAge time.Duration) (bool, string, []byte, fileEventMetadata) {
	ts := time.Now().UnixMilli()
	fileSHA256, fileSize, signerHint := common.FileMetadata(path)
	attribution, attributed := contextStore.FindFileAttribution(nodeID, path, time.UnixMilli(ts), fileAccessMaxAge, execMaxAge)
	username := "unknown"
	message := fmt.Sprintf("FILE path=%q action=%s user=unknown src=127.0.0.1 ts=%d node=%s", path, action, ts, nodeID)
	if attributed {
		username = attribution.User
		message = fmt.Sprintf("FILE path=%q action=%s user=%s src=127.0.0.1 ts=%d node=%s", path, action, username, ts, nodeID)
	}
	eventID := common.EventID("evt.inotify.", sourceType, nodeID, common.SHA256Hex([]byte(message)), ts)
	payload := map[string]any{
		"event_idem_key":      eventID,
		"observed_at_unix_ms": ts,
		"event_ts_unix_ms":    ts,
		"recv_ts_unix_ms":     ts,
		"message":             message,
		"raw_line":            message,
		"host":                nodeID,
		"node_id":             nodeID,
		"group_key":           nodeID,
		"source":              "collector-inotify",
		"source_type":         sourceType,
		"user":                username,
		"src_ip":              "127.0.0.1",
		"event_type":          "file_change",
		"file_path":           path,
		"action":              action,
	}
	if attributed {
		payload["pid"] = attribution.PID
		if attribution.ExecPath != "" {
			payload["exec_path"] = attribution.ExecPath
		}
		if attribution.Comm != "" {
			payload["comm"] = attribution.Comm
		}
		if attribution.Cmdline != "" {
			payload["cmdline"] = attribution.Cmdline
		}
		if attribution.Source != "" {
			payload["attribution_source"] = attribution.Source
		}
	}
	if fileSHA256 != "" {
		payload["file_sha256"] = fileSHA256
	}
	if fileSize > 0 {
		payload["file_size_bytes"] = fileSize
	}
	if signerHint != "" {
		payload["signer_hint"] = signerHint
	}
	data, _ := json.Marshal(payload)
	return attributed, eventID, data, fileEventMetadata{
		path:              path,
		action:            action,
		user:              username,
		attributionSource: payloadString(payload, "attribution_source"),
	}
}

func shouldIgnorePath(path string, ignorePrefixes []string) bool {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" {
		return false
	}
	for _, prefix := range ignorePrefixes {
		prefix = filepath.Clean(strings.TrimSpace(prefix))
		if prefix == "" {
			continue
		}
		if path == prefix || strings.HasPrefix(path, prefix+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func payloadString(payload map[string]any, key string) string {
	if payload == nil {
		return ""
	}
	value, _ := payload[key].(string)
	return strings.TrimSpace(value)
}

func publishFileEvent(publisher eventPublisher, logger *slog.Logger, eventID string, data []byte, metadata fileEventMetadata) bool {
	if queued, err := publisher.Publish(context.Background(), eventID, data); err == nil {
		if queued {
			logger.Warn("collector_event_spooled",
				slog.String("collector", "inotify"),
				slog.String("event_idem_key", eventID),
				slog.String("path", metadata.path),
				slog.String("action", metadata.action),
			)
		}
		logger.Info("collector_event_published",
			slog.String("collector", "inotify"),
			slog.String("event_idem_key", eventID),
			slog.String("event_type", "file_change"),
			slog.String("path", metadata.path),
			slog.String("action", metadata.action),
			slog.String("user", metadata.user),
			slog.String("attribution_source", metadata.attributionSource),
		)
		return true
	}
	return false
}

func maskToAction(mask uint32) string {
	switch {
	case mask&syscall.IN_CREATE != 0:
		return "created"
	case mask&syscall.IN_CLOSE_WRITE != 0 || mask&syscall.IN_MODIFY != 0:
		return "modified"
	case mask&syscall.IN_DELETE != 0 || mask&syscall.IN_DELETE_SELF != 0:
		return "deleted"
	case mask&syscall.IN_MOVED_FROM != 0 || mask&syscall.IN_MOVED_TO != 0 || mask&syscall.IN_MOVE_SELF != 0:
		return "moved"
	case mask&syscall.IN_ATTRIB != 0:
		return "attrib"
	default:
		return ""
	}
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
	if len(cfg.Collector.Paths) == 0 {
		cfg.Collector.Paths = []string{"/etc"}
	}
	if strings.TrimSpace(cfg.Collector.SourceType) == "" {
		cfg.Collector.SourceType = "inotify"
	}
	if cfg.Collector.CoalesceWindowMS <= 0 {
		cfg.Collector.CoalesceWindowMS = 1000
	}
	if cfg.Collector.AttributionWaitMS <= 0 {
		cfg.Collector.AttributionWaitMS = 15000
	}
	if strings.TrimSpace(cfg.Collector.RecentContextRoot) == "" {
		cfg.Collector.RecentContextRoot = "/var/lib/rsiem/recent_context"
	}
	if cfg.Collector.RecentExecMaxAgeMS <= 0 {
		cfg.Collector.RecentExecMaxAgeMS = 120000
	}
	if cfg.Collector.RecentFileAccessMaxAgeMS <= 0 {
		cfg.Collector.RecentFileAccessMaxAgeMS = 30000
	}
	if len(cfg.Collector.IgnorePrefixes) == 0 {
		cfg.Collector.IgnorePrefixes = []string{"/etc/rsiem", "/etc/systemd/system/rsiem-"}
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
