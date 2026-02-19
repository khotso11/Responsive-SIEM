package tail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
)

const maxBytesPerPoll = uint64(1 << 20) // 1 MiB per poll to bound backlog

var (
	ipv4FromPattern = regexp.MustCompile(`(?i)\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b`)
	ipv4SrcPattern  = regexp.MustCompile(`(?i)\bsrc[=: ]+(\d{1,3}(?:\.\d{1,3}){3})\b`)
	userPattern     = regexp.MustCompile(`(?i)\buser(?:name)?[=: ]+([a-z0-9._-]+)\b`)
	hostPattern     = regexp.MustCompile(`(?i)\bhost[=: ]+([a-z0-9._-]+)\b`)
	authFailedA     = regexp.MustCompile(`(?i)^FAILED login user=([a-z0-9._-]+)\s+src=(\d{1,3}(?:\.\d{1,3}){3})\s+ts=([0-9]{9,13})$`)
	sshdFailed      = regexp.MustCompile(`(?i)Failed password for(?: invalid user)? ([a-z0-9._-]+) from (\d{1,3}(?:\.\d{1,3}){3})`)
	explicitTSPat   = regexp.MustCompile(`\bts=([0-9]{9,13})\b`)
)

type Collector struct {
	cfg    Config
	logger *slog.Logger
	js     nats.JetStreamContext

	cancel context.CancelFunc
	wg     sync.WaitGroup

	running    atomic.Bool
	lastErr    atomic.Value
	published  atomic.Uint64
	errors     atomic.Uint64
	lastOffset atomic.Uint64
}

func New(cfg Config, logger *slog.Logger, js nats.JetStreamContext) *Collector {
	cfg.applyDefaults()
	return &Collector{cfg: cfg, logger: logger, js: js}
}

func (c *Collector) Start(ctx context.Context) error {
	if c.js == nil {
		return fmt.Errorf("jetstream required")
	}
	if strings.TrimSpace(c.cfg.Path) == "" {
		return fmt.Errorf("path required")
	}
	if strings.TrimSpace(c.cfg.Subject) == "" || strings.TrimSpace(c.cfg.Stream) == "" {
		return fmt.Errorf("stream and subject required")
	}
	if c.running.Load() {
		return fmt.Errorf("collector already running")
	}

	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.running.Store(true)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.run(ctx)
	}()
	return nil
}

func (c *Collector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	c.running.Store(false)
	return nil
}

func (c *Collector) run(ctx context.Context) {
	state, err := loadCheckpoint(c.cfg.CheckpointPath)
	if err != nil {
		c.setError(err)
		c.logger.Error("collector_tail_checkpoint_load_failed", slog.String("error", err.Error()))
		state = checkpointState{}
	}
	offset := state.Offset
	c.lastOffset.Store(offset)
	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_tail_checkpoint_state",
		slog.String("checkpoint_path", c.cfg.CheckpointPath),
		slog.Uint64("offset", offset),
		slog.Bool("resumed_from_checkpoint", offset > 0),
	)

	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_started",
		slog.String("path", c.cfg.Path),
		slog.String("subject", c.cfg.Subject),
		slog.String("stream", c.cfg.Stream),
		slog.String("checkpoint_path", c.cfg.CheckpointPath),
	)

	file, err := openTailFile(c.cfg.Path)
	if err != nil {
		c.setError(err)
		c.logger.Error("collector_tail_open_failed", slog.String("error", err.Error()))
		return
	}
	defer file.Close()

	pending := bytes.Buffer{}
	pendingOffset := offset
	processedCount := uint64(0)
	skippedCount := uint64(0)
	lastProgressLogAt := time.Now()
	lastProgressProcessed := uint64(0)

	for {
		if ctx.Err() != nil {
			break
		}

		info, err := file.Stat()
		if err != nil {
			c.setError(err)
			c.logger.Error("collector_tail_stat_failed", slog.String("error", err.Error()))
			time.Sleep(c.cfg.PollInterval)
			continue
		}
		if uint64(info.Size()) < offset {
			offset = 0
			pending.Reset()
			pendingOffset = 0
			c.lastOffset.Store(0)
			if err := writeCheckpoint(c.cfg.CheckpointPath, checkpointState{Offset: 0}); err != nil {
				c.setError(err)
				c.logger.Error("collector_tail_checkpoint_write_failed", slog.String("error", err.Error()))
			} else {
				c.logger.LogAttrs(context.Background(), slog.LevelInfo, "checkpoint_written",
					slog.Uint64("offset", 0),
				)
			}
		}

		if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
			c.setError(err)
			c.logger.Error("collector_tail_seek_failed", slog.String("error", err.Error()))
			time.Sleep(c.cfg.PollInterval)
			continue
		}
		reader := bufio.NewReader(file)
		bytesThisPoll := uint64(0)

		for {
			if ctx.Err() != nil {
				return
			}
			chunk, err := reader.ReadBytes('\n')
			if len(chunk) > 0 {
				if pending.Len() == 0 {
					pendingOffset = offset
				}
				offset += uint64(len(chunk))
				bytesThisPoll += uint64(len(chunk))
				pending.Write(chunk)
			}
			if err != nil && !errors.Is(err, io.EOF) {
				c.setError(err)
				c.logger.Error("collector_tail_read_failed", slog.String("error", err.Error()))
				break
			}
			if len(chunk) == 0 && errors.Is(err, io.EOF) {
				break
			}

			if len(chunk) > 0 && chunk[len(chunk)-1] == '\n' {
				lineBytes := pending.Bytes()
				line := strings.TrimRight(string(lineBytes), "\r\n")
				bytesRead := len(lineBytes)
				pending.Reset()
				processedCount++
				eventID, published, publishErr := c.publishLine(ctx, line, pendingOffset)
				if publishErr != nil {
					offset = pendingOffset
					pending.Reset()
					break
				}
				if !published {
					skippedCount++
				}
				c.lastOffset.Store(offset)
				if err := writeCheckpoint(c.cfg.CheckpointPath, checkpointState{Offset: offset}); err != nil {
					c.setError(err)
					c.logger.Error("collector_tail_checkpoint_write_failed", slog.String("error", err.Error()))
				} else {
					c.logger.LogAttrs(context.Background(), slog.LevelInfo, "checkpoint_written",
						slog.Uint64("offset", offset),
					)
				}
				if published {
					c.logger.LogAttrs(context.Background(), slog.LevelInfo, "event_published",
						slog.String("event_idem_key", eventID),
						slog.Uint64("offset", pendingOffset),
						slog.Int("bytes", bytesRead),
					)
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if bytesThisPoll >= maxBytesPerPoll {
				break
			}
		}

		if processedCount > 0 && (processedCount-lastProgressProcessed >= 100 || time.Since(lastProgressLogAt) >= 15*time.Second) {
			c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_tail_progress",
				slog.Uint64("processed_count", processedCount),
				slog.Uint64("published_count", c.published.Load()),
				slog.Uint64("skipped_count", skippedCount),
				slog.Uint64("offset", offset),
			)
			lastProgressLogAt = time.Now()
			lastProgressProcessed = processedCount
		}

		time.Sleep(c.cfg.PollInterval)
	}

	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_tail_stopped")
}

func (c *Collector) publishLine(ctx context.Context, line string, offset uint64) (string, bool, error) {
	eventType, srcIP, user, tsUnix := extractAuthMetadata(line)
	if eventType != "auth_failed" {
		return "", false, nil
	}
	source := fmt.Sprintf("tail:%s", c.cfg.Path)
	eventID := eventIdemKey(source, offset, line)
	host := extractHost(line)
	if host == "" {
		host = resolveHost()
	}

	groupKey := host
	if srcIP != "" {
		groupKey = srcIP
	}
	if user == "" {
		user = "unknown"
	}
	payload := map[string]any{
		"event_idem_key":      eventID,
		"observed_at_unix_ms": time.Now().UnixMilli(),
		"message":             line,
		"raw_line":            line,
		"host":                host,
		"group_key":           groupKey,
		"source":              source,
		"user":                user,
		"src_ip":              srcIP,
		"event_type":          eventType,
		"ts":                  tsUnix,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		c.setError(err)
		c.errors.Add(1)
		c.logger.Error("collector_tail_event_encode_failed", slog.String("error", err.Error()))
		return "", false, err
	}

	if _, err := c.js.Publish(c.cfg.Subject, data, nats.MsgId(eventID)); err != nil {
		c.setError(err)
		c.errors.Add(1)
		c.logger.Error("collector_tail_publish_failed", slog.String("error", err.Error()))
		time.Sleep(c.cfg.PollInterval)
		return "", false, err
	}
	c.published.Add(1)
	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_event_published",
		slog.String("event_idem_key", eventID),
		slog.String("event_type", eventType),
		slog.String("src_ip", srcIP),
		slog.String("user", user),
		slog.Int64("ts", tsUnix),
	)
	return eventID, true, nil
}

func (c *Collector) setError(err error) {
	if err == nil {
		return
	}
	c.lastErr.Store(err.Error())
}

func eventIdemKey(source string, offset uint64, line string) string {
	raw := fmt.Sprintf("%s:%d:%s", source, offset, line)
	sum := sha256.Sum256([]byte(raw))
	return "evt." + hex.EncodeToString(sum[:])
}

func resolveHost() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "unknown"
	}
	return strings.TrimSpace(host)
}

func extractIPv4(line string) string {
	match := ipv4FromPattern.FindStringSubmatch(line)
	if len(match) >= 2 {
		return match[1]
	}
	match = ipv4SrcPattern.FindStringSubmatch(line)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractUser(line string) string {
	match := userPattern.FindStringSubmatch(line)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractHost(line string) string {
	match := hostPattern.FindStringSubmatch(line)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func extractAuthMetadata(line string) (eventType, srcIP, user string, tsUnix int64) {
	if m := authFailedA.FindStringSubmatch(line); len(m) == 4 {
		eventType = "auth_failed"
		user = m[1]
		srcIP = m[2]
		parsedTs, err := parseUnix(m[3])
		if err == nil {
			tsUnix = parsedTs
		}
		if tsUnix == 0 {
			tsUnix = deriveDeterministicTS(line)
		}
		return
	}

	if m := sshdFailed.FindStringSubmatch(line); len(m) == 3 {
		eventType = "auth_failed"
		user = m[1]
		srcIP = m[2]
		tsUnix = deriveTimestamp(line)
		return
	}

	if strings.Contains(strings.ToLower(line), "invalid user") {
		srcIP = extractIPv4(line)
		if srcIP == "" {
			return "", "", "", 0
		}
		eventType = "auth_failed"
		user = extractUser(line)
		if user == "" {
			user = "unknown"
		}
		tsUnix = deriveTimestamp(line)
		return
	}

	return "", "", "", 0
}

func deriveTimestamp(line string) int64 {
	if m := explicitTSPat.FindStringSubmatch(line); len(m) == 2 {
		if parsed, err := parseUnix(m[1]); err == nil && parsed > 0 {
			return parsed
		}
	}
	return deriveDeterministicTS(line)
}

func deriveDeterministicTS(line string) int64 {
	const baseUnix = int64(1700000000)
	const spanSeconds = uint64(365 * 24 * 60 * 60)

	sum := sha256.Sum256([]byte(line))
	value := binary.BigEndian.Uint64(sum[:8])
	return baseUnix + int64(value%spanSeconds)
}

func parseUnix(raw string) (int64, error) {
	if len(raw) >= 13 {
		// Treat as unix milliseconds and convert to seconds.
		tsMs, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return 0, err
		}
		return tsMs / 1000, nil
	}
	ts, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	return ts, nil
}

func openTailFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0644)
}
