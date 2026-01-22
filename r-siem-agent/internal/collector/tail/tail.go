package tail

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"r-siem-agent/internal/buffer"
	"r-siem-agent/internal/collector"
	"r-siem-agent/internal/event"
	"r-siem-agent/internal/proto/pb"
)

var failedPasswordIP = regexp.MustCompile(`from (\d+\.\d+\.\d+\.\d+)`)

type Collector struct {
	cfg       Config
	logger    *slog.Logger
	publisher *buffer.JetStreamPublisher

	cancel context.CancelFunc
	wg     sync.WaitGroup

	running    atomic.Bool
	lastErr    atomic.Value
	published  atomic.Uint64
	errors     atomic.Uint64
	lastOffset atomic.Uint64
	lastSeq    atomic.Uint64
}

func New(cfg Config, logger *slog.Logger, publisher *buffer.JetStreamPublisher) *Collector {
	cfg.applyDefaults()
	return &Collector{cfg: cfg, logger: logger, publisher: publisher}
}

func (c *Collector) Name() string {
	return "collector-tail"
}

func (c *Collector) Start(ctx context.Context) error {
	if c.publisher == nil {
		return fmt.Errorf("publisher required")
	}
	if strings.TrimSpace(c.cfg.Path) == "" {
		return fmt.Errorf("path required")
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

func (c *Collector) Health() collector.Health {
	var lastErr string
	if val := c.lastErr.Load(); val != nil {
		lastErr, _ = val.(string)
	}
	return collector.Health{
		Running:    c.running.Load(),
		LastError:  lastErr,
		Published:  c.published.Load(),
		Errors:     c.errors.Load(),
		LastOffset: c.lastOffset.Load(),
		LastSeq:    c.lastSeq.Load(),
	}
}

func (c *Collector) run(ctx context.Context) {
	state, err := loadCheckpoint(c.cfg.CheckpointPath)
	if err != nil {
		c.setError(err)
		c.logger.Error("collector_tail_checkpoint_load_failed", slog.String("error", err.Error()))
		state = checkpointState{}
	}
	c.lastOffset.Store(state.Offset)
	c.lastSeq.Store(state.Seq)

	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_tail_started",
		slog.String("path", c.cfg.Path),
		slog.String("checkpoint", c.cfg.CheckpointPath),
	)
	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_tail_checkpoint_loaded",
		slog.Uint64("offset", state.Offset),
	)

	file, err := os.OpenFile(c.cfg.Path, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		c.setError(err)
		c.logger.Error("collector_tail_open_failed", slog.String("error", err.Error()))
		return
	}
	defer file.Close()

	committedOffset := state.Offset
	currentOffset := state.Offset
	seq := state.Seq
	pending := bytes.Buffer{}

	for {
		if ctx.Err() != nil {
			break
		}

		if err := c.ensureOffset(&committedOffset, &currentOffset, &pending, file); err != nil {
			c.setError(err)
			c.logger.Error("collector_tail_offset_check_failed", slog.String("error", err.Error()))
			time.Sleep(c.cfg.PollInterval)
			continue
		}

		if _, err := file.Seek(int64(currentOffset), io.SeekStart); err != nil {
			c.setError(err)
			c.logger.Error("collector_tail_seek_failed", slog.String("error", err.Error()))
			time.Sleep(c.cfg.PollInterval)
			continue
		}
		reader := bufio.NewReader(file)

		for {
			if ctx.Err() != nil {
				return
			}
			chunk, err := reader.ReadBytes('\n')
			if len(chunk) > 0 {
				currentOffset += uint64(len(chunk))
			}
			if err != nil && !errors.Is(err, io.EOF) {
				c.setError(err)
				c.logger.Error("collector_tail_read_failed", slog.String("error", err.Error()))
				break
			}
			if len(chunk) == 0 && errors.Is(err, io.EOF) {
				break
			}

			if len(chunk) > 0 {
				pending.Write(chunk)
				if chunk[len(chunk)-1] != '\n' {
					if errors.Is(err, io.EOF) {
						break
					}
					continue
				}
				line := strings.TrimRight(pending.String(), "\r\n")
				pending.Reset()
				seq++
				published, publishErr := c.publishLine(ctx, line, seq)
				if publishErr != nil {
					seq--
					currentOffset = committedOffset
					pending.Reset()
					break
				}
				if published {
					committedOffset = currentOffset
					c.lastOffset.Store(committedOffset)
					c.lastSeq.Store(seq)
					if err := writeCheckpoint(c.cfg.CheckpointPath, checkpointState{Offset: committedOffset, Seq: seq}); err != nil {
						c.setError(err)
						c.logger.Error("collector_tail_checkpoint_write_failed", slog.String("error", err.Error()))
					}
					c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_tail_event_published",
						slog.Uint64("count", c.published.Load()),
						slog.Uint64("last_offset", committedOffset),
					)
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
		}

		time.Sleep(c.cfg.PollInterval)
	}

	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_tail_stopped")
}

func (c *Collector) ensureOffset(committedOffset, currentOffset *uint64, pending *bytes.Buffer, file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	size := uint64(info.Size())
	if size < *committedOffset {
		c.logger.Warn("collector_tail_checkpoint_truncated",
			slog.Uint64("offset", *committedOffset),
			slog.Uint64("size", size),
		)
		*committedOffset = 0
		*currentOffset = 0
		pending.Reset()
		return nil
	}
	if *currentOffset < *committedOffset {
		*currentOffset = *committedOffset
	}
	return nil
}

func (c *Collector) publishLine(ctx context.Context, line string, seq uint64) (bool, error) {
	if strings.TrimSpace(line) == "" {
		return false, nil
	}
	ip := extractIP(line)
	if ip == "" {
		ip = "unknown"
	}
	payload := tailEventPayload(line, ip, seq)
	data, err := json.Marshal(payload)
	if err != nil {
		c.setError(err)
		c.errors.Add(1)
		c.logger.Error("collector_tail_event_encode_failed", slog.String("error", err.Error()))
		return false, err
	}
	batch := &pb.Batch{
		ProducerId: "collector-tail",
		Lane:       "FAST",
		SeqStart:   seq,
		SeqEnd:     seq,
		Payload:    data,
	}
	encoded, err := proto.Marshal(batch)
	if err != nil {
		c.setError(err)
		c.errors.Add(1)
		c.logger.Error("collector_tail_batch_encode_failed", slog.String("error", err.Error()))
		return false, err
	}
	if _, err := c.publisher.PublishBatch(ctx, "FAST", encoded); err != nil {
		c.setError(err)
		c.errors.Add(1)
		c.logger.Error("collector_tail_publish_failed", slog.String("error", err.Error()))
		time.Sleep(c.cfg.PollInterval)
		return false, err
	}
	c.published.Add(1)
	return true, nil
}

func (c *Collector) setError(err error) {
	if err == nil {
		return
	}
	c.lastErr.Store(err.Error())
}

type tailEvent struct {
	event.Event
	SrcIP string `json:"src_ip,omitempty"`
}

func tailEventPayload(line string, srcIP string, seq uint64) tailEvent {
	return tailEvent{
		Event: event.Event{
			ID:        fmt.Sprintf("tail-%d", seq),
			Seq:       seq,
			Timestamp: time.Now().UTC(),
			Source:    "collector-tail",
			Type:      "auth",
			Severity:  "high",
			Message:   line,
		},
		SrcIP: srcIP,
	}
}

func extractIP(line string) string {
	match := failedPasswordIP.FindStringSubmatch(line)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}
