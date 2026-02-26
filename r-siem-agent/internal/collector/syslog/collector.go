package syslog

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"

	"r-siem-agent/internal/collector/common"
)

type udpPacket struct {
	payload []byte
	srcIP   string
	recvTS  int64
}

// Collector implements bounded UDP syslog ingestion.
type Collector struct {
	cfg             Config
	logger          *slog.Logger
	js              nats.JetStreamContext
	nodeID          string
	rate            *common.RateLimiter
	queue           chan udpPacket
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	running         atomic.Bool
	published       atomic.Uint64
	droppedTooLarge atomic.Uint64
	droppedQueue    atomic.Uint64
	droppedRate     atomic.Uint64
	parseFailures   atomic.Uint64
}

func New(cfg Config, logger *slog.Logger, js nats.JetStreamContext) *Collector {
	cfg.applyDefaults()
	return &Collector{
		cfg:    cfg,
		logger: logger,
		js:     js,
		nodeID: common.ResolveNodeID(cfg.NodeID),
		rate:   common.NewRateLimiter(cfg.RateLimitPPS),
		queue:  make(chan udpPacket, cfg.QueueSize),
	}
}

func (c *Collector) Start(ctx context.Context) error {
	if c.js == nil {
		return fmt.Errorf("jetstream required")
	}
	if c.running.Load() {
		return fmt.Errorf("collector already running")
	}
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.running.Store(true)

	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		c.readLoop(ctx)
	}()
	go func() {
		defer c.wg.Done()
		c.publishLoop(ctx)
	}()
	return nil
}

func (c *Collector) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	c.running.Store(false)
}

func (c *Collector) readLoop(ctx context.Context) {
	addr := fmt.Sprintf("%s:%d", c.cfg.BindAddr, c.cfg.Port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		c.logger.Error("collector_start_failed", slog.String("error", err.Error()))
		return
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		c.logger.Error("collector_start_failed", slog.String("error", err.Error()))
		return
	}
	defer conn.Close()

	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_started",
		slog.String("collector", "syslog"),
		slog.String("bind_addr", c.cfg.BindAddr),
		slog.Int("port", c.cfg.Port),
		slog.Int("max_packet_bytes", c.cfg.MaxPacketBytes),
		slog.Int("queue_size", c.cfg.QueueSize),
		slog.Int("rate_limit_pps", c.cfg.RateLimitPPS),
		slog.String("raw_subject", c.cfg.RawSubject),
	)

	buf := make([]byte, c.cfg.MaxPacketBytes+1)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			c.logger.Warn("packet_read_error", slog.String("error", err.Error()))
			continue
		}
		if n <= 0 {
			continue
		}
		srcIP := ""
		if remote != nil {
			srcIP = remote.IP.String()
		}
		c.logger.LogAttrs(context.Background(), slog.LevelDebug, "packet_received",
			slog.String("collector", "syslog"),
			slog.String("src_ip", srcIP),
			slog.Int("size", n),
		)
		if n > c.cfg.MaxPacketBytes {
			d := c.droppedTooLarge.Add(1)
			c.logger.Warn("packet_dropped_too_large", slog.String("collector", "syslog"), slog.Uint64("drops", d), slog.Int("size", n))
			continue
		}
		if !c.rate.Allow() {
			d := c.droppedRate.Add(1)
			c.logger.Warn("packet_dropped_rate_limit", slog.String("collector", "syslog"), slog.Uint64("drops", d))
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		pkt := udpPacket{payload: payload, srcIP: srcIP, recvTS: time.Now().UnixMilli()}
		select {
		case c.queue <- pkt:
		default:
			d := c.droppedQueue.Add(1)
			c.logger.Warn("packet_dropped_queue_full", slog.String("collector", "syslog"), slog.Uint64("drops", d))
		}
	}
}

func (c *Collector) publishLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-c.queue:
			if err := c.publishPacket(ctx, pkt); err != nil {
				c.logger.Warn("publish_failed", slog.String("collector", "syslog"), slog.String("error", err.Error()))
			}
		}
	}
}

func (c *Collector) publishPacket(ctx context.Context, pkt udpPacket) error {
	line := strings.TrimSpace(string(pkt.payload))
	if line == "" {
		fails := c.parseFailures.Add(1)
		if fails <= 5 || fails%100 == 0 {
			c.logger.Warn("parse_failed", slog.String("collector", "syslog"), slog.Uint64("count", fails), slog.String("reason", "empty_message"))
		}
		return nil
	}
	parsed := parseSyslogMessage(line, pkt.recvTS)
	msg, truncated := common.TruncateString(parsed.Message, c.cfg.MaxMessageLen)
	rawHash := common.SHA256Hex(pkt.payload)
	eventID := common.EventID("evt.syslog.", c.cfg.SourceType, c.nodeID, rawHash, parsed.EventTSUnixM)
	groupKey := pkt.srcIP
	if groupKey == "" {
		groupKey = c.nodeID
	}
	host := parsed.Host
	if host == "" {
		host = c.nodeID
	}
	payload := map[string]any{
		"event_idem_key":      eventID,
		"observed_at_unix_ms": pkt.recvTS,
		"event_ts_unix_ms":    parsed.EventTSUnixM,
		"recv_ts_unix_ms":     pkt.recvTS,
		"message":             msg,
		"raw_line_trunc":      msg,
		"raw_line":            msg,
		"host":                host,
		"group_key":           groupKey,
		"source":              "collector-syslog",
		"source_type":         c.cfg.SourceType,
		"node_id":             c.nodeID,
		"src_ip":              pkt.srcIP,
		"event_type":          parsed.EventType,
		"user":                parsed.User,
		"severity":            parsed.Severity,
		"raw_bytes_sha256":    rawHash,
		"raw_truncated":       truncated,
		"ts":                  parsed.EventTSUnixM,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := c.js.Publish(c.cfg.RawSubject, data, nats.MsgId(eventID)); err != nil {
		return err
	}
	count := c.published.Add(1)
	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_event_published",
		slog.String("collector", "syslog"),
		slog.Uint64("count", count),
		slog.String("event_idem_key", eventID),
		slog.String("event_type", parsed.EventType),
		slog.String("source_type", c.cfg.SourceType),
		slog.String("src_ip", pkt.srcIP),
		slog.String("user", parsed.User),
	)
	return nil
}
