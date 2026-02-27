package snmptrap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
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

// Collector implements bounded UDP SNMP trap ingestion.
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
		c.logger.Error("collector_start_failed", slog.String("collector", "snmp_trap"), slog.String("error", err.Error()))
		return
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		c.logger.Error("collector_start_failed", slog.String("collector", "snmp_trap"), slog.String("error", err.Error()))
		return
	}
	defer conn.Close()

	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_started",
		slog.String("collector", "snmp_trap"),
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
			c.logger.Warn("packet_read_error", slog.String("collector", "snmp_trap"), slog.String("error", err.Error()))
			continue
		}
		if n <= 0 {
			continue
		}
		srcIP := ""
		if remote != nil {
			srcIP = remote.IP.String()
		}
		if n > c.cfg.MaxPacketBytes {
			d := c.droppedTooLarge.Add(1)
			c.logger.Warn("packet_dropped_too_large", slog.String("collector", "snmp_trap"), slog.Uint64("drops", d), slog.Int("size", n))
			continue
		}
		if !c.rate.Allow() {
			d := c.droppedRate.Add(1)
			c.logger.Warn("packet_dropped_rate_limited", slog.String("collector", "snmp_trap"), slog.Uint64("drops", d))
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		pkt := udpPacket{payload: payload, srcIP: srcIP, recvTS: time.Now().UnixMilli()}
		select {
		case c.queue <- pkt:
		default:
			d := c.droppedQueue.Add(1)
			c.logger.Warn("packet_dropped_queue_full", slog.String("collector", "snmp_trap"), slog.Uint64("drops", d))
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
				c.logger.Warn("publish_failed", slog.String("collector", "snmp_trap"), slog.String("error", err.Error()))
			}
		}
	}
}

func (c *Collector) publishPacket(ctx context.Context, pkt udpPacket) error {
	rawHash := common.SHA256Hex(pkt.payload)
	bucket := pkt.recvTS / 1000
	eventID := "evt.snmptrap." + common.SHA256Hex([]byte(fmt.Sprintf("%s|%s|%s|%d", c.cfg.SourceType, pkt.srcIP, rawHash, bucket)))
	community := guessCommunity(pkt.payload)
	versionGuess := guessVersion(pkt.payload)
	groupKey := pkt.srcIP
	if groupKey == "" {
		groupKey = c.nodeID
	}

	payload := map[string]any{
		"event_idem_key":      eventID,
		"observed_at_unix_ms": pkt.recvTS,
		"event_ts_unix_ms":    pkt.recvTS,
		"recv_ts_unix_ms":     pkt.recvTS,
		"message":             "snmp trap",
		"raw_line":            "snmp trap",
		"host":                c.nodeID,
		"group_key":           groupKey,
		"source":              "collector-snmptrap",
		"source_type":         c.cfg.SourceType,
		"node_id":             c.nodeID,
		"event_type":          "snmp_trap",
		"src_ip":              pkt.srcIP,
		"community":           community,
		"version_guess":       versionGuess,
		"raw_len":             len(pkt.payload),
		"raw_bytes_sha256":    rawHash,
		"ts":                  pkt.recvTS,
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
		slog.String("collector", "snmp_trap"),
		slog.Uint64("count", count),
		slog.String("event_idem_key", eventID),
		slog.String("event_type", "snmp_trap"),
		slog.String("source_type", c.cfg.SourceType),
		slog.String("src_ip", pkt.srcIP),
		slog.Int("raw_len", len(pkt.payload)),
		slog.String("raw_sha256", rawHash),
		slog.String("community", community),
	)
	return nil
}
