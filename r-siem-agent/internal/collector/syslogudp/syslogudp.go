package syslogudp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
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

type packet struct {
	data []byte
	addr *net.UDPAddr
}

type Collector struct {
	cfg       Config
	logger    *slog.Logger
	publisher *buffer.JetStreamPublisher

	cancel context.CancelFunc
	wg     sync.WaitGroup
	queue  chan packet

	running   atomic.Bool
	lastErr   atomic.Value
	published atomic.Uint64
	errors    atomic.Uint64
	lastSeq   atomic.Uint64
	drops     atomic.Uint64
}

func New(cfg Config, logger *slog.Logger, publisher *buffer.JetStreamPublisher) *Collector {
	cfg.applyDefaults()
	return &Collector{cfg: cfg, logger: logger, publisher: publisher}
}

func (c *Collector) Name() string {
	return "collector-syslog-udp"
}

func (c *Collector) Start(ctx context.Context) error {
	if c.publisher == nil {
		return fmt.Errorf("publisher required")
	}
	if strings.TrimSpace(c.cfg.ListenAddr) == "" {
		return fmt.Errorf("listen addr required")
	}
	if c.running.Load() {
		return fmt.Errorf("collector already running")
	}

	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.queue = make(chan packet, c.cfg.QueueSize)
	c.running.Store(true)

	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		c.runPublisher(ctx)
	}()
	go func() {
		defer c.wg.Done()
		c.runReader(ctx)
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
		Running:   c.running.Load(),
		LastError: lastErr,
		Published: c.published.Load(),
		Errors:    c.errors.Load(),
		LastSeq:   c.lastSeq.Load(),
	}
}

func (c *Collector) runReader(ctx context.Context) {
	addr, err := net.ResolveUDPAddr("udp", c.cfg.ListenAddr)
	if err != nil {
		c.setError(err)
		c.logger.Error("collector_syslog_listen_failed", slog.String("error", err.Error()))
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		c.setError(err)
		c.logger.Error("collector_syslog_listen_failed", slog.String("error", err.Error()))
		return
	}
	defer conn.Close()
	defer close(c.queue)

	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_syslog_started",
		slog.String("listen_addr", c.cfg.ListenAddr),
	)

	buf := make([]byte, c.cfg.MaxDatagramBytes)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(c.cfg.ReadTimeout))
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			c.setError(err)
			c.errors.Add(1)
			c.logger.Error("collector_syslog_read_failed", slog.String("error", err.Error()))
			continue
		}
		if n <= 0 {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		pkt := packet{data: payload, addr: remote}

		select {
		case c.queue <- pkt:
		default:
			drops := c.drops.Add(1)
			c.logger.Warn("collector_syslog_drop_backpressure",
				slog.Uint64("drops", drops),
			)
		}
	}
}

func (c *Collector) runPublisher(ctx context.Context) {
	seq := c.lastSeq.Load()
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-c.queue:
			if !ok {
				return
			}
			seq++
			if err := c.publishPacket(ctx, pkt, seq); err != nil {
				seq--
				continue
			}
			c.lastSeq.Store(seq)
			count := c.published.Add(1)
			c.logger.LogAttrs(context.Background(), slog.LevelInfo, "collector_syslog_event_published",
				slog.Uint64("count", count),
				slog.Uint64("last_seq", seq),
			)
		}
	}
}

func (c *Collector) publishPacket(ctx context.Context, pkt packet, seq uint64) error {
	message := strings.TrimRight(string(pkt.data), "\r\n")
	if strings.TrimSpace(message) == "" {
		return nil
	}
	host := parseRFC3164Host(message)
	srcIP := ""
	if pkt.addr != nil {
		srcIP = pkt.addr.IP.String()
	}
	eventType, severity := classifySyslog(message)
	sum := sha256.Sum256(pkt.data)

	payload := syslogEventPayload(message, host, srcIP, seq, hex.EncodeToString(sum[:]), len(pkt.data), eventType, severity)
	data, err := json.Marshal(payload)
	if err != nil {
		c.setError(err)
		c.errors.Add(1)
		c.logger.Error("collector_syslog_event_encode_failed", slog.String("error", err.Error()))
		return err
	}

	batch := &pb.Batch{
		ProducerId: "collector-syslog-udp",
		Lane:       event.LaneFast,
		SeqStart:   seq,
		SeqEnd:     seq,
		Payload:    data,
	}
	encoded, err := proto.Marshal(batch)
	if err != nil {
		c.setError(err)
		c.errors.Add(1)
		c.logger.Error("collector_syslog_batch_encode_failed", slog.String("error", err.Error()))
		return err
	}
	if _, err := c.publisher.PublishBatch(ctx, event.LaneFast, encoded); err != nil {
		c.setError(err)
		c.errors.Add(1)
		c.logger.Error("collector_syslog_publish_failed", slog.String("error", err.Error()))
		return err
	}
	return nil
}

func (c *Collector) setError(err error) {
	if err == nil {
		return
	}
	c.lastErr.Store(err.Error())
}

type syslogEvent struct {
	event.Event
	SrcIP     string `json:"src_ip,omitempty"`
	RawSHA256 string `json:"raw_sha256,omitempty"`
	SizeBytes int    `json:"size_bytes,omitempty"`
}

func syslogEventPayload(message, host, srcIP string, seq uint64, rawSHA string, sizeBytes int, eventType, severity string) syslogEvent {
	return syslogEvent{
		Event: event.Event{
			ID:        fmt.Sprintf("syslog-udp-%d", seq),
			Seq:       seq,
			Timestamp: time.Now().UTC(),
			Host:      host,
			Source:    "collector-syslog-udp",
			Type:      eventType,
			Severity:  severity,
			Message:   message,
		},
		SrcIP:     srcIP,
		RawSHA256: rawSHA,
		SizeBytes: sizeBytes,
	}
}

func classifySyslog(message string) (string, string) {
	if strings.Contains(message, "sshd") || strings.Contains(message, "Failed password") {
		if strings.Contains(message, "Failed password") {
			return "auth", "high"
		}
		return "auth", "medium"
	}
	return "syslog", "medium"
}

func parseRFC3164Host(message string) string {
	msg := strings.TrimSpace(message)
	if strings.HasPrefix(msg, "<") {
		if idx := strings.Index(msg, ">"); idx != -1 {
			msg = strings.TrimSpace(msg[idx+1:])
		}
	}
	parts := strings.Fields(msg)
	if len(parts) < 4 {
		return ""
	}
	if !looksLikeMonth(parts[0]) {
		return ""
	}
	if !looksLikeDay(parts[1]) {
		return ""
	}
	if !strings.Contains(parts[2], ":") {
		return ""
	}
	return parts[3]
}

func looksLikeMonth(val string) bool {
	switch val {
	case "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec":
		return true
	default:
		return false
	}
}

func looksLikeDay(val string) bool {
	if len(val) == 0 || len(val) > 2 {
		return false
	}
	day, err := strconv.Atoi(val)
	if err != nil {
		return false
	}
	return day >= 1 && day <= 31
}
