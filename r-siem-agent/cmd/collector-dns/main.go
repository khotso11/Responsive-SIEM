package main

import (
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
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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
		Interface            string `yaml:"interface"`
		NodeID               string `yaml:"node_id"`
		SourceType           string `yaml:"source_type"`
		CoalesceWindowMS     int    `yaml:"coalesce_window_ms"`
		SuppressLoopbackStub *bool  `yaml:"suppress_loopback_stub"`
	} `yaml:"collector"`
}

type dnsEvent struct {
	NodeID  string
	SrcIP   string
	DstIP   string
	DNSName string
	DNSType string
}

type pendingDNSEvent struct {
	evt      dnsEvent
	deadline time.Time
}

func main() {
	configPath := flag.String("config", "configs/collector-dns.yaml", "Path to collector config")
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
		Name:          "r-siem-collector-dns",
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
	fd, ifName, err := openPacketSocket(strings.TrimSpace(cfg.Collector.Interface))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 200000})

	nodeID := common.ResolveNodeID(cfg.Collector.NodeID)
	coalesceWindow := time.Duration(cfg.Collector.CoalesceWindowMS) * time.Millisecond
	pending := make(map[string]pendingDNSEvent)
	logger.Info("collector_started",
		slog.String("collector", "dns"),
		slog.String("interface", ifName),
	)

	buf := make([]byte, 65536)
	for {
		flushPendingDNSEvents(pending, time.Now(), false, publisher, cfg.Collector.SourceType, logger)
		select {
		case <-ctx.Done():
			flushPendingDNSEvents(pending, time.Now(), true, publisher, cfg.Collector.SourceType, logger)
			return ctx.Err()
		default:
		}

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			return err
		}
		if n <= 0 {
			continue
		}
		if evt, ok := parsePacket(buf[:n], nodeID); ok {
			if shouldSuppressLoopbackStub(cfg, evt) {
				continue
			}
			enqueueDNSEvent(pending, evt, coalesceWindow)
		}
	}
}

func openPacketSocket(iface string) (int, string, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return -1, "", err
	}
	if iface == "" || iface == "any" {
		return fd, "any", nil
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		unix.Close(fd)
		return -1, "", err
	}
	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return -1, "", err
	}
	return fd, iface, nil
}

func parsePacket(frame []byte, nodeID string) (dnsEvent, bool) {
	if len(frame) < 14 {
		return dnsEvent{}, false
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	switch etherType {
	case 0x0800:
		return parseIPv4Packet(frame[14:], nodeID)
	case 0x86dd:
		return parseIPv6Packet(frame[14:], nodeID)
	default:
		return dnsEvent{}, false
	}
}

func parseIPv4Packet(pkt []byte, nodeID string) (dnsEvent, bool) {
	if len(pkt) < 20 {
		return dnsEvent{}, false
	}
	version := pkt[0] >> 4
	if version != 4 {
		return dnsEvent{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return dnsEvent{}, false
	}
	if pkt[9] != 17 && pkt[9] != 6 {
		return dnsEvent{}, false
	}
	srcIP := net.IP(pkt[12:16]).String()
	dstIP := net.IP(pkt[16:20]).String()
	if pkt[9] == 17 {
		return parseUDPDNS(pkt[ihl:], nodeID, srcIP, dstIP)
	}
	return parseTCPDNS(pkt[ihl:], nodeID, srcIP, dstIP)
}

func parseIPv6Packet(pkt []byte, nodeID string) (dnsEvent, bool) {
	if len(pkt) < 40 {
		return dnsEvent{}, false
	}
	version := pkt[0] >> 4
	if version != 6 {
		return dnsEvent{}, false
	}
	nextHeader := pkt[6]
	if nextHeader != 17 && nextHeader != 6 {
		return dnsEvent{}, false
	}
	srcIP := net.IP(pkt[8:24]).String()
	dstIP := net.IP(pkt[24:40]).String()
	if nextHeader == 17 {
		return parseUDPDNS(pkt[40:], nodeID, srcIP, dstIP)
	}
	return parseTCPDNS(pkt[40:], nodeID, srcIP, dstIP)
}

func parseUDPDNS(pkt []byte, nodeID, srcIP, dstIP string) (dnsEvent, bool) {
	if len(pkt) < 8 {
		return dnsEvent{}, false
	}
	dstPort := binary.BigEndian.Uint16(pkt[2:4])
	if dstPort != 53 {
		return dnsEvent{}, false
	}
	return parseDNSPayload(pkt[8:], nodeID, srcIP, dstIP)
}

func parseTCPDNS(pkt []byte, nodeID, srcIP, dstIP string) (dnsEvent, bool) {
	if len(pkt) < 20 {
		return dnsEvent{}, false
	}
	dstPort := binary.BigEndian.Uint16(pkt[2:4])
	if dstPort != 53 {
		return dnsEvent{}, false
	}
	dataOffset := int((pkt[12] >> 4) * 4)
	if dataOffset < 20 || len(pkt) < dataOffset+2 {
		return dnsEvent{}, false
	}
	dnsPayload := pkt[dataOffset:]
	if len(dnsPayload) < 2 {
		return dnsEvent{}, false
	}
	msgLen := int(binary.BigEndian.Uint16(dnsPayload[:2]))
	if msgLen <= 0 || len(dnsPayload) < 2+msgLen {
		return dnsEvent{}, false
	}
	return parseDNSPayload(dnsPayload[2:2+msgLen], nodeID, srcIP, dstIP)
}

func parseDNSPayload(msg []byte, nodeID, srcIP, dstIP string) (dnsEvent, bool) {
	qname, qtype, ok := parseDNSQuestion(msg)
	if !ok || !isAcceptedDNSName(qname) {
		return dnsEvent{}, false
	}
	return dnsEvent{
		NodeID:  nodeID,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		DNSName: qname,
		DNSType: qtype,
	}, true
}

func parseDNSQuestion(msg []byte) (string, string, bool) {
	if len(msg) < 12 {
		return "", "", false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 != 0 {
		return "", "", false
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	if qdCount < 1 {
		return "", "", false
	}
	off := 12
	labels := make([]string, 0, 4)
	for {
		if off >= len(msg) {
			return "", "", false
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 {
			return "", "", false
		}
		if off+l > len(msg) {
			return "", "", false
		}
		labels = append(labels, strings.ToLower(string(msg[off:off+l])))
		off += l
	}
	if len(labels) == 0 || off+4 > len(msg) {
		return "", "", false
	}
	qtype := dnsTypeName(binary.BigEndian.Uint16(msg[off : off+2]))
	return strings.Join(labels, "."), qtype, true
}

func dnsTypeName(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}

func isAcceptedDNSName(name string) bool {
	name = strings.ToLower(strings.Trim(strings.TrimSpace(name), "."))
	if name == "" || len(name) > 253 || strings.Contains(name, "_") {
		return false
	}
	if isLocalServiceNamespace(name) {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 || len(tld) > 24 {
		return false
	}
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	switch tld {
	case "local", "localhost", "internal", "lan", "home", "localdomain", "invalid", "test", "example", "service":
		return false
	}
	return true
}

func isLocalServiceNamespace(name string) bool {
	for _, prefix := range []string{
		"org.freedesktop",
		"org.jackaudio",
		"org.gnome",
		"org.kde",
		"org.pipewire",
		"org.pulseaudio",
		"org.bluez",
		"org.mpris",
		"org.a11y",
		"com.canonical",
		"com.ubuntu",
		"io.snapcraft",
	} {
		if name == prefix || strings.HasPrefix(name, prefix+".") {
			return true
		}
	}
	return false
}

func publishDNSEvent(publisher *common.OfflinePublisher, sourceType string, evt dnsEvent, logger *slog.Logger) {
	ts := time.Now().UnixMilli()
	message := fmt.Sprintf("DNS query=%s type=%s src=%s dst=%s ts=%d node=%s",
		evt.DNSName, evt.DNSType, evt.SrcIP, evt.DstIP, ts, evt.NodeID)
	eventID := common.EventID("evt.dns.", sourceType, evt.NodeID, common.SHA256Hex([]byte(evt.SrcIP+"|"+evt.DstIP+"|"+evt.DNSName+"|"+evt.DNSType)), ts)
	payload := map[string]any{
		"event_idem_key":      eventID,
		"observed_at_unix_ms": ts,
		"event_ts_unix_ms":    ts,
		"recv_ts_unix_ms":     ts,
		"message":             message,
		"raw_line":            message,
		"host":                evt.NodeID,
		"node_id":             evt.NodeID,
		"group_key":           evt.DNSName,
		"source":              "collector-dns",
		"source_type":         sourceType,
		"user":                "unknown",
		"src_ip":              evt.SrcIP,
		"dst_ip":              evt.DstIP,
		"dns_name":            evt.DNSName,
		"dns_type":            evt.DNSType,
		"event_type":          "dns_query",
	}
	data, _ := json.Marshal(payload)
	if queued, err := publisher.Publish(context.Background(), eventID, data); err == nil {
		if queued {
			logger.Warn("collector_event_spooled",
				slog.String("collector", "dns"),
				slog.String("event_idem_key", eventID),
				slog.String("dns_name", evt.DNSName),
				slog.String("dns_type", evt.DNSType),
				slog.String("src_ip", evt.SrcIP),
				slog.String("dst_ip", evt.DstIP),
			)
		}
		logger.Info("collector_event_published",
			slog.String("collector", "dns"),
			slog.String("event_idem_key", eventID),
			slog.String("dns_name", evt.DNSName),
			slog.String("dns_type", evt.DNSType),
			slog.String("src_ip", evt.SrcIP),
			slog.String("dst_ip", evt.DstIP),
		)
	}
}

func enqueueDNSEvent(pending map[string]pendingDNSEvent, evt dnsEvent, window time.Duration) {
	key := dnsEventKey(evt)
	entry, ok := pending[key]
	deadline := time.Now().Add(window)
	if !ok {
		pending[key] = pendingDNSEvent{evt: evt, deadline: deadline}
		return
	}
	if dnsEventScore(evt) > dnsEventScore(entry.evt) {
		entry.evt = evt
	}
	entry.deadline = deadline
	pending[key] = entry
}

func flushPendingDNSEvents(pending map[string]pendingDNSEvent, now time.Time, force bool, publisher *common.OfflinePublisher, sourceType string, logger *slog.Logger) {
	for key, entry := range pending {
		if !force && now.Before(entry.deadline) {
			continue
		}
		publishDNSEvent(publisher, sourceType, entry.evt, logger)
		delete(pending, key)
	}
}

func dnsEventKey(evt dnsEvent) string {
	return evt.NodeID + "|" + strings.ToLower(evt.DNSName) + "|" + strings.ToUpper(evt.DNSType)
}

func dnsEventScore(evt dnsEvent) int {
	score := 0
	if !isLoopbackIP(evt.SrcIP) {
		score += 2
	}
	if !isLoopbackIP(evt.DstIP) {
		score += 1
	}
	return score
}

func isLoopbackIP(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func shouldSuppressLoopbackStub(cfg *configFile, evt dnsEvent) bool {
	if cfg.Collector.SuppressLoopbackStub != nil && !*cfg.Collector.SuppressLoopbackStub {
		return false
	}
	src := net.ParseIP(strings.TrimSpace(evt.SrcIP))
	dst := net.ParseIP(strings.TrimSpace(evt.DstIP))
	if src == nil || dst == nil {
		return false
	}
	return src.IsLoopback() && dst.IsLoopback() && dst.Equal(net.ParseIP("127.0.0.53"))
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
	if strings.TrimSpace(cfg.Collector.SourceType) == "" {
		cfg.Collector.SourceType = "dns_packet"
	}
	if cfg.Collector.CoalesceWindowMS <= 0 {
		cfg.Collector.CoalesceWindowMS = 400
	}
	if cfg.Collector.SuppressLoopbackStub == nil {
		enabled := true
		cfg.Collector.SuppressLoopbackStub = &enabled
	}
	return &cfg, nil
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}
