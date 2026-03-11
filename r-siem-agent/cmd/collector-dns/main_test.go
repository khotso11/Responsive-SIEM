package main

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestParseDNSQuestion(t *testing.T) {
	msg := buildDNSQuery("example.com", 1)
	name, qtype, ok := parseDNSQuestion(msg)
	if !ok {
		t.Fatalf("expected query to parse")
	}
	if name != "example.com" {
		t.Fatalf("unexpected name %q", name)
	}
	if qtype != "A" {
		t.Fatalf("unexpected type %q", qtype)
	}
}

func TestParseDNSQuestionRejectsResponse(t *testing.T) {
	msg := buildDNSQuery("example.com", 1)
	msg[2] = 0x80
	if _, _, ok := parseDNSQuestion(msg); ok {
		t.Fatalf("expected response packet to be rejected")
	}
}

func TestIsAcceptedDNSNameRejectsServiceNamespace(t *testing.T) {
	for _, name := range []string{
		"org.freedesktop",
		"org.jackaudio.service",
		"org.gnome.settingsdaemon",
	} {
		if isAcceptedDNSName(name) {
			t.Fatalf("expected %q to be rejected", name)
		}
	}
}

func TestEnqueueDNSEventPrefersNonLoopbackPacket(t *testing.T) {
	pending := map[string]pendingDNSEvent{}
	loopback := dnsEvent{
		NodeID:  "node-1",
		SrcIP:   "127.0.0.1",
		DstIP:   "127.0.0.53",
		DNSName: "example.com",
		DNSType: "A",
	}
	outbound := dnsEvent{
		NodeID:  "node-1",
		SrcIP:   "192.2.42.182",
		DstIP:   "192.2.42.1",
		DNSName: "example.com",
		DNSType: "A",
	}

	enqueueDNSEvent(pending, loopback, 100*time.Millisecond)
	enqueueDNSEvent(pending, outbound, 100*time.Millisecond)

	entry, ok := pending[dnsEventKey(loopback)]
	if !ok {
		t.Fatalf("expected pending event")
	}
	if entry.evt.SrcIP != outbound.SrcIP || entry.evt.DstIP != outbound.DstIP {
		t.Fatalf("expected outbound event to replace loopback, got %+v", entry.evt)
	}
}

func TestShouldSuppressLoopbackStubDefaultsTrue(t *testing.T) {
	evt := dnsEvent{
		SrcIP: "127.0.0.1",
		DstIP: "127.0.0.53",
	}
	loaded, err := loadConfigFromBytes([]byte("log_level: INFO\ncollector:\n  interface: any\n"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !shouldSuppressLoopbackStub(loaded, evt) {
		t.Fatalf("expected loopback stub to be suppressed by default")
	}
}

func TestShouldSuppressLoopbackStubCanBeDisabled(t *testing.T) {
	cfg, err := loadConfigFromBytes([]byte("log_level: INFO\ncollector:\n  suppress_loopback_stub: false\n"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	evt := dnsEvent{
		SrcIP: "127.0.0.1",
		DstIP: "127.0.0.53",
	}
	if shouldSuppressLoopbackStub(cfg, evt) {
		t.Fatalf("expected loopback stub suppression to be disabled")
	}
}

func buildDNSQuery(name string, qtype uint16) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[4:6], 1)
	body := make([]byte, 0, 64)
	for _, label := range []string{"example", "com"} {
		body = append(body, byte(len(label)))
		body = append(body, label...)
	}
	body = append(body, 0)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1)
	body = append(body, tail[:]...)
	return append(header, body...)
}

func loadConfigFromBytes(data []byte) (*configFile, error) {
	var cfg configFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
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
