package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
)

type rawEvent struct {
	EventIdemKey string `json:"event_idem_key"`
	Source       string `json:"source"`
	IngestUnixMs int64  `json:"ingest_unix_ms"`
	Line         string `json:"line"`
}

func main() {
	configPath := flag.String("config", "configs/master.yaml", "Path to master config")
	eventID := flag.String("event_idem_key", "", "Event idempotency key")
	line := flag.String("line", "", "Raw log line")
	flag.Parse()

	if strings.TrimSpace(*eventID) == "" || strings.TrimSpace(*line) == "" {
		fmt.Fprintf(os.Stderr, "event_idem_key and line are required\n")
		os.Exit(1)
	}

	cfg, err := config.LoadMaster(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}
	logger, err := logging.NewLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}

	nc, err := nats.Connect(cfg.JetStream.URL, nats.Name("r-siem-master-pubevent"))
	if err != nil {
		logger.Error("nats_connect_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		logger.Error("jetstream_context_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	evt := rawEvent{
		EventIdemKey: strings.TrimSpace(*eventID),
		Source:       "master-pubevent",
		IngestUnixMs: time.Now().UnixMilli(),
		Line:         strings.TrimSpace(*line),
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		logger.Error("event_encode_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	msg := &nats.Msg{Subject: "rsiem.events.raw", Data: payload}
	msg.Header = nats.Header{}
	msg.Header.Set(nats.MsgIdHdr, evt.EventIdemKey)

	ack, err := js.PublishMsg(msg)
	if err != nil {
		logger.Error("event_publish_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	attrs := []slog.Attr{slog.String("event_idem_key", evt.EventIdemKey)}
	if ack != nil {
		attrs = append(attrs, slog.Uint64("js_seq", ack.Sequence))
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "event_pub_ok", attrs...)
}
