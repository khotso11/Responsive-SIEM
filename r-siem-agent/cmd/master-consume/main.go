package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
	"r-siem-agent/internal/proto/pb"
	"r-siem-agent/internal/roe/trigger"
)

type consumerParams struct {
	lane        string
	subject     string
	durable     string
	workerCount int
}

func main() {
	configPath := flag.String("config", "configs/master.yaml", "Path to master config")
	flag.Parse()

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

	exportCfg, err := loadExportConfig(*configPath)
	if err != nil {
		logger.Error("export_config_load_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	exporter, err := newExporter(logger, exportCfg)
	if err != nil {
		logger.Error("export_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if exporter != nil {
		defer exporter.Close()
	}

	incidentCfg, err := loadIncidentConfig(*configPath)
	if err != nil {
		logger.Error("incident_config_load_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	incidentMgr, err := newIncidentManager(logger, incidentCfg)
	if err != nil {
		logger.Error("incident_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if incidentMgr != nil {
		defer incidentMgr.Close()
	}

	logger.Info("master_consumer_starting", slog.Any("config", cfg.Summary()))

	nc, err := nats.Connect(cfg.JetStream.URL, nats.Name("r-siem-master-consume"))
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

	respCfg, err := loadResponseTriggerConfig(*configPath)
	if err != nil {
		logger.Error("response_trigger_config_load_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	triggerPublisher, err := newResponseTriggerPublisher(logger, js, respCfg)
	if err != nil {
		logger.Error("response_trigger_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	var rawTriggerPublisher *trigger.Publisher
	if respCfg != nil && respCfg.Enabled {
		rawTriggerPublisher, err = trigger.NewPublisher(logger, js)
		if err != nil {
			logger.Error("response_trigger_init_failed", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	rceCfg, err := loadRCEConfig(*configPath)
	if err != nil {
		logger.Error("rce_config_load_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	rce := newRCE(logger, rceCfg, exporter, incidentMgr, triggerPublisher, rawTriggerPublisher)

	params := []consumerParams{
		{
			lane:        "FAST",
			subject:     cfg.JetStream.SubjectFast,
			durable:     cfg.JetStream.DurableNameFast,
			workerCount: cfg.Consumer.FastWorkers,
		},
		{
			lane:        "STANDARD",
			subject:     cfg.JetStream.SubjectStandard,
			durable:     cfg.JetStream.DurableNameStandard,
			workerCount: cfg.Consumer.StandardWorkers,
		},
	}

	ctx, cancel := signalContext()
	defer cancel()

	var wg sync.WaitGroup
	for _, p := range params {
		if err := ensureConsumer(js, cfg.JetStream.Stream, p.subject, p.durable); err != nil {
			logger.Error("ensure_consumer_failed", slog.String("lane", p.lane), slog.String("error", err.Error()))
			os.Exit(1)
		}

		sub, err := js.PullSubscribe(p.subject, p.durable, nats.BindStream(cfg.JetStream.Stream))
		if err != nil {
			logger.Error("subscribe_failed", slog.String("lane", p.lane), slog.String("error", err.Error()))
			os.Exit(1)
		}

		for i := 0; i < p.workerCount; i++ {
			wg.Add(1)
			go func(p consumerParams, sub *nats.Subscription) {
				defer wg.Done()
				runWorker(ctx, logger, sub, p.lane, cfg.JetStream.Stream, rce, cfg.Consumer.PullBatch, time.Duration(cfg.Consumer.PullTimeoutMs)*time.Millisecond)
			}(p, sub)
		}
	}

	wg.Wait()
	logger.Info("master_consumer_stopped")
}

func ensureConsumer(js nats.JetStreamContext, stream, subject, durable string) error {
	_, err := js.AddConsumer(stream, &nats.ConsumerConfig{
		Durable:       durable,
		FilterSubject: subject,
		AckPolicy:     nats.AckExplicitPolicy,
	})
	if err != nil && !errors.Is(err, nats.ErrConsumerNameAlreadyInUse) {
		return err
	}
	return nil
}

func runWorker(ctx context.Context, logger *slog.Logger, sub *nats.Subscription, lane string, stream string, rce *RCE, batch int, timeout time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgs, err := sub.Fetch(batch, nats.MaxWait(timeout))
		if err != nil {
			if err == nats.ErrTimeout {
				continue
			}
			logger.Error("fetch_failed", slog.String("lane", lane), slog.String("error", err.Error()))
			continue
		}

		for _, msg := range msgs {
			processMsg(logger, msg, lane, stream, rce)
		}
	}
}

func processMsg(logger *slog.Logger, msg *nats.Msg, lane string, stream string, rce *RCE) {
	meta, err := msg.Metadata()
	jsSeqVal := uint64(0)
	var jsSeq *uint64
	if err == nil && meta != nil {
		seq := meta.Sequence.Stream
		jsSeq = &seq
		jsSeqVal = seq
	}

	var batch pb.Batch
	if err := proto.Unmarshal(msg.Data, &batch); err != nil {
		logger.Error("consume_decode_failed",
			slog.String("lane", lane),
			slog.Uint64("js_seq", jsSeqVal),
			slog.String("subject", msg.Subject),
			slog.String("error", err.Error()),
		)
		_ = msg.Ack()
		return
	}

	payloadLen := len(batch.GetPayload())
	logger.Info("master_consume_batch",
		slog.String("lane", lane),
		slog.Uint64("seq_start", batch.SeqStart),
		slog.Uint64("seq_end", batch.SeqEnd),
		slog.Int("payload_len", payloadLen),
		slog.Uint64("js_seq", jsSeqVal),
		slog.String("subject", msg.Subject),
	)

	if err := emitNormalizedEvents(logger, msg.Subject, stream, jsSeq, lane, &batch, rce); err != nil {
		return
	}

	if err := msg.Ack(); err != nil {
		logger.Error("consume_ack_failed",
			slog.String("lane", lane),
			slog.Uint64("js_seq", jsSeqVal),
			slog.String("error", err.Error()),
		)
	}
}

func emitNormalizedEvents(logger *slog.Logger, subject string, stream string, jsSeq *uint64, fallbackLane string, batch *pb.Batch, rce *RCE) error {
	lane := deriveLane(batch.GetLane(), subject, fallbackLane)
	seqStart := batch.GetSeqStart()
	seqEnd := batch.GetSeqEnd()
	batchKey := fmt.Sprintf("batch.%s.%d.%d", lane, seqStart, seqEnd)
	agentID := strings.TrimSpace(batch.GetProducerId())
	stream = strings.TrimSpace(stream)

	records, _ := extractRecords(batch)
	if len(records) == 0 {
		records = [][]byte{batch.GetPayload()}
	}
	eventCount := len(records)

	var exportErr error
	for i, record := range records {
		observedAt := time.Now().UnixMilli()
		rawHash := sha256.Sum256(record)
		recordType := "unknown"
		normalized := map[string]any{
			"type":       recordType,
			"raw_sha256": hex.EncodeToString(rawHash[:]),
			"size_bytes": len(record),
		}
		jsonType, jsonTS, jsonFields, ok := parseJSONRecord(record)
		if ok {
			if jsonType != "" {
				recordType = jsonType
				normalized["type"] = jsonType
			}
			if jsonTS != nil {
				normalized["ts_unix_ms"] = *jsonTS
			}
			if len(jsonFields) > 0 {
				normalized["fields"] = jsonFields
			}
		}
		if preview, ok := previewText(record, 200); ok {
			normalized["preview"] = preview
		}

		fields := []slog.Attr{
			slog.String("lane", lane),
			slog.String("subject", subject),
			slog.String("stream", stream),
			slog.String("consumer", "master-consume"),
			slog.String("batch_key", batchKey),
			slog.Uint64("seq_start", seqStart),
			slog.Uint64("seq_end", seqEnd),
			slog.Int("event_index", i),
			slog.Int("event_count", eventCount),
			slog.String("normalized_version", "v0"),
			slog.Int64("observed_at_unix_ms", observedAt),
			slog.Any("normalized", normalized),
		}
		if jsSeq != nil {
			fields = append(fields, slog.Uint64("js_seq", *jsSeq))
		}
		if agentID != "" {
			fields = append(fields, slog.String("agent_id", agentID))
		}
		logger.LogAttrs(context.Background(), slog.LevelInfo, "normalized_event", fields...)

		if rce != nil {
			if err := rce.Process(NormalizedRecord{
				Lane:              lane,
				Subject:           subject,
				Stream:            stream,
				Consumer:          "master-consume",
				NormalizedVersion: "v0",
				JSSeq:             jsSeq,
				BatchKey:          batchKey,
				SeqStart:          seqStart,
				SeqEnd:            seqEnd,
				EventIndex:        i,
				EventCount:        eventCount,
				AgentID:           agentID,
				ObservedAt:        observedAt,
				Type:              recordType,
				TsUnixMs:          jsonTS,
				Fields:            jsonFields,
				RawSHA256:         hex.EncodeToString(rawHash[:]),
				SizeBytes:         len(record),
			}); err != nil && exportErr == nil {
				exportErr = err
			}
		}
	}
	return exportErr
}

func deriveLane(batchLane, subject, fallbackLane string) string {
	if strings.TrimSpace(batchLane) != "" {
		return strings.ToUpper(strings.TrimSpace(batchLane))
	}
	subject = strings.ToLower(subject)
	switch subject {
	case "rsiem.fast":
		return "FAST"
	case "rsiem.standard":
		return "STANDARD"
	default:
		return fallbackLane
	}
}

func previewText(data []byte, maxChars int) (string, bool) {
	if len(data) == 0 || !utf8.Valid(data) {
		return "", false
	}
	if !isMostlyPrintable(string(data)) {
		return "", false
	}

	preview := string(data)
	if utf8.RuneCountInString(preview) <= maxChars {
		return preview, true
	}

	count := 0
	for i := range preview {
		if count >= maxChars {
			return preview[:i], true
		}
		count++
	}
	return preview, true
}

func isMostlyPrintable(s string) bool {
	if s == "" {
		return false
	}
	printable := 0
	total := 0
	for _, r := range s {
		total++
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			printable++
		}
	}
	if total == 0 {
		return false
	}
	return float64(printable)/float64(total) >= 0.9
}

func parseJSONRecord(record []byte) (string, *int64, map[string]any, bool) {
	if len(record) == 0 {
		return "", nil, nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(record))
	decoder.UseNumber()
	var obj map[string]any
	if err := decoder.Decode(&obj); err != nil {
		return "", nil, nil, false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return "", nil, nil, false
	}

	var jsonType string
	if v, ok := obj["type"].(string); ok {
		jsonType = v
	}

	var ts *int64
	if v, ok := obj["ts_unix_ms"]; ok {
		if parsed, ok := parseTimestampValue(v); ok {
			ts = &parsed
		}
	}

	allow := []string{"host", "user", "process", "src_ip", "dst_ip", "severity", "message"}
	fields := make(map[string]any)
	for _, key := range allow {
		val, ok := obj[key]
		if !ok {
			continue
		}
		if normalized, ok := normalizeScalar(val); ok {
			fields[key] = normalized
		}
	}
	if len(fields) == 0 {
		fields = nil
	}
	return jsonType, ts, fields, true
}

func parseTimestampValue(val any) (int64, bool) {
	switch v := val.(type) {
	case json.Number:
		if ts, err := v.Int64(); err == nil {
			return ts, true
		}
		if f, err := v.Float64(); err == nil && math.Trunc(f) == f {
			return int64(f), true
		}
	case float64:
		if math.Trunc(v) == v {
			return int64(v), true
		}
	case string:
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			return ts, true
		}
	}
	return 0, false
}

func normalizeScalar(val any) (any, bool) {
	switch v := val.(type) {
	case string:
		return v, true
	case bool:
		return v, true
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, true
		}
		if f, err := v.Float64(); err == nil {
			return f, true
		}
	case float64:
		return v, true
	case int64:
		return v, true
	case int:
		return int64(v), true
	case uint64:
		return int64(v), true
	case uint:
		return int64(v), true
	}
	return nil, false
}

type ExportConfig struct {
	Enabled  bool
	Path     string
	Include  ExportIncludeConfig
	Required bool
	Flush    bool
}

type ExportIncludeConfig struct {
	Alerts             bool
	CorrelationMatches bool
}

type exportConfigRaw struct {
	Enabled  bool             `yaml:"enabled"`
	Path     string           `yaml:"path"`
	Include  exportIncludeRaw `yaml:"include"`
	Required *bool            `yaml:"required"`
	Flush    *bool            `yaml:"flush"`
}

type exportIncludeRaw struct {
	Alerts             *bool `yaml:"alerts"`
	CorrelationMatches *bool `yaml:"correlation_matches"`
}

type Exporter struct {
	logger *slog.Logger
	cfg    ExportConfig
	mu     sync.Mutex
	file   *os.File
}

type ExportMeta struct {
	Msg      string
	RuleID   string
	AlertKey string
}

const defaultExportPath = "exports/alerts.jsonl"

func loadExportConfig(path string) (*ExportConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var wrapper struct {
		Export *exportConfigRaw `yaml:"export"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse export config: %w", err)
	}
	if wrapper.Export == nil {
		return nil, nil
	}
	cfg := resolveExportConfig(*wrapper.Export)
	if !cfg.Enabled {
		return nil, nil
	}
	return &cfg, nil
}

func resolveExportConfig(raw exportConfigRaw) ExportConfig {
	cfg := ExportConfig{
		Enabled:  raw.Enabled,
		Path:     strings.TrimSpace(raw.Path),
		Required: true,
		Flush:    true,
		Include: ExportIncludeConfig{
			Alerts:             true,
			CorrelationMatches: false,
		},
	}
	if raw.Required != nil {
		cfg.Required = *raw.Required
	}
	if raw.Flush != nil {
		cfg.Flush = *raw.Flush
	}
	if raw.Include.Alerts != nil {
		cfg.Include.Alerts = *raw.Include.Alerts
	}
	if raw.Include.CorrelationMatches != nil {
		cfg.Include.CorrelationMatches = *raw.Include.CorrelationMatches
	}
	if cfg.Path == "" {
		cfg.Path = defaultExportPath
	}
	return cfg
}

func newExporter(logger *slog.Logger, cfg *ExportConfig) (*Exporter, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	dir := filepath.Dir(cfg.Path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create export dir: %w", err)
		}
	}
	file, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open export file: %w", err)
	}
	return &Exporter{
		logger: logger,
		cfg:    *cfg,
		file:   file,
	}, nil
}

func (e *Exporter) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file != nil {
		_ = e.file.Close()
		e.file = nil
	}
}

func (e *Exporter) IncludeAlerts() bool {
	return e != nil && e.cfg.Enabled && e.cfg.Include.Alerts
}

func (e *Exporter) IncludeCorrelationMatches() bool {
	return e != nil && e.cfg.Enabled && e.cfg.Include.CorrelationMatches
}

func (e *Exporter) WriteJSONL(obj map[string]any, meta ExportMeta) error {
	if e == nil || !e.cfg.Enabled {
		return nil
	}
	payload, err := json.Marshal(obj)
	if err != nil {
		e.logError(err, meta)
		if e.cfg.Required {
			return err
		}
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file == nil {
		err = fmt.Errorf("export file not available")
		e.logError(err, meta)
		if e.cfg.Required {
			return err
		}
		return nil
	}
	if _, err := e.file.Write(append(payload, '\n')); err != nil {
		e.logError(err, meta)
		if e.cfg.Required {
			return err
		}
		return nil
	}
	if e.cfg.Flush {
		if err := e.file.Sync(); err != nil {
			e.logError(err, meta)
			if e.cfg.Required {
				return err
			}
		}
	}
	return nil
}

func (e *Exporter) logError(err error, meta ExportMeta) {
	attrs := []slog.Attr{
		slog.String("path", e.cfg.Path),
		slog.String("error", err.Error()),
	}
	if meta.Msg != "" {
		attrs = append(attrs, slog.String("export_msg", meta.Msg))
	}
	if meta.RuleID != "" {
		attrs = append(attrs, slog.String("rule_id", meta.RuleID))
	}
	if meta.AlertKey != "" {
		attrs = append(attrs, slog.String("alert_key", meta.AlertKey))
	}
	e.logger.LogAttrs(context.Background(), slog.LevelError, "export_error", attrs...)
}

type ResponseTriggerConfig struct {
	Enabled         bool
	Required        bool
	Stream          string
	SubjectFast     string
	SubjectStandard string
	LanePolicy      string
}

type responseTriggerConfigRaw struct {
	Enabled         bool   `yaml:"enabled"`
	Required        *bool  `yaml:"required"`
	Stream          string `yaml:"stream"`
	SubjectFast     string `yaml:"subject_fast"`
	SubjectStandard string `yaml:"subject_standard"`
	LanePolicy      string `yaml:"lane_policy"`
}

type ResponseTriggerPublisher struct {
	logger *slog.Logger
	js     nats.JetStreamContext
	cfg    ResponseTriggerConfig
}

const (
	defaultResponseStream      = "RSIEM_RESPONSE"
	defaultResponseSubjectFast = "rsiem.response.triggers.fast"
	defaultResponseSubjectStd  = "rsiem.response.triggers.standard"
	defaultResponseLanePolicy  = "from_alert"
)

func loadResponseTriggerConfig(path string) (*ResponseTriggerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var wrapper struct {
		ResponseTriggers *responseTriggerConfigRaw `yaml:"response_triggers"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse response_triggers config: %w", err)
	}
	if wrapper.ResponseTriggers == nil {
		return nil, nil
	}
	cfg := resolveResponseTriggerConfig(*wrapper.ResponseTriggers)
	if !cfg.Enabled {
		return nil, nil
	}
	return &cfg, nil
}

func resolveResponseTriggerConfig(raw responseTriggerConfigRaw) ResponseTriggerConfig {
	cfg := ResponseTriggerConfig{
		Enabled:         raw.Enabled,
		Required:        true,
		Stream:          strings.TrimSpace(raw.Stream),
		SubjectFast:     strings.TrimSpace(raw.SubjectFast),
		SubjectStandard: strings.TrimSpace(raw.SubjectStandard),
		LanePolicy:      strings.TrimSpace(raw.LanePolicy),
	}
	if raw.Required != nil {
		cfg.Required = *raw.Required
	}
	if cfg.Stream == "" {
		cfg.Stream = defaultResponseStream
	}
	if cfg.SubjectFast == "" {
		cfg.SubjectFast = defaultResponseSubjectFast
	}
	if cfg.SubjectStandard == "" {
		cfg.SubjectStandard = defaultResponseSubjectStd
	}
	if cfg.LanePolicy == "" {
		cfg.LanePolicy = defaultResponseLanePolicy
	}
	return cfg
}

func newResponseTriggerPublisher(logger *slog.Logger, js nats.JetStreamContext, cfg *ResponseTriggerConfig) (*ResponseTriggerPublisher, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	if err := ensureResponseStream(js, cfg); err != nil {
		return nil, err
	}
	return &ResponseTriggerPublisher{
		logger: logger,
		js:     js,
		cfg:    *cfg,
	}, nil
}

func ensureResponseStream(js nats.JetStreamContext, cfg *ResponseTriggerConfig) error {
	_, err := js.AddStream(&nats.StreamConfig{
		Name: cfg.Stream,
		Subjects: []string{
			cfg.SubjectFast,
			cfg.SubjectStandard,
			"rsiem.response.steps.fast",
			"rsiem.response.steps.standard",
		},
	})
	if err != nil && !errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return err
	}
	return nil
}

func (p *ResponseTriggerPublisher) PublishAlert(alert ResponseTriggerAlert) error {
	if p == nil || !p.cfg.Enabled {
		return nil
	}
	lane := p.resolveLane(alert.Lane, alert.Severity)
	subject := p.cfg.SubjectStandard
	if lane == "FAST" {
		subject = p.cfg.SubjectFast
	}
	alertKey := strings.TrimSpace(alert.AlertKey)
	triggerID := fmt.Sprintf("trig.alert.%s", alertKey)
	payload := map[string]any{
		"msg":                 "response_trigger",
		"lane":                lane,
		"trigger_kind":        "alert",
		"trigger_idem_key":    triggerID,
		"alert_key":           alertKey,
		"rule_id":             alert.RuleID,
		"rule_kind":           alert.RuleKind,
		"severity":            alert.Severity,
		"observed_at_unix_ms": alert.ObservedAtUnixMs,
		"stream":              alert.Stream,
		"consumer":            alert.Consumer,
		"subject":             alert.Subject,
		"batch_key":           alert.BatchKey,
	}
	if alert.GroupBy != "" {
		payload["group_by"] = alert.GroupBy
	}
	if alert.GroupKey != "" {
		payload["group_key"] = alert.GroupKey
	}
	if alert.AgentID != "" {
		payload["agent_id"] = alert.AgentID
	}
	if alert.JSSeq != nil {
		payload["js_seq"] = *alert.JSSeq
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return p.handleError(err, triggerID, subject, alert)
	}
	if _, err := p.js.Publish(subject, data); err != nil {
		return p.handleError(err, triggerID, subject, alert)
	}
	return nil
}

func (p *ResponseTriggerPublisher) resolveLane(alertLane, severity string) string {
	switch strings.ToLower(p.cfg.LanePolicy) {
	case "by_severity":
		if strings.ToLower(severity) == "high" {
			return "FAST"
		}
		return "STANDARD"
	default:
		if strings.TrimSpace(alertLane) == "" {
			return "STANDARD"
		}
		return alertLane
	}
}

func (p *ResponseTriggerPublisher) handleError(err error, triggerID, subject string, alert ResponseTriggerAlert) error {
	if p.cfg.Required {
		return err
	}
	attrs := []slog.Attr{
		slog.String("error", err.Error()),
		slog.String("trigger_idem_key", triggerID),
		slog.String("subject", subject),
		slog.String("rule_id", alert.RuleID),
		slog.String("alert_key", alert.AlertKey),
	}
	p.logger.LogAttrs(context.Background(), slog.LevelError, "response_trigger_publish_error", attrs...)
	return nil
}

type ResponseTriggerAlert struct {
	AlertKey         string
	RuleID           string
	RuleKind         string
	Severity         string
	GroupBy          string
	GroupKey         string
	AgentID          string
	ObservedAtUnixMs int64
	Lane             string
	Stream           string
	Consumer         string
	Subject          string
	JSSeq            *uint64
	BatchKey         string
}

type IncidentConfig struct {
	Enabled           bool
	MaxOpenIncidents  int
	InactivityTTLMS   int64
	CleanupIntervalMS int64
	RecentEvidenceMax int
	Export            IncidentExportConfig
}

type IncidentExportConfig struct {
	Enabled  bool
	Required bool
	Path     string
	Flush    bool
}

type incidentConfigRaw struct {
	Enabled           bool                 `yaml:"enabled"`
	MaxOpenIncidents  int                  `yaml:"max_open_incidents"`
	InactivityTTLMS   int64                `yaml:"inactivity_ttl_ms"`
	CleanupIntervalMS int64                `yaml:"cleanup_interval_ms"`
	RecentEvidenceMax int                  `yaml:"recent_evidence_max"`
	Export            incidentExportConfig `yaml:"export"`
}

type incidentExportConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Required *bool  `yaml:"required"`
	Path     string `yaml:"path"`
	Flush    *bool  `yaml:"flush"`
}

type IncidentManager struct {
	logger  *slog.Logger
	cfg     IncidentConfig
	mu      sync.Mutex
	state   map[string]*IncidentState
	export  *IncidentExporter
	closing chan struct{}
}

type IncidentState struct {
	IncidentID        string
	IncidentKey       string
	RuleID            string
	RuleKind          string
	GroupBy           string
	GroupKey          string
	SeverityCurrent   string
	OpenedAtUnixMs    int64
	LastUpdatedUnixMs int64
	AlertCountTotal   int
	LastAlertKey      string
	LastJSSeq         *uint64
	LastSubject       string
	LastLane          string
	LastAgentID       string
	RecentEvidence    []IncidentEvidence
}

type IncidentEvidence struct {
	EmittedAtUnixMs          int64  `json:"emitted_at_unix_ms"`
	AlertKey                 string `json:"alert_key"`
	RawSHA256                string `json:"raw_sha256"`
	CorrelationEvidenceCount int    `json:"correlation_evidence_count"`
}

type IncidentAlert struct {
	RuleID                   string
	RuleKind                 string
	Severity                 string
	GroupBy                  string
	GroupKey                 string
	AlertKey                 string
	EmittedAtUnixMs          int64
	CorrelationEvidenceCount int
	RawSHA256                string
	Lane                     string
	Subject                  string
	Stream                   string
	Consumer                 string
	NormalizedVersion        string
	JSSeq                    *uint64
	BatchKey                 string
	AgentID                  string
}

type IncidentExporter struct {
	logger *slog.Logger
	cfg    IncidentExportConfig
	mu     sync.Mutex
	file   *os.File
}

func loadIncidentConfig(path string) (*IncidentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var wrapper struct {
		Incidents *incidentConfigRaw `yaml:"incidents"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse incidents config: %w", err)
	}
	if wrapper.Incidents == nil {
		return nil, nil
	}
	cfg := resolveIncidentConfig(*wrapper.Incidents)
	if !cfg.Enabled {
		return nil, nil
	}
	return &cfg, nil
}

func resolveIncidentConfig(raw incidentConfigRaw) IncidentConfig {
	cfg := IncidentConfig{
		Enabled:           raw.Enabled,
		MaxOpenIncidents:  raw.MaxOpenIncidents,
		InactivityTTLMS:   raw.InactivityTTLMS,
		CleanupIntervalMS: raw.CleanupIntervalMS,
		RecentEvidenceMax: raw.RecentEvidenceMax,
		Export: IncidentExportConfig{
			Enabled:  raw.Export.Enabled,
			Path:     strings.TrimSpace(raw.Export.Path),
			Required: true,
			Flush:    true,
		},
	}
	if cfg.MaxOpenIncidents <= 0 {
		cfg.MaxOpenIncidents = 50000
	}
	if cfg.InactivityTTLMS <= 0 {
		cfg.InactivityTTLMS = 10 * 60 * 1000
	}
	if cfg.CleanupIntervalMS <= 0 {
		cfg.CleanupIntervalMS = 5000
	}
	if cfg.RecentEvidenceMax <= 0 {
		cfg.RecentEvidenceMax = 10
	}
	if raw.Export.Required != nil {
		cfg.Export.Required = *raw.Export.Required
	}
	if raw.Export.Flush != nil {
		cfg.Export.Flush = *raw.Export.Flush
	}
	if cfg.Export.Path == "" {
		cfg.Export.Path = "exports/incidents.jsonl"
	}
	return cfg
}

func newIncidentManager(logger *slog.Logger, cfg *IncidentConfig) (*IncidentManager, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	var exporter *IncidentExporter
	var err error
	if cfg.Export.Enabled {
		exporter, err = newIncidentExporter(logger, cfg.Export)
		if err != nil {
			return nil, err
		}
	}
	manager := &IncidentManager{
		logger:  logger,
		cfg:     *cfg,
		state:   make(map[string]*IncidentState),
		export:  exporter,
		closing: make(chan struct{}),
	}
	go manager.cleanupLoop()
	return manager, nil
}

func (m *IncidentManager) Close() {
	if m == nil {
		return
	}
	close(m.closing)
	if m.export != nil {
		m.export.Close()
	}
}

func (m *IncidentManager) cleanupLoop() {
	ticker := time.NewTicker(time.Duration(m.cfg.CleanupIntervalMS) * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.cleanup()
		case <-m.closing:
			return
		}
	}
}

func (m *IncidentManager) cleanup() {
	now := time.Now().UnixMilli()
	var closed []*IncidentState
	m.mu.Lock()
	for key, state := range m.state {
		if now-state.LastUpdatedUnixMs > m.cfg.InactivityTTLMS {
			closed = append(closed, state)
			delete(m.state, key)
		}
	}
	m.mu.Unlock()

	for _, state := range closed {
		m.emitIncidentClosed(state, now)
	}
}

func (m *IncidentManager) ProcessAlert(alert IncidentAlert) error {
	if m == nil {
		return nil
	}
	groupKey := alert.GroupKey
	if groupKey == "" {
		groupKey = "global"
	}
	incidentKey := fmt.Sprintf("inc.%s.%s", alert.RuleID, groupKey)
	incidentID := incidentIDFromKey(incidentKey)
	now := alert.EmittedAtUnixMs

	m.mu.Lock()
	state, exists := m.state[incidentKey]
	if !exists {
		if len(m.state) >= m.cfg.MaxOpenIncidents {
			m.mu.Unlock()
			m.emitIncidentDrop(alert, incidentKey)
			return nil
		}
		state = &IncidentState{
			IncidentID:        incidentID,
			IncidentKey:       incidentKey,
			RuleID:            alert.RuleID,
			RuleKind:          alert.RuleKind,
			GroupBy:           alert.GroupBy,
			GroupKey:          alert.GroupKey,
			SeverityCurrent:   alert.Severity,
			OpenedAtUnixMs:    now,
			LastUpdatedUnixMs: now,
			AlertCountTotal:   1,
			LastAlertKey:      alert.AlertKey,
			LastJSSeq:         alert.JSSeq,
			LastSubject:       alert.Subject,
			LastLane:          alert.Lane,
			LastAgentID:       alert.AgentID,
			RecentEvidence:    nil,
		}
		state.RecentEvidence = appendIncidentEvidence(state.RecentEvidence, alert, m.cfg.RecentEvidenceMax)
		m.state[incidentKey] = state
		m.mu.Unlock()
		return m.emitIncidentOpened(alert, state)
	}

	if severityRank(alert.Severity) > severityRank(state.SeverityCurrent) {
		state.SeverityCurrent = alert.Severity
	}
	state.LastUpdatedUnixMs = now
	state.AlertCountTotal++
	state.LastAlertKey = alert.AlertKey
	state.LastJSSeq = alert.JSSeq
	state.LastSubject = alert.Subject
	state.LastLane = alert.Lane
	state.LastAgentID = alert.AgentID
	state.RecentEvidence = appendIncidentEvidence(state.RecentEvidence, alert, m.cfg.RecentEvidenceMax)
	m.mu.Unlock()
	return m.emitIncidentUpdated(alert, state)
}

func appendIncidentEvidence(existing []IncidentEvidence, alert IncidentAlert, max int) []IncidentEvidence {
	entry := IncidentEvidence{
		EmittedAtUnixMs:          alert.EmittedAtUnixMs,
		AlertKey:                 alert.AlertKey,
		RawSHA256:                alert.RawSHA256,
		CorrelationEvidenceCount: alert.CorrelationEvidenceCount,
	}
	existing = append(existing, entry)
	if max > 0 && len(existing) > max {
		return append([]IncidentEvidence(nil), existing[len(existing)-max:]...)
	}
	return existing
}

func (m *IncidentManager) emitIncidentOpened(alert IncidentAlert, state *IncidentState) error {
	attrs := m.incidentBaseAttrs(alert, state)
	attrs = append(attrs,
		slog.String("severity_current", state.SeverityCurrent),
		slog.Int64("opened_at_unix_ms", state.OpenedAtUnixMs),
		slog.Int64("last_updated_at_unix_ms", state.LastUpdatedUnixMs),
		slog.String("first_alert_key", state.LastAlertKey),
	)
	m.logger.LogAttrs(context.Background(), slog.LevelInfo, "incident_opened", attrs...)

	if m.export != nil && m.export.cfg.Enabled {
		obj := m.incidentOpenedObject(alert, state)
		if err := m.export.WriteJSONL(obj, ExportMeta{
			Msg:      "incident_opened",
			RuleID:   state.RuleID,
			AlertKey: state.LastAlertKey,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (m *IncidentManager) emitIncidentUpdated(alert IncidentAlert, state *IncidentState) error {
	attrs := m.incidentBaseAttrs(alert, state)
	attrs = append(attrs,
		slog.String("severity_current", state.SeverityCurrent),
		slog.Int64("opened_at_unix_ms", state.OpenedAtUnixMs),
		slog.Int64("last_updated_at_unix_ms", state.LastUpdatedUnixMs),
		slog.Int("alert_count_total", state.AlertCountTotal),
		slog.String("last_alert_key", state.LastAlertKey),
		slog.Any("recent_evidence", state.RecentEvidence),
	)
	m.logger.LogAttrs(context.Background(), slog.LevelInfo, "incident_updated", attrs...)

	if m.export != nil && m.export.cfg.Enabled {
		obj := m.incidentUpdatedObject(alert, state)
		if err := m.export.WriteJSONL(obj, ExportMeta{
			Msg:      "incident_updated",
			RuleID:   state.RuleID,
			AlertKey: state.LastAlertKey,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (m *IncidentManager) emitIncidentClosed(state *IncidentState, now int64) {
	duration := now - state.OpenedAtUnixMs
	attrs := []slog.Attr{
		slog.String("incident_id", state.IncidentID),
		slog.String("incident_key", state.IncidentKey),
		slog.String("rule_id", state.RuleID),
		slog.String("rule_kind", state.RuleKind),
		slog.String("severity_current", state.SeverityCurrent),
		slog.Int64("opened_at_unix_ms", state.OpenedAtUnixMs),
		slog.Int64("closed_at_unix_ms", now),
		slog.Int64("duration_ms", duration),
		slog.Int("alert_count_total", state.AlertCountTotal),
	}
	if state.GroupBy != "" && state.GroupKey != "" {
		attrs = append(attrs, slog.String("group_by", state.GroupBy), slog.String("group_key", state.GroupKey))
	}
	m.logger.LogAttrs(context.Background(), slog.LevelInfo, "incident_closed", attrs...)

	if m.export != nil && m.export.cfg.Enabled {
		obj := map[string]any{
			"msg":               "incident_closed",
			"incident_id":       state.IncidentID,
			"incident_key":      state.IncidentKey,
			"rule_id":           state.RuleID,
			"rule_kind":         state.RuleKind,
			"severity_current":  state.SeverityCurrent,
			"opened_at_unix_ms": state.OpenedAtUnixMs,
			"closed_at_unix_ms": now,
			"duration_ms":       duration,
			"alert_count_total": state.AlertCountTotal,
		}
		if state.GroupBy != "" && state.GroupKey != "" {
			obj["group_by"] = state.GroupBy
			obj["group_key"] = state.GroupKey
		}
		_ = m.export.WriteJSONL(obj, ExportMeta{
			Msg:    "incident_closed",
			RuleID: state.RuleID,
		})
	}
}

func (m *IncidentManager) emitIncidentDrop(alert IncidentAlert, incidentKey string) {
	attrs := []slog.Attr{
		slog.String("incident_key", incidentKey),
		slog.String("rule_id", alert.RuleID),
		slog.String("alert_key", alert.AlertKey),
		slog.String("reason", "max_open_incidents"),
		slog.Int64("observed_at_unix_ms", alert.EmittedAtUnixMs),
	}
	if alert.GroupKey != "" {
		attrs = append(attrs, slog.String("group_key", alert.GroupKey))
	}
	m.logger.LogAttrs(context.Background(), slog.LevelWarn, "incident_drop", attrs...)
}

func (m *IncidentManager) incidentBaseAttrs(alert IncidentAlert, state *IncidentState) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("incident_id", state.IncidentID),
		slog.String("incident_key", state.IncidentKey),
		slog.String("rule_id", state.RuleID),
		slog.String("rule_kind", state.RuleKind),
		slog.String("lane", alert.Lane),
		slog.String("subject", alert.Subject),
		slog.String("stream", alert.Stream),
		slog.String("consumer", alert.Consumer),
		slog.String("normalized_version", alert.NormalizedVersion),
		slog.String("batch_key", alert.BatchKey),
	}
	if alert.JSSeq != nil {
		attrs = append(attrs, slog.Uint64("js_seq", *alert.JSSeq))
	}
	if alert.AgentID != "" {
		attrs = append(attrs, slog.String("agent_id", alert.AgentID))
	}
	if state.GroupBy != "" && state.GroupKey != "" {
		attrs = append(attrs, slog.String("group_by", state.GroupBy), slog.String("group_key", state.GroupKey))
	}
	return attrs
}

func (m *IncidentManager) incidentOpenedObject(alert IncidentAlert, state *IncidentState) map[string]any {
	obj := map[string]any{
		"msg":                     "incident_opened",
		"incident_id":             state.IncidentID,
		"incident_key":            state.IncidentKey,
		"rule_id":                 state.RuleID,
		"rule_kind":               state.RuleKind,
		"severity_current":        state.SeverityCurrent,
		"opened_at_unix_ms":       state.OpenedAtUnixMs,
		"last_updated_at_unix_ms": state.LastUpdatedUnixMs,
		"first_alert_key":         state.LastAlertKey,
		"lane":                    alert.Lane,
		"subject":                 alert.Subject,
		"stream":                  alert.Stream,
		"consumer":                alert.Consumer,
		"normalized_version":      alert.NormalizedVersion,
		"batch_key":               alert.BatchKey,
	}
	if alert.JSSeq != nil {
		obj["js_seq"] = *alert.JSSeq
	}
	if alert.AgentID != "" {
		obj["agent_id"] = alert.AgentID
	}
	if state.GroupBy != "" && state.GroupKey != "" {
		obj["group_by"] = state.GroupBy
		obj["group_key"] = state.GroupKey
	}
	return obj
}

func (m *IncidentManager) incidentUpdatedObject(alert IncidentAlert, state *IncidentState) map[string]any {
	obj := map[string]any{
		"msg":                     "incident_updated",
		"incident_id":             state.IncidentID,
		"incident_key":            state.IncidentKey,
		"rule_id":                 state.RuleID,
		"rule_kind":               state.RuleKind,
		"severity_current":        state.SeverityCurrent,
		"opened_at_unix_ms":       state.OpenedAtUnixMs,
		"last_updated_at_unix_ms": state.LastUpdatedUnixMs,
		"alert_count_total":       state.AlertCountTotal,
		"last_alert_key":          state.LastAlertKey,
		"recent_evidence":         state.RecentEvidence,
		"lane":                    alert.Lane,
		"subject":                 alert.Subject,
		"stream":                  alert.Stream,
		"consumer":                alert.Consumer,
		"normalized_version":      alert.NormalizedVersion,
		"batch_key":               alert.BatchKey,
	}
	if alert.JSSeq != nil {
		obj["js_seq"] = *alert.JSSeq
	}
	if alert.AgentID != "" {
		obj["agent_id"] = alert.AgentID
	}
	if state.GroupBy != "" && state.GroupKey != "" {
		obj["group_by"] = state.GroupBy
		obj["group_key"] = state.GroupKey
	}
	return obj
}

func incidentIDFromKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:16]
}

func newIncidentExporter(logger *slog.Logger, cfg IncidentExportConfig) (*IncidentExporter, error) {
	dir := filepath.Dir(cfg.Path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create incidents export dir: %w", err)
		}
	}
	file, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open incidents export file: %w", err)
	}
	return &IncidentExporter{
		logger: logger,
		cfg:    cfg,
		file:   file,
	}, nil
}

func (e *IncidentExporter) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file != nil {
		_ = e.file.Close()
		e.file = nil
	}
}

func (e *IncidentExporter) WriteJSONL(obj map[string]any, meta ExportMeta) error {
	if e == nil || !e.cfg.Enabled {
		return nil
	}
	payload, err := json.Marshal(obj)
	if err != nil {
		e.logError(err, meta)
		if e.cfg.Required {
			return err
		}
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file == nil {
		err = fmt.Errorf("incident export file not available")
		e.logError(err, meta)
		if e.cfg.Required {
			return err
		}
		return nil
	}
	if _, err := e.file.Write(append(payload, '\n')); err != nil {
		e.logError(err, meta)
		if e.cfg.Required {
			return err
		}
		return nil
	}
	if e.cfg.Flush {
		if err := e.file.Sync(); err != nil {
			e.logError(err, meta)
			if e.cfg.Required {
				return err
			}
		}
	}
	return nil
}

func (e *IncidentExporter) logError(err error, meta ExportMeta) {
	attrs := []slog.Attr{
		slog.String("path", e.cfg.Path),
		slog.String("error", err.Error()),
	}
	if meta.Msg != "" {
		attrs = append(attrs, slog.String("export_msg", meta.Msg))
	}
	if meta.RuleID != "" {
		attrs = append(attrs, slog.String("rule_id", meta.RuleID))
	}
	if meta.AlertKey != "" {
		attrs = append(attrs, slog.String("alert_key", meta.AlertKey))
	}
	e.logger.LogAttrs(context.Background(), slog.LevelError, "export_error", attrs...)
}

type RCEConfig struct {
	Enabled     bool                 `yaml:"enabled"`
	Dispatch    RCEDispatchConfig    `yaml:"dispatch"`
	Guardrails  RCEGuardrailsConfig  `yaml:"guardrails"`
	State       RCEStateConfig       `yaml:"state"`
	Suppression RCESuppressionConfig `yaml:"suppression"`
	Rules       []RCERule            `yaml:"rules"`
}

type RCEDispatchConfig struct {
	MaxQueue                int `yaml:"max_queue"`
	DegradeHighWatermarkPct int `yaml:"degrade_high_watermark_pct"`
}

type RCEGuardrailsConfig struct {
	MaxEventSizeBytes int   `yaml:"max_event_size_bytes"`
	MaxClockSkewMs    int64 `yaml:"max_clock_skew_ms"`
}

type RCEStateConfig struct {
	TTLMS             int64 `yaml:"ttl_ms"`
	MaxKeysPerRule    int   `yaml:"max_keys_per_rule"`
	CleanupIntervalMs int64 `yaml:"cleanup_interval_ms"`
}

type RCESuppressionConfig struct {
	DefaultCooldownMs int64 `yaml:"default_cooldown_ms"`
}

type RCERule struct {
	ID         string    `yaml:"id"`
	Enabled    bool      `yaml:"enabled"`
	Kind       string    `yaml:"kind"`
	Severity   string    `yaml:"severity"`
	GroupBy    string    `yaml:"group_by"`
	WindowMs   int64     `yaml:"window_ms"`
	Threshold  int       `yaml:"threshold"`
	When       RCEWhen   `yaml:"when"`
	Steps      []RCEWhen `yaml:"steps"`
	Predicates []RCEWhen `yaml:"predicates"`
	CooldownMs int64     `yaml:"cooldown_ms"`
}

type RCEWhen struct {
	Type   string            `yaml:"type"`
	Fields map[string]string `yaml:"fields"`
}

type NormalizedRecord struct {
	Lane              string
	Subject           string
	Stream            string
	Consumer          string
	NormalizedVersion string
	JSSeq             *uint64
	BatchKey          string
	SeqStart          uint64
	SeqEnd            uint64
	EventIndex        int
	EventCount        int
	AgentID           string
	ObservedAt        int64
	Type              string
	TsUnixMs          *int64
	Fields            map[string]any
	RawSHA256         string
	SizeBytes         int
}

type rceWork struct {
	record NormalizedRecord
	done   chan struct{}
	err    error
}

type RCE struct {
	logger      *slog.Logger
	cfg         RCEConfig
	queue       chan *rceWork
	mu          sync.Mutex
	state       map[string]*ruleState
	suppression map[string]int64
	exporter    *Exporter
	incidents   *IncidentManager
	triggers    *ResponseTriggerPublisher
	rawTriggers *trigger.Publisher
}

type ruleState struct {
	kind  string
	count map[string]*countState
	seq   map[string]*sequenceState
	join  map[string]*joinState
}

type countState struct {
	timestamps []int64
	lastSeen   int64
	hashes     []string
}

type sequenceState struct {
	step      int
	firstSeen int64
	lastSeen  int64
	hashes    []string
}

type joinState struct {
	satisfied map[int]predicateMatch
	firstSeen int64
	lastSeen  int64
	hashes    []string
}

type predicateMatch struct {
	ts   int64
	hash string
}

const (
	defaultRCEMaxQueue                = 1024
	defaultRCEDegradeHighWatermarkPct = 80
	defaultRCEMaxEventSizeBytes       = 65536
	defaultRCEMaxClockSkewMs          = int64(24 * 60 * 60 * 1000)
	defaultRCETTLMS                   = int64(5 * 60 * 1000)
	defaultRCEMaxKeysPerRule          = 50000
	defaultRCECleanupIntervalMs       = int64(5000)
	defaultRCEDefaultCooldownMs       = int64(60000)
	maxEvidenceHashes                 = 5
)

func loadRCEConfig(path string) (*RCEConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var wrapper struct {
		RCE *RCEConfig `yaml:"rce"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse rce config: %w", err)
	}
	if wrapper.RCE == nil {
		return nil, nil
	}
	cfg := *wrapper.RCE
	applyRCEDefaults(&cfg)
	if !cfg.Enabled {
		return nil, nil
	}
	return &cfg, nil
}

func applyRCEDefaults(cfg *RCEConfig) {
	if cfg.Dispatch.MaxQueue <= 0 {
		cfg.Dispatch.MaxQueue = defaultRCEMaxQueue
	}
	if cfg.Dispatch.DegradeHighWatermarkPct <= 0 {
		cfg.Dispatch.DegradeHighWatermarkPct = defaultRCEDegradeHighWatermarkPct
	}
	if cfg.Guardrails.MaxEventSizeBytes <= 0 {
		cfg.Guardrails.MaxEventSizeBytes = defaultRCEMaxEventSizeBytes
	}
	if cfg.Guardrails.MaxClockSkewMs <= 0 {
		cfg.Guardrails.MaxClockSkewMs = defaultRCEMaxClockSkewMs
	}
	if cfg.State.TTLMS <= 0 {
		cfg.State.TTLMS = defaultRCETTLMS
	}
	if cfg.State.MaxKeysPerRule <= 0 {
		cfg.State.MaxKeysPerRule = defaultRCEMaxKeysPerRule
	}
	if cfg.State.CleanupIntervalMs <= 0 {
		cfg.State.CleanupIntervalMs = defaultRCECleanupIntervalMs
	}
	if cfg.Suppression.DefaultCooldownMs <= 0 {
		cfg.Suppression.DefaultCooldownMs = defaultRCEDefaultCooldownMs
	}
}

func newRCE(logger *slog.Logger, cfg *RCEConfig, exporter *Exporter, incidents *IncidentManager, triggers *ResponseTriggerPublisher, rawTriggers *trigger.Publisher) *RCE {
	if cfg == nil {
		return nil
	}
	r := &RCE{
		logger:      logger,
		cfg:         *cfg,
		queue:       make(chan *rceWork, cfg.Dispatch.MaxQueue),
		state:       make(map[string]*ruleState),
		suppression: make(map[string]int64),
		exporter:    exporter,
		incidents:   incidents,
		triggers:    triggers,
		rawTriggers: rawTriggers,
	}
	go r.worker()
	go r.cleanupLoop()
	return r
}

func (r *RCE) Process(record NormalizedRecord) error {
	if r == nil {
		return nil
	}
	done := make(chan struct{})
	work := &rceWork{record: record, done: done}
	r.queue <- work
	<-done
	return work.err
}

func (r *RCE) worker() {
	for work := range r.queue {
		work.err = r.processRecord(work.record)
		close(work.done)
	}
}

func (r *RCE) cleanupLoop() {
	ticker := time.NewTicker(time.Duration(r.cfg.State.CleanupIntervalMs) * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		r.cleanup()
	}
}

func (r *RCE) cleanup() {
	now := time.Now().UnixMilli()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rs := range r.state {
		switch rs.kind {
		case "count":
			for key, st := range rs.count {
				if now-st.lastSeen > r.cfg.State.TTLMS {
					delete(rs.count, key)
				}
			}
		case "sequence":
			for key, st := range rs.seq {
				if now-st.lastSeen > r.cfg.State.TTLMS {
					delete(rs.seq, key)
				}
			}
		case "join":
			for key, st := range rs.join {
				if now-st.lastSeen > r.cfg.State.TTLMS {
					delete(rs.join, key)
				}
			}
		}
	}
	for key, next := range r.suppression {
		if now > next+r.cfg.State.TTLMS {
			delete(r.suppression, key)
		}
	}
}

func (r *RCE) processRecord(rec NormalizedRecord) error {
	if r.cfg.Guardrails.MaxEventSizeBytes > 0 && rec.SizeBytes > r.cfg.Guardrails.MaxEventSizeBytes {
		return nil
	}
	if rec.TsUnixMs != nil && r.cfg.Guardrails.MaxClockSkewMs > 0 {
		if absInt64(time.Now().UnixMilli()-*rec.TsUnixMs) > r.cfg.Guardrails.MaxClockSkewMs {
			return nil
		}
	}

	degraded := r.isDegraded()
	for _, rule := range r.cfg.Rules {
		if !rule.Enabled {
			continue
		}
		switch rule.Kind {
		case "stateless":
			if r.matchWhen(rule.When, rec) {
				r.emitRuleMatch(rule, rec, r.groupKey(rule.GroupBy, rec))
				if err := r.emitAlert(rule, rec, r.groupKey(rule.GroupBy, rec), "stateless", nil); err != nil {
					return err
				}
			}
		case "trigger":
			if r.matchWhen(rule.When, rec) {
				groupKey := r.groupKey(rule.GroupBy, rec)
				r.emitRuleMatch(rule, rec, groupKey)
				if err := r.emitTrigger(rule, rec, groupKey); err != nil {
					return err
				}
			}
		case "count":
			if err := r.evalCount(rule, rec); err != nil {
				return err
			}
		case "sequence":
			if degraded {
				continue
			}
			if err := r.evalSequence(rule, rec); err != nil {
				return err
			}
		case "join":
			if degraded {
				continue
			}
			if err := r.evalJoin(rule, rec); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *RCE) isDegraded() bool {
	if r.cfg.Dispatch.MaxQueue <= 0 {
		return false
	}
	occupancy := len(r.queue) * 100 / r.cfg.Dispatch.MaxQueue
	return occupancy >= r.cfg.Dispatch.DegradeHighWatermarkPct
}

func (r *RCE) matchWhen(when RCEWhen, rec NormalizedRecord) bool {
	if strings.TrimSpace(when.Type) != "" && !strings.EqualFold(when.Type, rec.Type) {
		return false
	}
	for key, expected := range when.Fields {
		if key == "message_contains" {
			message, ok := rec.Fields["message"].(string)
			if !ok || !strings.Contains(message, expected) {
				return false
			}
			continue
		}
		if key == "severity" {
			if !severityAtLeast(rec.Fields, expected) {
				return false
			}
			continue
		}
		val, ok := rec.Fields[key]
		if !ok {
			return false
		}
		strVal, ok := val.(string)
		if !ok {
			return false
		}
		if strVal != expected {
			return false
		}
	}
	return true
}

func severityAtLeast(fields map[string]any, expected string) bool {
	if fields == nil {
		return false
	}
	val, ok := fields["severity"]
	if !ok {
		return false
	}
	strVal, ok := val.(string)
	if !ok {
		return false
	}
	return severityRank(strVal) >= severityRank(expected)
}

func severityRank(val string) int {
	switch strings.ToLower(val) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func (r *RCE) groupKey(groupBy string, rec NormalizedRecord) string {
	switch groupBy {
	case "host":
		return normalizeHost(stringField(rec.Fields, "host"))
	case "user":
		return normalizeUser(stringField(rec.Fields, "user"))
	case "user_host":
		user := normalizeUser(stringField(rec.Fields, "user"))
		host := normalizeHost(stringField(rec.Fields, "host"))
		if user == "" || host == "" {
			return ""
		}
		return fmt.Sprintf("%s@%s", user, host)
	case "process_host":
		process := normalizeProcess(stringField(rec.Fields, "process"))
		host := normalizeHost(stringField(rec.Fields, "host"))
		if process == "" || host == "" {
			return ""
		}
		return fmt.Sprintf("%s@%s", process, host)
	case "src_ip":
		return normalizeIP(stringField(rec.Fields, "src_ip"))
	case "dst_ip":
		return normalizeIP(stringField(rec.Fields, "dst_ip"))
	case "agent_id":
		return normalizeAgentID(rec.AgentID)
	default:
		return ""
	}
}

func stringField(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	val, ok := fields[key]
	if !ok {
		return ""
	}
	strVal, ok := val.(string)
	if !ok {
		return ""
	}
	return strVal
}

func (r *RCE) evalCount(rule RCERule, rec NormalizedRecord) error {
	if !r.matchWhen(rule.When, rec) {
		return nil
	}
	groupKey := r.groupKey(rule.GroupBy, rec)
	if groupKey == "" {
		return nil
	}
	eventTs := rec.ObservedAt
	if rec.TsUnixMs != nil {
		eventTs = *rec.TsUnixMs
	}
	var match bool
	var matchCount int
	var firstSeen int64
	var lastSeen int64
	var hashes []string

	r.mu.Lock()
	state := r.ruleState(rule.ID, "count")
	if state == nil {
		r.mu.Unlock()
		return nil
	}
	st, exists := state.count[groupKey]
	if !exists {
		if len(state.count) >= r.cfg.State.MaxKeysPerRule {
			r.mu.Unlock()
			r.emitDropState(rule.ID)
			return nil
		}
		st = &countState{}
		state.count[groupKey] = st
	}
	st.timestamps = append(st.timestamps, eventTs)
	st.lastSeen = eventTs
	st.hashes = appendHash(st.hashes, rec.RawSHA256)
	windowStart := eventTs - rule.WindowMs
	st.timestamps = pruneTimestamps(st.timestamps, windowStart)
	matchCount = len(st.timestamps)
	if matchCount >= rule.Threshold {
		match = true
		firstSeen = st.timestamps[0]
		lastSeen = st.timestamps[len(st.timestamps)-1]
		hashes = append([]string(nil), st.hashes...)
	}
	r.mu.Unlock()

	if match {
		if err := r.emitCorrelationMatch(rule, rec, groupKey, matchCount, firstSeen, lastSeen, hashes, rule.Threshold, nil, nil); err != nil {
			return err
		}
		if err := r.emitAlert(rule, rec, groupKey, "count", hashes); err != nil {
			return err
		}
	}
	return nil
}

func (r *RCE) evalSequence(rule RCERule, rec NormalizedRecord) error {
	if len(rule.Steps) == 0 {
		return nil
	}
	groupKey := r.groupKey(rule.GroupBy, rec)
	if groupKey == "" {
		return nil
	}
	eventTs := rec.ObservedAt
	if rec.TsUnixMs != nil {
		eventTs = *rec.TsUnixMs
	}
	var match bool
	var firstSeen int64
	var lastSeen int64
	var hashes []string

	r.mu.Lock()
	state := r.ruleState(rule.ID, "sequence")
	if state == nil {
		r.mu.Unlock()
		return nil
	}
	st, exists := state.seq[groupKey]
	if !exists {
		if len(state.seq) >= r.cfg.State.MaxKeysPerRule {
			r.mu.Unlock()
			r.emitDropState(rule.ID)
			return nil
		}
		st = &sequenceState{step: 0}
		state.seq[groupKey] = st
	}
	if st.firstSeen == 0 || eventTs-st.firstSeen > rule.WindowMs {
		st.step = 0
		st.firstSeen = 0
		st.hashes = nil
	}
	currentStep := st.step
	if currentStep < len(rule.Steps) && r.matchWhen(rule.Steps[currentStep], rec) {
		if st.step == 0 {
			st.firstSeen = eventTs
		}
		st.step++
		st.lastSeen = eventTs
		st.hashes = appendHash(st.hashes, rec.RawSHA256)
		if st.step >= len(rule.Steps) {
			match = true
			firstSeen = st.firstSeen
			lastSeen = st.lastSeen
			hashes = append([]string(nil), st.hashes...)
			st.step = 0
			st.firstSeen = 0
			st.hashes = nil
		}
	}
	r.mu.Unlock()

	if match {
		if err := r.emitCorrelationMatch(rule, rec, groupKey, len(rule.Steps), firstSeen, lastSeen, hashes, 0, rule.Steps, nil); err != nil {
			return err
		}
		if err := r.emitAlert(rule, rec, groupKey, "sequence", hashes); err != nil {
			return err
		}
	}
	return nil
}

func (r *RCE) evalJoin(rule RCERule, rec NormalizedRecord) error {
	if len(rule.Predicates) == 0 {
		return nil
	}
	groupKey := r.groupKey(rule.GroupBy, rec)
	if groupKey == "" {
		return nil
	}
	eventTs := rec.ObservedAt
	if rec.TsUnixMs != nil {
		eventTs = *rec.TsUnixMs
	}
	var match bool
	var firstSeen int64
	var lastSeen int64
	var hashes []string

	r.mu.Lock()
	state := r.ruleState(rule.ID, "join")
	if state == nil {
		r.mu.Unlock()
		return nil
	}
	st, exists := state.join[groupKey]
	satisfied := map[int]predicateMatch{}
	if exists {
		satisfied = st.satisfied
	}
	windowStart := eventTs - rule.WindowMs
	for idx, match := range satisfied {
		if match.ts < windowStart {
			delete(satisfied, idx)
		}
	}
	matchIdx, matched := r.firstUnsatisfiedPredicate(rule.Predicates, satisfied, rec)
	if matched {
		if !exists {
			if len(state.join) >= r.cfg.State.MaxKeysPerRule {
				r.mu.Unlock()
				r.emitDropState(rule.ID)
				return nil
			}
			st = &joinState{satisfied: make(map[int]predicateMatch)}
			state.join[groupKey] = st
			satisfied = st.satisfied
		}
		st.satisfied = satisfied
		st.satisfied[matchIdx] = predicateMatch{ts: eventTs, hash: rec.RawSHA256}
		st.hashes = appendHash(st.hashes, rec.RawSHA256)
		st.lastSeen = eventTs
	}
	if exists || matched {
		st = state.join[groupKey]
	}
	if st != nil && len(st.satisfied) == len(rule.Predicates) {
		match = true
		firstSeen, lastSeen, hashes = collectJoinEvidence(st.satisfied)
		st.satisfied = make(map[int]predicateMatch)
		st.hashes = nil
	}
	r.mu.Unlock()

	if match {
		if err := r.emitCorrelationMatch(rule, rec, groupKey, len(rule.Predicates), firstSeen, lastSeen, hashes, 0, nil, rule.Predicates); err != nil {
			return err
		}
		if err := r.emitAlert(rule, rec, groupKey, "join", hashes); err != nil {
			return err
		}
	}
	return nil
}

func (r *RCE) ruleState(ruleID, kind string) *ruleState {
	state, ok := r.state[ruleID]
	if !ok {
		state = &ruleState{
			kind:  kind,
			count: make(map[string]*countState),
			seq:   make(map[string]*sequenceState),
			join:  make(map[string]*joinState),
		}
		r.state[ruleID] = state
	}
	return state
}

func (r *RCE) emitRuleMatch(rule RCERule, rec NormalizedRecord, correlationKey string) {
	attrs := r.baseAttrs(rec)
	attrs = append(attrs,
		slog.String("rule_id", rule.ID),
		slog.String("rule_kind", "stateless"),
		slog.String("severity", rule.Severity),
		slog.Int64("observed_at_unix_ms", rec.ObservedAt),
		slog.Any("evidence", r.evidence(rec)),
	)
	if correlationKey != "" {
		attrs = append(attrs, slog.String("correlation_key", correlationKey))
	}
	r.logger.LogAttrs(context.Background(), slog.LevelInfo, "rule_match", attrs...)
}

func (r *RCE) emitCorrelationMatch(rule RCERule, rec NormalizedRecord, groupKey string, matchCount int, firstSeen int64, lastSeen int64, hashes []string, threshold int, steps []RCEWhen, predicates []RCEWhen) error {
	attrs := r.baseAttrs(rec)
	attrs = append(attrs,
		slog.String("rule_id", rule.ID),
		slog.String("rule_kind", rule.Kind),
		slog.String("severity", rule.Severity),
		slog.String("group_by", rule.GroupBy),
		slog.String("group_key", groupKey),
		slog.Int64("window_ms", rule.WindowMs),
		slog.Int("match_count", matchCount),
		slog.Int64("first_seen", firstSeen),
		slog.Int64("last_seen", lastSeen),
		slog.Int64("observed_at_unix_ms", rec.ObservedAt),
		slog.Any("evidence", map[string]any{"raw_sha256": hashes}),
	)
	if threshold > 0 {
		attrs = append(attrs, slog.Int("threshold", threshold))
	}
	if steps != nil {
		attrs = append(attrs, slog.Any("steps", steps))
	}
	if predicates != nil {
		attrs = append(attrs, slog.Any("predicates", predicates))
	}
	r.logger.LogAttrs(context.Background(), slog.LevelInfo, "correlation_match", attrs...)

	if r.exporter != nil && r.exporter.IncludeCorrelationMatches() {
		obj := r.correlationMatchObject(rule, rec, groupKey, matchCount, firstSeen, lastSeen, hashes, threshold, steps, predicates)
		if err := r.exporter.WriteJSONL(obj, ExportMeta{
			Msg:    "correlation_match",
			RuleID: rule.ID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r *RCE) emitAlert(rule RCERule, rec NormalizedRecord, groupKey string, ruleKind string, correlationHashes []string) error {
	now := rec.ObservedAt
	cooldown := rule.CooldownMs
	if cooldown <= 0 {
		cooldown = r.cfg.Suppression.DefaultCooldownMs
	}
	window := rule.WindowMs
	if window <= 0 {
		window = cooldown
	}
	if window <= 0 {
		window = defaultRCEDefaultCooldownMs
	}
	bucket := now / maxInt64(window, cooldown)
	key := groupKey
	if key == "" {
		key = "global"
	}
	alertKey := fmt.Sprintf("alert.%s.%s.%d", rule.ID, key, bucket)
	nextAllowed := now + cooldown

	r.mu.Lock()
	existing, ok := r.suppression[alertKey]
	if ok && now < existing {
		r.mu.Unlock()
		attrs := r.baseAlertAttrs(rec)
		attrs = append(attrs,
			slog.String("alert_key", alertKey),
			slog.String("rule_id", rule.ID),
			slog.String("rule_kind", ruleKind),
			slog.String("suppressed_reason", "cooldown"),
			slog.Int64("next_allowed_at_unix_ms", existing),
		)
		if groupKey != "" {
			attrs = append(attrs, slog.String("group_by", rule.GroupBy), slog.String("group_key", groupKey))
		}
		r.logger.LogAttrs(context.Background(), slog.LevelInfo, "alert_suppressed", attrs...)
		return nil
	}
	r.suppression[alertKey] = nextAllowed
	r.mu.Unlock()

	attrs := r.baseAlertAttrs(rec)
	attrs = append(attrs,
		slog.String("alert_key", alertKey),
		slog.String("rule_id", rule.ID),
		slog.String("rule_kind", ruleKind),
		slog.String("severity", rule.Severity),
		slog.Int64("cooldown_ms", cooldown),
		slog.Int64("emitted_at_unix_ms", now),
		slog.Any("evidence", r.alertEvidence(rec)),
	)
	if ruleKind != "stateless" && len(correlationHashes) > 0 {
		attrs = append(attrs,
			slog.Any("correlation_evidence", map[string]any{"raw_sha256": correlationHashes}),
			slog.Int("correlation_evidence_count", len(correlationHashes)),
		)
	}
	if groupKey != "" {
		attrs = append(attrs, slog.String("group_by", rule.GroupBy), slog.String("group_key", groupKey))
	}
	r.logger.LogAttrs(context.Background(), slog.LevelInfo, "alert", attrs...)

	if r.exporter != nil && r.exporter.IncludeAlerts() {
		obj := r.alertObject(rule, rec, groupKey, ruleKind, alertKey, cooldown, correlationHashes)
		if err := r.exporter.WriteJSONL(obj, ExportMeta{
			Msg:      "alert",
			RuleID:   rule.ID,
			AlertKey: alertKey,
		}); err != nil {
			return err
		}
	}
	if r.incidents != nil {
		incidentAlert := IncidentAlert{
			RuleID:                   rule.ID,
			RuleKind:                 ruleKind,
			Severity:                 rule.Severity,
			GroupBy:                  rule.GroupBy,
			GroupKey:                 groupKey,
			AlertKey:                 alertKey,
			EmittedAtUnixMs:          now,
			CorrelationEvidenceCount: len(correlationHashes),
			RawSHA256:                rec.RawSHA256,
			Lane:                     rec.Lane,
			Subject:                  rec.Subject,
			Stream:                   rec.Stream,
			Consumer:                 rec.Consumer,
			NormalizedVersion:        rec.NormalizedVersion,
			JSSeq:                    rec.JSSeq,
			BatchKey:                 rec.BatchKey,
			AgentID:                  rec.AgentID,
		}
		if err := r.incidents.ProcessAlert(incidentAlert); err != nil {
			return err
		}
	}
	if r.triggers != nil {
		triggerAlert := ResponseTriggerAlert{
			AlertKey:         alertKey,
			RuleID:           rule.ID,
			RuleKind:         ruleKind,
			Severity:         rule.Severity,
			GroupBy:          rule.GroupBy,
			GroupKey:         groupKey,
			AgentID:          rec.AgentID,
			ObservedAtUnixMs: now,
			Lane:             rec.Lane,
			Stream:           rec.Stream,
			Consumer:         rec.Consumer,
			Subject:          rec.Subject,
			JSSeq:            rec.JSSeq,
			BatchKey:         rec.BatchKey,
		}
		if err := r.triggers.PublishAlert(triggerAlert); err != nil {
			return err
		}
	}
	return nil
}

func (r *RCE) emitTrigger(rule RCERule, rec NormalizedRecord, groupKey string) error {
	if r.rawTriggers == nil {
		return nil
	}
	key := strings.TrimSpace(groupKey)
	if key == "" {
		key = "unknown"
	}
	alertKey := deterministicAlertKey(rule.ID, key)
	lane := strings.TrimSpace(rec.Lane)
	if lane == "" {
		lane = "STANDARD"
	}
	alert := trigger.Alert{
		AlertKey:         alertKey,
		RuleID:           rule.ID,
		Severity:         rule.Severity,
		Lane:             lane,
		GroupBy:          rule.GroupBy,
		GroupKey:         key,
		ObservedAtUnixMs: rec.ObservedAt,
	}
	_, _, err := r.rawTriggers.PublishAlert(alert)
	return err
}

func deterministicAlertKey(ruleID, groupKey string) string {
	base := strings.TrimSpace(ruleID)
	if strings.HasPrefix(base, "R-") && len(base) > 2 {
		base = base[2:]
	}
	return fmt.Sprintf("A-%s-%s", base, strings.TrimSpace(groupKey))
}

func (r *RCE) emitDropState(ruleID string) {
	r.logger.LogAttrs(context.Background(), slog.LevelWarn, "rce_drop_state",
		slog.String("rule_id", ruleID),
		slog.String("reason", "max_keys"),
		slog.Int64("observed_at_unix_ms", time.Now().UnixMilli()),
	)
}

func (r *RCE) baseAttrs(rec NormalizedRecord) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("lane", rec.Lane),
		slog.String("subject", rec.Subject),
		slog.String("stream", rec.Stream),
		slog.String("consumer", rec.Consumer),
		slog.String("normalized_version", rec.NormalizedVersion),
		slog.String("batch_key", rec.BatchKey),
		slog.Uint64("seq_start", rec.SeqStart),
		slog.Uint64("seq_end", rec.SeqEnd),
		slog.Int("event_index", rec.EventIndex),
		slog.Int("event_count", rec.EventCount),
	}
	if rec.JSSeq != nil {
		attrs = append(attrs, slog.Uint64("js_seq", *rec.JSSeq))
	}
	if rec.AgentID != "" {
		attrs = append(attrs, slog.String("agent_id", rec.AgentID))
	}
	return attrs
}

func (r *RCE) baseAlertAttrs(rec NormalizedRecord) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("lane", rec.Lane),
		slog.String("subject", rec.Subject),
		slog.String("stream", rec.Stream),
		slog.String("consumer", rec.Consumer),
		slog.String("normalized_version", rec.NormalizedVersion),
		slog.String("batch_key", rec.BatchKey),
	}
	if rec.JSSeq != nil {
		attrs = append(attrs, slog.Uint64("js_seq", *rec.JSSeq))
	}
	if rec.AgentID != "" {
		attrs = append(attrs, slog.String("agent_id", rec.AgentID))
	}
	return attrs
}

func (r *RCE) baseExportMap(rec NormalizedRecord) map[string]any {
	obj := map[string]any{
		"lane":               rec.Lane,
		"subject":            rec.Subject,
		"stream":             rec.Stream,
		"consumer":           rec.Consumer,
		"normalized_version": rec.NormalizedVersion,
		"batch_key":          rec.BatchKey,
		"seq_start":          rec.SeqStart,
		"seq_end":            rec.SeqEnd,
		"event_index":        rec.EventIndex,
		"event_count":        rec.EventCount,
	}
	if rec.JSSeq != nil {
		obj["js_seq"] = *rec.JSSeq
	}
	if rec.AgentID != "" {
		obj["agent_id"] = rec.AgentID
	}
	return obj
}

func (r *RCE) baseAlertExportMap(rec NormalizedRecord) map[string]any {
	obj := map[string]any{
		"lane":               rec.Lane,
		"subject":            rec.Subject,
		"stream":             rec.Stream,
		"consumer":           rec.Consumer,
		"normalized_version": rec.NormalizedVersion,
		"batch_key":          rec.BatchKey,
	}
	if rec.JSSeq != nil {
		obj["js_seq"] = *rec.JSSeq
	}
	if rec.AgentID != "" {
		obj["agent_id"] = rec.AgentID
	}
	return obj
}

func (r *RCE) correlationMatchObject(rule RCERule, rec NormalizedRecord, groupKey string, matchCount int, firstSeen int64, lastSeen int64, hashes []string, threshold int, steps []RCEWhen, predicates []RCEWhen) map[string]any {
	obj := r.baseExportMap(rec)
	obj["msg"] = "correlation_match"
	obj["rule_id"] = rule.ID
	obj["rule_kind"] = rule.Kind
	obj["severity"] = rule.Severity
	obj["group_by"] = rule.GroupBy
	obj["group_key"] = groupKey
	obj["window_ms"] = rule.WindowMs
	obj["match_count"] = matchCount
	obj["first_seen"] = firstSeen
	obj["last_seen"] = lastSeen
	obj["observed_at_unix_ms"] = rec.ObservedAt
	obj["evidence"] = map[string]any{"raw_sha256": hashes}
	if threshold > 0 {
		obj["threshold"] = threshold
	}
	if steps != nil {
		obj["steps"] = steps
	}
	if predicates != nil {
		obj["predicates"] = predicates
	}
	return obj
}

func (r *RCE) alertObject(rule RCERule, rec NormalizedRecord, groupKey string, ruleKind string, alertKey string, cooldown int64, correlationHashes []string) map[string]any {
	obj := r.baseAlertExportMap(rec)
	obj["msg"] = "alert"
	obj["alert_key"] = alertKey
	obj["rule_id"] = rule.ID
	obj["rule_kind"] = ruleKind
	obj["severity"] = rule.Severity
	obj["cooldown_ms"] = cooldown
	obj["emitted_at_unix_ms"] = rec.ObservedAt
	obj["evidence"] = r.alertEvidence(rec)
	if ruleKind != "stateless" && len(correlationHashes) > 0 {
		obj["correlation_evidence"] = map[string]any{"raw_sha256": correlationHashes}
		obj["correlation_evidence_count"] = len(correlationHashes)
	}
	if groupKey != "" {
		obj["group_by"] = rule.GroupBy
		obj["group_key"] = groupKey
	}
	return obj
}

func (r *RCE) evidence(rec NormalizedRecord) map[string]any {
	evidence := map[string]any{
		"type":       rec.Type,
		"raw_sha256": rec.RawSHA256,
	}
	if rec.TsUnixMs != nil {
		evidence["ts_unix_ms"] = *rec.TsUnixMs
	}
	if rec.Fields != nil {
		evidence["fields"] = rec.Fields
	}
	return evidence
}

func (r *RCE) alertEvidence(rec NormalizedRecord) map[string]any {
	evidence := map[string]any{
		"type":       rec.Type,
		"raw_sha256": rec.RawSHA256,
	}
	if rec.Fields != nil {
		evidence["fields"] = rec.Fields
	}
	return evidence
}

func pruneTimestamps(values []int64, windowStart int64) []int64 {
	idx := 0
	for idx < len(values) && values[idx] < windowStart {
		idx++
	}
	if idx == 0 {
		return values
	}
	return append([]int64(nil), values[idx:]...)
}

func appendHash(hashes []string, hash string) []string {
	if hash == "" {
		return hashes
	}
	hashes = append(hashes, hash)
	if len(hashes) > maxEvidenceHashes {
		hashes = hashes[len(hashes)-maxEvidenceHashes:]
	}
	return hashes
}

func (r *RCE) firstUnsatisfiedPredicate(predicates []RCEWhen, satisfied map[int]predicateMatch, rec NormalizedRecord) (int, bool) {
	for idx, pred := range predicates {
		if _, ok := satisfied[idx]; ok {
			continue
		}
		if r.matchWhen(pred, rec) {
			return idx, true
		}
	}
	return 0, false
}

func collectJoinEvidence(satisfied map[int]predicateMatch) (int64, int64, []string) {
	if len(satisfied) == 0 {
		return 0, 0, nil
	}
	maxIndex := -1
	for idx := range satisfied {
		if idx > maxIndex {
			maxIndex = idx
		}
	}
	hashes := make([]string, 0, len(satisfied))
	firstSeen := int64(0)
	lastSeen := int64(0)
	for i := 0; i <= maxIndex; i++ {
		match, ok := satisfied[i]
		if !ok {
			continue
		}
		hashes = append(hashes, match.hash)
		if firstSeen == 0 || match.ts < firstSeen {
			firstSeen = match.ts
		}
		if match.ts > lastSeen {
			lastSeen = match.ts
		}
	}
	return firstSeen, lastSeen, hashes
}

func absInt64(val int64) int64 {
	if val < 0 {
		return -val
	}
	return val
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func normalizeHost(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeUser(value string) string {
	return strings.TrimSpace(value)
}

func normalizeProcess(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeIP(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip.String()
	}
	return trimmed
}

func normalizeAgentID(value string) string {
	return strings.TrimSpace(value)
}

func extractRecords(batch *pb.Batch) ([][]byte, []int64) {
	if batch == nil {
		return nil, nil
	}
	return extractRecordsFromValue(reflect.ValueOf(batch))
}

func extractRecordsFromValue(val reflect.Value) ([][]byte, []int64) {
	if !val.IsValid() {
		return nil, nil
	}
	methods := []string{"GetRecords", "GetEvents", "GetEntries", "GetItems", "GetPayloads"}
	for _, name := range methods {
		out, ok := callMethodZeroArg(val, name)
		if !ok {
			continue
		}
		if len(out) != 1 {
			continue
		}
		records, timestamps := extractRecordSlice(out[0])
		if len(records) > 0 {
			return records, timestamps
		}
	}
	return nil, nil
}

func extractRecordSlice(val reflect.Value) ([][]byte, []int64) {
	for val.IsValid() && val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return nil, nil
		}
		val = val.Elem()
	}
	if !val.IsValid() || val.Kind() != reflect.Slice {
		return nil, nil
	}
	if val.Len() == 0 {
		return nil, nil
	}

	var records [][]byte
	var timestamps []int64
	for i := 0; i < val.Len(); i++ {
		item := val.Index(i)
		record, ts, ok := extractRecordBytes(item)
		if !ok {
			continue
		}
		records = append(records, record)
		timestamps = append(timestamps, ts)
	}
	if len(records) == 0 {
		return nil, nil
	}
	return records, timestamps
}

func extractRecordBytes(val reflect.Value) ([]byte, int64, bool) {
	for val.IsValid() && val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return nil, 0, false
		}
		val = val.Elem()
	}
	if !val.IsValid() {
		return nil, 0, false
	}

	switch val.Kind() {
	case reflect.Slice:
		if val.Type().Elem().Kind() == reflect.Uint8 {
			data := make([]byte, val.Len())
			reflect.Copy(reflect.ValueOf(data), val)
			return data, extractTimestampValue(val), true
		}
	case reflect.String:
		return []byte(val.String()), 0, true
	case reflect.Struct:
		return extractBytesFromStruct(val)
	}
	return nil, 0, false
}

func extractBytesFromStruct(val reflect.Value) ([]byte, int64, bool) {
	getters := []string{"GetPayload", "GetData", "GetBody", "GetRaw"}
	for _, name := range getters {
		out, ok := callMethodZeroArg(val, name)
		if !ok {
			continue
		}
		if len(out) != 1 {
			continue
		}
		dataVal := out[0]
		for dataVal.IsValid() && dataVal.Kind() == reflect.Pointer {
			if dataVal.IsNil() {
				break
			}
			dataVal = dataVal.Elem()
		}
		if dataVal.IsValid() && dataVal.Kind() == reflect.Slice && dataVal.Type().Elem().Kind() == reflect.Uint8 {
			data := make([]byte, dataVal.Len())
			reflect.Copy(reflect.ValueOf(data), dataVal)
			return data, extractTimestampValue(val), true
		}
	}
	return nil, 0, false
}

func extractTimestampValue(val reflect.Value) int64 {
	if !val.IsValid() {
		return 0
	}
	methods := []string{"GetTsUnixMs", "GetTimestampUnixMs", "GetTimeUnixMs", "GetTimestampMs", "GetTsMs"}
	for _, name := range methods {
		out, ok := callMethodZeroArg(val, name)
		if !ok {
			continue
		}
		if len(out) != 1 {
			continue
		}
		if ts, ok := numericToInt64(out[0]); ok {
			return ts
		}
	}
	return 0
}

func callMethodZeroArg(val reflect.Value, name string) ([]reflect.Value, bool) {
	method := val.MethodByName(name)
	if !method.IsValid() && val.Kind() != reflect.Pointer && val.CanAddr() {
		method = val.Addr().MethodByName(name)
	}
	if !method.IsValid() || method.Type().NumIn() != 0 || method.Type().NumOut() != 1 {
		return nil, false
	}
	return method.Call(nil), true
}

func numericToInt64(val reflect.Value) (int64, bool) {
	for val.IsValid() && val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return 0, false
		}
		val = val.Elem()
	}
	if !val.IsValid() {
		return 0, false
	}
	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return val.Int(), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int64(val.Uint()), true
	default:
		return 0, false
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
	}()
	return ctx, cancel
}
