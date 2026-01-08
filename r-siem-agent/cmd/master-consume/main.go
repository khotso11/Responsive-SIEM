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

	rceCfg, err := loadRCEConfig(*configPath)
	if err != nil {
		logger.Error("rce_config_load_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	rce := newRCE(logger, rceCfg)

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

	emitNormalizedEvents(logger, msg.Subject, stream, jsSeq, lane, &batch, rce)

	if err := msg.Ack(); err != nil {
		logger.Error("consume_ack_failed",
			slog.String("lane", lane),
			slog.Uint64("js_seq", jsSeqVal),
			slog.String("error", err.Error()),
		)
	}
}

func emitNormalizedEvents(logger *slog.Logger, subject string, stream string, jsSeq *uint64, fallbackLane string, batch *pb.Batch, rce *RCE) {
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
			rce.Process(NormalizedRecord{
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
			})
		}
	}
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
}

type RCE struct {
	logger      *slog.Logger
	cfg         RCEConfig
	queue       chan rceWork
	mu          sync.Mutex
	state       map[string]*ruleState
	suppression map[string]int64
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

func newRCE(logger *slog.Logger, cfg *RCEConfig) *RCE {
	if cfg == nil {
		return nil
	}
	r := &RCE{
		logger:      logger,
		cfg:         *cfg,
		queue:       make(chan rceWork, cfg.Dispatch.MaxQueue),
		state:       make(map[string]*ruleState),
		suppression: make(map[string]int64),
	}
	go r.worker()
	go r.cleanupLoop()
	return r
}

func (r *RCE) Process(record NormalizedRecord) {
	if r == nil {
		return
	}
	done := make(chan struct{})
	r.queue <- rceWork{record: record, done: done}
	<-done
}

func (r *RCE) worker() {
	for work := range r.queue {
		r.processRecord(work.record)
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

func (r *RCE) processRecord(rec NormalizedRecord) {
	if r.cfg.Guardrails.MaxEventSizeBytes > 0 && rec.SizeBytes > r.cfg.Guardrails.MaxEventSizeBytes {
		return
	}
	if rec.TsUnixMs != nil && r.cfg.Guardrails.MaxClockSkewMs > 0 {
		if absInt64(time.Now().UnixMilli()-*rec.TsUnixMs) > r.cfg.Guardrails.MaxClockSkewMs {
			return
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
				r.emitAlert(rule, rec, r.groupKey(rule.GroupBy, rec), "stateless", nil)
			}
		case "count":
			r.evalCount(rule, rec)
		case "sequence":
			if degraded {
				continue
			}
			r.evalSequence(rule, rec)
		case "join":
			if degraded {
				continue
			}
			r.evalJoin(rule, rec)
		}
	}
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

func (r *RCE) evalCount(rule RCERule, rec NormalizedRecord) {
	if !r.matchWhen(rule.When, rec) {
		return
	}
	groupKey := r.groupKey(rule.GroupBy, rec)
	if groupKey == "" {
		return
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
		return
	}
	st, exists := state.count[groupKey]
	if !exists {
		if len(state.count) >= r.cfg.State.MaxKeysPerRule {
			r.mu.Unlock()
			r.emitDropState(rule.ID)
			return
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
		r.emitCorrelationMatch(rule, rec, groupKey, matchCount, firstSeen, lastSeen, hashes, rule.Threshold, nil, nil)
		r.emitAlert(rule, rec, groupKey, "count", hashes)
	}
}

func (r *RCE) evalSequence(rule RCERule, rec NormalizedRecord) {
	if len(rule.Steps) == 0 {
		return
	}
	groupKey := r.groupKey(rule.GroupBy, rec)
	if groupKey == "" {
		return
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
		return
	}
	st, exists := state.seq[groupKey]
	if !exists {
		if len(state.seq) >= r.cfg.State.MaxKeysPerRule {
			r.mu.Unlock()
			r.emitDropState(rule.ID)
			return
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
		r.emitCorrelationMatch(rule, rec, groupKey, len(rule.Steps), firstSeen, lastSeen, hashes, 0, rule.Steps, nil)
		r.emitAlert(rule, rec, groupKey, "sequence", hashes)
	}
}

func (r *RCE) evalJoin(rule RCERule, rec NormalizedRecord) {
	if len(rule.Predicates) == 0 {
		return
	}
	groupKey := r.groupKey(rule.GroupBy, rec)
	if groupKey == "" {
		return
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
		return
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
				return
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
		r.emitCorrelationMatch(rule, rec, groupKey, len(rule.Predicates), firstSeen, lastSeen, hashes, 0, nil, rule.Predicates)
		r.emitAlert(rule, rec, groupKey, "join", hashes)
	}
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

func (r *RCE) emitCorrelationMatch(rule RCERule, rec NormalizedRecord, groupKey string, matchCount int, firstSeen int64, lastSeen int64, hashes []string, threshold int, steps []RCEWhen, predicates []RCEWhen) {
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
}

func (r *RCE) emitAlert(rule RCERule, rec NormalizedRecord, groupKey string, ruleKind string, correlationHashes []string) {
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
		return
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
