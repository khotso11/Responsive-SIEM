package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"r-siem-agent/internal/config"
)

type normalizedEventDBSink struct {
	logger *slog.Logger
	cfg    config.MasterDBConfig
	db     *sql.DB
}

type normalizedEventDBRecord struct {
	EventTsUnixMs  int64
	RecvTsUnixMs   int64
	NodeID         string
	SourceType     string
	EventType      string
	SrcIP          string
	DstIP          string
	DstPort        int
	ProtocolFamily string
	UserName       string
	Severity       string
	RuleID         string
	ExecPath       string
	Comm           string
	Cmdline        string
	DNSName        string
	FileSHA256     string
	ExecSHA256     string
	EventIdemKey   string
	RawLineSHA256  string
}

func newNormalizedEventDBSink(logger *slog.Logger, cfg config.MasterDBConfig) (*normalizedEventDBSink, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	db, err := sql.Open("postgres", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	sink := &normalizedEventDBSink{
		logger: logger,
		cfg:    cfg,
		db:     db,
	}
	if err := sink.ensureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ensure db schema: %w", err)
	}
	return sink, nil
}

func (s *normalizedEventDBSink) Close() {
	if s == nil || s.db == nil {
		return
	}
	_ = s.db.Close()
}

func (s *normalizedEventDBSink) ensureSchema(ctx context.Context) error {
	const schemaSQL = `
CREATE TABLE IF NOT EXISTS normalized_events (
  id BIGSERIAL PRIMARY KEY,
  ingest_ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  event_ts_unix_ms BIGINT NOT NULL,
  recv_ts_unix_ms BIGINT NOT NULL,
  node_id TEXT NOT NULL,
  source_type TEXT NOT NULL,
  event_type TEXT NOT NULL,
  src_ip INET NULL,
  dst_ip INET NULL,
  dst_port INT NULL,
  protocol_family TEXT NULL,
  user_name TEXT NULL,
  severity TEXT NULL,
  rule_id TEXT NULL,
  exec_path TEXT NULL,
  comm TEXT NULL,
  cmdline TEXT NULL,
  dns_name TEXT NULL,
  file_sha256 TEXT NULL,
  exec_sha256 TEXT NULL,
  event_idem_key TEXT NOT NULL,
  raw_line_sha256 TEXT NULL
);
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS dst_ip INET NULL;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS dst_port INT NULL;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS protocol_family TEXT NULL;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS exec_path TEXT NULL;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS comm TEXT NULL;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS cmdline TEXT NULL;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS dns_name TEXT NULL;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS file_sha256 TEXT NULL;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS exec_sha256 TEXT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS normalized_events_event_idem_key_uidx ON normalized_events(event_idem_key);
CREATE INDEX IF NOT EXISTS normalized_events_event_ts_idx ON normalized_events(event_ts_unix_ms);
CREATE INDEX IF NOT EXISTS normalized_events_node_id_idx ON normalized_events(node_id);
`
	_, err := s.db.ExecContext(ctx, schemaSQL)
	return err
}

func (s *normalizedEventDBSink) Insert(rec normalizedEventDBRecord) error {
	if s == nil || s.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const q = `
INSERT INTO normalized_events (
  event_ts_unix_ms, recv_ts_unix_ms, node_id, source_type, event_type,
  src_ip, dst_ip, dst_port, protocol_family, user_name, severity, rule_id,
  exec_path, comm, cmdline, dns_name, file_sha256, exec_sha256, event_idem_key, raw_line_sha256
) VALUES ($1,$2,$3,$4,$5,CAST($6 AS inet),CAST($7 AS inet),$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
ON CONFLICT (event_idem_key) DO NOTHING;
`
	_, err := s.db.ExecContext(ctx, q,
		rec.EventTsUnixMs,
		rec.RecvTsUnixMs,
		trimmedOrUnknown(rec.NodeID),
		trimmedOrUnknown(rec.SourceType),
		trimmedOrUnknown(rec.EventType),
		nullableTrimmedString(rec.SrcIP),
		nullableTrimmedString(rec.DstIP),
		nullableInt(rec.DstPort),
		nullableTrimmedString(rec.ProtocolFamily),
		nullableTrimmedString(rec.UserName),
		nullableTrimmedString(rec.Severity),
		nullableTrimmedString(rec.RuleID),
		nullableTrimmedString(rec.ExecPath),
		nullableTrimmedString(rec.Comm),
		nullableTrimmedString(rec.Cmdline),
		nullableTrimmedString(rec.DNSName),
		nullableTrimmedString(rec.FileSHA256),
		nullableTrimmedString(rec.ExecSHA256),
		trimmedOrUnknown(rec.EventIdemKey),
		nullableTrimmedString(rec.RawLineSHA256),
	)
	if err == nil {
		return nil
	}
	if s.cfg.FailClosed {
		return err
	}
	s.logger.LogAttrs(context.Background(), slog.LevelWarn, "normalized_event_db_insert_failed",
		slog.String("error", err.Error()),
		slog.String("event_idem_key", rec.EventIdemKey),
	)
	return nil
}

func buildNormalizedEventDBRecord(raw []byte, observedAt int64, agentID string, lane string, stream string, subject string, seqStart uint64, seqEnd uint64, eventIndex int, eventCount int, recordType string, jsonTS *int64, jsonFields map[string]any) normalizedEventDBRecord {
	rawHash := sha256.Sum256(raw)
	eventTs := observedAt
	if jsonTS != nil && *jsonTS > 0 {
		eventTs = *jsonTS
	}

	nodeID := firstNonEmpty(
		fieldString(jsonFields, "node_id"),
		agentID,
	)
	sourceType := firstNonEmpty(
		fieldString(jsonFields, "source_type"),
		strings.TrimSpace(recordType),
	)
	eventType := firstNonEmpty(
		fieldString(jsonFields, "event_type"),
		strings.TrimSpace(recordType),
	)
	srcIP := fieldString(jsonFields, "src_ip")
	dstIP := fieldString(jsonFields, "dst_ip")
	protocolFamily := firstNonEmpty(
		fieldString(jsonFields, "protocol_family"),
		fieldString(jsonFields, "proto"),
	)
	userName := firstNonEmpty(
		fieldString(jsonFields, "user_name"),
		fieldString(jsonFields, "user"),
	)
	issueKey := firstNonEmpty(
		fieldString(jsonFields, "event_idem_key"),
		deterministicNormalizedEventID(lane, stream, subject, seqStart, seqEnd, eventIndex, agentID, raw),
	)
	return normalizedEventDBRecord{
		EventTsUnixMs:  eventTs,
		RecvTsUnixMs:   observedAt,
		NodeID:         nodeID,
		SourceType:     sourceType,
		EventType:      eventType,
		SrcIP:          srcIP,
		DstIP:          dstIP,
		DstPort:        firstIntField(jsonFields, "dst_port"),
		ProtocolFamily: protocolFamily,
		UserName:       userName,
		Severity:       fieldString(jsonFields, "severity"),
		RuleID:         fieldString(jsonFields, "rule_id"),
		ExecPath:       fieldString(jsonFields, "exec_path"),
		Comm:           fieldString(jsonFields, "comm"),
		Cmdline:        fieldString(jsonFields, "cmdline"),
		DNSName:        fieldString(jsonFields, "dns_name"),
		FileSHA256:     fieldString(jsonFields, "file_sha256"),
		ExecSHA256:     fieldString(jsonFields, "exec_sha256"),
		EventIdemKey:   issueKey,
		RawLineSHA256:  hex.EncodeToString(rawHash[:]),
	}
}

func deterministicNormalizedEventID(lane string, stream string, subject string, seqStart uint64, seqEnd uint64, eventIndex int, agentID string, raw []byte) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d|%d|%d|%s|%x", strings.TrimSpace(lane), strings.TrimSpace(stream), strings.TrimSpace(subject), seqStart, seqEnd, eventIndex, strings.TrimSpace(agentID), raw)))
	return "evt.consume." + hex.EncodeToString(sum[:])
}

func fieldString(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	val, ok := fields[key]
	if !ok {
		return ""
	}
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstIntField(fields map[string]any, key string) int {
	if fields == nil {
		return 0
	}
	val, ok := fields[key]
	if !ok {
		return 0
	}
	switch v := val.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float32:
		return int(v)
	case float64:
		return int(v)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return 0
}

func trimmedOrUnknown(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}

func nullableTrimmedString(value string) any {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return trimmed
}

func nullableInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}
