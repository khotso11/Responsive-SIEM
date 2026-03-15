package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/nats-io/nats.go"

	"r-siem-agent/internal/investigation"
	"r-siem-agent/internal/investigation/providers"
)

type jobPayload struct {
	JobID       string                     `json:"job_id"`
	RunID       string                     `json:"run_id"`
	Observables []investigation.Observable `json:"observables"`
	RequestedBy string                     `json:"requested_by"`
	Refresh     bool                       `json:"refresh"`
}

func main() {
	cfg := loadConfig()

	db, err := sql.Open("postgres", cfg.DBDSN)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := ensureInvestigationSchema(context.Background(), db); err != nil {
		log.Fatalf("ensure investigation schema: %v", err)
	}
	if count, err := markStaleJobsTimedOut(context.Background(), db, cfg.StaleJobAfter); err != nil {
		log.Printf("stale job cleanup failed: %v", err)
	} else if count > 0 {
		log.Printf("stale job cleanup marked %d jobs timed_out", count)
	}

	nc, err := nats.Connect(cfg.NATSURL, nats.Name("investigation-enricher"))
	if err != nil {
		log.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()

	eng, err := newEngine(cfg.EnabledProviders)
	if err != nil {
		log.Fatalf("configure providers: %v", err)
	}

	handler := func(msg *nats.Msg) {
		var payload jobPayload
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			log.Printf("invalid job payload: %v", err)
			return
		}
		if payload.JobID == "" {
			payload.JobID = "ienrich." + strings.ReplaceAll(nats.NewInbox(), "INBOX.", "")
		}
		ctx, cancel := context.WithTimeout(context.Background(), cfg.JobTimeout)
		defer cancel()
		if _, err := db.ExecContext(ctx, `
UPDATE enrichment_jobs
SET status='running', error_text=''
WHERE job_id=$1 AND status IN ('requested','running');
`, payload.JobID); err != nil {
			log.Printf("job %s: failed to mark running: %v", payload.JobID, err)
		}

		existing := loadExistingObservables(ctx, db, payload.RunID)
		objs := uniqueObservables(payload.Observables)
		if len(objs) == 0 {
			// Best effort load existing observables for the run.
			objs = existing
		}
		if len(objs) == 0 {
			_, _ = db.ExecContext(ctx, `
INSERT INTO enrichment_jobs (job_id, run_id, status, requested_by, requested_at_unix_ms, completed_at_unix_ms, refresh, error_text)
VALUES ($1,$2,'skipped',$3,EXTRACT(EPOCH FROM now())*1000,EXTRACT(EPOCH FROM now())*1000,$4,'no observables')
ON CONFLICT (job_id)
DO UPDATE SET status='skipped', completed_at_unix_ms=EXCLUDED.completed_at_unix_ms, error_text='no observables';
`, payload.JobID, payload.RunID, coalesce(payload.RequestedBy, "system"), payload.Refresh)
			log.Printf("job %s: no observables; run_id=%s", payload.JobID, payload.RunID)
			return
		}

		// Upsert observables to DB for this run.
		existingKeys := make(map[string]struct{}, len(existing))
		for _, o := range existing {
			existingKeys[observableKey(o)] = struct{}{}
		}
		for _, o := range objs {
			if _, ok := existingKeys[observableKey(o)]; ok {
				continue
			}
			_, _ = db.ExecContext(ctx, `
INSERT INTO incident_observables (run_id, observable_kind, observable_value, observable_role, observable_source, created_at_unix_ms)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT DO NOTHING;
`, payload.RunID, string(o.Kind), o.Value, o.Role, o.Source, time.Now().UnixMilli())
		}

		totalResults := 0
		for _, o := range objs {
			rs, _ := eng.Enrich(ctx, o)
			for _, r := range rs {
				totalResults++
				logProviderMetric(payload.JobID, o, r)
				_, _ = db.ExecContext(ctx, `
INSERT INTO observable_enrichments (
  observable_kind, observable_value, provider, status, provider_verdict, provider_score, summary,
  evidence_url, data_json, fetched_at_unix_ms, expires_at_unix_ms
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (observable_kind, observable_value, provider)
DO UPDATE SET status=EXCLUDED.status,
  provider_verdict=EXCLUDED.provider_verdict,
  provider_score=EXCLUDED.provider_score,
  summary=EXCLUDED.summary,
  evidence_url=EXCLUDED.evidence_url,
  data_json=EXCLUDED.data_json,
  fetched_at_unix_ms=EXCLUDED.fetched_at_unix_ms,
  expires_at_unix_ms=EXCLUDED.expires_at_unix_ms;
`, string(o.Kind), o.Value, r.Provider, r.Status, r.Verdict, r.Score, r.Summary, r.EvidenceURL, mustJSON(r.Data), r.FetchedAtUnix, r.ExpiresAtUnix)
			}
		}

		_, _ = db.ExecContext(ctx, `
INSERT INTO enrichment_jobs (job_id, run_id, status, requested_by, requested_at_unix_ms, completed_at_unix_ms, refresh, error_text)
VALUES ($1,$2,'completed',$3,EXTRACT(EPOCH FROM now())*1000,EXTRACT(EPOCH FROM now())*1000,$4,'')
ON CONFLICT (job_id)
DO UPDATE SET status='completed', completed_at_unix_ms=EXCLUDED.completed_at_unix_ms, error_text='';
`, payload.JobID, payload.RunID, coalesce(payload.RequestedBy, "system"), payload.Refresh)

		log.Printf("job %s: enriched %d observables (provider results: %d)", payload.JobID, len(objs), totalResults)
	}

	sub, err := nc.QueueSubscribe("rsiem.investigation.enrich.requested", "investigation-enrichers", handler)
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	if cfg.StaleSweepEvery > 0 {
		go func() {
			ticker := time.NewTicker(cfg.StaleSweepEvery)
			defer ticker.Stop()
			for range ticker.C {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				count, err := markStaleJobsTimedOut(cleanupCtx, db, cfg.StaleJobAfter)
				cancel()
				if err != nil {
					log.Printf("stale job cleanup failed: %v", err)
					continue
				}
				if count > 0 {
					log.Printf("stale job cleanup marked %d jobs timed_out", count)
				}
			}
		}()
	}

	log.Printf("investigation-enricher ready (providers: %d enabled=%s)", len(eng.Providers()), strings.Join(providerNames(eng.Providers()), ","))
	select {}
}

type config struct {
	DBDSN            string
	NATSURL          string
	EnabledProviders []string
	StaleJobAfter    time.Duration
	StaleSweepEvery  time.Duration
	JobTimeout       time.Duration
}

func loadConfig() config {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = "postgres://rsiem:rsiem@127.0.0.1:5432/rsiem?sslmode=disable"
	}
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://127.0.0.1:4222"
	}
	return config{
		DBDSN:            dsn,
		NATSURL:          natsURL,
		EnabledProviders: parseEnabledProviders(os.Getenv("INVESTIGATION_ENABLED_PROVIDERS")),
		StaleJobAfter:    envDuration("INVESTIGATION_STALE_JOB_AFTER", 2*time.Minute),
		StaleSweepEvery:  envDuration("INVESTIGATION_STALE_SWEEP_EVERY", 1*time.Minute),
		JobTimeout:       envDuration("INVESTIGATION_JOB_TIMEOUT", 15*time.Second),
	}
}

func newEngine(enabled []string) (*investigation.Engine, error) {
	all := []investigation.Provider{
		providers.NewGreyNoise(),
		providers.NewAbuseIPDB(),
		providers.NewVirusTotal(),
		providers.NewURLScan(),
	}
	selected, err := selectProviders(all, enabled)
	if err != nil {
		return nil, err
	}
	return investigation.NewEngine(selected...), nil
}

func selectProviders(all []investigation.Provider, enabled []string) ([]investigation.Provider, error) {
	if len(enabled) == 0 {
		return all, nil
	}
	index := make(map[string]investigation.Provider, len(all))
	for _, p := range all {
		index[strings.ToLower(strings.TrimSpace(p.Name()))] = p
	}
	selected := make([]investigation.Provider, 0, len(enabled))
	seen := make(map[string]struct{}, len(enabled))
	var unknown []string
	for _, name := range enabled {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		p, ok := index[key]
		if !ok {
			unknown = append(unknown, key)
			continue
		}
		selected = append(selected, p)
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("unknown providers in INVESTIGATION_ENABLED_PROVIDERS: %s", strings.Join(unknown, ","))
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("INVESTIGATION_ENABLED_PROVIDERS resolved to zero providers")
	}
	return selected, nil
}

func parseEnabledProviders(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.EqualFold(raw, "all") {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func providerNames(in []investigation.Provider) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.Name())
	}
	sort.Strings(out)
	return out
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{}`)
	}
	return b
}

func coalesce(v string, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func envDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

func ensureInvestigationSchema(ctx context.Context, db *sql.DB) error {
	const schemaSQL = `
CREATE TABLE IF NOT EXISTS incident_observables (
  id BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL,
  observable_kind TEXT NOT NULL,
  observable_value TEXT NOT NULL,
  observable_role TEXT NOT NULL,
  observable_source TEXT NOT NULL,
  created_at_unix_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS incident_observables_run_idx
  ON incident_observables(run_id);
CREATE INDEX IF NOT EXISTS incident_observables_value_idx
  ON incident_observables(observable_kind, observable_value);

CREATE TABLE IF NOT EXISTS observable_enrichments (
  id BIGSERIAL PRIMARY KEY,
  observable_kind TEXT NOT NULL,
  observable_value TEXT NOT NULL,
  provider TEXT NOT NULL,
  status TEXT NOT NULL,
  provider_verdict TEXT NOT NULL,
  provider_score INT NOT NULL,
  summary TEXT NOT NULL,
  evidence_url TEXT NOT NULL,
  data_json JSONB NOT NULL,
  fetched_at_unix_ms BIGINT NOT NULL,
  expires_at_unix_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS observable_enrichments_lookup_idx
  ON observable_enrichments(observable_kind, observable_value, provider);
CREATE UNIQUE INDEX IF NOT EXISTS observable_enrichments_uq
  ON observable_enrichments(observable_kind, observable_value, provider);

CREATE TABLE IF NOT EXISTS enrichment_jobs (
  job_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  status TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at_unix_ms BIGINT NOT NULL,
  completed_at_unix_ms BIGINT NULL,
  refresh BOOLEAN NOT NULL DEFAULT FALSE,
  error_text TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS enrichment_jobs_run_idx
  ON enrichment_jobs(run_id);
`
	_, err := db.ExecContext(ctx, schemaSQL)
	return err
}

func loadExistingObservables(ctx context.Context, db *sql.DB, runID string) []investigation.Observable {
	rows, err := db.QueryContext(ctx, `
SELECT observable_kind, observable_value, observable_role, observable_source
FROM incident_observables
WHERE run_id=$1
`, runID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var observables []investigation.Observable
	for rows.Next() {
		var k, v, r, s string
		if err := rows.Scan(&k, &v, &r, &s); err == nil {
			observables = append(observables, investigation.Observable{
				Kind:   investigation.ObservableKind(k),
				Value:  v,
				Role:   r,
				Source: s,
			})
		}
	}
	return uniqueObservables(observables)
}

func markStaleJobsTimedOut(ctx context.Context, db *sql.DB, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, nil
	}
	cutoff := time.Now().Add(-olderThan).UnixMilli()
	res, err := db.ExecContext(ctx, `
UPDATE enrichment_jobs
SET status='timed_out',
    completed_at_unix_ms=EXTRACT(EPOCH FROM now())*1000,
    error_text=CASE
      WHEN error_text = '' THEN 'stale job cleanup'
      ELSE error_text
    END
WHERE status IN ('requested','running')
  AND requested_at_unix_ms < $1;
`, cutoff)
	if err != nil {
		return 0, err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return count, nil
}

func uniqueObservables(in []investigation.Observable) []investigation.Observable {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]investigation.Observable, 0, len(in))
	for _, obs := range in {
		key := observableKey(obs)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, obs)
	}
	return out
}

func observableKey(obs investigation.Observable) string {
	return strings.Join([]string{string(obs.Kind), obs.Value, obs.Role, obs.Source}, "|")
}

func logProviderMetric(jobID string, obs investigation.Observable, res investigation.ProviderResult) {
	meta := providerMetricMeta(res.Data)
	log.Printf(
		"job %s: provider=%s observable=%s:%s status=%s verdict=%s latency_ms=%d attempts=%d http_status=%d error_class=%s",
		jobID,
		res.Provider,
		obs.Kind,
		obs.Value,
		res.Status,
		res.Verdict,
		meta.latencyMs,
		meta.attempts,
		meta.httpStatus,
		meta.errorClass,
	)
}

type providerMetric struct {
	attempts   int
	latencyMs  int64
	httpStatus int
	errorClass string
}

func providerMetricMeta(data map[string]any) providerMetric {
	var meta providerMetric
	raw, ok := data["_request"]
	if !ok {
		return meta
	}
	reqMap, ok := raw.(map[string]any)
	if !ok {
		return meta
	}
	meta.attempts = intFromAny(reqMap["attempts"])
	meta.latencyMs = int64FromAny(reqMap["latency_ms"])
	meta.httpStatus = intFromAny(reqMap["http_status"])
	meta.errorClass = stringFromAny(reqMap["error_class"])
	return meta
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

func int64FromAny(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	default:
		return 0
	}
}

func stringFromAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
