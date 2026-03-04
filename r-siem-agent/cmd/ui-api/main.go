package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/nats-io/nats.go"
	"gopkg.in/yaml.v3"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
)

const (
	defaultAPIAddr         = "127.0.0.1:8090"
	defaultRunsPath        = "exports/roe_runs.jsonl"
	defaultStepsPath       = "exports/roe_steps.jsonl"
	defaultMasterLogPath   = "logs/master-roe.log"
	defaultUIAPILogPath    = "logs/ui-api.log"
	defaultArtifactsRoot   = "demo_artifacts"
	defaultRetainedRoot    = "retained"
	defaultAPIKey          = "dev-ui-key"
	defaultApprovalsSubj   = "rsiem.response.approvals"
	defaultNATSURL         = "nats://127.0.0.1:4222"
	defaultMasterConfig    = "configs/master.yaml"
	defaultStepFastSubject = "rsiem.response.steps.fast"
	maxListLimit           = 2000
	maxArtifactListEntries = 1000
)

type masterROEConfig struct {
	ROE struct {
		Jetstream struct {
			URL              string `yaml:"url"`
			SubjectApprovals string `yaml:"subject_approvals"`
		} `yaml:"jetstream"`
	} `yaml:"roe"`
}

type serverConfig struct {
	Addr          string
	MasterConfig  string
	RunsPath      string
	StepsPath     string
	MasterLogPath string
	UIAPILogPath  string
	APIKey        string
	ArtifactsRoot string
	RetainedRoot  string
	DBDSN         string
	NATSURL       string
	ApprovalsSubj string
}

type app struct {
	cfg    serverConfig
	logger *slog.Logger

	db *sql.DB

	nc *nats.Conn
	js nats.JetStreamContext

	mu sync.RWMutex
}

type incident struct {
	RunID                 string `json:"run_id"`
	Status                string `json:"status"`
	RuleID                string `json:"rule_id,omitempty"`
	PlaybookID            string `json:"playbook_id,omitempty"`
	PlaybookVersion       string `json:"playbook_version,omitempty"`
	Severity              string `json:"severity,omitempty"`
	Lane                  string `json:"lane,omitempty"`
	NodeID                string `json:"node_id,omitempty"`
	SourceType            string `json:"source_type,omitempty"`
	EventType             string `json:"event_type,omitempty"`
	SrcIP                 string `json:"src_ip,omitempty"`
	User                  string `json:"user_name,omitempty"`
	Target                string `json:"target,omitempty"`
	TargetAgentID         string `json:"target_agent_id,omitempty"`
	Actor                 string `json:"actor,omitempty"`
	EventIdemKey          string `json:"event_idem_key,omitempty"`
	StepTotal             int    `json:"step_total,omitempty"`
	StepSucceededCount    int    `json:"step_succeeded_count,omitempty"`
	StepFailedSafeCount   int    `json:"step_failed_safe_count,omitempty"`
	StepFailedTransient   int    `json:"step_failed_transient_count,omitempty"`
	FailedSafeReason      string `json:"failed_safe_reason,omitempty"`
	OperatorAction        string `json:"operator_action,omitempty"`
	ApprovalDecision      string `json:"approval_decision,omitempty"`
	ApprovalActor         string `json:"approval_actor,omitempty"`
	ApprovalRequestedAtMs int64  `json:"approval_requested_at_unix_ms,omitempty"`
	ApprovalTimeoutMs     int64  `json:"approval_timeout_ms,omitempty"`
	LastUpdatedAtUnixMs   int64  `json:"last_updated_at_unix_ms,omitempty"`
	Source                string `json:"source"`
}

type stepResult struct {
	RunID         string         `json:"run_id"`
	StepID        string         `json:"step_id"`
	StepIndex     int            `json:"step_index"`
	StepKey       string         `json:"step_key,omitempty"`
	Status        string         `json:"status"`
	ActionType    string         `json:"action_type,omitempty"`
	Lane          string         `json:"lane,omitempty"`
	Actor         string         `json:"actor,omitempty"`
	Attempt       int            `json:"attempt,omitempty"`
	FinishedAtMs  int64          `json:"finished_at_unix_ms,omitempty"`
	Target        string         `json:"target,omitempty"`
	TargetAgentID string         `json:"target_agent_id,omitempty"`
	LastError     string         `json:"last_error,omitempty"`
	Receipt       map[string]any `json:"receipt,omitempty"`
}

type createdMeta struct {
	RuleID          string
	PlaybookID      string
	PlaybookVersion string
	Severity        string
}

type eventRow struct {
	EventTSUnixMs int64  `json:"event_ts_unix_ms"`
	RecvTSUnixMs  int64  `json:"recv_ts_unix_ms"`
	NodeID        string `json:"node_id"`
	SourceType    string `json:"source_type"`
	EventType     string `json:"event_type"`
	SrcIP         string `json:"src_ip,omitempty"`
	UserName      string `json:"user_name,omitempty"`
	Severity      string `json:"severity,omitempty"`
	RuleID        string `json:"rule_id,omitempty"`
	EventIdemKey  string `json:"event_idem_key"`
}

type endpointSummary struct {
	NodeID            string         `json:"node_id"`
	LastSeenUnixMs    int64          `json:"last_seen_unix_ms"`
	EventCount5m      int64          `json:"event_count_5m"`
	EventCount1h      int64          `json:"event_count_1h"`
	SourceTypeDist    map[string]int `json:"source_type_distribution"`
	DerivedFrom       string         `json:"derived_from"`
	SourceTypeSamples []string       `json:"source_types,omitempty"`
}

type auditEntry struct {
	TS       string         `json:"ts"`
	Msg      string         `json:"msg"`
	RunID    string         `json:"run_id,omitempty"`
	Actor    string         `json:"actor,omitempty"`
	Decision string         `json:"decision,omitempty"`
	Status   string         `json:"status,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
	Source   string         `json:"source"`
}

func main() {
	cfg := serverConfig{}
	flag.StringVar(&cfg.Addr, "addr", defaultAPIAddr, "UI API listen address")
	flag.StringVar(&cfg.MasterConfig, "master-config", defaultMasterConfig, "Path to master config")
	flag.StringVar(&cfg.RunsPath, "runs-path", defaultRunsPath, "Path to roe runs JSONL")
	flag.StringVar(&cfg.StepsPath, "steps-path", defaultStepsPath, "Path to roe steps JSONL")
	flag.StringVar(&cfg.MasterLogPath, "master-log-path", defaultMasterLogPath, "Path to master log JSONL")
	flag.StringVar(&cfg.UIAPILogPath, "ui-api-log-path", defaultUIAPILogPath, "Path to ui api log")
	flag.StringVar(&cfg.ArtifactsRoot, "artifacts-root", defaultArtifactsRoot, "Allowed artifacts root")
	flag.StringVar(&cfg.RetainedRoot, "retained-root", defaultRetainedRoot, "Allowed retained root")
	flag.Parse()

	cfg.APIKey = strings.TrimSpace(os.Getenv("UI_API_KEY"))
	if cfg.APIKey == "" {
		cfg.APIKey = defaultAPIKey
	}

	masterCfg, err := config.LoadMaster(cfg.MasterConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load master config: %v\n", err)
		os.Exit(1)
	}
	cfg.DBDSN = strings.TrimSpace(os.Getenv("UI_DB_DSN"))
	if cfg.DBDSN == "" {
		cfg.DBDSN = strings.TrimSpace(masterCfg.DB.DSN)
	}
	cfg.NATSURL = strings.TrimSpace(os.Getenv("UI_NATS_URL"))
	if cfg.NATSURL == "" {
		cfg.NATSURL = strings.TrimSpace(masterCfg.JetStream.URL)
	}
	if cfg.NATSURL == "" {
		cfg.NATSURL = defaultNATSURL
	}

	approvalsSubj, roeNATSURL := loadROESettings(cfg.MasterConfig)
	if approvalsSubj == "" {
		approvalsSubj = defaultApprovalsSubj
	}
	cfg.ApprovalsSubj = approvalsSubj
	if strings.TrimSpace(os.Getenv("UI_NATS_URL")) == "" && roeNATSURL != "" {
		cfg.NATSURL = roeNATSURL
	}

	logger, err := logging.NewLogger("INFO")
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}

	a := &app{cfg: cfg, logger: logger}

	if cfg.DBDSN != "" {
		db, dErr := sql.Open("postgres", cfg.DBDSN)
		if dErr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			pErr := db.PingContext(ctx)
			cancel()
			if pErr == nil {
				a.db = db
				logger.Info("ui_api_db_connected", slog.String("dsn", cfg.DBDSN))
			} else {
				logger.Warn("ui_api_db_unavailable", slog.String("error", pErr.Error()))
				_ = db.Close()
			}
		} else {
			logger.Warn("ui_api_db_open_failed", slog.String("error", dErr.Error()))
		}
	}

	nc, nErr := nats.Connect(cfg.NATSURL, nats.Name("r-siem-ui-api"))
	if nErr == nil {
		js, jErr := nc.JetStream()
		if jErr == nil {
			a.nc = nc
			a.js = js
			logger.Info("ui_api_nats_connected", slog.String("url", cfg.NATSURL), slog.String("approvals_subject", cfg.ApprovalsSubj))
		} else {
			logger.Warn("ui_api_jetstream_unavailable", slog.String("error", jErr.Error()))
			nc.Close()
		}
	} else {
		logger.Warn("ui_api_nats_unavailable", slog.String("error", nErr.Error()))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", a.handleHealth)
	mux.HandleFunc("GET /api/meta", a.withAPIKey(a.handleMeta))
	mux.HandleFunc("GET /api/incidents", a.withAPIKey(a.handleIncidents))
	mux.HandleFunc("GET /api/incidents/{run_id}", a.withAPIKey(a.handleIncidentDetail))
	mux.HandleFunc("POST /api/incidents/{run_id}/approve", a.withAPIKey(a.handleIncidentApprove))
	mux.HandleFunc("GET /api/incidents/{run_id}/events", a.withAPIKey(a.handleIncidentEvents))
	mux.HandleFunc("GET /api/search", a.withAPIKey(a.handleSearch))
	mux.HandleFunc("GET /api/stream", a.withAPIKey(a.handleStream))
	mux.HandleFunc("GET /api/endpoints", a.withAPIKey(a.handleEndpoints))
	mux.HandleFunc("GET /api/endpoints/{node_id}/events", a.withAPIKey(a.handleEndpointEvents))
	mux.HandleFunc("GET /api/endpoints/{node_id}/runs", a.withAPIKey(a.handleEndpointRuns))
	mux.HandleFunc("POST /api/endpoints/{node_id}/targeted-test", a.withAPIKey(a.handleEndpointTargetedTest))
	mux.HandleFunc("GET /api/audit", a.withAPIKey(a.handleAudit))
	mux.HandleFunc("GET /api/artifacts", a.withAPIKey(a.handleArtifacts))
	mux.HandleFunc("GET /api/artifact", a.withAPIKey(a.handleArtifactDownload))

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           a.cors(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	logger.Info("ui_api_started", slog.String("addr", cfg.Addr))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("ui_api_stopped", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func loadROESettings(path string) (approvalsSubject string, natsURL string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	var cfg masterROEConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", ""
	}
	return strings.TrimSpace(cfg.ROE.Jetstream.SubjectApprovals), strings.TrimSpace(cfg.ROE.Jetstream.URL)
}

func (a *app) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) withAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.APIKey == "" {
			next(w, r)
			return
		}
		apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if apiKey == "" {
			auth := strings.TrimSpace(r.Header.Get("Authorization"))
			if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
				apiKey = strings.TrimSpace(auth[7:])
			}
		}
		if apiKey == "" {
			apiKey = strings.TrimSpace(r.URL.Query().Get("api_key"))
		}
		if apiKey != a.cfg.APIKey {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (a *app) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"ts":      time.Now().UTC().Format(time.RFC3339),
		"version": "fr06-ui-api-v1",
	})
}

func (a *app) handleMeta(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "ui-api",
		"routes": []map[string]any{
			{"method": "GET", "path": "/api/health", "summary": "Service health"},
			{"method": "GET", "path": "/api/meta", "summary": "Route + schema summary"},
			{"method": "GET", "path": "/api/incidents", "summary": "List incidents", "query": []string{"status", "severity", "lane", "playbook_id", "rule_id", "node_id", "from", "to", "q", "limit", "page", "sort"}},
			{"method": "GET", "path": "/api/incidents/{run_id}", "summary": "Incident detail"},
			{"method": "POST", "path": "/api/incidents/{run_id}/approve", "summary": "Approve/reject FAST action", "body": map[string]string{"decision": "approve|reject|deny", "actor": "string"}},
			{"method": "GET", "path": "/api/incidents/{run_id}/events", "summary": "Timeline events around incident", "query": []string{"window_seconds"}},
			{"method": "GET", "path": "/api/search", "summary": "Global search across incidents and events", "query": []string{"q", "from", "to", "limit"}},
			{"method": "GET", "path": "/api/stream", "summary": "SSE refresh hints and approval queue counts"},
			{"method": "GET", "path": "/api/endpoints", "summary": "Endpoint summaries"},
			{"method": "GET", "path": "/api/endpoints/{node_id}/events", "summary": "Recent endpoint events", "query": []string{"from", "to", "limit"}},
			{"method": "GET", "path": "/api/endpoints/{node_id}/runs", "summary": "Recent runs affecting endpoint", "query": []string{"limit"}},
			{"method": "POST", "path": "/api/endpoints/{node_id}/targeted-test", "summary": "Publish harmless targeted step", "body": map[string]string{"actor": "string", "target_agent_id": "string (optional)"}},
			{"method": "GET", "path": "/api/audit", "summary": "Approvals and key actions audit"},
			{"method": "GET", "path": "/api/artifacts", "summary": "List artifacts", "query": []string{"prefix"}},
			{"method": "GET", "path": "/api/artifact", "summary": "Download artifact", "query": []string{"path"}},
		},
		"schemas": map[string]any{
			"incident":  incident{},
			"step":      stepResult{},
			"event_row": eventRow{},
		},
	})
}

func (a *app) handleIncidents(w http.ResponseWriter, r *http.Request) {
	runs, stepsByRun, created := a.loadState()
	if len(runs) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"items": []incident{}, "count": 0})
		return
	}

	statusFilter := strings.TrimSpace(strings.ToUpper(r.URL.Query().Get("status")))
	sevFilter := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("severity")))
	laneFilter := strings.TrimSpace(strings.ToUpper(r.URL.Query().Get("lane")))
	playbookFilter := strings.TrimSpace(r.URL.Query().Get("playbook_id"))
	ruleFilter := strings.TrimSpace(r.URL.Query().Get("rule_id"))
	nodeFilter := strings.TrimSpace(r.URL.Query().Get("node_id"))
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))
	fromMs := parseInt64(r.URL.Query().Get("from"), 0)
	toMs := parseInt64(r.URL.Query().Get("to"), 0)
	limit := int(parseInt64(r.URL.Query().Get("limit"), 200))
	page := int(parseInt64(r.URL.Query().Get("page"), 1))
	sortBy := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("sort")))
	if sortBy == "" {
		sortBy = "updated_desc"
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}
	if page <= 0 {
		page = 1
	}

	items := make([]incident, 0, len(runs))
	for _, run := range runs {
		if meta, ok := created[run.RunID]; ok {
			if run.RuleID == "" {
				run.RuleID = meta.RuleID
			}
			if run.PlaybookID == "" {
				run.PlaybookID = meta.PlaybookID
			}
			if run.PlaybookVersion == "" {
				run.PlaybookVersion = meta.PlaybookVersion
			}
			if run.Severity == "" {
				run.Severity = meta.Severity
			}
		}
		if steps := stepsByRun[run.RunID]; len(steps) > 0 {
			if run.Lane == "" {
				run.Lane = strings.ToUpper(steps[0].Lane)
			}
			if run.TargetAgentID == "" {
				for _, st := range steps {
					if st.TargetAgentID != "" {
						run.TargetAgentID = st.TargetAgentID
						break
					}
				}
			}
		}
		if statusFilter != "" && strings.ToUpper(run.Status) != statusFilter {
			continue
		}
		if sevFilter != "" && strings.ToLower(run.Severity) != sevFilter {
			continue
		}
		if laneFilter != "" && strings.ToUpper(run.Lane) != laneFilter {
			continue
		}
		if playbookFilter != "" && run.PlaybookID != playbookFilter {
			continue
		}
		if ruleFilter != "" && run.RuleID != ruleFilter {
			continue
		}
		if nodeFilter != "" && run.NodeID != nodeFilter {
			continue
		}
		if fromMs > 0 && run.LastUpdatedAtUnixMs < fromMs {
			continue
		}
		if toMs > 0 && run.LastUpdatedAtUnixMs > toMs {
			continue
		}
		if q != "" {
			hay := strings.ToLower(strings.Join([]string{run.RunID, run.RuleID, run.PlaybookID, run.NodeID, run.SourceType, run.EventType, run.SrcIP, run.User}, "|"))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		items = append(items, run)
	}

	sort.SliceStable(items, func(i, j int) bool {
		switch sortBy {
		case "updated_asc":
			if items[i].LastUpdatedAtUnixMs == items[j].LastUpdatedAtUnixMs {
				return items[i].RunID < items[j].RunID
			}
			return items[i].LastUpdatedAtUnixMs < items[j].LastUpdatedAtUnixMs
		case "severity_desc":
			if strings.ToLower(items[i].Severity) == strings.ToLower(items[j].Severity) {
				return items[i].RunID < items[j].RunID
			}
			return severityRank(items[i].Severity) > severityRank(items[j].Severity)
		case "status_asc":
			if strings.ToUpper(items[i].Status) == strings.ToUpper(items[j].Status) {
				return items[i].RunID < items[j].RunID
			}
			return strings.ToUpper(items[i].Status) < strings.ToUpper(items[j].Status)
		default:
			if items[i].LastUpdatedAtUnixMs == items[j].LastUpdatedAtUnixMs {
				return items[i].RunID < items[j].RunID
			}
			return items[i].LastUpdatedAtUnixMs > items[j].LastUpdatedAtUnixMs
		}
	})
	total := len(items)
	offset := (page - 1) * limit
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items[offset:end],
		"count":  len(items[offset:end]),
		"total":  total,
		"page":   page,
		"limit":  limit,
		"sort":   sortBy,
		"source": "exports",
	})
}

func (a *app) handleIncidentDetail(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}

	runs, stepsByRun, created := a.loadState()
	var found *incident
	for i := range runs {
		if runs[i].RunID == runID {
			r := runs[i]
			if meta, ok := created[r.RunID]; ok {
				if r.RuleID == "" {
					r.RuleID = meta.RuleID
				}
				if r.PlaybookID == "" {
					r.PlaybookID = meta.PlaybookID
				}
				if r.PlaybookVersion == "" {
					r.PlaybookVersion = meta.PlaybookVersion
				}
				if r.Severity == "" {
					r.Severity = meta.Severity
				}
			}
			if steps := stepsByRun[r.RunID]; len(steps) > 0 && r.Lane == "" {
				r.Lane = strings.ToUpper(steps[0].Lane)
			}
			found = &r
			break
		}
	}
	if found == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "run not found"})
		return
	}
	steps := stepsByRun[runID]
	if found.TargetAgentID == "" {
		for _, st := range steps {
			if st.TargetAgentID != "" {
				found.TargetAgentID = st.TargetAgentID
				break
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"run":    found,
		"steps":  steps,
		"source": "exports",
	})
}

func (a *app) handleIncidentApprove(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}
	if a.js == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "nats unavailable"})
		return
	}
	var body struct {
		Decision string `json:"decision"`
		Actor    string `json:"actor"`
		Reason   string `json:"reason"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	decision := strings.ToLower(strings.TrimSpace(body.Decision))
	switch decision {
	case "approve":
		decision = "approve"
	case "reject", "deny":
		decision = "deny"
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "decision must be approve or reject"})
		return
	}
	actor := strings.TrimSpace(body.Actor)
	if actor == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "actor is required"})
		return
	}

	payload := map[string]any{
		"run_id":     runID,
		"decision":   decision,
		"actor":      actor,
		"reason":     strings.TrimSpace(body.Reason),
		"ts_unix_ms": time.Now().UnixMilli(),
	}
	data, _ := json.Marshal(payload)
	if _, err := a.js.Publish(a.cfg.ApprovalsSubj, data); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	a.logger.Info("ui_approval_published",
		slog.String("run_id", runID),
		slog.String("decision", decision),
		slog.String("actor", actor),
		slog.String("subject", a.cfg.ApprovalsSubj),
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"run_id":   runID,
		"decision": decision,
		"actor":    actor,
		"subject":  a.cfg.ApprovalsSubj,
		"ts":       time.Now().UTC().Format(time.RFC3339),
	})
}

func (a *app) handleIncidentEvents(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}
	windowSec := parseInt64(r.URL.Query().Get("window_seconds"), 300)
	if windowSec <= 0 {
		windowSec = 300
	}
	limit := int(parseInt64(r.URL.Query().Get("limit"), 500))
	if limit <= 0 {
		limit = 500
	}
	if limit > 2000 {
		limit = 2000
	}
	pivotNode := strings.TrimSpace(r.URL.Query().Get("node_id"))
	pivotSrcIP := strings.TrimSpace(r.URL.Query().Get("src_ip"))
	pivotUser := strings.TrimSpace(r.URL.Query().Get("user_name"))

	runs, _, _ := a.loadState()
	var run *incident
	for i := range runs {
		if runs[i].RunID == runID {
			r := runs[i]
			run = &r
			break
		}
	}
	if run == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "run not found"})
		return
	}
	if a.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []eventRow{}, "count": 0, "source": "exports"})
		return
	}

	center := run.LastUpdatedAtUnixMs
	if center <= 0 {
		center = time.Now().UnixMilli()
	}
	fromMs := parseInt64(r.URL.Query().Get("from"), center-(windowSec*1000))
	toMs := parseInt64(r.URL.Query().Get("to"), center+(windowSec*1000))
	if fromMs > toMs {
		fromMs, toMs = toMs, fromMs
	}

	clauses := []string{"recv_ts_unix_ms BETWEEN $1 AND $2"}
	args := []any{fromMs, toMs}
	idx := 3
	nodeMatch := chooseNonEmpty(pivotNode, run.NodeID)
	if nodeMatch != "" {
		clauses = append(clauses, fmt.Sprintf("node_id = $%d", idx))
		args = append(args, nodeMatch)
		idx++
	}
	userMatch := chooseNonEmpty(pivotUser, run.User)
	if userMatch != "" {
		clauses = append(clauses, fmt.Sprintf("COALESCE(user_name,'') = $%d", idx))
		args = append(args, userMatch)
		idx++
	}
	srcIPMatch := chooseNonEmpty(pivotSrcIP, run.SrcIP)
	if srcIPMatch != "" {
		clauses = append(clauses, fmt.Sprintf("COALESCE(src_ip::text,'') = $%d", idx))
		args = append(args, srcIPMatch)
		idx++
	}
	if run.SourceType != "" {
		clauses = append(clauses, fmt.Sprintf("source_type = $%d", idx))
		args = append(args, run.SourceType)
		idx++
	}
	if run.EventType != "" {
		clauses = append(clauses, fmt.Sprintf("event_type = $%d", idx))
		args = append(args, run.EventType)
		idx++
	}
	query := "SELECT event_ts_unix_ms, recv_ts_unix_ms, node_id, source_type, event_type, COALESCE(src_ip::text,''), COALESCE(user_name,''), COALESCE(severity,''), COALESCE(rule_id,''), event_idem_key FROM normalized_events WHERE " + strings.Join(clauses, " AND ") + fmt.Sprintf(" ORDER BY recv_ts_unix_ms DESC LIMIT %d", limit)
	rows, err := a.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()

	items := make([]eventRow, 0, 128)
	for rows.Next() {
		var ev eventRow
		if err := rows.Scan(&ev.EventTSUnixMs, &ev.RecvTSUnixMs, &ev.NodeID, &ev.SourceType, &ev.EventType, &ev.SrcIP, &ev.UserName, &ev.Severity, &ev.RuleID, &ev.EventIdemKey); err == nil {
			items = append(items, ev)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items), "source": "db"})
}

func (a *app) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))
	if q == "" {
		writeJSON(w, http.StatusOK, map[string]any{"q": "", "incidents": []incident{}, "events": []eventRow{}, "count_incidents": 0, "count_events": 0})
		return
	}
	limit := int(parseInt64(r.URL.Query().Get("limit"), 50))
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	fromMs := parseInt64(r.URL.Query().Get("from"), 0)
	toMs := parseInt64(r.URL.Query().Get("to"), 0)

	runs, _, _ := a.loadState()
	incidents := make([]incident, 0, limit)
	for _, run := range runs {
		hay := strings.ToLower(strings.Join([]string{run.RunID, run.RuleID, run.PlaybookID, run.NodeID, run.SourceType, run.EventType, run.SrcIP, run.User}, "|"))
		if !strings.Contains(hay, q) {
			continue
		}
		if fromMs > 0 && run.LastUpdatedAtUnixMs < fromMs {
			continue
		}
		if toMs > 0 && run.LastUpdatedAtUnixMs > toMs {
			continue
		}
		incidents = append(incidents, run)
	}
	sort.SliceStable(incidents, func(i, j int) bool {
		if incidents[i].LastUpdatedAtUnixMs == incidents[j].LastUpdatedAtUnixMs {
			return incidents[i].RunID < incidents[j].RunID
		}
		return incidents[i].LastUpdatedAtUnixMs > incidents[j].LastUpdatedAtUnixMs
	})
	if len(incidents) > limit {
		incidents = incidents[:limit]
	}

	events := make([]eventRow, 0, limit)
	if a.db != nil {
		if fromMs <= 0 {
			fromMs = time.Now().Add(-24 * time.Hour).UnixMilli()
		}
		if toMs <= 0 {
			toMs = time.Now().UnixMilli()
		}
		like := "%" + q + "%"
		rows, err := a.db.QueryContext(r.Context(), `
SELECT event_ts_unix_ms, recv_ts_unix_ms, node_id, source_type, event_type, COALESCE(src_ip::text,''), COALESCE(user_name,''), COALESCE(severity,''), COALESCE(rule_id,''), event_idem_key
FROM normalized_events
WHERE recv_ts_unix_ms BETWEEN $1 AND $2
  AND (
    LOWER(COALESCE(user_name,'')) LIKE $3
    OR LOWER(COALESCE(src_ip::text,'')) LIKE $3
    OR LOWER(COALESCE(node_id,'')) LIKE $3
    OR LOWER(COALESCE(rule_id,'')) LIKE $3
    OR LOWER(COALESCE(source_type,'')) LIKE $3
    OR LOWER(COALESCE(event_type,'')) LIKE $3
    OR LOWER(COALESCE(event_idem_key,'')) LIKE $3
  )
ORDER BY recv_ts_unix_ms DESC
LIMIT $4
`, fromMs, toMs, like, limit)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var ev eventRow
				if err := rows.Scan(&ev.EventTSUnixMs, &ev.RecvTSUnixMs, &ev.NodeID, &ev.SourceType, &ev.EventType, &ev.SrcIP, &ev.UserName, &ev.Severity, &ev.RuleID, &ev.EventIdemKey); err == nil {
					events = append(events, ev)
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"q":               q,
		"incidents":       incidents,
		"events":          events,
		"count_incidents": len(incidents),
		"count_events":    len(events),
	})
}

func (a *app) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	send := func() bool {
		runs, _, _ := a.loadState()
		waiting := 0
		for _, run := range runs {
			if strings.ToUpper(strings.TrimSpace(run.Status)) == "WAITING_APPROVAL" {
				waiting++
			}
		}
		payload := map[string]any{
			"type":              "refresh_hint",
			"ts":                time.Now().UTC().Format(time.RFC3339),
			"incidents_total":   len(runs),
			"waiting_approvals": waiting,
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: hint\ndata: %s\n\n", string(data)); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if !send() {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !send() {
				return
			}
		}
	}
}

func (a *app) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		// fallback from run exports
		runs, _, _ := a.loadState()
		byNode := map[string]*endpointSummary{}
		for _, run := range runs {
			node := run.NodeID
			if node == "" {
				continue
			}
			ep := byNode[node]
			if ep == nil {
				ep = &endpointSummary{NodeID: node, SourceTypeDist: map[string]int{}, DerivedFrom: "exports"}
				byNode[node] = ep
			}
			if run.LastUpdatedAtUnixMs > ep.LastSeenUnixMs {
				ep.LastSeenUnixMs = run.LastUpdatedAtUnixMs
			}
			ep.EventCount1h++
			ep.EventCount5m++
			if run.SourceType != "" {
				ep.SourceTypeDist[run.SourceType]++
			}
		}
		items := make([]endpointSummary, 0, len(byNode))
		for _, ep := range byNode {
			for st := range ep.SourceTypeDist {
				ep.SourceTypeSamples = append(ep.SourceTypeSamples, st)
			}
			items = append(items, *ep)
		}
		sort.SliceStable(items, func(i, j int) bool { return items[i].LastSeenUnixMs > items[j].LastSeenUnixMs })
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items), "source": "exports"})
		return
	}

	nowMs := time.Now().UnixMilli()
	fiveMin := nowMs - 5*60*1000
	oneHour := nowMs - 60*60*1000

	query := `
SELECT node_id,
       MAX(recv_ts_unix_ms) AS last_seen,
       SUM(CASE WHEN recv_ts_unix_ms >= $1 THEN 1 ELSE 0 END) AS count_5m,
       SUM(CASE WHEN recv_ts_unix_ms >= $2 THEN 1 ELSE 0 END) AS count_1h
FROM normalized_events
GROUP BY node_id
ORDER BY last_seen DESC
LIMIT 500`
	rows, err := a.db.QueryContext(r.Context(), query, fiveMin, oneHour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()

	items := make([]endpointSummary, 0, 128)
	idx := map[string]int{}
	for rows.Next() {
		var node string
		var lastSeen, c5, c1 sql.NullInt64
		if err := rows.Scan(&node, &lastSeen, &c5, &c1); err != nil {
			continue
		}
		ep := endpointSummary{NodeID: node, LastSeenUnixMs: lastSeen.Int64, EventCount5m: c5.Int64, EventCount1h: c1.Int64, SourceTypeDist: map[string]int{}, DerivedFrom: "db"}
		idx[node] = len(items)
		items = append(items, ep)
	}

	dRows, err := a.db.QueryContext(r.Context(), `SELECT node_id, source_type, COUNT(*) FROM normalized_events WHERE recv_ts_unix_ms >= $1 GROUP BY node_id, source_type`, oneHour)
	if err == nil {
		defer dRows.Close()
		for dRows.Next() {
			var node, st string
			var c int
			if err := dRows.Scan(&node, &st, &c); err == nil {
				if i, ok := idx[node]; ok {
					items[i].SourceTypeDist[st] = c
				}
			}
		}
	}
	for i := range items {
		for st := range items[i].SourceTypeDist {
			items[i].SourceTypeSamples = append(items[i].SourceTypeSamples, st)
		}
		sort.Strings(items[i].SourceTypeSamples)
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items), "source": "db"})
}

func (a *app) handleEndpointEvents(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("node_id"))
	if nodeID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing node_id"})
		return
	}
	limit := int(parseInt64(r.URL.Query().Get("limit"), 200))
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	fromMs := parseInt64(r.URL.Query().Get("from"), time.Now().Add(-1*time.Hour).UnixMilli())
	toMs := parseInt64(r.URL.Query().Get("to"), time.Now().UnixMilli())
	if fromMs > toMs {
		fromMs, toMs = toMs, fromMs
	}
	if a.db == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []eventRow{}, "count": 0, "source": "exports"})
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `
SELECT event_ts_unix_ms, recv_ts_unix_ms, node_id, source_type, event_type, COALESCE(src_ip::text,''), COALESCE(user_name,''), COALESCE(severity,''), COALESCE(rule_id,''), event_idem_key
FROM normalized_events
WHERE node_id = $1 AND recv_ts_unix_ms BETWEEN $2 AND $3
ORDER BY recv_ts_unix_ms DESC
LIMIT $4
`, nodeID, fromMs, toMs, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()
	items := make([]eventRow, 0, limit)
	for rows.Next() {
		var ev eventRow
		if err := rows.Scan(&ev.EventTSUnixMs, &ev.RecvTSUnixMs, &ev.NodeID, &ev.SourceType, &ev.EventType, &ev.SrcIP, &ev.UserName, &ev.Severity, &ev.RuleID, &ev.EventIdemKey); err == nil {
			items = append(items, ev)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items), "source": "db"})
}

func (a *app) handleEndpointRuns(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("node_id"))
	if nodeID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing node_id"})
		return
	}
	limit := int(parseInt64(r.URL.Query().Get("limit"), 100))
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	runs, _, _ := a.loadState()
	items := make([]incident, 0, limit)
	for _, run := range runs {
		if strings.TrimSpace(run.NodeID) != nodeID {
			continue
		}
		items = append(items, run)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].LastUpdatedAtUnixMs == items[j].LastUpdatedAtUnixMs {
			return items[i].RunID < items[j].RunID
		}
		return items[i].LastUpdatedAtUnixMs > items[j].LastUpdatedAtUnixMs
	})
	if len(items) > limit {
		items = items[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items), "source": "exports"})
}

func (a *app) handleEndpointTargetedTest(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("node_id"))
	if nodeID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing node_id"})
		return
	}
	if a.js == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "nats unavailable"})
		return
	}
	var body struct {
		Actor         string `json:"actor"`
		TargetAgentID string `json:"target_agent_id"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	actor := strings.TrimSpace(body.Actor)
	if actor == "" {
		actor = "ui"
	}
	targetAgentID := strings.TrimSpace(body.TargetAgentID)
	if targetAgentID == "" {
		targetAgentID = nodeID
	}
	now := time.Now().UnixMilli()
	runID := fmt.Sprintf("ui_target_%d", now)
	stepID := fmt.Sprintf("%016x", now)
	payload := map[string]any{
		"run_id":         runID,
		"step_id":        stepID,
		"step_index":     0,
		"action_type":    "agent_command",
		"lane":           "FAST",
		"step_idem_key":   fmt.Sprintf("step.%s.%s", runID, stepID),
		"attempt":         0,
		"target":          nodeID,
		"target_agent_id": targetAgentID,
		"actor":           actor,
		"planned_at_unix_ms": now,
		"emitted_at_unix_ms": now,
		"params": map[string]any{
			"command":     "ping",
			"marker_file": fmt.Sprintf("ui_targeted_test_%d.txt", now),
		},
	}
	data, _ := json.Marshal(payload)
	if _, err := a.js.Publish(defaultStepFastSubject, data); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	a.logger.Info("ui_targeted_test_published",
		slog.String("run_id", runID),
		slog.String("step_id", stepID),
		slog.String("node_id", nodeID),
		slog.String("target_agent_id", targetAgentID),
		slog.String("actor", actor),
		slog.String("subject", defaultStepFastSubject),
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"run_id":          runID,
		"step_id":         stepID,
		"node_id":         nodeID,
		"target_agent_id": targetAgentID,
		"subject":         defaultStepFastSubject,
		"ts":              time.Now().UTC().Format(time.RFC3339),
	})
}

func (a *app) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries := make([]auditEntry, 0, 512)
	entries = append(entries, parseAuditLog(a.cfg.MasterLogPath, "master")...)
	entries = append(entries, parseAuditLog(a.cfg.UIAPILogPath, "ui-api")...)
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))
	fromMs := parseInt64(r.URL.Query().Get("from"), 0)
	toMs := parseInt64(r.URL.Query().Get("to"), 0)
	filtered := make([]auditEntry, 0, len(entries))
	for _, entry := range entries {
		if fromMs > 0 || toMs > 0 {
			tsMs := parseInt64(entry.TS, 0)
			if tsMs == 0 {
				if parsed, err := time.Parse(time.RFC3339Nano, entry.TS); err == nil {
					tsMs = parsed.UnixMilli()
				}
			}
			if fromMs > 0 && tsMs > 0 && tsMs < fromMs {
				continue
			}
			if toMs > 0 && tsMs > 0 && tsMs > toMs {
				continue
			}
		}
		if q != "" {
			hay := strings.ToLower(strings.Join([]string{entry.Msg, entry.RunID, entry.Actor, entry.Decision, entry.Status, entry.Source}, "|"))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		filtered = append(filtered, entry)
	}
	entries = filtered
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].TS > entries[j].TS
	})
	if len(entries) > 500 {
		entries = entries[:500]
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries, "count": len(entries)})
}

func (a *app) handleArtifacts(w http.ResponseWriter, r *http.Request) {
	prefix := strings.TrimSpace(r.URL.Query().Get("prefix"))
	if prefix == "" {
		prefix = a.cfg.ArtifactsRoot
	}
	path, err := a.safePath(prefix)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "prefix not found"})
		return
	}
	if !st.IsDir() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "prefix is not a directory"})
		return
	}
	entries := make([]map[string]any, 0, 128)
	count := 0
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if p == path {
			return nil
		}
		if count >= maxArtifactListEntries {
			return io.EOF
		}
		rel, _ := filepath.Rel(".", p)
		info, _ := d.Info()
		entries = append(entries, map[string]any{
			"path":     filepath.ToSlash(rel),
			"is_dir":   d.IsDir(),
			"size":     info.Size(),
			"modified": info.ModTime().UTC().Format(time.RFC3339),
		})
		count++
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries, "count": len(entries), "source": "filesystem"})
}

func (a *app) handleArtifactDownload(w http.ResponseWriter, r *http.Request) {
	pathParam := strings.TrimSpace(r.URL.Query().Get("path"))
	if pathParam == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "path is required"})
		return
	}
	absPath, err := a.safePath(pathParam)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	st, err := os.Stat(absPath)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "file not found"})
		return
	}
	if st.IsDir() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "path is a directory"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(absPath)))
	http.ServeFile(w, r, absPath)
}

func (a *app) safePath(rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return "", fmt.Errorf("empty path")
	}
	if strings.Contains(rel, "\x00") {
		return "", fmt.Errorf("invalid path")
	}
	rel = filepath.Clean(rel)
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path traversal denied")
	}
	allowed := []string{filepath.Clean(a.cfg.ArtifactsRoot), filepath.Clean(a.cfg.RetainedRoot)}
	ok := false
	for _, root := range allowed {
		if rel == root || strings.HasPrefix(rel, root+string(os.PathSeparator)) {
			ok = true
			break
		}
	}
	if !ok {
		return "", fmt.Errorf("path not in allowed roots")
	}
	abs, err := filepath.Abs(rel)
	if err != nil {
		return "", err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(abs, filepath.Clean(cwd)+string(os.PathSeparator)) && abs != filepath.Clean(cwd) {
		return "", fmt.Errorf("path outside workspace")
	}
	return abs, nil
}

func (a *app) loadState() ([]incident, map[string][]stepResult, map[string]createdMeta) {
	runsByID := map[string]incident{}
	_ = scanJSONLines(a.cfg.RunsPath, func(obj map[string]any) {
		runID := strVal(obj["run_id"])
		if runID == "" {
			return
		}
		r := runsByID[runID]
		r.RunID = runID
		r.Status = chooseNonEmpty(strVal(obj["status"]), r.Status)
		r.RuleID = chooseNonEmpty(strVal(obj["rule_id"]), r.RuleID)
		r.PlaybookID = chooseNonEmpty(strVal(obj["playbook_id"]), r.PlaybookID)
		r.PlaybookVersion = chooseNonEmpty(strVal(obj["playbook_version"]), r.PlaybookVersion)
		r.Severity = chooseNonEmpty(strVal(obj["severity"]), r.Severity)
		r.Lane = chooseNonEmpty(strings.ToUpper(strVal(obj["lane"])), r.Lane)
		r.NodeID = chooseNonEmpty(strVal(obj["node_id"]), r.NodeID)
		r.SourceType = chooseNonEmpty(strVal(obj["source_type"]), r.SourceType)
		r.EventType = chooseNonEmpty(strVal(obj["event_type"]), r.EventType)
		r.SrcIP = chooseNonEmpty(strVal(obj["src_ip"]), r.SrcIP)
		r.User = chooseNonEmpty(strVal(obj["user_name"]), r.User)
		r.User = chooseNonEmpty(strVal(obj["user"]), r.User)
		r.Actor = chooseNonEmpty(strVal(obj["actor"]), r.Actor)
		r.Target = chooseNonEmpty(strVal(obj["target"]), r.Target)
		r.TargetAgentID = chooseNonEmpty(strVal(obj["target_agent_id"]), r.TargetAgentID)
		r.EventIdemKey = chooseNonEmpty(strVal(obj["event_idem_key"]), r.EventIdemKey)
		r.FailedSafeReason = chooseNonEmpty(strVal(obj["failed_safe_reason"]), r.FailedSafeReason)
		r.OperatorAction = chooseNonEmpty(strVal(obj["operator_action"]), r.OperatorAction)
		r.ApprovalDecision = chooseNonEmpty(strVal(obj["approval_decision"]), r.ApprovalDecision)
		r.ApprovalActor = chooseNonEmpty(strVal(obj["approval_actor"]), r.ApprovalActor)
		r.StepTotal = intVal(obj["step_total"], r.StepTotal)
		r.StepSucceededCount = intVal(obj["step_succeeded_count"], r.StepSucceededCount)
		r.StepFailedSafeCount = intVal(obj["step_failed_safe_count"], r.StepFailedSafeCount)
		r.StepFailedTransient = intVal(obj["step_failed_transient_count"], r.StepFailedTransient)
		r.LastUpdatedAtUnixMs = int64Val(obj["last_updated_at_unix_ms"], r.LastUpdatedAtUnixMs)
		r.ApprovalRequestedAtMs = int64Val(obj["approval_requested_at_unix_ms"], r.ApprovalRequestedAtMs)
		r.ApprovalTimeoutMs = int64Val(obj["approval_timeout_ms"], r.ApprovalTimeoutMs)
		r.Source = "exports"
		runsByID[runID] = r
	})

	stepsByRun := map[string][]stepResult{}
	_ = scanJSONLines(a.cfg.StepsPath, func(obj map[string]any) {
		runID := strVal(obj["run_id"])
		if runID == "" {
			return
		}
		st := stepResult{
			RunID:         runID,
			StepID:        strVal(obj["step_id"]),
			StepIndex:     intVal(obj["step_index"], 0),
			StepKey:       strVal(obj["step_key"]),
			Status:        strVal(obj["status"]),
			ActionType:    strVal(obj["action_type"]),
			Lane:          strVal(obj["lane"]),
			Actor:         strVal(obj["actor"]),
			Attempt:       intVal(obj["attempt"], 0),
			FinishedAtMs:  int64Val(obj["finished_at_unix_ms"], 0),
			Target:        strVal(obj["target"]),
			TargetAgentID: strVal(obj["target_agent_id"]),
			LastError:     strVal(obj["last_error"]),
			Receipt:       mapVal(obj["receipt"]),
		}
		stepsByRun[runID] = append(stepsByRun[runID], st)
	})
	for runID := range stepsByRun {
		sort.SliceStable(stepsByRun[runID], func(i, j int) bool {
			if stepsByRun[runID][i].StepIndex == stepsByRun[runID][j].StepIndex {
				return stepsByRun[runID][i].FinishedAtMs < stepsByRun[runID][j].FinishedAtMs
			}
			return stepsByRun[runID][i].StepIndex < stepsByRun[runID][j].StepIndex
		})
	}

	created := map[string]createdMeta{}
	_ = scanJSONLinesTail(a.cfg.MasterLogPath, 8*1024*1024, func(obj map[string]any) {
		msg := strVal(obj["msg"])
		runID := strVal(obj["run_id"])
		if runID == "" {
			if msg == "response_run_created" {
				return
			}
			if !strings.HasPrefix(msg, "response_run_") && !strings.HasPrefix(msg, "approval_") {
				return
			}
		}

		logTsMs := logTimeUnixMs(obj["time"])
		lastUpdatedMs := int64Val(obj["last_updated_at_unix_ms"], 0)
		if lastUpdatedMs == 0 {
			lastUpdatedMs = logTsMs
		}

		switch msg {
		case "response_run_created":
			created[runID] = createdMeta{
				RuleID:          strVal(obj["rule_id"]),
				PlaybookID:      strVal(obj["playbook_id"]),
				PlaybookVersion: strVal(obj["playbook_version"]),
				Severity:        strVal(obj["severity"]),
			}
			r := runsByID[runID]
			r.RunID = runID
			r.Status = chooseNonEmpty(strings.ToUpper(strVal(obj["status"])), r.Status)
			r.Status = chooseNonEmpty("CREATED", r.Status)
			r.RuleID = chooseNonEmpty(strVal(obj["rule_id"]), r.RuleID)
			r.PlaybookID = chooseNonEmpty(strVal(obj["playbook_id"]), r.PlaybookID)
			r.PlaybookVersion = chooseNonEmpty(strVal(obj["playbook_version"]), r.PlaybookVersion)
			r.Severity = chooseNonEmpty(strVal(obj["severity"]), r.Severity)
			r.LastUpdatedAtUnixMs = int64Val(lastUpdatedMs, r.LastUpdatedAtUnixMs)
			if r.Source == "" {
				r.Source = "master_log"
			}
			runsByID[runID] = r
		case "response_run_waiting_approval":
			r := runsByID[runID]
			r.RunID = runID
			r.Status = "WAITING_APPROVAL"
			r.RuleID = chooseNonEmpty(strVal(obj["rule_id"]), r.RuleID)
			r.PlaybookID = chooseNonEmpty(strVal(obj["playbook_id"]), r.PlaybookID)
			r.ApprovalTimeoutMs = int64Val(obj["timeout_ms"], r.ApprovalTimeoutMs)
			r.ApprovalRequestedAtMs = int64Val(logTsMs, r.ApprovalRequestedAtMs)
			r.LastUpdatedAtUnixMs = int64Val(lastUpdatedMs, r.LastUpdatedAtUnixMs)
			if r.Source == "" {
				r.Source = "master_log"
			}
			runsByID[runID] = r
		case "approval_requested":
			r := runsByID[runID]
			r.RunID = runID
			r.Status = chooseNonEmpty("WAITING_APPROVAL", r.Status)
			r.RuleID = chooseNonEmpty(strVal(obj["rule_id"]), r.RuleID)
			r.PlaybookID = chooseNonEmpty(strVal(obj["playbook_id"]), r.PlaybookID)
			r.PlaybookVersion = chooseNonEmpty(strVal(obj["playbook_version"]), r.PlaybookVersion)
			r.ApprovalTimeoutMs = int64Val(obj["timeout_ms"], r.ApprovalTimeoutMs)
			r.ApprovalRequestedAtMs = int64Val(logTsMs, r.ApprovalRequestedAtMs)
			r.LastUpdatedAtUnixMs = int64Val(lastUpdatedMs, r.LastUpdatedAtUnixMs)
			if r.Source == "" {
				r.Source = "master_log"
			}
			runsByID[runID] = r
		case "approval_approved", "approval_denied", "approval_timed_out":
			r := runsByID[runID]
			r.RunID = runID
			r.ApprovalDecision = chooseNonEmpty(strVal(obj["decision"]), r.ApprovalDecision)
			if msg == "approval_denied" {
				r.ApprovalDecision = chooseNonEmpty("deny", r.ApprovalDecision)
			}
			if msg == "approval_timed_out" {
				r.ApprovalDecision = chooseNonEmpty("timeout", r.ApprovalDecision)
			}
			r.ApprovalActor = chooseNonEmpty(strVal(obj["actor"]), r.ApprovalActor)
			r.LastUpdatedAtUnixMs = int64Val(lastUpdatedMs, r.LastUpdatedAtUnixMs)
			if r.Source == "" {
				r.Source = "master_log"
			}
			runsByID[runID] = r
		case "response_run_updated":
			r := runsByID[runID]
			r.RunID = runID
			r.Status = chooseNonEmpty(strings.ToUpper(strVal(obj["status"])), r.Status)
			r.RuleID = chooseNonEmpty(strVal(obj["rule_id"]), r.RuleID)
			r.PlaybookID = chooseNonEmpty(strVal(obj["playbook_id"]), r.PlaybookID)
			r.PlaybookVersion = chooseNonEmpty(strVal(obj["playbook_version"]), r.PlaybookVersion)
			r.Severity = chooseNonEmpty(strVal(obj["severity"]), r.Severity)
			r.Lane = chooseNonEmpty(strings.ToUpper(strVal(obj["lane"])), r.Lane)
			r.NodeID = chooseNonEmpty(strVal(obj["node_id"]), r.NodeID)
			r.SourceType = chooseNonEmpty(strVal(obj["source_type"]), r.SourceType)
			r.EventType = chooseNonEmpty(strVal(obj["event_type"]), r.EventType)
			r.SrcIP = chooseNonEmpty(strVal(obj["src_ip"]), r.SrcIP)
			r.User = chooseNonEmpty(strVal(obj["user_name"]), r.User)
			r.User = chooseNonEmpty(strVal(obj["user"]), r.User)
			r.Actor = chooseNonEmpty(strVal(obj["actor"]), r.Actor)
			r.Target = chooseNonEmpty(strVal(obj["target"]), r.Target)
			r.TargetAgentID = chooseNonEmpty(strVal(obj["target_agent_id"]), r.TargetAgentID)
			r.EventIdemKey = chooseNonEmpty(strVal(obj["event_idem_key"]), r.EventIdemKey)
			r.FailedSafeReason = chooseNonEmpty(strVal(obj["failed_safe_reason"]), r.FailedSafeReason)
			r.OperatorAction = chooseNonEmpty(strVal(obj["operator_action"]), r.OperatorAction)
			r.ApprovalDecision = chooseNonEmpty(strVal(obj["approval_decision"]), r.ApprovalDecision)
			r.ApprovalActor = chooseNonEmpty(strVal(obj["approval_actor"]), r.ApprovalActor)
			r.StepTotal = intVal(obj["step_total"], r.StepTotal)
			r.StepSucceededCount = intVal(obj["step_succeeded_count"], r.StepSucceededCount)
			r.StepFailedSafeCount = intVal(obj["step_failed_safe_count"], r.StepFailedSafeCount)
			r.StepFailedTransient = intVal(obj["step_failed_transient_count"], r.StepFailedTransient)
			r.LastUpdatedAtUnixMs = int64Val(lastUpdatedMs, r.LastUpdatedAtUnixMs)
			if r.Source == "" {
				r.Source = "master_log"
			}
			runsByID[runID] = r
		}
	})

	runs := make([]incident, 0, len(runsByID))
	for _, v := range runsByID {
		runs = append(runs, v)
	}
	return runs, stepsByRun, created
}

func scanJSONLinesTail(path string, maxBytes int64, fn func(map[string]any)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return err
	}
	start := int64(0)
	if st.Size() > maxBytes {
		start = st.Size() - maxBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}

	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	s.Buffer(buf, 10*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		obj := map[string]any{}
		if err := json.Unmarshal([]byte(line), &obj); err == nil {
			fn(obj)
		}
	}
	return s.Err()
}

func parseAuditLog(path string, source string) []auditEntry {
	entries := make([]auditEntry, 0, 256)
	_ = scanJSONLines(path, func(obj map[string]any) {
		msg := strVal(obj["msg"])
		if msg == "" {
			return
		}
		keep := false
		switch msg {
		case "approval_received", "approval_approved", "approval_denied", "approval_timed_out", "response_run_partial_completion", "ui_approval_published":
			keep = true
		case "response_run_updated":
			status := strings.ToUpper(strVal(obj["status"]))
			keep = status == "FAILED_SAFE" || status == "FAILED_TRANSIENT"
		}
		if !keep {
			return
		}
		details := map[string]any{}
		for k, v := range obj {
			switch k {
			case "time", "msg", "run_id", "actor", "decision", "status":
			default:
				details[k] = v
			}
		}
		entries = append(entries, auditEntry{
			TS:       strVal(obj["time"]),
			Msg:      msg,
			RunID:    strVal(obj["run_id"]),
			Actor:    strVal(obj["actor"]),
			Decision: strVal(obj["decision"]),
			Status:   strVal(obj["status"]),
			Details:  details,
			Source:   source,
		})
	})
	return entries
}

func scanJSONLines(path string, fn func(map[string]any)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	s.Buffer(buf, 10*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		obj := map[string]any{}
		if err := json.Unmarshal([]byte(line), &obj); err == nil {
			fn(obj)
		}
	}
	return s.Err()
}

func decodeJSONBody(r io.Reader, dst any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid json body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func chooseNonEmpty(v string, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

func strVal(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

func intVal(v any, fallback int) int {
	return int(int64Val(v, int64(fallback)))
}

func int64Val(v any, fallback int64) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return n
		}
	case string:
		if t == "" {
			return fallback
		}
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

func parseInt64(s string, fallback int64) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts.UnixMilli()
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UnixMilli()
	}
	return fallback
}

func severityRank(v string) int {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func logTimeUnixMs(v any) int64 {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0
		}
		if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return ts.UnixMilli()
		}
		if ts, err := time.Parse(time.RFC3339, s); err == nil {
			return ts.UnixMilli()
		}
	}
	return 0
}

func mapVal(v any) map[string]any {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func buildURL(base string, p string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base + p
	}
	u.Path = p
	return u.String()
}
