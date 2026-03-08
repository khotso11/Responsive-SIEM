package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
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
	"golang.org/x/crypto/bcrypt"
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
	defaultUsersPath       = "configs/ui_users.json"
	defaultGeoEndpoints    = "configs/ui_geo_endpoints.json"
	defaultUIStatePath     = "retained/ui_state/ui_actions.jsonl"
	defaultUIStateDir      = "ui_state"
	defaultArtifactLimit   = 200
	maxArtifactPageLimit   = 1000
	maxArtifactScanEntries = 50000
	maxListLimit           = 2000
	maxArtifactListEntries = 1000
	sessionTTL             = 12 * time.Hour
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
	UsersPath     string
	GeoConfigPath string
	UIStatePath   string
	UIStateDir    string
	SessionSecret string
}

type app struct {
	cfg    serverConfig
	logger *slog.Logger

	db *sql.DB

	nc *nats.Conn
	js nats.JetStreamContext

	mu sync.RWMutex

	usersMu sync.RWMutex
	users   map[string]uiUser
}

func (a *app) natsReadyLocked() bool {
	if a.nc == nil || a.js == nil {
		return false
	}
	switch a.nc.Status() {
	case nats.CONNECTED, nats.RECONNECTING:
		return true
	default:
		return false
	}
}

func (a *app) connectNATSLocked() error {
	if a.nc != nil {
		a.nc.Close()
		a.nc = nil
		a.js = nil
	}

	nc, err := nats.Connect(a.cfg.NATSURL, nats.Name("r-siem-ui-api"))
	if err != nil {
		a.logger.Warn("ui_api_nats_unavailable", slog.String("error", err.Error()))
		return err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		a.logger.Warn("ui_api_jetstream_unavailable", slog.String("error", err.Error()))
		return err
	}
	a.nc = nc
	a.js = js
	a.logger.Info("ui_api_nats_connected",
		slog.String("url", a.cfg.NATSURL),
		slog.String("approvals_subject", a.cfg.ApprovalsSubj),
	)
	return nil
}

func (a *app) ensureNATS() error {
	a.mu.RLock()
	ready := a.natsReadyLocked()
	a.mu.RUnlock()
	if ready {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.natsReadyLocked() {
		return nil
	}
	return a.connectNATSLocked()
}

func (a *app) publishNATS(subject string, data []byte) error {
	if err := a.ensureNATS(); err != nil {
		return err
	}

	a.mu.RLock()
	js := a.js
	a.mu.RUnlock()
	if js == nil {
		return errors.New("nats unavailable")
	}
	if _, err := js.Publish(subject, data); err == nil {
		return nil
	}

	if err := a.ensureNATS(); err != nil {
		return err
	}
	a.mu.RLock()
	js = a.js
	a.mu.RUnlock()
	if js == nil {
		return errors.New("nats unavailable")
	}
	_, err := js.Publish(subject, data)
	return err
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

type endpointGeoConfigEntry struct {
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
	Label string  `json:"label,omitempty"`
}

type endpointGeoPoint struct {
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Label  string  `json:"label,omitempty"`
	Source string  `json:"source"`
}

type endpointGeoSummary struct {
	NodeID          string           `json:"node_id"`
	LastSeenRFC3339 string           `json:"last_seen_rfc3339"`
	Events5m        int64            `json:"events_5m"`
	Events1h        int64            `json:"events_1h"`
	Status          string           `json:"status"`
	SourceDist      map[string]int   `json:"source_dist"`
	Geo             endpointGeoPoint `json:"geo"`
}

type tacticTile struct {
	Tactic       string `json:"tactic"`
	Count        int    `json:"count"`
	HighCritical int    `json:"high_critical"`
	Delta        int    `json:"delta,omitempty"`
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

type uiUser struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Role         string `json:"role"`
	Disabled     bool   `json:"disabled,omitempty"`
}

type authClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
}

type uiStateRecord struct {
	TS             string `json:"ts"`
	Action         string `json:"action"`
	RunID          string `json:"run_id"`
	Actor          string `json:"actor"`
	Assignee       string `json:"assignee,omitempty"`
	Note           string `json:"note,omitempty"`
	Status         string `json:"status,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

type roleContext struct {
	Username string
	Role     string
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
	flag.StringVar(&cfg.UsersPath, "users-path", defaultUsersPath, "Path to UI users JSON")
	flag.StringVar(&cfg.GeoConfigPath, "geo-config-path", defaultGeoEndpoints, "Path to UI geo endpoint mapping JSON")
	flag.StringVar(&cfg.UIStatePath, "ui-state-path", defaultUIStatePath, "Path to UI state actions JSONL")
	flag.StringVar(&cfg.UIStateDir, "ui-state-dir", defaultUIStateDir, "Path to UI state directory (notes.jsonl + assignments.jsonl)")
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
	cfg.SessionSecret = strings.TrimSpace(os.Getenv("UI_SESSION_SECRET"))
	if cfg.SessionSecret == "" {
		cfg.SessionSecret = "dev-session-secret-change-me"
	}
	if strings.TrimSpace(cfg.UIStateDir) == "" {
		if strings.TrimSpace(cfg.UIStatePath) != "" {
			cfg.UIStateDir = filepath.Dir(cfg.UIStatePath)
		} else {
			cfg.UIStateDir = defaultUIStateDir
		}
	}

	logger, err := logging.NewLogger("INFO")
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}

	a := &app{
		cfg:    cfg,
		logger: logger,
		users:  map[string]uiUser{},
	}
	if err := a.loadUsers(); err != nil {
		fmt.Fprintf(os.Stderr, "load ui users: %v\n", err)
		os.Exit(1)
	}

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

	_ = a.ensureNATS()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", a.handleHealth)
	mux.HandleFunc("POST /api/auth/login", a.handleAuthLogin)
	mux.HandleFunc("POST /api/auth/logout", a.handleAuthLogout)
	mux.HandleFunc("GET /api/auth/me", a.withAuthRole(a.handleAuthMe, "analyst"))
	mux.HandleFunc("GET /api/meta", a.withAuthRole(a.handleMeta, "analyst"))
	mux.HandleFunc("GET /api/dashboard/summary", a.withAuthRole(a.handleDashboardSummary, "analyst"))
	mux.HandleFunc("GET /api/dashboard/series/incidents", a.withAuthRole(a.handleDashboardIncidentsSeries, "analyst"))
	mux.HandleFunc("GET /api/dashboard/series/severity", a.withAuthRole(a.handleDashboardSeveritySeries, "analyst"))
	mux.HandleFunc("GET /api/dashboard/series/lanes", a.withAuthRole(a.handleDashboardLanesSeries, "analyst"))
	mux.HandleFunc("GET /api/dashboard/top/entities", a.withAuthRole(a.handleDashboardTopEntities, "analyst"))
	mux.HandleFunc("GET /api/incidents", a.withAuthRole(a.handleIncidents, "analyst"))
	mux.HandleFunc("GET /api/incidents/{run_id}", a.withAuthRole(a.handleIncidentDetail, "analyst"))
	mux.HandleFunc("POST /api/incidents/{run_id}/approve", a.withAuthRole(a.handleIncidentApprove, "analyst"))
	mux.HandleFunc("POST /api/incidents/{run_id}/reject", a.withAuthRole(a.handleIncidentReject, "analyst"))
	mux.HandleFunc("POST /api/incidents/{run_id}/assign", a.withAuthRole(a.handleIncidentAssign, "analyst"))
	mux.HandleFunc("POST /api/incidents/{run_id}/notes", a.withAuthRole(a.handleIncidentNotes, "analyst"))
	mux.HandleFunc("POST /api/incidents/{run_id}/review", a.withAuthRole(a.handleIncidentMarkReviewed, "analyst"))
	mux.HandleFunc("GET /api/incidents/{run_id}/events", a.withAuthRole(a.handleIncidentEvents, "analyst"))
	mux.HandleFunc("GET /api/search", a.withAuthRole(a.handleSearch, "analyst"))
	mux.HandleFunc("GET /api/stream", a.withAuthRole(a.handleStream, "analyst"))
	mux.HandleFunc("GET /api/endpoints", a.withAuthRole(a.handleEndpoints, "analyst"))
	mux.HandleFunc("GET /api/endpoints/geo", a.withAuthRole(a.handleEndpointsGeo, "analyst"))
	mux.HandleFunc("GET /api/endpoints/{node_id}/events", a.withAuthRole(a.handleEndpointEvents, "analyst"))
	mux.HandleFunc("GET /api/endpoints/{node_id}/runs", a.withAuthRole(a.handleEndpointRuns, "analyst"))
	mux.HandleFunc("POST /api/endpoints/{node_id}/targeted-test", a.withAuthRole(a.handleEndpointTargetedTest, "analyst"))
	mux.HandleFunc("GET /api/audit", a.withAuthRole(a.handleAudit, "analyst"))
	mux.HandleFunc("GET /api/artifacts", a.withAuthRole(a.handleArtifacts, "analyst"))
	mux.HandleFunc("GET /api/artifact", a.withAuthRole(a.handleArtifactDownload, "analyst"))
	mux.HandleFunc("GET /api/users", a.withAuthRole(a.handleAdminUsersList, "admin"))
	mux.HandleFunc("POST /api/users", a.withAuthRole(a.handleAdminUsersUpsert, "admin"))
	mux.HandleFunc("POST /api/users/{id}/disable", a.withAuthRole(a.handleAdminUsersDisable, "admin"))
	mux.HandleFunc("GET /api/admin/users", a.withAuthRole(a.handleAdminUsersList, "admin"))
	mux.HandleFunc("POST /api/admin/users", a.withAuthRole(a.handleAdminUsersUpsert, "admin"))

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

type requestContextKey string

const roleCtxKey requestContextKey = "role_ctx"

func (a *app) withAuthRole(next http.HandlerFunc, requiredRole string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		roleCtx, ok, err := a.authContextFromRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login required"})
			return
		}
		if !roleAllowed(roleCtx.Role, requiredRole) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
			return
		}
		ctx := context.WithValue(r.Context(), roleCtxKey, roleCtx)
		next(w, r.WithContext(ctx))
	}
}

func roleAllowed(actualRole string, requiredRole string) bool {
	order := map[string]int{"analyst": 1, "admin": 2}
	actual := order[strings.ToLower(strings.TrimSpace(actualRole))]
	required := order[strings.ToLower(strings.TrimSpace(requiredRole))]
	if required == 0 {
		required = 1
	}
	return actual >= required
}

func (a *app) authContextFromRequest(r *http.Request) (roleContext, bool, error) {
	apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if apiKey == "" {
		apiKey = strings.TrimSpace(r.URL.Query().Get("api_key"))
	}
	if apiKey != "" && apiKey == a.cfg.APIKey {
		return roleContext{Username: "api-key", Role: "admin"}, true, nil
	}

	token := ""
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token = strings.TrimSpace(auth[7:])
	}
	if token == "" {
		if c, err := r.Cookie("rsiem_ui_session"); err == nil {
			token = strings.TrimSpace(c.Value)
		}
	}
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if token == "" {
		return roleContext{}, false, nil
	}
	claims, err := a.verifySessionToken(token)
	if err != nil {
		return roleContext{}, false, err
	}
	return roleContext{
		Username: claims.Username,
		Role:     claims.Role,
	}, true, nil
}

func roleFromRequest(r *http.Request) roleContext {
	v := r.Context().Value(roleCtxKey)
	if v == nil {
		return roleContext{}
	}
	if rc, ok := v.(roleContext); ok {
		return rc
	}
	return roleContext{}
}

func (a *app) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"ts":      time.Now().UTC().Format(time.RFC3339),
		"version": "fr06-ui-api-v1",
	})
}

func (a *app) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	username := strings.TrimSpace(strings.ToLower(body.Username))
	if username == "" || strings.TrimSpace(body.Password) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "username and password are required"})
		return
	}
	a.usersMu.RLock()
	user, ok := a.users[username]
	a.usersMu.RUnlock()
	if !ok || user.Disabled {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.Password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	now := time.Now().Unix()
	token, err := a.signSessionToken(authClaims{
		Username: user.Username,
		Role:     user.Role,
		Iat:      now,
		Exp:      now + int64(sessionTTL.Seconds()),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to issue token"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "rsiem_ui_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"user": map[string]any{
			"username": user.Username,
			"role":     user.Role,
		},
		"token": token,
	})
}

func (a *app) handleAuthLogout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "rsiem_ui_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *app) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	roleCtx := roleFromRequest(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"user": map[string]any{
			"username": roleCtx.Username,
			"role":     roleCtx.Role,
		},
	})
}

func (a *app) handleMeta(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "ui-api",
		"routes": []map[string]any{
			{"method": "GET", "path": "/api/health", "summary": "Service health"},
			{"method": "POST", "path": "/api/auth/login", "summary": "Login and issue session token"},
			{"method": "POST", "path": "/api/auth/logout", "summary": "Logout current session"},
			{"method": "GET", "path": "/api/auth/me", "summary": "Current authenticated user"},
			{"method": "GET", "path": "/api/meta", "summary": "Route + schema summary"},
			{"method": "GET", "path": "/api/dashboard/summary", "summary": "Dashboard posture KPIs", "query": []string{"window"}},
			{"method": "GET", "path": "/api/dashboard/series/incidents", "summary": "Incident trend time buckets", "query": []string{"window", "bucket"}},
			{"method": "GET", "path": "/api/dashboard/series/severity", "summary": "Severity distribution", "query": []string{"window"}},
			{"method": "GET", "path": "/api/dashboard/series/lanes", "summary": "FAST vs STANDARD distribution", "query": []string{"window"}},
			{"method": "GET", "path": "/api/dashboard/top/entities", "summary": "Top src_ip/user/node entities", "query": []string{"window"}},
			{"method": "GET", "path": "/api/incidents", "summary": "List incidents", "query": []string{"status", "severity", "lane", "playbook_id", "rule_id", "node_id", "from", "to", "q", "limit", "page", "sort"}},
			{"method": "GET", "path": "/api/incidents/{run_id}", "summary": "Incident detail"},
			{"method": "POST", "path": "/api/incidents/{run_id}/approve", "summary": "Approve/reject FAST action", "body": map[string]string{"decision": "approve|reject|deny", "actor": "string"}},
			{"method": "POST", "path": "/api/incidents/{run_id}/reject", "summary": "Reject FAST action", "body": map[string]string{"actor": "string"}},
			{"method": "POST", "path": "/api/incidents/{run_id}/assign", "summary": "Assign run to analyst/admin", "body": map[string]string{"assignee": "string"}},
			{"method": "POST", "path": "/api/incidents/{run_id}/notes", "summary": "Add incident note", "body": map[string]string{"note": "string"}},
			{"method": "POST", "path": "/api/incidents/{run_id}/review", "summary": "Mark run reviewed"},
			{"method": "GET", "path": "/api/incidents/{run_id}/events", "summary": "Timeline events around incident", "query": []string{"window_seconds"}},
			{"method": "GET", "path": "/api/search", "summary": "Global search across incidents and events", "query": []string{"q", "from", "to", "limit"}},
			{"method": "GET", "path": "/api/stream", "summary": "SSE refresh hints and approval queue counts"},
			{"method": "GET", "path": "/api/endpoints", "summary": "Endpoint summaries"},
			{"method": "GET", "path": "/api/endpoints/geo", "summary": "Endpoint summaries with geo posture", "query": []string{"window"}},
			{"method": "GET", "path": "/api/endpoints/{node_id}/events", "summary": "Recent endpoint events", "query": []string{"from", "to", "limit"}},
			{"method": "GET", "path": "/api/endpoints/{node_id}/runs", "summary": "Recent runs affecting endpoint", "query": []string{"limit"}},
			{"method": "POST", "path": "/api/endpoints/{node_id}/targeted-test", "summary": "Publish harmless targeted step", "body": map[string]string{"actor": "string", "target_agent_id": "string (optional)"}},
			{"method": "GET", "path": "/api/audit", "summary": "Approvals and key actions audit"},
			{"method": "GET", "path": "/api/users", "summary": "List UI users (admin only)"},
			{"method": "POST", "path": "/api/users", "summary": "Create/update user (admin only)"},
			{"method": "POST", "path": "/api/users/{id}/disable", "summary": "Disable user (admin only)"},
			{"method": "GET", "path": "/api/admin/users", "summary": "Alias for /api/users (admin only)"},
			{"method": "POST", "path": "/api/admin/users", "summary": "Alias for /api/users (admin only)"},
			{"method": "GET", "path": "/api/artifacts", "summary": "List artifacts", "query": []string{"prefix"}},
			{"method": "GET", "path": "/api/artifact", "summary": "Download artifact", "query": []string{"path"}},
		},
		"schemas": map[string]any{
			"incident":     incident{},
			"step":         stepResult{},
			"event_row":    eventRow{},
			"endpoint_geo": endpointGeoSummary{},
			"auth_claim":   authClaims{},
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
		"run":      found,
		"steps":    steps,
		"ui_state": a.loadUIStateForRun(runID),
		"source":   "exports",
	})
}

func (a *app) handleIncidentApprove(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}
	if err := a.ensureNATS(); err != nil {
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
	roleCtx := roleFromRequest(r)
	actor := strings.TrimSpace(body.Actor)
	if actor == "" {
		actor = roleCtx.Username
	}
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
	if err := a.publishNATS(a.cfg.ApprovalsSubj, data); err != nil {
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

func (a *app) handleIncidentReject(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}
	roleCtx := roleFromRequest(r)
	var body struct {
		Actor  string `json:"actor"`
		Reason string `json:"reason"`
	}
	_ = decodeJSONBody(r.Body, &body)
	actor := strings.TrimSpace(body.Actor)
	if actor == "" {
		actor = roleCtx.Username
	}
	if actor == "" {
		actor = "analyst"
	}
	reqBody := map[string]any{
		"decision": "reject",
		"actor":    actor,
		"reason":   strings.TrimSpace(body.Reason),
	}
	buf, _ := json.Marshal(reqBody)
	r.Body = io.NopCloser(strings.NewReader(string(buf)))
	a.handleIncidentApprove(w, r)
}

func (a *app) handleIncidentAssign(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}
	roleCtx := roleFromRequest(r)
	var body struct {
		Assignee string `json:"assignee"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	assignee := strings.TrimSpace(strings.ToLower(body.Assignee))
	if assignee == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "assignee is required"})
		return
	}
	if strings.ToLower(roleCtx.Role) != "admin" && assignee != strings.ToLower(roleCtx.Username) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "analyst can only assign to self"})
		return
	}
	rec := uiStateRecord{
		TS:       time.Now().UTC().Format(time.RFC3339Nano),
		Action:   "assign",
		RunID:    runID,
		Actor:    roleCtx.Username,
		Assignee: assignee,
	}
	rec.IdempotencyKey = a.uiStateIdempotencyKey(rec)
	if err := a.appendUIStateRecord(a.assignmentsStatePath(), rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "run_id": runID, "assignee": assignee, "actor": roleCtx.Username})
}

func (a *app) handleIncidentNotes(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}
	roleCtx := roleFromRequest(r)
	var body struct {
		Note string `json:"note"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	note := strings.TrimSpace(body.Note)
	if note == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "note is required"})
		return
	}
	rec := uiStateRecord{
		TS:     time.Now().UTC().Format(time.RFC3339Nano),
		Action: "note",
		RunID:  runID,
		Actor:  roleCtx.Username,
		Note:   note,
	}
	rec.IdempotencyKey = a.uiStateIdempotencyKey(rec)
	if err := a.appendUIStateRecord(a.notesStatePath(), rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "run_id": runID})
}

func (a *app) handleIncidentMarkReviewed(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}
	roleCtx := roleFromRequest(r)
	rec := uiStateRecord{
		TS:     time.Now().UTC().Format(time.RFC3339Nano),
		Action: "mark_reviewed",
		RunID:  runID,
		Actor:  roleCtx.Username,
		Status: "reviewed",
	}
	rec.IdempotencyKey = a.uiStateIdempotencyKey(rec)
	if err := a.appendUIStateRecord(a.assignmentsStatePath(), rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "run_id": runID, "status": "reviewed"})
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

	loadEvents := func(clauses []string, args []any) ([]eventRow, error) {
		query := "SELECT event_ts_unix_ms, recv_ts_unix_ms, node_id, source_type, event_type, COALESCE(src_ip::text,''), COALESCE(user_name,''), COALESCE(severity,''), COALESCE(rule_id,''), event_idem_key FROM normalized_events WHERE " + strings.Join(clauses, " AND ") + fmt.Sprintf(" ORDER BY recv_ts_unix_ms DESC LIMIT %d", limit)
		rows, err := a.db.QueryContext(r.Context(), query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		items := make([]eventRow, 0, 128)
		for rows.Next() {
			var ev eventRow
			if err := rows.Scan(&ev.EventTSUnixMs, &ev.RecvTSUnixMs, &ev.NodeID, &ev.SourceType, &ev.EventType, &ev.SrcIP, &ev.UserName, &ev.Severity, &ev.RuleID, &ev.EventIdemKey); err == nil {
				items = append(items, ev)
			}
		}
		return items, nil
	}

	// First pass: strict run-scoped matching.
	strictClauses := []string{"recv_ts_unix_ms BETWEEN $1 AND $2"}
	strictArgs := []any{fromMs, toMs}
	idx := 3
	nodeMatch := chooseNonEmpty(pivotNode, run.NodeID)
	if nodeMatch != "" {
		strictClauses = append(strictClauses, fmt.Sprintf("node_id = $%d", idx))
		strictArgs = append(strictArgs, nodeMatch)
		idx++
	}
	userMatch := chooseNonEmpty(pivotUser, run.User)
	if userMatch != "" {
		strictClauses = append(strictClauses, fmt.Sprintf("COALESCE(user_name,'') = $%d", idx))
		strictArgs = append(strictArgs, userMatch)
		idx++
	}
	srcIPMatch := chooseNonEmpty(pivotSrcIP, run.SrcIP)
	if srcIPMatch != "" {
		strictClauses = append(strictClauses, fmt.Sprintf("COALESCE(src_ip::text,'') = $%d", idx))
		strictArgs = append(strictArgs, srcIPMatch)
		idx++
	}
	if run.SourceType != "" {
		strictClauses = append(strictClauses, fmt.Sprintf("source_type = $%d", idx))
		strictArgs = append(strictArgs, run.SourceType)
		idx++
	}
	if run.EventType != "" {
		strictClauses = append(strictClauses, fmt.Sprintf("event_type = $%d", idx))
		strictArgs = append(strictArgs, run.EventType)
		idx++
	}
	items, err := loadEvents(strictClauses, strictArgs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if len(items) > 0 {
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items), "source": "db", "query_mode": "strict"})
		return
	}

	// Fallback: wider time window + less strict entity matching.
	wideWindowSec := windowSec * 2
	if wideWindowSec < 1800 {
		wideWindowSec = 1800
	}
	fallbackFrom := center - (wideWindowSec * 1000)
	fallbackTo := center + (wideWindowSec * 1000)
	fallbackClauses := []string{"recv_ts_unix_ms BETWEEN $1 AND $2"}
	fallbackArgs := []any{fallbackFrom, fallbackTo}
	idx = 3

	// Respect explicit pivots when provided.
	if pivotNode != "" {
		fallbackClauses = append(fallbackClauses, fmt.Sprintf("node_id = $%d", idx))
		fallbackArgs = append(fallbackArgs, pivotNode)
		idx++
	}
	if pivotUser != "" {
		fallbackClauses = append(fallbackClauses, fmt.Sprintf("COALESCE(user_name,'') = $%d", idx))
		fallbackArgs = append(fallbackArgs, pivotUser)
		idx++
	}
	if pivotSrcIP != "" {
		fallbackClauses = append(fallbackClauses, fmt.Sprintf("COALESCE(src_ip::text,'') = $%d", idx))
		fallbackArgs = append(fallbackArgs, pivotSrcIP)
		idx++
	}

	// If no explicit pivots, match any known run entities (OR) to avoid empty timelines.
	if pivotNode == "" && pivotUser == "" && pivotSrcIP == "" {
		entityOr := make([]string, 0, 4)
		if run.NodeID != "" {
			entityOr = append(entityOr, fmt.Sprintf("node_id = $%d", idx))
			fallbackArgs = append(fallbackArgs, run.NodeID)
			idx++
		}
		if run.SrcIP != "" {
			entityOr = append(entityOr, fmt.Sprintf("COALESCE(src_ip::text,'') = $%d", idx))
			fallbackArgs = append(fallbackArgs, run.SrcIP)
			idx++
		}
		if run.User != "" {
			entityOr = append(entityOr, fmt.Sprintf("COALESCE(user_name,'') = $%d", idx))
			fallbackArgs = append(fallbackArgs, run.User)
			idx++
		}
		if run.EventIdemKey != "" {
			entityOr = append(entityOr, fmt.Sprintf("event_idem_key = $%d", idx))
			fallbackArgs = append(fallbackArgs, run.EventIdemKey)
			idx++
		}
		if len(entityOr) > 0 {
			fallbackClauses = append(fallbackClauses, "("+strings.Join(entityOr, " OR ")+")")
		}
	}

	items, err = loadEvents(fallbackClauses, fallbackArgs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":         items,
		"count":         len(items),
		"source":        "db",
		"query_mode":    "fallback",
		"fallback_from": fallbackFrom,
		"fallback_to":   fallbackTo,
	})
}

func (a *app) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	windowMs := parseWindowMs(r.URL.Query().Get("window"), 24*time.Hour)
	nowMs := time.Now().UnixMilli()
	fromMs := nowMs - windowMs
	prevFromMs := fromMs - windowMs
	prevToMs := fromMs

	runs, _, _ := a.loadState()
	incidents := 0
	waiting := 0
	failedSafe := 0
	criticalIncidents := 0
	activeNodes := map[string]struct{}{}
	mitreNow := map[string]*tacticTile{}
	mitrePrev := map[string]int{}
	initMitre := func() {
		for _, tactic := range []string{
			"Privilege Escalation",
			"Lateral Movement",
			"Discovery",
			"Impact",
			"Command & Control",
			"Exfiltration",
		} {
			mitreNow[tactic] = &tacticTile{Tactic: tactic}
			mitrePrev[tactic] = 0
		}
	}
	initMitre()
	for _, run := range runs {
		ts := run.LastUpdatedAtUnixMs
		if ts >= fromMs {
			incidents++
			if strings.ToUpper(run.Status) == "WAITING_APPROVAL" {
				waiting++
			}
			if strings.ToUpper(run.Status) == "FAILED_SAFE" {
				failedSafe++
			}
			if severityRank(run.Severity) >= severityRank("critical") {
				criticalIncidents++
			}
			if run.NodeID != "" {
				activeNodes[run.NodeID] = struct{}{}
			}
			if tactic := mitreTacticFromRun(run); tactic != "" {
				tile := mitreNow[tactic]
				tile.Count++
				if severityRank(run.Severity) >= severityRank("high") {
					tile.HighCritical++
				}
			}
		}
		if ts >= prevFromMs && ts < prevToMs {
			if tactic := mitreTacticFromRun(run); tactic != "" {
				mitrePrev[tactic]++
			}
		}
	}
	endpointsActive := len(activeNodes)
	ingestionPerMin := 0.0
	latencyP95Ms := int64(0)
	totalEventsWindow := int64(0)
	modelAlertsWindow := int64(0)
	if a.db != nil {
		var c int64
		if err := a.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM normalized_events WHERE recv_ts_unix_ms >= $1`, nowMs-5*60*1000).Scan(&c); err == nil {
			ingestionPerMin = float64(c) / 5.0
		}
		_ = a.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM normalized_events WHERE recv_ts_unix_ms >= $1`, fromMs).Scan(&totalEventsWindow)
		_ = a.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM normalized_events WHERE recv_ts_unix_ms >= $1 AND COALESCE(rule_id,'') <> ''`, fromMs).Scan(&modelAlertsWindow)
		var p95 sql.NullFloat64
		if err := a.db.QueryRowContext(r.Context(), `
SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY GREATEST(recv_ts_unix_ms - event_ts_unix_ms,0))
FROM normalized_events
WHERE recv_ts_unix_ms >= $1 AND event_ts_unix_ms > 0
`, fromMs).Scan(&p95); err == nil && p95.Valid {
			latencyP95Ms = int64(p95.Float64)
		}
	}
	mitreTiles := make([]tacticTile, 0, len(mitreNow))
	for tactic, tile := range mitreNow {
		cp := *tile
		cp.Delta = cp.Count - mitrePrev[tactic]
		mitreTiles = append(mitreTiles, cp)
	}
	sort.SliceStable(mitreTiles, func(i, j int) bool {
		if mitreTiles[i].Count == mitreTiles[j].Count {
			return mitreTiles[i].Tactic < mitreTiles[j].Tactic
		}
		return mitreTiles[i].Count > mitreTiles[j].Count
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"window_ms":                      windowMs,
		"from_unix_ms":                   fromMs,
		"to_unix_ms":                     nowMs,
		"incidents_last_window":          incidents,
		"critical_incidents_last_window": criticalIncidents,
		"approvals_pending":              waiting,
		"failed_safe_count":              failedSafe,
		"endpoints_active":               endpointsActive,
		"ingestion_rate_per_min":         ingestionPerMin,
		"latency_p95_ms":                 latencyP95Ms,
		"total_events_last_window":       totalEventsWindow,
		"model_alerts_last_window":       modelAlertsWindow,
		"mitre_tactics_processed":        mitreTiles,
	})
}

func (a *app) handleDashboardIncidentsSeries(w http.ResponseWriter, r *http.Request) {
	windowMs := parseWindowMs(r.URL.Query().Get("window"), 24*time.Hour)
	bucketMs := parseWindowMs(r.URL.Query().Get("bucket"), time.Hour)
	if bucketMs <= 0 {
		bucketMs = int64(time.Hour / time.Millisecond)
	}
	nowMs := time.Now().UnixMilli()
	fromMs := nowMs - windowMs
	runs, _, _ := a.loadState()
	type point struct {
		TS         int64 `json:"ts_unix_ms"`
		Count      int   `json:"count"`
		Fast       int   `json:"fast"`
		Standard   int   `json:"standard"`
		FailedSafe int   `json:"failed_safe"`
	}
	m := map[int64]*point{}
	for _, run := range runs {
		if run.LastUpdatedAtUnixMs < fromMs {
			continue
		}
		b := (run.LastUpdatedAtUnixMs / bucketMs) * bucketMs
		p := m[b]
		if p == nil {
			p = &point{TS: b}
			m[b] = p
		}
		p.Count++
		switch strings.ToUpper(run.Lane) {
		case "FAST":
			p.Fast++
		case "STANDARD":
			p.Standard++
		}
		if strings.ToUpper(run.Status) == "FAILED_SAFE" {
			p.FailedSafe++
		}
	}
	out := make([]point, 0, len(m))
	for _, p := range m {
		out = append(out, *p)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS < out[j].TS })
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "count": len(out), "window_ms": windowMs, "bucket_ms": bucketMs})
}

func (a *app) handleDashboardSeveritySeries(w http.ResponseWriter, r *http.Request) {
	windowMs := parseWindowMs(r.URL.Query().Get("window"), 24*time.Hour)
	nowMs := time.Now().UnixMilli()
	fromMs := nowMs - windowMs
	runs, _, _ := a.loadState()
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
	for _, run := range runs {
		if run.LastUpdatedAtUnixMs < fromMs {
			continue
		}
		sev := strings.ToLower(strings.TrimSpace(run.Severity))
		if sev == "" {
			sev = "unknown"
		}
		if _, ok := counts[sev]; !ok {
			counts[sev] = 0
		}
		counts[sev]++
	}
	items := make([]map[string]any, 0, len(counts))
	for k, v := range counts {
		items = append(items, map[string]any{"severity": k, "count": v})
	}
	sort.SliceStable(items, func(i, j int) bool {
		ri := severityRank(strVal(items[i]["severity"]))
		rj := severityRank(strVal(items[j]["severity"]))
		if ri == rj {
			return strVal(items[i]["severity"]) < strVal(items[j]["severity"])
		}
		return ri > rj
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items), "window_ms": windowMs})
}

func (a *app) handleDashboardLanesSeries(w http.ResponseWriter, r *http.Request) {
	windowMs := parseWindowMs(r.URL.Query().Get("window"), 24*time.Hour)
	nowMs := time.Now().UnixMilli()
	fromMs := nowMs - windowMs
	runs, _, _ := a.loadState()
	fast := 0
	standard := 0
	unknown := 0
	for _, run := range runs {
		if run.LastUpdatedAtUnixMs < fromMs {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(run.Lane)) {
		case "FAST":
			fast++
		case "STANDARD":
			standard++
		default:
			unknown++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": []map[string]any{
			{"lane": "FAST", "count": fast},
			{"lane": "STANDARD", "count": standard},
			{"lane": "UNKNOWN", "count": unknown},
		},
		"window_ms": windowMs,
	})
}

func (a *app) handleDashboardTopEntities(w http.ResponseWriter, r *http.Request) {
	windowMs := parseWindowMs(r.URL.Query().Get("window"), time.Hour)
	nowMs := time.Now().UnixMilli()
	fromMs := nowMs - windowMs
	resp := map[string]any{
		"window_ms": windowMs,
		"src_ip":    []map[string]any{},
		"user_name": []map[string]any{},
		"node_id":   []map[string]any{},
	}
	if a.db == nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	queryTop := func(col string) []map[string]any {
		rows, err := a.db.QueryContext(r.Context(), fmt.Sprintf(`
SELECT %s AS v, COUNT(*) AS c
FROM normalized_events
WHERE recv_ts_unix_ms >= $1 AND COALESCE(%s::text,'') <> ''
GROUP BY %s
ORDER BY c DESC, v ASC
LIMIT 8
`, col, col, col), fromMs)
		if err != nil {
			return []map[string]any{}
		}
		defer rows.Close()
		out := make([]map[string]any, 0, 8)
		for rows.Next() {
			var v string
			var c int64
			if err := rows.Scan(&v, &c); err == nil {
				out = append(out, map[string]any{"value": v, "count": c})
			}
		}
		return out
	}
	resp["src_ip"] = queryTop("src_ip")
	resp["user_name"] = queryTop("user_name")
	resp["node_id"] = queryTop("node_id")
	writeJSON(w, http.StatusOK, resp)
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
		if _, err := fmt.Fprintf(w, "event: incidents_updated\ndata: %s\n\n", string(data)); err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: approvals_pending_count\ndata: %s\n\n", string(data)); err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: endpoints_activity_updated\ndata: %s\n\n", string(data)); err != nil {
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
	items, source, err := a.endpointSummaries(r.Context(), int64(time.Hour/time.Millisecond))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items), "source": source})
}

func (a *app) handleEndpointsGeo(w http.ResponseWriter, r *http.Request) {
	windowMs := parseWindowMs(r.URL.Query().Get("window"), time.Hour)
	items, source, err := a.endpointSummaries(r.Context(), windowMs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	geoCfg := a.loadGeoConfig()
	nowMs := time.Now().UnixMilli()
	failedSafeByNode := a.failedSafeCountsByNode(nowMs - windowMs)

	out := make([]endpointGeoSummary, 0, len(items))
	for _, ep := range items {
		geo := geoForNode(ep.NodeID, geoCfg)
		status := endpointStatus(ep, nowMs, failedSafeByNode[ep.NodeID], geo.Source)
		lastSeen := ""
		if ep.LastSeenUnixMs > 0 {
			lastSeen = time.UnixMilli(ep.LastSeenUnixMs).UTC().Format(time.RFC3339)
		}
		out = append(out, endpointGeoSummary{
			NodeID:          ep.NodeID,
			LastSeenRFC3339: lastSeen,
			Events5m:        ep.EventCount5m,
			Events1h:        ep.EventCount1h,
			Status:          status,
			SourceDist:      ep.SourceTypeDist,
			Geo:             geo,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window":       r.URL.Query().Get("window"),
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"endpoints":    out,
		"count":        len(out),
		"source":       source,
	})
}

func (a *app) endpointSummaries(ctx context.Context, windowMs int64) ([]endpointSummary, string, error) {
	nowMs := time.Now().UnixMilli()
	fiveMin := nowMs - 5*60*1000
	windowStart := nowMs - windowMs
	if windowStart <= 0 {
		windowStart = nowMs - 60*60*1000
	}

	if a.db == nil {
		runs, _, _ := a.loadState()
		byNode := map[string]*endpointSummary{}
		for _, run := range runs {
			node := strings.TrimSpace(run.NodeID)
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
			if run.LastUpdatedAtUnixMs >= fiveMin {
				ep.EventCount5m++
			}
			if run.LastUpdatedAtUnixMs >= windowStart {
				ep.EventCount1h++
				if run.SourceType != "" {
					ep.SourceTypeDist[run.SourceType]++
				}
			}
		}
		items := make([]endpointSummary, 0, len(byNode))
		for _, ep := range byNode {
			for st := range ep.SourceTypeDist {
				ep.SourceTypeSamples = append(ep.SourceTypeSamples, st)
			}
			sort.Strings(ep.SourceTypeSamples)
			items = append(items, *ep)
		}
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].LastSeenUnixMs == items[j].LastSeenUnixMs {
				return items[i].NodeID < items[j].NodeID
			}
			return items[i].LastSeenUnixMs > items[j].LastSeenUnixMs
		})
		return items, "exports", nil
	}

	query := `
SELECT node_id,
       MAX(recv_ts_unix_ms) AS last_seen,
       SUM(CASE WHEN recv_ts_unix_ms >= $1 THEN 1 ELSE 0 END) AS count_5m,
       SUM(CASE WHEN recv_ts_unix_ms >= $2 THEN 1 ELSE 0 END) AS count_window
FROM normalized_events
WHERE COALESCE(node_id,'') <> ''
GROUP BY node_id
ORDER BY last_seen DESC
LIMIT 500`
	rows, err := a.db.QueryContext(ctx, query, fiveMin, windowStart)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	items := make([]endpointSummary, 0, 128)
	idx := map[string]int{}
	for rows.Next() {
		var node string
		var lastSeen, c5, cW sql.NullInt64
		if err := rows.Scan(&node, &lastSeen, &c5, &cW); err != nil {
			continue
		}
		ep := endpointSummary{
			NodeID:         node,
			LastSeenUnixMs: lastSeen.Int64,
			EventCount5m:   c5.Int64,
			EventCount1h:   cW.Int64,
			SourceTypeDist: map[string]int{},
			DerivedFrom:    "db",
		}
		idx[node] = len(items)
		items = append(items, ep)
	}

	dRows, err := a.db.QueryContext(ctx, `SELECT node_id, source_type, COUNT(*) FROM normalized_events WHERE recv_ts_unix_ms >= $1 AND COALESCE(node_id,'') <> '' GROUP BY node_id, source_type`, windowStart)
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
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].LastSeenUnixMs == items[j].LastSeenUnixMs {
			return items[i].NodeID < items[j].NodeID
		}
		return items[i].LastSeenUnixMs > items[j].LastSeenUnixMs
	})
	return items, "db", nil
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
	if err := a.ensureNATS(); err != nil {
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
		actor = roleFromRequest(r).Username
	}
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
		"run_id":             runID,
		"step_id":            stepID,
		"step_index":         0,
		"action_type":        "agent_command",
		"lane":               "FAST",
		"step_idem_key":      fmt.Sprintf("step.%s.%s", runID, stepID),
		"attempt":            0,
		"target":             nodeID,
		"target_agent_id":    targetAgentID,
		"actor":              actor,
		"planned_at_unix_ms": now,
		"emitted_at_unix_ms": now,
		"params": map[string]any{
			"command":     "ping",
			"marker_file": fmt.Sprintf("ui_targeted_test_%d.txt", now),
		},
	}
	data, _ := json.Marshal(payload)
	if err := a.publishNATS(defaultStepFastSubject, data); err != nil {
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
	roleCtx := roleFromRequest(r)
	entries := make([]auditEntry, 0, 512)
	entries = append(entries, parseAuditLog(a.cfg.MasterLogPath, "master")...)
	entries = append(entries, parseAuditLog(a.cfg.UIAPILogPath, "ui-api")...)
	entries = append(entries, a.parseUIStateAudit()...)
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
	if strings.ToLower(roleCtx.Role) != "admin" {
		for i := range entries {
			if entries[i].Details != nil {
				entries[i].Details = map[string]any{
					"summary": "restricted_to_admin",
				}
			}
		}
	}
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
	filterQ := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))
	page := int(parseInt64(r.URL.Query().Get("page"), 1))
	limit := int(parseInt64(r.URL.Query().Get("limit"), defaultArtifactLimit))
	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = defaultArtifactLimit
	}
	if limit > maxArtifactPageLimit {
		limit = maxArtifactPageLimit
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

	entries := make([]map[string]any, 0, 256)
	scanned := 0
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if p == path {
			return nil
		}
		if scanned >= maxArtifactScanEntries {
			return io.EOF
		}
		rel, _ := filepath.Rel(".", p)
		relPath := filepath.ToSlash(rel)
		if filterQ != "" && !strings.Contains(strings.ToLower(relPath), filterQ) {
			scanned++
			return nil
		}
		info, _ := d.Info()
		entries = append(entries, map[string]any{
			"path":     relPath,
			"is_dir":   d.IsDir(),
			"size":     info.Size(),
			"modified": info.ModTime().UTC().Format(time.RFC3339),
		})
		scanned++
		if filterQ == "" && len(entries) >= maxArtifactListEntries {
			return io.EOF
		}
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	sort.SliceStable(entries, func(i, j int) bool {
		pi := strVal(entries[i]["path"])
		pj := strVal(entries[j]["path"])
		if pi == pj {
			return strVal(entries[i]["modified"]) > strVal(entries[j]["modified"])
		}
		return pi > pj
	})

	total := len(entries)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":     entries[start:end],
		"count":     len(entries[start:end]),
		"total":     total,
		"page":      page,
		"limit":     limit,
		"has_more":  end < total,
		"source":    "filesystem",
		"filter_q":  filterQ,
		"scan_path": filepath.ToSlash(prefix),
	})
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

func (a *app) handleAdminUsersList(w http.ResponseWriter, _ *http.Request) {
	a.usersMu.RLock()
	defer a.usersMu.RUnlock()
	items := make([]map[string]any, 0, len(a.users))
	for _, user := range a.users {
		items = append(items, map[string]any{
			"username": user.Username,
			"role":     user.Role,
			"disabled": user.Disabled,
		})
	}
	sort.SliceStable(items, func(i, j int) bool { return strVal(items[i]["username"]) < strVal(items[j]["username"]) })
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

func (a *app) handleAdminUsersUpsert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Disabled bool   `json:"disabled"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	username := strings.TrimSpace(strings.ToLower(body.Username))
	if username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "username is required"})
		return
	}
	role := normalizeRole(body.Role)
	if role == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "role must be admin or analyst"})
		return
	}
	a.usersMu.Lock()
	user, exists := a.users[username]
	user.Username = username
	user.Role = role
	user.Disabled = body.Disabled
	if strings.TrimSpace(body.Password) != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err != nil {
			a.usersMu.Unlock()
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "password hash failed"})
			return
		}
		user.PasswordHash = string(hash)
	} else if !exists || user.PasswordHash == "" {
		a.usersMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "password required for new user"})
		return
	}
	a.users[username] = user
	a.usersMu.Unlock()
	if err := a.saveUsers(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username, "role": role, "disabled": body.Disabled})
}

func (a *app) handleAdminUsersDisable(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(strings.ToLower(r.PathValue("id")))
	if username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id is required"})
		return
	}
	a.usersMu.Lock()
	user, exists := a.users[username]
	if !exists {
		a.usersMu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "user not found"})
		return
	}
	user.Disabled = true
	a.users[username] = user
	a.usersMu.Unlock()
	if err := a.saveUsers(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username, "disabled": true})
}

func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin":
		return "admin"
	case "analyst", "soc_analyst", "soc-analyst":
		return "analyst"
	default:
		return ""
	}
}

func (a *app) loadUsers() error {
	data, err := os.ReadFile(a.cfg.UsersPath)
	if err != nil {
		return err
	}
	type userFile struct {
		Users []uiUser `json:"users"`
	}
	parsed := userFile{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	if len(parsed.Users) == 0 {
		return fmt.Errorf("no users defined in %s", a.cfg.UsersPath)
	}
	a.usersMu.Lock()
	defer a.usersMu.Unlock()
	a.users = map[string]uiUser{}
	for _, u := range parsed.Users {
		name := strings.TrimSpace(strings.ToLower(u.Username))
		role := normalizeRole(u.Role)
		if name == "" || role == "" || strings.TrimSpace(u.PasswordHash) == "" {
			continue
		}
		u.Username = name
		u.Role = role
		a.users[name] = u
	}
	if len(a.users) == 0 {
		return fmt.Errorf("no valid users in %s", a.cfg.UsersPath)
	}
	return nil
}

func (a *app) saveUsers() error {
	a.usersMu.RLock()
	items := make([]uiUser, 0, len(a.users))
	for _, u := range a.users {
		items = append(items, u)
	}
	a.usersMu.RUnlock()
	sort.SliceStable(items, func(i, j int) bool { return items[i].Username < items[j].Username })
	payload := map[string]any{
		"users": items,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.cfg.UsersPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(a.cfg.UsersPath, append(data, '\n'), 0o644)
}

func (a *app) signSessionToken(claims authClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	msg := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(a.cfg.SessionSecret))
	if _, err := mac.Write([]byte(msg)); err != nil {
		return "", err
	}
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return msg + "." + sig, nil
}

func (a *app) verifySessionToken(token string) (authClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return authClaims{}, fmt.Errorf("invalid token format")
	}
	msg := parts[0]
	gotSig := parts[1]
	mac := hmac.New(sha256.New, []byte(a.cfg.SessionSecret))
	if _, err := mac.Write([]byte(msg)); err != nil {
		return authClaims{}, err
	}
	expectSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(gotSig), []byte(expectSig)) != 1 {
		return authClaims{}, fmt.Errorf("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(msg)
	if err != nil {
		return authClaims{}, err
	}
	var claims authClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return authClaims{}, err
	}
	if claims.Exp <= time.Now().Unix() {
		return authClaims{}, fmt.Errorf("token expired")
	}
	if normalizeRole(claims.Role) == "" || strings.TrimSpace(claims.Username) == "" {
		return authClaims{}, fmt.Errorf("invalid claims")
	}
	return claims, nil
}

func (a *app) notesStatePath() string {
	return filepath.Join(a.cfg.UIStateDir, "notes.jsonl")
}

func (a *app) assignmentsStatePath() string {
	return filepath.Join(a.cfg.UIStateDir, "assignments.jsonl")
}

func (a *app) uiStateIdempotencyKey(rec uiStateRecord) string {
	base := strings.Join([]string{
		strings.TrimSpace(rec.Action),
		strings.TrimSpace(rec.RunID),
		strings.TrimSpace(strings.ToLower(rec.Actor)),
		strings.TrimSpace(strings.ToLower(rec.Assignee)),
		strings.TrimSpace(rec.Note),
		strings.TrimSpace(rec.Status),
	}, "|")
	sum := sha256.Sum256([]byte(base))
	return "ui." + hex.EncodeToString(sum[:12])
}

func (a *app) appendUIStateRecord(path string, rec uiStateRecord) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("ui state path is empty")
	}
	if strings.TrimSpace(rec.IdempotencyKey) == "" {
		rec.IdempotencyKey = a.uiStateIdempotencyKey(rec)
	}
	exists, err := uiStateRecordExists(path, rec.IdempotencyKey)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	a.logger.Info("ui_state_event",
		slog.String("action", rec.Action),
		slog.String("run_id", rec.RunID),
		slog.String("actor", rec.Actor),
		slog.String("assignee", rec.Assignee),
		slog.String("idempotency_key", rec.IdempotencyKey),
		slog.String("path", path),
	)
	return nil
}

func uiStateRecordExists(path string, key string) (bool, error) {
	if strings.TrimSpace(key) == "" {
		return false, nil
	}
	found := false
	err := scanJSONLines(path, func(obj map[string]any) {
		if strVal(obj["idempotency_key"]) == key {
			found = true
		}
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return found, nil
}

func (a *app) loadUIStateForRun(runID string) map[string]any {
	out := map[string]any{
		"assignment": "",
		"notes":      []map[string]any{},
		"reviewed":   false,
	}
	_ = scanJSONLines(a.assignmentsStatePath(), func(obj map[string]any) {
		if strVal(obj["run_id"]) != runID {
			return
		}
		action := strVal(obj["action"])
		switch action {
		case "assign":
			out["assignment"] = strVal(obj["assignee"])
		case "mark_reviewed":
			out["reviewed"] = true
		}
	})
	_ = scanJSONLines(a.notesStatePath(), func(obj map[string]any) {
		if strVal(obj["run_id"]) != runID {
			return
		}
		action := strVal(obj["action"])
		switch action {
		case "note":
			notes, _ := out["notes"].([]map[string]any)
			notes = append(notes, map[string]any{
				"ts":    strVal(obj["ts"]),
				"actor": strVal(obj["actor"]),
				"note":  strVal(obj["note"]),
			})
			out["notes"] = notes
		}
	})
	return out
}

func (a *app) parseUIStateAudit() []auditEntry {
	entries := make([]auditEntry, 0, 128)
	appendEntry := func(obj map[string]any) {
		action := strVal(obj["action"])
		if action == "" {
			return
		}
		msg := "ui_" + action
		entries = append(entries, auditEntry{
			TS:       strVal(obj["ts"]),
			Msg:      msg,
			RunID:    strVal(obj["run_id"]),
			Actor:    strVal(obj["actor"]),
			Decision: "",
			Status:   strVal(obj["status"]),
			Details: map[string]any{
				"assignee": strVal(obj["assignee"]),
				"note":     strVal(obj["note"]),
				"idem_key": strVal(obj["idempotency_key"]),
			},
			Source: "ui-state",
		})
	}
	_ = scanJSONLines(a.assignmentsStatePath(), appendEntry)
	_ = scanJSONLines(a.notesStatePath(), appendEntry)
	return entries
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

func (a *app) failedSafeCountsByNode(fromMs int64) map[string]int {
	out := map[string]int{}
	runs, _, _ := a.loadState()
	for _, run := range runs {
		if run.LastUpdatedAtUnixMs < fromMs {
			continue
		}
		if strings.ToUpper(strings.TrimSpace(run.Status)) != "FAILED_SAFE" {
			continue
		}
		node := strings.TrimSpace(run.NodeID)
		if node == "" {
			continue
		}
		out[node]++
	}
	return out
}

func (a *app) loadGeoConfig() map[string]endpointGeoConfigEntry {
	out := map[string]endpointGeoConfigEntry{}
	path := strings.TrimSpace(a.cfg.GeoConfigPath)
	if path == "" {
		return out
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	parsed := map[string]endpointGeoConfigEntry{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return out
	}
	for k, v := range parsed {
		node := strings.TrimSpace(k)
		if node == "" {
			continue
		}
		if v.Lat < -90 || v.Lat > 90 || v.Lon < -180 || v.Lon > 180 {
			continue
		}
		v.Label = strings.TrimSpace(v.Label)
		out[node] = v
	}
	return out
}

func geoForNode(nodeID string, cfg map[string]endpointGeoConfigEntry) endpointGeoPoint {
	node := strings.TrimSpace(nodeID)
	if node == "" {
		return endpointGeoPoint{Source: "none"}
	}
	if v, ok := cfg[node]; ok {
		label := v.Label
		if label == "" {
			label = node
		}
		return endpointGeoPoint{
			Lat:    roundCoord(v.Lat),
			Lon:    roundCoord(v.Lon),
			Label:  label,
			Source: "configured",
		}
	}
	sum := sha256.Sum256([]byte(strings.ToLower(node)))
	latRaw := (uint16(sum[0]) << 8) | uint16(sum[1])
	lonRaw := (uint16(sum[2]) << 8) | uint16(sum[3])
	lat := -55.0 + (float64(latRaw)/65535.0)*125.0
	lon := -170.0 + (float64(lonRaw)/65535.0)*340.0
	return endpointGeoPoint{
		Lat:    roundCoord(lat),
		Lon:    roundCoord(lon),
		Label:  "Derived " + node,
		Source: "derived",
	}
}

func roundCoord(v float64) float64 {
	if v >= 0 {
		return float64(int64(v*10000.0+0.5)) / 10000.0
	}
	return float64(int64(v*10000.0-0.5)) / 10000.0
}

func endpointStatus(ep endpointSummary, nowMs int64, failedSafeCount int, geoSource string) string {
	if strings.TrimSpace(ep.NodeID) == "" || geoSource == "none" {
		return "unknown"
	}
	if failedSafeCount >= 3 || ep.EventCount1h == 0 {
		return "critical"
	}
	if ep.LastSeenUnixMs <= 0 {
		return "unknown"
	}
	age := nowMs - ep.LastSeenUnixMs
	if age > int64((15*time.Minute)/time.Millisecond) || ep.EventCount5m == 0 {
		return "warning"
	}
	return "active"
}

func mitreTacticFromRun(run incident) string {
	hay := strings.ToUpper(strings.Join([]string{
		run.RuleID,
		run.PlaybookID,
		run.EventType,
		run.SourceType,
		run.FailedSafeReason,
	}, "|"))
	switch {
	case strings.Contains(hay, "PRIVESC") || strings.Contains(hay, "PRIVILEGE"):
		return "Privilege Escalation"
	case strings.Contains(hay, "LATERAL"):
		return "Lateral Movement"
	case strings.Contains(hay, "DISCOVER") || strings.Contains(hay, "PROCESS"):
		return "Discovery"
	case strings.Contains(hay, "RANSOM") || strings.Contains(hay, "QUARANTINE") || strings.Contains(hay, "IMPACT"):
		return "Impact"
	case strings.Contains(hay, "C2") || strings.Contains(hay, "BEACON") || strings.Contains(hay, "COMMAND"):
		return "Command & Control"
	case strings.Contains(hay, "EXFIL"):
		return "Exfiltration"
	default:
		return ""
	}
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

func parseWindowMs(s string, fallback time.Duration) int64 {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return int64(fallback / time.Millisecond)
	}
	d, err := time.ParseDuration(s)
	if err == nil && d > 0 {
		return int64(d / time.Millisecond)
	}
	switch s {
	case "24h":
		return int64((24 * time.Hour) / time.Millisecond)
	case "7d":
		return int64((7 * 24 * time.Hour) / time.Millisecond)
	case "1h":
		return int64(time.Hour / time.Millisecond)
	case "15m":
		return int64((15 * time.Minute) / time.Millisecond)
	case "5m":
		return int64((5 * time.Minute) / time.Millisecond)
	}
	return int64(fallback / time.Millisecond)
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
