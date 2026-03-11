package main

import (
	"bufio"
	"bytes"
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
	"html"
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
	"r-siem-agent/internal/roe/trigger"
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
	defaultAgentCommandSub = "rsiem.agent.command"
	defaultUsersPath       = "configs/ui_users.json"
	defaultGeoEndpoints    = "configs/ui_geo_endpoints.json"
	defaultUIStatePath     = "retained/ui_state/ui_actions.jsonl"
	defaultUIStateDir      = "ui_state"
	defaultArtifactLimit   = 200
	maxArtifactPageLimit   = 1000
	maxArtifactScanEntries = 50000
	maxListLimit           = 2000
	maxArtifactListEntries = 1000
	defaultApprovalTimeout = int64(60000)
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

	ruleSeverityByID   map[string]string
	playbookApprovalBy map[string]string
	retentionRules     []retentionRule
	defaultAssetEnv    string
	assetByNodeID      map[string]assetInventoryEntry
	assetByTargetAgent map[string]assetInventoryEntry
	identityByUser     map[string]identityInventoryEntry
}

type assetInventoryEntry struct {
	Environment string
	Criticality string
	Owner       string
	Team        string
	Role        string
}

type identityInventoryEntry struct {
	DisplayName    string
	Department     string
	Manager        string
	Privileged     bool
	ServiceAccount bool
}

type dashboardHintsConfig struct {
	RCE struct {
		Rules []struct {
			ID       string `yaml:"id"`
			Severity string `yaml:"severity"`
		} `yaml:"rules"`
	} `yaml:"rce"`
	Playbooks []struct {
		ID                 string `yaml:"id"`
		PolicyRequirements struct {
			Approval string `yaml:"approval"`
		} `yaml:"policy_requirements"`
	} `yaml:"playbooks"`
	Policies struct {
		Assets struct {
			DefaultEnvironment string `yaml:"default_environment"`
			Nodes              []struct {
				NodeID        string `yaml:"node_id"`
				TargetAgentID string `yaml:"target_agent_id"`
				Environment   string `yaml:"environment"`
				Criticality   string `yaml:"criticality"`
				Owner         string `yaml:"owner"`
				Team          string `yaml:"team"`
				Role          string `yaml:"role"`
			} `yaml:"nodes"`
		} `yaml:"assets"`
		Identity struct {
			Users []struct {
				Username       string `yaml:"username"`
				DisplayName    string `yaml:"display_name"`
				Department     string `yaml:"department"`
				Manager        string `yaml:"manager"`
				Privileged     bool   `yaml:"privileged"`
				ServiceAccount bool   `yaml:"service_account"`
			} `yaml:"users"`
		} `yaml:"identity"`
		Retention struct {
			Rules []struct {
				ID   string `yaml:"id"`
				When struct {
					EnvironmentIn      []string `yaml:"environment_in"`
					LifecycleIn        []string `yaml:"lifecycle_in"`
					AssetCriticalityIn []string `yaml:"asset_criticality_in"`
					ServiceAccount     *bool    `yaml:"service_account"`
					HighImpact         *bool    `yaml:"high_impact"`
				} `yaml:"when"`
				Decision struct {
					Class            string `yaml:"class"`
					ArchiveAfterDays int    `yaml:"archive_after_days"`
					PurgeAfterDays   int    `yaml:"purge_after_days"`
				} `yaml:"decision"`
			} `yaml:"rules"`
		} `yaml:"retention"`
	} `yaml:"policies"`
}

type retentionRule struct {
	ID                 string
	EnvironmentIn      []string
	LifecycleIn        []string
	AssetCriticalityIn []string
	ServiceAccount     *bool
	HighImpact         *bool
	Class              string
	ArchiveAfterDays   int
	PurgeAfterDays     int
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

func (a *app) requestAgentCommand(subject string, req agentCommandRequest, timeout time.Duration) (agentCommandReply, error) {
	if err := a.ensureNATS(); err != nil {
		return agentCommandReply{}, err
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	data, err := json.Marshal(req)
	if err != nil {
		return agentCommandReply{}, err
	}
	a.mu.RLock()
	nc := a.nc
	a.mu.RUnlock()
	if nc == nil {
		return agentCommandReply{}, errors.New("nats unavailable")
	}
	msg, err := nc.Request(subject, data, timeout)
	if err != nil {
		return agentCommandReply{}, err
	}
	var reply agentCommandReply
	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return agentCommandReply{}, err
	}
	return reply, nil
}

type incident struct {
	RunID                    string `json:"run_id"`
	TriggerIdemKey           string `json:"trigger_idem_key,omitempty"`
	AlertKey                 string `json:"alert_key,omitempty"`
	Status                   string `json:"status"`
	RuleID                   string `json:"rule_id,omitempty"`
	PlaybookID               string `json:"playbook_id,omitempty"`
	PlaybookVersion          string `json:"playbook_version,omitempty"`
	Severity                 string `json:"severity,omitempty"`
	ConfidenceScore          int    `json:"confidence_score,omitempty"`
	Lane                     string `json:"lane,omitempty"`
	NodeID                   string `json:"node_id,omitempty"`
	AssetEnvironment         string `json:"asset_environment,omitempty"`
	AssetCriticality         string `json:"asset_criticality,omitempty"`
	AssetOwner               string `json:"asset_owner,omitempty"`
	AssetTeam                string `json:"asset_team,omitempty"`
	AssetRole                string `json:"asset_role,omitempty"`
	SourceType               string `json:"source_type,omitempty"`
	EventType                string `json:"event_type,omitempty"`
	SrcIP                    string `json:"src_ip,omitempty"`
	DstIP                    string `json:"dst_ip,omitempty"`
	User                     string `json:"user_name,omitempty"`
	ExecPath                 string `json:"exec_path,omitempty"`
	Comm                     string `json:"comm,omitempty"`
	Cmdline                  string `json:"cmdline,omitempty"`
	IdentityDisplayName      string `json:"identity_display_name,omitempty"`
	IdentityDepartment       string `json:"identity_department,omitempty"`
	IdentityManager          string `json:"identity_manager,omitempty"`
	IdentityPrivileged       bool   `json:"identity_privileged,omitempty"`
	IdentityServiceAccount   bool   `json:"identity_service_account,omitempty"`
	Target                   string `json:"target,omitempty"`
	TargetAgentID            string `json:"target_agent_id,omitempty"`
	Actor                    string `json:"actor,omitempty"`
	EventIdemKey             string `json:"event_idem_key,omitempty"`
	StepTotal                int    `json:"step_total,omitempty"`
	StepSucceededCount       int    `json:"step_succeeded_count,omitempty"`
	StepFailedSafeCount      int    `json:"step_failed_safe_count,omitempty"`
	StepFailedTransient      int    `json:"step_failed_transient_count,omitempty"`
	FailedSafeReason         string `json:"failed_safe_reason,omitempty"`
	OperatorAction           string `json:"operator_action,omitempty"`
	ApprovalPolicyMode       string `json:"approval_policy_mode,omitempty"`
	ApprovalPolicyRuleID     string `json:"approval_policy_rule_id,omitempty"`
	AllowlistRuleID          string `json:"allowlist_rule_id,omitempty"`
	ApprovalPolicyReason     string `json:"approval_policy_reason,omitempty"`
	PlaybookReversibility    string `json:"playbook_reversibility,omitempty"`
	ApprovalDecision         string `json:"approval_decision,omitempty"`
	ApprovalActor            string `json:"approval_actor,omitempty"`
	ApprovalRequestedAtMs    int64  `json:"approval_requested_at_unix_ms,omitempty"`
	ApprovalTimeoutMs        int64  `json:"approval_timeout_ms,omitempty"`
	LastUpdatedAtUnixMs      int64  `json:"last_updated_at_unix_ms,omitempty"`
	LifecycleState           string `json:"lifecycle_state,omitempty"`
	EnvironmentClass         string `json:"environment_class,omitempty"`
	RetentionClass           string `json:"retention_class,omitempty"`
	RetentionRuleID          string `json:"retention_rule_id,omitempty"`
	ArchiveAfterDays         int    `json:"archive_after_days,omitempty"`
	PurgeAfterDays           int    `json:"purge_after_days,omitempty"`
	AgeDays                  int    `json:"age_days,omitempty"`
	Archived                 bool   `json:"archived,omitempty"`
	PurgeEligible            bool   `json:"purge_eligible,omitempty"`
	IdentityWorkflowEligible bool   `json:"identity_workflow_eligible,omitempty"`
	IdentityWorkflowReason   string `json:"identity_workflow_reason,omitempty"`
	Source                   string `json:"source"`
}

type stepResult struct {
	RunID            string         `json:"run_id"`
	StepID           string         `json:"step_id"`
	StepIndex        int            `json:"step_index"`
	StepKey          string         `json:"step_key,omitempty"`
	Status           string         `json:"status"`
	ActionType       string         `json:"action_type,omitempty"`
	Lane             string         `json:"lane,omitempty"`
	Actor            string         `json:"actor,omitempty"`
	Attempt          int            `json:"attempt,omitempty"`
	FinishedAtMs     int64          `json:"finished_at_unix_ms,omitempty"`
	Target           string         `json:"target,omitempty"`
	TargetAgentID    string         `json:"target_agent_id,omitempty"`
	LastError        string         `json:"last_error,omitempty"`
	Receipt          map[string]any `json:"receipt,omitempty"`
	AllowlistRuleID  string         `json:"allowlist_rule_id,omitempty"`
	GuardrailRuleIDs []string       `json:"guardrail_rule_ids,omitempty"`
}

type createdMeta struct {
	RuleID                 string
	PlaybookID             string
	PlaybookVersion        string
	Severity               string
	NodeID                 string
	AssetEnvironment       string
	AssetCriticality       string
	AssetOwner             string
	AssetTeam              string
	AssetRole              string
	SourceType             string
	EventType              string
	SrcIP                  string
	DstIP                  string
	User                   string
	ExecPath               string
	Comm                   string
	Cmdline                string
	IdentityDisplayName    string
	IdentityDepartment     string
	IdentityManager        string
	IdentityPrivileged     bool
	IdentityServiceAccount bool
	TargetAgentID          string
	EventIdemKey           string
}

type eventRow struct {
	EventTSUnixMs int64  `json:"event_ts_unix_ms"`
	RecvTSUnixMs  int64  `json:"recv_ts_unix_ms"`
	NodeID        string `json:"node_id"`
	SourceType    string `json:"source_type"`
	EventType     string `json:"event_type"`
	SrcIP         string `json:"src_ip,omitempty"`
	DstIP         string `json:"dst_ip,omitempty"`
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

type seriesPoint struct {
	TS         int64 `json:"ts_unix_ms"`
	Count      int   `json:"count"`
	Fast       int   `json:"fast"`
	Standard   int   `json:"standard"`
	FailedSafe int   `json:"failed_safe"`
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
	Method         string `json:"method,omitempty"`
	Reference      string `json:"reference,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Scope          string `json:"scope,omitempty"`
	Result         string `json:"result,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

type agentCommandRequest struct {
	RunID         string         `json:"run_id"`
	StepID        string         `json:"step_id"`
	Lane          string         `json:"lane"`
	ActionType    string         `json:"action_type"`
	Target        string         `json:"target"`
	TargetAgentID string         `json:"target_agent_id,omitempty"`
	Params        map[string]any `json:"params"`
}

type agentCommandReply struct {
	Status          string `json:"status"`
	ExitCode        int    `json:"exit_code"`
	DurationMs      int64  `json:"duration_ms"`
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	TruncatedStdout bool   `json:"truncated_stdout,omitempty"`
	TruncatedStderr bool   `json:"truncated_stderr,omitempty"`
	ErrorClass      string `json:"error_class,omitempty"`
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
		cfg:                cfg,
		logger:             logger,
		users:              map[string]uiUser{},
		ruleSeverityByID:   map[string]string{},
		playbookApprovalBy: map[string]string{},
		retentionRules:     nil,
		assetByNodeID:      map[string]assetInventoryEntry{},
		assetByTargetAgent: map[string]assetInventoryEntry{},
		identityByUser:     map[string]identityInventoryEntry{},
	}
	a.ruleSeverityByID, a.playbookApprovalBy, a.retentionRules, a.defaultAssetEnv, a.assetByNodeID, a.assetByTargetAgent, a.identityByUser = loadDashboardHints(cfg.MasterConfig)
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
	mux.HandleFunc("POST /api/incidents/{run_id}/reissue", a.withAuthRole(a.handleIncidentReissue, "analyst"))
	mux.HandleFunc("POST /api/incidents/{run_id}/verify-user", a.withAuthRole(a.handleIncidentVerifyUser, "analyst"))
	mux.HandleFunc("POST /api/incidents/{run_id}/restore-access", a.withAuthRole(a.handleIncidentRestoreAccess, "analyst"))
	mux.HandleFunc("POST /api/incidents/{run_id}/assign", a.withAuthRole(a.handleIncidentAssign, "analyst"))
	mux.HandleFunc("POST /api/incidents/{run_id}/notes", a.withAuthRole(a.handleIncidentNotes, "analyst"))
	mux.HandleFunc("POST /api/incidents/{run_id}/review", a.withAuthRole(a.handleIncidentMarkReviewed, "analyst"))
	mux.HandleFunc("GET /api/incidents/{run_id}/events", a.withAuthRole(a.handleIncidentEvents, "analyst"))
	mux.HandleFunc("GET /api/incidents/{run_id}/report", a.withAuthRole(a.handleIncidentReport, "analyst"))
	mux.HandleFunc("GET /api/reports/soc/operations", a.withAuthRole(a.handleSOCOperationsReport, "analyst"))
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
	mux.HandleFunc("DELETE /api/users/{id}", a.withAuthRole(a.handleAdminUsersDelete, "admin"))
	mux.HandleFunc("POST /api/users/{id}/delete", a.withAuthRole(a.handleAdminUsersDelete, "admin"))
	mux.HandleFunc("POST /api/admin/incidents/purge_demo_test", a.withAuthRole(a.handleAdminPurgeDemoTestIncidents, "admin"))
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

func normalizeInventoryKey(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func loadDashboardHints(path string) (map[string]string, map[string]string, []retentionRule, string, map[string]assetInventoryEntry, map[string]assetInventoryEntry, map[string]identityInventoryEntry) {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}, map[string]string{}, defaultRetentionRules(), "", map[string]assetInventoryEntry{}, map[string]assetInventoryEntry{}, map[string]identityInventoryEntry{}
	}
	var cfg dashboardHintsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return map[string]string{}, map[string]string{}, defaultRetentionRules(), "", map[string]assetInventoryEntry{}, map[string]assetInventoryEntry{}, map[string]identityInventoryEntry{}
	}
	ruleSeverityByID := make(map[string]string, len(cfg.RCE.Rules))
	for _, rule := range cfg.RCE.Rules {
		id := strings.TrimSpace(rule.ID)
		sev := strings.ToLower(strings.TrimSpace(rule.Severity))
		if id == "" || sev == "" {
			continue
		}
		ruleSeverityByID[id] = sev
	}
	playbookApprovalBy := make(map[string]string, len(cfg.Playbooks))
	for _, pb := range cfg.Playbooks {
		id := strings.TrimSpace(pb.ID)
		approval := strings.ToLower(strings.TrimSpace(pb.PolicyRequirements.Approval))
		if id == "" || approval == "" {
			continue
		}
		playbookApprovalBy[id] = approval
	}
	retentionRules := make([]retentionRule, 0, len(cfg.Policies.Retention.Rules))
	for _, rule := range cfg.Policies.Retention.Rules {
		id := strings.TrimSpace(rule.ID)
		if id == "" {
			continue
		}
		retentionRules = append(retentionRules, retentionRule{
			ID:                 id,
			EnvironmentIn:      append([]string(nil), rule.When.EnvironmentIn...),
			LifecycleIn:        append([]string(nil), rule.When.LifecycleIn...),
			AssetCriticalityIn: append([]string(nil), rule.When.AssetCriticalityIn...),
			ServiceAccount:     rule.When.ServiceAccount,
			HighImpact:         rule.When.HighImpact,
			Class:              strings.TrimSpace(rule.Decision.Class),
			ArchiveAfterDays:   rule.Decision.ArchiveAfterDays,
			PurgeAfterDays:     rule.Decision.PurgeAfterDays,
		})
	}
	if len(retentionRules) == 0 {
		retentionRules = defaultRetentionRules()
	}
	defaultAssetEnv := strings.TrimSpace(cfg.Policies.Assets.DefaultEnvironment)
	assetByNodeID := make(map[string]assetInventoryEntry, len(cfg.Policies.Assets.Nodes))
	assetByTargetAgent := make(map[string]assetInventoryEntry, len(cfg.Policies.Assets.Nodes))
	for _, node := range cfg.Policies.Assets.Nodes {
		entry := assetInventoryEntry{
			Environment: strings.TrimSpace(node.Environment),
			Criticality: strings.TrimSpace(node.Criticality),
			Owner:       strings.TrimSpace(node.Owner),
			Team:        strings.TrimSpace(node.Team),
			Role:        strings.TrimSpace(node.Role),
		}
		if key := normalizeInventoryKey(node.NodeID); key != "" {
			assetByNodeID[key] = entry
		}
		if key := normalizeInventoryKey(node.TargetAgentID); key != "" {
			assetByTargetAgent[key] = entry
		}
	}
	identityByUser := make(map[string]identityInventoryEntry, len(cfg.Policies.Identity.Users))
	for _, user := range cfg.Policies.Identity.Users {
		key := normalizeInventoryKey(user.Username)
		if key == "" {
			continue
		}
		identityByUser[key] = identityInventoryEntry{
			DisplayName:    strings.TrimSpace(user.DisplayName),
			Department:     strings.TrimSpace(user.Department),
			Manager:        strings.TrimSpace(user.Manager),
			Privileged:     user.Privileged,
			ServiceAccount: user.ServiceAccount,
		}
	}
	return ruleSeverityByID, playbookApprovalBy, retentionRules, defaultAssetEnv, assetByNodeID, assetByTargetAgent, identityByUser
}

func defaultRetentionRules() []retentionRule {
	return []retentionRule{
		{
			ID:               "demo_test",
			EnvironmentIn:    []string{"demo_test"},
			Class:            "demo_test",
			ArchiveAfterDays: 7,
			PurgeAfterDays:   14,
		},
		{
			ID:               "operational_high_review",
			HighImpact:       boolPtr(true),
			Class:            "operational_high_review",
			ArchiveAfterDays: 30,
			PurgeAfterDays:   365,
		},
		{
			ID:               "operational_standard",
			Class:            "operational_standard",
			ArchiveAfterDays: 30,
			PurgeAfterDays:   180,
		},
	}
}

func boolPtr(v bool) *bool {
	return &v
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
			{"method": "GET", "path": "/api/incidents", "summary": "List incidents", "query": []string{"status", "severity", "lane", "playbook_id", "rule_id", "node_id", "lifecycle", "environment", "view=active|archived|all", "from", "to", "q", "limit", "page", "sort"}},
			{"method": "GET", "path": "/api/incidents/{run_id}", "summary": "Incident detail"},
			{"method": "POST", "path": "/api/incidents/{run_id}/approve", "summary": "Approve/reject FAST action", "body": map[string]string{"decision": "approve|reject|deny", "actor": "string"}},
			{"method": "POST", "path": "/api/incidents/{run_id}/reject", "summary": "Reject FAST action", "body": map[string]string{"actor": "string"}},
			{"method": "POST", "path": "/api/incidents/{run_id}/reissue", "summary": "Re-issue a fresh response trigger for MANUAL_REVIEW_REQUIRED runs", "body": map[string]string{"actor": "string", "reason": "string"}},
			{"method": "POST", "path": "/api/incidents/{run_id}/assign", "summary": "Assign run to analyst/admin", "body": map[string]string{"assignee": "string"}},
			{"method": "POST", "path": "/api/incidents/{run_id}/notes", "summary": "Add incident note", "body": map[string]string{"note": "string"}},
			{"method": "POST", "path": "/api/incidents/{run_id}/review", "summary": "Mark run reviewed"},
			{"method": "GET", "path": "/api/incidents/{run_id}/events", "summary": "Timeline events around incident", "query": []string{"window_seconds"}},
			{"method": "GET", "path": "/api/incidents/{run_id}/report", "summary": "Incident report download", "query": []string{"format=json|html|pdf"}},
			{"method": "GET", "path": "/api/reports/soc/operations", "summary": "SOC operations report download", "query": []string{"window", "bucket", "format=json|html|pdf"}},
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
			{"method": "DELETE", "path": "/api/users/{id}", "summary": "Delete user (admin only)"},
			{"method": "POST", "path": "/api/admin/incidents/purge_demo_test", "summary": "Mask archived demo/test incidents older than retention threshold", "body": map[string]string{"older_than_days": "optional integer", "dry_run": "true|false", "actor": "optional string"}},
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
	lifecycleFilter := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("lifecycle")))
	environmentFilter := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("environment")))
	viewFilter := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("view")))
	if viewFilter == "" {
		viewFilter = "active"
	}
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
		if lifecycleFilter != "" && strings.ToLower(run.LifecycleState) != lifecycleFilter {
			continue
		}
		if environmentFilter != "" && strings.ToLower(run.EnvironmentClass) != environmentFilter {
			continue
		}
		switch viewFilter {
		case "active":
			if run.Archived {
				continue
			}
		case "archived":
			if !run.Archived {
				continue
			}
		case "all":
		default:
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
			hay := strings.ToLower(strings.Join([]string{run.RunID, run.RuleID, run.PlaybookID, run.NodeID, run.SourceType, run.EventType, run.SrcIP, run.DstIP, run.User}, "|"))
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
		"view":   viewFilter,
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

func normalizeIncidentLane(lane, severity string) string {
	switch strings.ToUpper(strings.TrimSpace(lane)) {
	case "FAST":
		return "FAST"
	case "STANDARD":
		return "STANDARD"
	}
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return "FAST"
	default:
		return "STANDARD"
	}
}

func reissueGrouping(run incident) (string, string) {
	switch {
	case strings.TrimSpace(run.SrcIP) != "":
		return "src_ip", strings.TrimSpace(run.SrcIP)
	case strings.TrimSpace(run.User) != "":
		return "user", strings.TrimSpace(run.User)
	case strings.TrimSpace(run.NodeID) != "":
		return "node_id", strings.TrimSpace(run.NodeID)
	default:
		return "run_id", strings.TrimSpace(run.RunID)
	}
}

func enrichIncidentFromCreatedMeta(run incident, meta createdMeta) incident {
	run.RuleID = chooseNonEmpty(meta.RuleID, run.RuleID)
	run.PlaybookID = chooseNonEmpty(meta.PlaybookID, run.PlaybookID)
	run.PlaybookVersion = chooseNonEmpty(meta.PlaybookVersion, run.PlaybookVersion)
	run.Severity = chooseNonEmpty(meta.Severity, run.Severity)
	run.NodeID = chooseNonEmpty(meta.NodeID, run.NodeID)
	run.AssetEnvironment = chooseNonEmpty(meta.AssetEnvironment, run.AssetEnvironment)
	run.AssetCriticality = chooseNonEmpty(meta.AssetCriticality, run.AssetCriticality)
	run.AssetOwner = chooseNonEmpty(meta.AssetOwner, run.AssetOwner)
	run.AssetTeam = chooseNonEmpty(meta.AssetTeam, run.AssetTeam)
	run.AssetRole = chooseNonEmpty(meta.AssetRole, run.AssetRole)
	run.SourceType = chooseNonEmpty(meta.SourceType, run.SourceType)
	run.EventType = chooseNonEmpty(meta.EventType, run.EventType)
	run.SrcIP = chooseNonEmpty(meta.SrcIP, run.SrcIP)
	run.DstIP = chooseNonEmpty(meta.DstIP, run.DstIP)
	run.User = chooseNonEmpty(meta.User, run.User)
	run.ExecPath = chooseNonEmpty(meta.ExecPath, run.ExecPath)
	run.Comm = chooseNonEmpty(meta.Comm, run.Comm)
	run.Cmdline = chooseNonEmpty(meta.Cmdline, run.Cmdline)
	run.IdentityDisplayName = chooseNonEmpty(meta.IdentityDisplayName, run.IdentityDisplayName)
	run.IdentityDepartment = chooseNonEmpty(meta.IdentityDepartment, run.IdentityDepartment)
	run.IdentityManager = chooseNonEmpty(meta.IdentityManager, run.IdentityManager)
	run.IdentityPrivileged = run.IdentityPrivileged || meta.IdentityPrivileged
	run.IdentityServiceAccount = run.IdentityServiceAccount || meta.IdentityServiceAccount
	run.TargetAgentID = chooseNonEmpty(meta.TargetAgentID, run.TargetAgentID)
	run.EventIdemKey = chooseNonEmpty(meta.EventIdemKey, run.EventIdemKey)
	return run
}

func (a *app) enrichIncidentFromInventory(run incident) incident {
	if key := normalizeInventoryKey(run.NodeID); key != "" {
		if asset, ok := a.assetByNodeID[key]; ok {
			run.AssetEnvironment = chooseNonEmpty(asset.Environment, run.AssetEnvironment)
			run.AssetCriticality = chooseNonEmpty(asset.Criticality, run.AssetCriticality)
			run.AssetOwner = chooseNonEmpty(asset.Owner, run.AssetOwner)
			run.AssetTeam = chooseNonEmpty(asset.Team, run.AssetTeam)
			run.AssetRole = chooseNonEmpty(asset.Role, run.AssetRole)
		}
	}
	if (run.AssetEnvironment == "" || run.AssetCriticality == "" || run.AssetOwner == "" || run.AssetTeam == "" || run.AssetRole == "") && run.TargetAgentID != "" {
		if asset, ok := a.assetByTargetAgent[normalizeInventoryKey(run.TargetAgentID)]; ok {
			run.AssetEnvironment = chooseNonEmpty(asset.Environment, run.AssetEnvironment)
			run.AssetCriticality = chooseNonEmpty(asset.Criticality, run.AssetCriticality)
			run.AssetOwner = chooseNonEmpty(asset.Owner, run.AssetOwner)
			run.AssetTeam = chooseNonEmpty(asset.Team, run.AssetTeam)
			run.AssetRole = chooseNonEmpty(asset.Role, run.AssetRole)
		}
	}
	if run.AssetEnvironment == "" {
		run.AssetEnvironment = strings.TrimSpace(a.defaultAssetEnv)
	}
	userKey := normalizeInventoryKey(run.User)
	if userKey != "" && userKey != "unknown" {
		if ident, ok := a.identityByUser[userKey]; ok {
			run.IdentityDisplayName = chooseNonEmpty(ident.DisplayName, run.IdentityDisplayName)
			run.IdentityDepartment = chooseNonEmpty(ident.Department, run.IdentityDepartment)
			run.IdentityManager = chooseNonEmpty(ident.Manager, run.IdentityManager)
			run.IdentityPrivileged = run.IdentityPrivileged || ident.Privileged
			run.IdentityServiceAccount = run.IdentityServiceAccount || ident.ServiceAccount
		}
	}
	return run
}

func (a *app) waitForRunByAlertKey(alertKey string, excludeRunID string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		runs, _, _ := a.loadState()
		for i := range runs {
			if strings.EqualFold(strings.TrimSpace(runs[i].AlertKey), alertKey) && !strings.EqualFold(strings.TrimSpace(runs[i].RunID), excludeRunID) {
				return strings.TrimSpace(runs[i].RunID)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return ""
}

func findIncidentByRunID(runs []incident, runID string) *incident {
	runID = strings.TrimSpace(runID)
	for i := range runs {
		if strings.EqualFold(strings.TrimSpace(runs[i].RunID), runID) {
			r := runs[i]
			return &r
		}
	}
	return nil
}

func isIdentityAccessIncident(run incident) bool {
	ruleID := strings.ToUpper(strings.TrimSpace(run.RuleID))
	playbookID := strings.ToUpper(strings.TrimSpace(run.PlaybookID))
	if strings.HasPrefix(ruleID, "R-AUTH-") || strings.HasPrefix(playbookID, "PB-AUTH-") {
		return true
	}
	return ruleID == "R-COLLECT-INVALID-USER"
}

func identityWorkflowEligibility(run incident) (bool, string) {
	if !isIdentityAccessIncident(run) {
		return false, "Identity workflow is only available for auth-identity incidents."
	}
	playbookID := strings.ToUpper(strings.TrimSpace(run.PlaybookID))
	if playbookID != "PB-AUTH-ABUSE-CONTAIN" {
		return false, "Identity workflow is only available after PB-AUTH-ABUSE-CONTAIN runs."
	}
	status := strings.ToUpper(strings.TrimSpace(run.Status))
	switch status {
	case "SUCCEEDED":
		if run.StepSucceededCount <= 0 {
			return false, "Containment has not completed successfully for this run."
		}
		return true, ""
	case "WAITING_APPROVAL":
		return false, "Containment has not run yet. Approve and complete containment before verification or restore."
	case "MANUAL_REVIEW_REQUIRED":
		return false, "Containment did not execute. Re-issue and complete containment before verification or restore."
	case "FAILED_SAFE", "FAILED_TRANSIENT", "DENIED", "TIMED_OUT", "CANCELLED", "CLOSED":
		return false, "Containment did not complete successfully for this run."
	default:
		return false, "Identity workflow becomes available only after a successful containment run."
	}
}

func agentCommandSubjectForIncident(run incident) string {
	targetAgentID := strings.TrimSpace(run.TargetAgentID)
	if targetAgentID == "" {
		return defaultAgentCommandSub
	}
	return defaultAgentCommandSub + "." + targetAgentID
}

func safeDeniedHTTPStatus(reply agentCommandReply) int {
	if strings.EqualFold(strings.TrimSpace(reply.ErrorClass), "SAFE_DENIED") {
		return http.StatusConflict
	}
	return http.StatusBadGateway
}

func (a *app) handleIncidentReissue(w http.ResponseWriter, r *http.Request) {
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
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "actor is required"})
		return
	}

	runs, _, created := a.loadState()
	var found *incident
	for i := range runs {
		if strings.EqualFold(strings.TrimSpace(runs[i].RunID), runID) {
			found = &runs[i]
			break
		}
	}
	if found == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "incident not found"})
		return
	}
	*found = enrichIncidentFromCreatedMeta(*found, created[runID])
	if strings.ToUpper(strings.TrimSpace(found.Status)) != "MANUAL_REVIEW_REQUIRED" {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "reissue only allowed for MANUAL_REVIEW_REQUIRED incidents"})
		return
	}
	if strings.TrimSpace(found.RuleID) == "" {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "incident is missing rule_id and cannot be reissued"})
		return
	}
	if isIdentityAccessIncident(*found) {
		if strings.TrimSpace(found.SrcIP) == "" || strings.TrimSpace(found.User) == "" || strings.TrimSpace(found.NodeID) == "" {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "identity reissue requires original auth context (src_ip, user, node_id)"})
			return
		}
	}
	if err := a.ensureNATS(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "nats unavailable"})
		return
	}
	publisher, err := trigger.NewPublisher(a.logger, a.js)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	nowMs := now.UnixMilli()
	groupBy, groupKey := reissueGrouping(*found)
	groupKey = fmt.Sprintf("%s.reissue.%d", groupKey, nowMs)
	lane := normalizeIncidentLane(found.Lane, found.Severity)
	alertKeyBase := strings.ReplaceAll(strings.TrimSpace(found.RuleID), " ", "-")
	if alertKeyBase == "" {
		alertKeyBase = "REISSUE"
	}
	alertKey := fmt.Sprintf("A-REISSUE-%s-%d", alertKeyBase, nowMs)
	reissueReason := strings.TrimSpace(body.Reason)
	if reissueReason == "" {
		reissueReason = "manual review reissue requested from incident workspace"
	}

	subject, triggerID, err := publisher.PublishAlert(trigger.Alert{
		AlertKey:         alertKey,
		RuleID:           strings.TrimSpace(found.RuleID),
		Severity:         strings.TrimSpace(found.Severity),
		ConfidenceScore:  found.ConfidenceScore,
		Lane:             lane,
		GroupBy:          groupBy,
		GroupKey:         groupKey,
		ObservedAtUnixMs: nowMs,
		EventTsUnixMs:    nowMs,
		AlertTsUnixMs:    nowMs,
		NodeID:           strings.TrimSpace(found.NodeID),
		SourceType:       strings.TrimSpace(found.SourceType),
		EventType:        strings.TrimSpace(found.EventType),
		SrcIP:            strings.TrimSpace(found.SrcIP),
		User:             strings.TrimSpace(found.User),
		EventIdemKey:     strings.TrimSpace(found.EventIdemKey),
		AgentID:          strings.TrimSpace(found.TargetAgentID),
		TargetAgentID:    strings.TrimSpace(found.TargetAgentID),
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}

	a.logger.Info("ui_response_reissued",
		slog.String("previous_run_id", runID),
		slog.String("rule_id", found.RuleID),
		slog.String("lane", lane),
		slog.String("actor", actor),
		slog.String("reason", reissueReason),
		slog.String("subject", subject),
		slog.String("trigger_idem_key", triggerID),
		slog.String("alert_key", alertKey),
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"previous_run_id":  runID,
		"new_run_id":       a.waitForRunByAlertKey(alertKey, runID, 3*time.Second),
		"rule_id":          found.RuleID,
		"lane":             lane,
		"subject":          subject,
		"trigger_idem_key": triggerID,
		"alert_key":        alertKey,
		"actor":            actor,
		"reason":           reissueReason,
		"ts":               now.Format(time.RFC3339),
	})
}

func (a *app) handleIncidentVerifyUser(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}
	roleCtx := roleFromRequest(r)
	var body struct {
		Actor                 string `json:"actor"`
		VerificationMethod    string `json:"verification_method"`
		VerificationReference string `json:"verification_reference"`
		Notes                 string `json:"notes"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	actor := strings.TrimSpace(body.Actor)
	if actor == "" {
		actor = roleCtx.Username
	}
	method := strings.TrimSpace(body.VerificationMethod)
	reference := strings.TrimSpace(body.VerificationReference)
	if actor == "" || method == "" || reference == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "actor, verification_method, and verification_reference are required"})
		return
	}

	runs, _, _ := a.loadState()
	found := findIncidentByRunID(runs, runID)
	if found == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "incident not found"})
		return
	}
	if !isIdentityAccessIncident(*found) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "identity verification is only supported for auth-identity incidents"})
		return
	}
	if ok, reason := identityWorkflowEligibility(*found); !ok {
		writeJSON(w, http.StatusConflict, map[string]any{"error": reason})
		return
	}

	req := agentCommandRequest{
		RunID:         runID,
		StepID:        fmt.Sprintf("verify-user.%d", time.Now().UnixMilli()),
		Lane:          normalizeIncidentLane(found.Lane, found.Severity),
		ActionType:    "agent_command",
		Target:        strings.TrimSpace(found.SrcIP),
		TargetAgentID: strings.TrimSpace(found.TargetAgentID),
		Params: map[string]any{
			"command":                "auth_mark_user_verified",
			"containment_run_id":     runID,
			"node_id":                strings.TrimSpace(found.NodeID),
			"user_name":              strings.TrimSpace(found.User),
			"src_ip":                 strings.TrimSpace(found.SrcIP),
			"verified_by":            actor,
			"actor":                  actor,
			"verification_method":    method,
			"verification_reference": reference,
			"notes":                  strings.TrimSpace(body.Notes),
		},
	}
	reply, err := a.requestAgentCommand(agentCommandSubjectForIncident(*found), req, 5*time.Second)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(reply.Status), "ok") {
		eventName := "identity_verification_failed_safe"
		if !strings.EqualFold(strings.TrimSpace(reply.ErrorClass), "SAFE_DENIED") {
			eventName = "identity_verification_failed"
		}
		a.logger.Info(eventName,
			slog.String("run_id", runID),
			slog.String("actor", actor),
			slog.String("verification_method", method),
			slog.String("verification_reference", reference),
			slog.String("error_class", reply.ErrorClass),
			slog.String("stderr", reply.Stderr),
		)
		writeJSON(w, safeDeniedHTTPStatus(reply), map[string]any{
			"error":       strings.TrimSpace(reply.Stderr),
			"error_class": reply.ErrorClass,
			"reply":       reply,
		})
		return
	}

	rec := uiStateRecord{
		TS:        time.Now().UTC().Format(time.RFC3339Nano),
		Action:    "verify_user",
		RunID:     runID,
		Actor:     actor,
		Note:      strings.TrimSpace(body.Notes),
		Method:    method,
		Reference: reference,
		Status:    "verified",
		Result:    "ok",
	}
	rec.IdempotencyKey = a.uiStateIdempotencyKey(rec)
	if err := a.appendUIStateRecord(a.identityStatePath(), rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	a.logger.Info("identity_verification_completed",
		slog.String("run_id", runID),
		slog.String("actor", actor),
		slog.String("verification_method", method),
		slog.String("verification_reference", reference),
		slog.String("status", "verified"),
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                     true,
		"run_id":                 runID,
		"actor":                  actor,
		"verification_method":    method,
		"verification_reference": reference,
		"status":                 "verified",
		"reply":                  reply,
	})
}

func (a *app) handleIncidentRestoreAccess(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}
	roleCtx := roleFromRequest(r)
	var body struct {
		Actor           string `json:"actor"`
		Scope           string `json:"scope"`
		Reason          string `json:"reason"`
		ChangeReference string `json:"change_reference"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	actor := strings.TrimSpace(body.Actor)
	if actor == "" {
		actor = roleCtx.Username
	}
	scope := strings.ToLower(strings.TrimSpace(body.Scope))
	if scope == "" {
		scope = "both"
	}
	reason := strings.TrimSpace(body.Reason)
	if actor == "" || reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "actor and reason are required"})
		return
	}

	runs, _, _ := a.loadState()
	found := findIncidentByRunID(runs, runID)
	if found == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "incident not found"})
		return
	}
	if !isIdentityAccessIncident(*found) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "access restore is only supported for auth-identity incidents"})
		return
	}
	if ok, reason := identityWorkflowEligibility(*found); !ok {
		writeJSON(w, http.StatusConflict, map[string]any{"error": reason})
		return
	}

	commandIDs := make([]string, 0, 2)
	switch scope {
	case "src_ip":
		commandIDs = append(commandIDs, "auth_restore_src_ip")
	case "user":
		commandIDs = append(commandIDs, "auth_restore_user_access")
	case "both":
		commandIDs = append(commandIDs, "auth_restore_src_ip", "auth_restore_user_access")
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "scope must be one of src_ip, user, both"})
		return
	}

	subject := agentCommandSubjectForIncident(*found)
	results := make([]map[string]any, 0, len(commandIDs))
	for _, commandID := range commandIDs {
		req := agentCommandRequest{
			RunID:         runID,
			StepID:        fmt.Sprintf("restore-access.%s.%d", commandID, time.Now().UnixMilli()),
			Lane:          normalizeIncidentLane(found.Lane, found.Severity),
			ActionType:    "agent_command",
			Target:        strings.TrimSpace(found.SrcIP),
			TargetAgentID: strings.TrimSpace(found.TargetAgentID),
			Params: map[string]any{
				"command":             commandID,
				"containment_run_id":  runID,
				"node_id":             strings.TrimSpace(found.NodeID),
				"user_name":           strings.TrimSpace(found.User),
				"src_ip":              strings.TrimSpace(found.SrcIP),
				"verified_by":         actor,
				"actor":               actor,
				"reason":              reason,
				"change_reference":    strings.TrimSpace(body.ChangeReference),
				"verification_reason": reason,
			},
		}
		reply, err := a.requestAgentCommand(subject, req, 5*time.Second)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		if !strings.EqualFold(strings.TrimSpace(reply.Status), "ok") {
			eventName := "auth_restore_failed_safe"
			if !strings.EqualFold(strings.TrimSpace(reply.ErrorClass), "SAFE_DENIED") {
				eventName = "auth_access_restore_failed"
			}
			a.logger.Info(eventName,
				slog.String("run_id", runID),
				slog.String("actor", actor),
				slog.String("scope", scope),
				slog.String("command_id", commandID),
				slog.String("error_class", reply.ErrorClass),
				slog.String("stderr", reply.Stderr),
			)
			writeJSON(w, safeDeniedHTTPStatus(reply), map[string]any{
				"error":       strings.TrimSpace(reply.Stderr),
				"error_class": reply.ErrorClass,
				"command_id":  commandID,
				"reply":       reply,
			})
			return
		}
		results = append(results, map[string]any{
			"command_id": commandID,
			"reply":      reply,
		})
	}

	rec := uiStateRecord{
		TS:        time.Now().UTC().Format(time.RFC3339Nano),
		Action:    "restore_access",
		RunID:     runID,
		Actor:     actor,
		Reason:    reason,
		Reference: strings.TrimSpace(body.ChangeReference),
		Scope:     scope,
		Status:    "restored",
		Result:    "ok",
	}
	rec.IdempotencyKey = a.uiStateIdempotencyKey(rec)
	if err := a.appendUIStateRecord(a.identityStatePath(), rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	a.logger.Info("auth_access_restored",
		slog.String("run_id", runID),
		slog.String("actor", actor),
		slog.String("scope", scope),
		slog.String("reason", reason),
		slog.String("change_reference", strings.TrimSpace(body.ChangeReference)),
		slog.String("status", "restored"),
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"run_id":           runID,
		"actor":            actor,
		"scope":            scope,
		"reason":           reason,
		"change_reference": strings.TrimSpace(body.ChangeReference),
		"status":           "restored",
		"results":          results,
	})
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
	fromMs := parseInt64(r.URL.Query().Get("from"), 0)
	toMs := parseInt64(r.URL.Query().Get("to"), 0)
	items, meta, err := a.loadIncidentTimeline(r.Context(), *run, limit, windowSec, fromMs, toMs, pivotNode, pivotSrcIP, pivotUser)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":      items,
		"count":      len(items),
		"source":     meta["source"],
		"query_mode": meta["query_mode"],
		"from":       meta["from"],
		"to":         meta["to"],
	})
}

func (a *app) loadIncidentTimeline(ctx context.Context, run incident, limit int, windowSec int64, fromMs int64, toMs int64, pivotNode, pivotSrcIP, pivotUser string) ([]eventRow, map[string]any, error) {
	if a.db == nil {
		return []eventRow{}, map[string]any{"source": "exports", "query_mode": "none"}, nil
	}
	center := run.LastUpdatedAtUnixMs
	if center <= 0 {
		center = time.Now().UnixMilli()
	}
	if fromMs <= 0 {
		fromMs = center - (windowSec * 1000)
	}
	if toMs <= 0 {
		toMs = center + (windowSec * 1000)
	}
	if fromMs > toMs {
		fromMs, toMs = toMs, fromMs
	}
	loadEvents := func(clauses []string, args []any) ([]eventRow, error) {
		query := "SELECT event_ts_unix_ms, recv_ts_unix_ms, node_id, source_type, event_type, COALESCE(src_ip::text,''), COALESCE(dst_ip::text,''), COALESCE(user_name,''), COALESCE(severity,''), COALESCE(rule_id,''), event_idem_key FROM normalized_events WHERE " + strings.Join(clauses, " AND ") + fmt.Sprintf(" ORDER BY recv_ts_unix_ms DESC LIMIT %d", limit)
		rows, err := a.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		items := make([]eventRow, 0, 128)
		for rows.Next() {
			var ev eventRow
			if err := rows.Scan(&ev.EventTSUnixMs, &ev.RecvTSUnixMs, &ev.NodeID, &ev.SourceType, &ev.EventType, &ev.SrcIP, &ev.DstIP, &ev.UserName, &ev.Severity, &ev.RuleID, &ev.EventIdemKey); err == nil {
				items = append(items, ev)
			}
		}
		return items, nil
	}
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
		return nil, nil, err
	}
	if len(items) > 0 {
		return items, map[string]any{"source": "db", "query_mode": "strict", "from": fromMs, "to": toMs}, nil
	}
	wideWindowSec := windowSec * 2
	if wideWindowSec < 1800 {
		wideWindowSec = 1800
	}
	fallbackFrom := center - (wideWindowSec * 1000)
	fallbackTo := center + (wideWindowSec * 1000)
	fallbackClauses := []string{"recv_ts_unix_ms BETWEEN $1 AND $2"}
	fallbackArgs := []any{fallbackFrom, fallbackTo}
	idx = 3
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
		return nil, nil, err
	}
	return items, map[string]any{"source": "db", "query_mode": "fallback", "from": fallbackFrom, "to": fallbackTo}, nil
}

func (a *app) handleIncidentReport(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	runs, stepsByRun, _ := a.loadState()
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
	steps := stepsByRun[runID]
	events, timelineMeta, err := a.loadIncidentTimeline(r.Context(), *run, 250, 900, 0, 0, "", "", "")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	uiState := a.loadUIStateForRun(runID)
	report := a.buildIncidentReport(*run, steps, events, uiState, timelineMeta)
	filenameBase := fmt.Sprintf("incident_report_%s", runID)
	switch format {
	case "json":
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filenameBase+".json"))
		writeJSON(w, http.StatusOK, report)
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filenameBase+".html"))
		_, _ = w.Write([]byte(renderIncidentReportHTML(report)))
	case "pdf":
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filenameBase+".pdf"))
		_, _ = w.Write(renderIncidentReportPDF(report))
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "format must be json, html, or pdf"})
	}
}

func defaultSOCBucket(windowMs int64) int64 {
	switch {
	case windowMs <= int64(time.Hour/time.Millisecond):
		return int64(5 * time.Minute / time.Millisecond)
	case windowMs <= int64(24*time.Hour/time.Millisecond):
		return int64(time.Hour / time.Millisecond)
	case windowMs <= int64(7*24*time.Hour/time.Millisecond):
		return int64(6 * time.Hour / time.Millisecond)
	default:
		return int64(24 * time.Hour / time.Millisecond)
	}
}

func (a *app) handleSOCOperationsReport(w http.ResponseWriter, r *http.Request) {
	windowMs := parseWindowMs(r.URL.Query().Get("window"), 24*time.Hour)
	bucketMs := parseWindowMs(r.URL.Query().Get("bucket"), 0)
	if bucketMs <= 0 {
		bucketMs = defaultSOCBucket(windowMs)
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	roleCtx := roleFromRequest(r)
	report, err := a.buildSOCOperationsReport(r.Context(), roleCtx, windowMs, bucketMs, 20, 30)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	ts := time.Now().UTC().Format("20060102_150405")
	filenameBase := fmt.Sprintf("soc_operations_report_%s_%s", normalizeWindowLabel(windowMs), ts)
	switch format {
	case "json":
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filenameBase+".json"))
		writeJSON(w, http.StatusOK, report)
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filenameBase+".html"))
		_, _ = w.Write([]byte(renderSOCOperationsReportHTML(report)))
	case "pdf":
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filenameBase+".pdf"))
		_, _ = w.Write(renderSOCOperationsReportPDF(report))
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "format must be json, html, or pdf"})
	}
}

func (a *app) buildSOCOperationsReport(ctx context.Context, roleCtx roleContext, windowMs, bucketMs int64, incidentLimit, auditLimit int) (map[string]any, error) {
	nowMs := time.Now().UnixMilli()
	fromMs := nowMs - windowMs
	runs, _, _ := a.loadState()

	incidents := 0
	waiting := 0
	failedSafe := 0
	criticalIncidents := 0
	activeNodes := map[string]struct{}{}
	totalEventsWindow := int64(0)
	modelAlertsWindow := int64(0)
	ingestionPerMin := 0.0
	latencyP95Ms := int64(0)
	maxLatencySampleMs := int64(10 * time.Minute / time.Millisecond)

	statusCounts := map[string]int{}
	severityCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
	laneCounts := map[string]int{"FAST": 0, "STANDARD": 0, "UNKNOWN": 0}
	manualReviewRuns := 0
	autoRuns := 0

	points := map[int64]*seriesPoint{}

	recent := make([]incident, 0, incidentLimit*2)
	for _, run := range runs {
		if run.LastUpdatedAtUnixMs < fromMs {
			continue
		}
		incidents++
		recent = append(recent, run)
		status := strings.ToUpper(strings.TrimSpace(run.Status))
		if status == "" {
			status = "UNKNOWN"
		}
		statusCounts[status]++
		if status == "WAITING_APPROVAL" {
			waiting++
			manualReviewRuns++
		}
		if status == "FAILED_SAFE" {
			failedSafe++
		}
		if severityRank(run.Severity) >= severityRank("critical") {
			criticalIncidents++
		}
		if run.NodeID != "" {
			activeNodes[run.NodeID] = struct{}{}
		}

		sev := strings.ToLower(strings.TrimSpace(run.Severity))
		if sev == "" {
			sev = "unknown"
		}
		if _, ok := severityCounts[sev]; !ok {
			severityCounts[sev] = 0
		}
		severityCounts[sev]++

		lane := strings.ToUpper(strings.TrimSpace(run.Lane))
		switch lane {
		case "FAST":
			laneCounts["FAST"]++
		case "STANDARD":
			laneCounts["STANDARD"]++
		default:
			lane = "UNKNOWN"
			laneCounts["UNKNOWN"]++
		}

		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(run.ApprovalPolicyMode)), "auto") {
			autoRuns++
		}

		b := (run.LastUpdatedAtUnixMs / bucketMs) * bucketMs
		p := points[b]
		if p == nil {
			p = &seriesPoint{TS: b}
			points[b] = p
		}
		p.Count++
		switch lane {
		case "FAST":
			p.Fast++
		case "STANDARD":
			p.Standard++
		}
		if status == "FAILED_SAFE" {
			p.FailedSafe++
		}
	}
	if a.db != nil {
		var c int64
		if err := a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM normalized_events WHERE recv_ts_unix_ms >= $1`, nowMs-5*60*1000).Scan(&c); err == nil {
			ingestionPerMin = float64(c) / 5.0
		}
		_ = a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM normalized_events WHERE recv_ts_unix_ms >= $1`, fromMs).Scan(&totalEventsWindow)
		_ = a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM normalized_events WHERE recv_ts_unix_ms >= $1 AND COALESCE(rule_id,'') <> ''`, fromMs).Scan(&modelAlertsWindow)
		var p95 sql.NullFloat64
		if err := a.db.QueryRowContext(ctx, `
SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY GREATEST(recv_ts_unix_ms - event_ts_unix_ms,0))
FROM normalized_events
WHERE recv_ts_unix_ms >= $1
  AND event_ts_unix_ms > 0
  AND event_ts_unix_ms <= recv_ts_unix_ms
  AND recv_ts_unix_ms - event_ts_unix_ms <= $2
`, fromMs, maxLatencySampleMs).Scan(&p95); err == nil && p95.Valid {
			latencyP95Ms = int64(p95.Float64)
		}
	}

	startBucket := (fromMs / bucketMs) * bucketMs
	endBucket := (nowMs / bucketMs) * bucketMs
	for ts := startBucket; ts <= endBucket; ts += bucketMs {
		if _, ok := points[ts]; ok {
			continue
		}
		points[ts] = &seriesPoint{TS: ts}
	}
	incidentTrend := make([]seriesPoint, 0, len(points))
	for _, p := range points {
		incidentTrend = append(incidentTrend, *p)
	}
	sort.SliceStable(incidentTrend, func(i, j int) bool { return incidentTrend[i].TS < incidentTrend[j].TS })

	severityMix := make([]map[string]any, 0, len(severityCounts))
	for sev, count := range severityCounts {
		severityMix = append(severityMix, map[string]any{"severity": sev, "count": count})
	}
	sort.SliceStable(severityMix, func(i, j int) bool {
		ri := severityRank(strVal(severityMix[i]["severity"]))
		rj := severityRank(strVal(severityMix[j]["severity"]))
		if ri == rj {
			return strVal(severityMix[i]["severity"]) < strVal(severityMix[j]["severity"])
		}
		return ri > rj
	})

	laneDistribution := []map[string]any{
		{"lane": "FAST", "count": laneCounts["FAST"]},
		{"lane": "STANDARD", "count": laneCounts["STANDARD"]},
		{"lane": "UNKNOWN", "count": laneCounts["UNKNOWN"]},
	}

	sort.SliceStable(recent, func(i, j int) bool { return recent[i].LastUpdatedAtUnixMs > recent[j].LastUpdatedAtUnixMs })
	if len(recent) > incidentLimit {
		recent = recent[:incidentLimit]
	}

	auditHighlights := a.collectAuditEntries(roleCtx, "", fromMs, nowMs, auditLimit)
	topEntities := map[string]any{
		"window_ms": windowMs,
		"src_ip":    []map[string]any{},
		"user_name": []map[string]any{},
		"node_id":   []map[string]any{},
	}
	if a.db != nil {
		queryTop := func(col string) []map[string]any {
			rows, err := a.db.QueryContext(ctx, fmt.Sprintf(`
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
		topEntities["src_ip"] = queryTop("src_ip")
		topEntities["user_name"] = queryTop("user_name")
		topEntities["node_id"] = queryTop("node_id")
	}

	summary := map[string]any{
		"window_ms":                      windowMs,
		"from_unix_ms":                   fromMs,
		"to_unix_ms":                     nowMs,
		"incidents_last_window":          incidents,
		"critical_incidents_last_window": criticalIncidents,
		"approvals_pending":              waiting,
		"failed_safe_count":              failedSafe,
		"endpoints_active":               len(activeNodes),
		"ingestion_rate_per_min":         ingestionPerMin,
		"latency_p95_ms":                 latencyP95Ms,
		"total_events_last_window":       totalEventsWindow,
		"model_alerts_last_window":       modelAlertsWindow,
		"manual_review_runs":             manualReviewRuns,
		"auto_runs":                      autoRuns,
		"status_counts":                  statusCounts,
	}

	report := map[string]any{
		"report_id":                fmt.Sprintf("soc.ops.%d", time.Now().UnixMilli()),
		"report_type":              "soc_operations",
		"generated_at":             time.Now().UTC().Format(time.RFC3339),
		"generated_by":             "ui-api",
		"window":                   normalizeWindowLabel(windowMs),
		"window_ms":                windowMs,
		"bucket_ms":                bucketMs,
		"summary":                  summary,
		"severity_mix":             severityMix,
		"lane_distribution":        laneDistribution,
		"incident_timeline":        incidentTrend,
		"recent_incidents":         recent,
		"audit_highlights":         auditHighlights,
		"top_entities":             topEntities,
		"operational_observations": buildSOCOperationalLessons(summary, severityMix, laneDistribution, recent, auditHighlights),
	}
	return report, nil
}

func buildSOCOperationalLessons(summary map[string]any, severityMix []map[string]any, laneDistribution []map[string]any, recent []incident, auditHighlights []auditEntry) []string {
	out := make([]string, 0, 8)
	if intVal(summary["approvals_pending"], 0) > 0 {
		out = append(out, fmt.Sprintf("There are %d approvals pending in the current window; keep manual review focused on irreversible or high-blast actions only.", intVal(summary["approvals_pending"], 0)))
	}
	if intVal(summary["failed_safe_count"], 0) > 0 {
		out = append(out, fmt.Sprintf("%d runs failed safe in the window; review rollback coverage and operator recovery guidance for those playbooks.", intVal(summary["failed_safe_count"], 0)))
	}
	if intVal(summary["endpoints_active"], 0) == 0 {
		out = append(out, "No active endpoints were observed in the report window; endpoint coverage is a prerequisite for meaningful SOC operations reporting.")
	}
	if intVal(summary["manual_review_runs"], 0) > intVal(summary["auto_runs"], 0) && intVal(summary["manual_review_runs"], 0) > 0 {
		out = append(out, "Manual review volume exceeded autonomous handling volume; tighten confidence and reversibility policy tuning if the goal is lower operator burden.")
	}
	for _, item := range severityMix {
		if strVal(item["severity"]) == "critical" && intVal(item["count"], 0) > 0 {
			out = append(out, fmt.Sprintf("Critical incidents are present (%d in window); confirm the containment playbooks for those rules remain approval-gated where business impact is high.", intVal(item["count"], 0)))
			break
		}
	}
	for _, item := range laneDistribution {
		if strVal(item["lane"]) == "FAST" && intVal(item["count"], 0) > 0 {
			out = append(out, fmt.Sprintf("FAST lane handled %d incidents in the current window; use this report to track how many still require approval versus auto-executed containment.", intVal(item["count"], 0)))
			break
		}
	}
	if len(auditHighlights) == 0 {
		out = append(out, "No audit highlights were available in the selected window; confirm UI API and master audit streams are retained for stakeholder reporting.")
	}
	if len(recent) > 0 && len(out) == 0 {
		out = append(out, "SOC posture is stable in the selected window; continue monitoring trend, approval burden, and failed-safe rates for policy tuning opportunities.")
	}
	return out
}

func renderSOCOperationsReportHTML(report map[string]any) string {
	summary, _ := report["summary"].(map[string]any)
	severityMix, _ := report["severity_mix"].([]map[string]any)
	laneDistribution, _ := report["lane_distribution"].([]map[string]any)
	timeline, _ := report["incident_timeline"].([]seriesPoint)
	recent, _ := report["recent_incidents"].([]incident)
	auditHighlights, _ := report["audit_highlights"].([]auditEntry)
	topEntities, _ := report["top_entities"].(map[string]any)
	observations, _ := report["operational_observations"].([]string)

	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>R-SIEM SOC Operations Report</title>")
	b.WriteString("<style>body{font-family:system-ui,sans-serif;background:#0b1020;color:#e7ecff;margin:0;padding:24px}h1,h2{margin:0 0 12px}section{margin:18px 0;padding:16px;border:1px solid #1e2a44;border-radius:12px;background:#101a2f}table{width:100%;border-collapse:collapse}th,td{padding:8px;border-top:1px solid #1e2a44;text-align:left;font-size:13px}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#a7b0d6}.meta{color:#a7b0d6;font-size:13px}.pill{display:inline-block;padding:4px 8px;border-radius:999px;background:#13203b;margin:0 8px 8px 0}.cols{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}</style></head><body>")
	b.WriteString("<h1>R-SIEM SOC Operations Report</h1>")
	b.WriteString("<div class=\"meta\">Generated at " + html.EscapeString(fmt.Sprint(report["generated_at"])) + "</div>")
	b.WriteString("<div class=\"meta\">Window " + html.EscapeString(fmt.Sprint(report["window"])) + "</div>")

	b.WriteString("<section><h2>Operational Summary</h2>")
	for _, pill := range []struct {
		label string
		value any
	}{
		{"Incidents", summary["incidents_last_window"]},
		{"Critical", summary["critical_incidents_last_window"]},
		{"Approvals Pending", summary["approvals_pending"]},
		{"Failed Safe", summary["failed_safe_count"]},
		{"Active Endpoints", summary["endpoints_active"]},
		{"Ingest Rate/min", fmt.Sprintf("%.1f", floatVal(summary["ingestion_rate_per_min"]))},
		{"p95 Latency ms", summary["latency_p95_ms"]},
		{"Manual Review Runs", summary["manual_review_runs"]},
		{"Auto Runs", summary["auto_runs"]},
	} {
		b.WriteString("<div class=\"pill\">" + html.EscapeString(pill.label) + " " + html.EscapeString(fmt.Sprint(pill.value)) + "</div>")
	}
	b.WriteString("</section>")

	b.WriteString("<section><h2>Severity and Lane Mix</h2><div class=\"cols\">")
	b.WriteString("<div><table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>")
	for _, item := range severityMix {
		b.WriteString("<tr><td>" + html.EscapeString(strVal(item["severity"])) + "</td><td>" + html.EscapeString(fmt.Sprint(item["count"])) + "</td></tr>")
	}
	b.WriteString("</tbody></table></div>")
	b.WriteString("<div><table><thead><tr><th>Lane</th><th>Count</th></tr></thead><tbody>")
	for _, item := range laneDistribution {
		b.WriteString("<tr><td>" + html.EscapeString(strVal(item["lane"])) + "</td><td>" + html.EscapeString(fmt.Sprint(item["count"])) + "</td></tr>")
	}
	b.WriteString("</tbody></table></div></div></section>")

	b.WriteString("<section><h2>Timeline Strip</h2><table><thead><tr><th>Bucket</th><th>Total</th><th>FAST</th><th>STANDARD</th><th>FAILED_SAFE</th></tr></thead><tbody>")
	for _, point := range timeline {
		b.WriteString("<tr><td>" + html.EscapeString(time.UnixMilli(point.TS).UTC().Format(time.RFC3339)) + "</td><td>" + html.EscapeString(fmt.Sprint(point.Count)) + "</td><td>" + html.EscapeString(fmt.Sprint(point.Fast)) + "</td><td>" + html.EscapeString(fmt.Sprint(point.Standard)) + "</td><td>" + html.EscapeString(fmt.Sprint(point.FailedSafe)) + "</td></tr>")
	}
	b.WriteString("</tbody></table></section>")

	b.WriteString("<section><h2>Recent Incidents</h2><table><thead><tr><th>Run</th><th>Status</th><th>Severity</th><th>Lane</th><th>Rule</th><th>Node</th><th>Policy Reason</th></tr></thead><tbody>")
	for _, run := range recent {
		b.WriteString("<tr><td>" + html.EscapeString(run.RunID) + "</td><td>" + html.EscapeString(run.Status) + "</td><td>" + html.EscapeString(run.Severity) + "</td><td>" + html.EscapeString(run.Lane) + "</td><td>" + html.EscapeString(run.RuleID) + "</td><td>" + html.EscapeString(run.NodeID) + "</td><td>" + html.EscapeString(run.ApprovalPolicyReason) + "</td></tr>")
	}
	b.WriteString("</tbody></table></section>")

	b.WriteString("<section><h2>Top Entities</h2><div class=\"cols\">")
	for _, key := range []string{"src_ip", "user_name", "node_id"} {
		items, _ := topEntities[key].([]map[string]any)
		b.WriteString("<div><table><thead><tr><th>" + html.EscapeString(strings.ToUpper(key)) + "</th><th>Count</th></tr></thead><tbody>")
		for _, item := range items {
			b.WriteString("<tr><td>" + html.EscapeString(strVal(item["value"])) + "</td><td>" + html.EscapeString(fmt.Sprint(item["count"])) + "</td></tr>")
		}
		b.WriteString("</tbody></table></div>")
	}
	b.WriteString("</div></section>")

	b.WriteString("<section><h2>Audit Highlights</h2><table><thead><tr><th>Time</th><th>Event</th><th>Run</th><th>Actor</th><th>Source</th></tr></thead><tbody>")
	for _, entry := range auditHighlights {
		b.WriteString("<tr><td>" + html.EscapeString(entry.TS) + "</td><td>" + html.EscapeString(entry.Msg) + "</td><td>" + html.EscapeString(entry.RunID) + "</td><td>" + html.EscapeString(entry.Actor) + "</td><td>" + html.EscapeString(entry.Source) + "</td></tr>")
	}
	b.WriteString("</tbody></table></section>")

	b.WriteString("<section><h2>Operational Observations</h2><ul>")
	for _, item := range observations {
		b.WriteString("<li>" + html.EscapeString(item) + "</li>")
	}
	b.WriteString("</ul></section></body></html>")
	return b.String()
}

func renderSOCOperationsReportPDF(report map[string]any) []byte {
	summary, _ := report["summary"].(map[string]any)
	severityMix, _ := report["severity_mix"].([]map[string]any)
	laneDistribution, _ := report["lane_distribution"].([]map[string]any)
	observations, _ := report["operational_observations"].([]string)
	lines := []string{
		"R-SIEM SOC Operations Report",
		"Window: " + fmt.Sprint(report["window"]),
		"Incidents: " + fmt.Sprint(summary["incidents_last_window"]),
		"Critical: " + fmt.Sprint(summary["critical_incidents_last_window"]),
		"Approvals Pending: " + fmt.Sprint(summary["approvals_pending"]),
		"Failed Safe: " + fmt.Sprint(summary["failed_safe_count"]),
		"Active Endpoints: " + fmt.Sprint(summary["endpoints_active"]),
		fmt.Sprintf("Ingest Rate/min: %.1f", floatVal(summary["ingestion_rate_per_min"])),
		"p95 Latency ms: " + fmt.Sprint(summary["latency_p95_ms"]),
		"Severity Mix:",
	}
	for _, item := range severityMix {
		lines = append(lines, fmt.Sprintf("- %s: %v", strVal(item["severity"]), item["count"]))
	}
	lines = append(lines, "Lane Distribution:")
	for _, item := range laneDistribution {
		lines = append(lines, fmt.Sprintf("- %s: %v", strVal(item["lane"]), item["count"]))
	}
	lines = append(lines, "Operational Observations:")
	for _, item := range observations {
		lines = append(lines, "- "+item)
	}
	return renderSimplePDF(lines)
}

func normalizeWindowLabel(windowMs int64) string {
	switch {
	case windowMs == int64(15*time.Minute/time.Millisecond):
		return "15m"
	case windowMs == int64(time.Hour/time.Millisecond):
		return "1h"
	case windowMs == int64(24*time.Hour/time.Millisecond):
		return "24h"
	case windowMs == int64(7*24*time.Hour/time.Millisecond):
		return "7d"
	default:
		return fmt.Sprintf("%dms", windowMs)
	}
}

func (a *app) buildIncidentReport(run incident, steps []stepResult, events []eventRow, uiState map[string]any, timelineMeta map[string]any) map[string]any {
	lessons := buildIncidentLessons(run, steps, events)
	return map[string]any{
		"report_id":    fmt.Sprintf("rep.%s.%d", run.RunID, time.Now().UnixMilli()),
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"generated_by": "ui-api",
		"run":          run,
		"steps":        steps,
		"timeline":     map[string]any{"items": events, "meta": timelineMeta},
		"ui_state":     uiState,
		"summary": map[string]any{
			"status":                 run.Status,
			"severity":               run.Severity,
			"confidence_score":       run.ConfidenceScore,
			"lane":                   run.Lane,
			"approval_policy_mode":   run.ApprovalPolicyMode,
			"approval_policy_reason": run.ApprovalPolicyReason,
			"playbook_reversibility": run.PlaybookReversibility,
			"approval_decision":      run.ApprovalDecision,
			"approval_actor":         run.ApprovalActor,
			"step_total":             run.StepTotal,
			"step_succeeded_count":   run.StepSucceededCount,
			"step_failed_safe_count": run.StepFailedSafeCount,
			"timeline_event_count":   len(events),
		},
		"lessons_learned": lessons,
	}
}

func buildIncidentLessons(run incident, steps []stepResult, events []eventRow) []string {
	lessons := make([]string, 0, 6)
	if strings.EqualFold(run.Status, "WAITING_APPROVAL") {
		lessons = append(lessons, fmt.Sprintf("Approval is pending because policy mode %s evaluated this run as %s.", chooseNonEmpty(run.ApprovalPolicyMode, "unknown"), chooseNonEmpty(run.ApprovalPolicyReason, "review required")))
	}
	if strings.EqualFold(run.Status, "FAILED_SAFE") {
		lessons = append(lessons, fmt.Sprintf("Run failed safe with reason %s; review reversibility and recovery guidance before retrying.", chooseNonEmpty(run.FailedSafeReason, "unspecified")))
	}
	if strings.EqualFold(run.ApprovalDecision, "deny") || strings.EqualFold(run.ApprovalDecision, "timeout") {
		lessons = append(lessons, "No disruptive action was released because the approval gate was denied or timed out.")
	}
	if run.ConfidenceScore > 0 && run.ConfidenceScore < 70 {
		lessons = append(lessons, "Confidence was below the normal autonomous threshold; investigate rule quality and supporting evidence before widening automation.")
	}
	if strings.EqualFold(run.PlaybookReversibility, "irreversible") {
		lessons = append(lessons, "The selected playbook contains irreversible actions; keep this behind explicit approval unless business policy changes.")
	}
	if len(events) == 0 {
		lessons = append(lessons, "Timeline evidence was sparse in the selected window; widen the window or improve endpoint/event coverage for better investigation context.")
	}
	if len(steps) > 0 && run.StepSucceededCount == len(steps) && strings.EqualFold(run.Status, "SUCCEEDED") {
		lessons = append(lessons, "Automation completed successfully; this is a candidate pattern for broader autonomous handling if the confidence and blast radius remain stable.")
	}
	if len(lessons) == 0 {
		lessons = append(lessons, "Incident completed without exceptional conditions; continue monitoring for repeat patterns and policy tuning opportunities.")
	}
	return lessons
}

func renderIncidentReportHTML(report map[string]any) string {
	run, _ := report["run"].(incident)
	summary, _ := report["summary"].(map[string]any)
	lessons, _ := report["lessons_learned"].([]string)
	timeline, _ := report["timeline"].(map[string]any)
	events, _ := timeline["items"].([]eventRow)
	steps, _ := report["steps"].([]stepResult)
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>R-SIEM Incident Report</title>")
	b.WriteString("<style>body{font-family:system-ui,sans-serif;background:#0b1020;color:#e7ecff;margin:0;padding:24px}h1,h2{margin:0 0 12px}section{margin:18px 0;padding:16px;border:1px solid #1e2a44;border-radius:12px;background:#101a2f}table{width:100%;border-collapse:collapse}th,td{padding:8px;border-top:1px solid #1e2a44;text-align:left;font-size:13px}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#a7b0d6}.meta{color:#a7b0d6;font-size:13px}.pill{display:inline-block;padding:4px 8px;border-radius:999px;background:#13203b;margin-right:8px}</style></head><body>")
	b.WriteString("<h1>R-SIEM Incident Report</h1>")
	b.WriteString("<div class=\"meta\">Generated at " + html.EscapeString(fmt.Sprint(report["generated_at"])) + "</div>")
	b.WriteString("<section><h2>Incident Summary</h2>")
	b.WriteString("<div class=\"pill\">Run " + html.EscapeString(run.RunID) + "</div>")
	b.WriteString("<div class=\"pill\">Status " + html.EscapeString(run.Status) + "</div>")
	b.WriteString("<div class=\"pill\">Severity " + html.EscapeString(run.Severity) + "</div>")
	b.WriteString("<div class=\"pill\">Lane " + html.EscapeString(run.Lane) + "</div>")
	b.WriteString("<p class=\"meta\">Policy: " + html.EscapeString(fmt.Sprint(summary["approval_policy_mode"])) + " | Reason: " + html.EscapeString(fmt.Sprint(summary["approval_policy_reason"])) + " | Confidence: " + html.EscapeString(fmt.Sprint(summary["confidence_score"])) + " | Reversibility: " + html.EscapeString(fmt.Sprint(summary["playbook_reversibility"])) + "</p>")
	b.WriteString("<p class=\"meta\">Rule: " + html.EscapeString(run.RuleID) + " | Playbook: " + html.EscapeString(run.PlaybookID) + " | Node: " + html.EscapeString(run.NodeID) + " | Source: " + html.EscapeString(run.SourceType) + "/" + html.EscapeString(run.EventType) + "</p></section>")
	b.WriteString("<section><h2>Lessons Learned</h2><ul>")
	for _, lesson := range lessons {
		b.WriteString("<li>" + html.EscapeString(lesson) + "</li>")
	}
	b.WriteString("</ul></section>")
	b.WriteString("<section><h2>Steps</h2><table><thead><tr><th>Index</th><th>Action</th><th>Status</th><th>Lane</th><th>Target</th></tr></thead><tbody>")
	for _, st := range steps {
		b.WriteString("<tr><td>" + html.EscapeString(fmt.Sprint(st.StepIndex)) + "</td><td>" + html.EscapeString(st.ActionType) + "</td><td>" + html.EscapeString(st.Status) + "</td><td>" + html.EscapeString(st.Lane) + "</td><td>" + html.EscapeString(st.Target) + "</td></tr>")
	}
	b.WriteString("</tbody></table></section>")
	b.WriteString("<section><h2>Timeline Evidence</h2><table><thead><tr><th>Time</th><th>Type</th><th>User</th><th>src_ip</th><th>Node</th></tr></thead><tbody>")
	for _, ev := range events {
		b.WriteString("<tr><td>" + html.EscapeString(time.UnixMilli(ev.RecvTSUnixMs).UTC().Format(time.RFC3339)) + "</td><td>" + html.EscapeString(ev.SourceType+"/"+ev.EventType) + "</td><td>" + html.EscapeString(ev.UserName) + "</td><td>" + html.EscapeString(ev.SrcIP) + "</td><td>" + html.EscapeString(ev.NodeID) + "</td></tr>")
	}
	b.WriteString("</tbody></table></section></body></html>")
	return b.String()
}

func renderIncidentReportPDF(report map[string]any) []byte {
	run, _ := report["run"].(incident)
	summary, _ := report["summary"].(map[string]any)
	lessons, _ := report["lessons_learned"].([]string)
	lines := []string{
		"R-SIEM Incident Report",
		"Run: " + run.RunID,
		"Status: " + run.Status,
		"Severity: " + run.Severity,
		"Lane: " + run.Lane,
		fmt.Sprintf("Confidence: %v", summary["confidence_score"]),
		"Policy Mode: " + fmt.Sprint(summary["approval_policy_mode"]),
		"Policy Reason: " + fmt.Sprint(summary["approval_policy_reason"]),
		"Reversibility: " + fmt.Sprint(summary["playbook_reversibility"]),
		"Rule: " + run.RuleID,
		"Playbook: " + run.PlaybookID,
		"Node: " + run.NodeID,
		"Source: " + run.SourceType + "/" + run.EventType,
		"Lessons Learned:",
	}
	for _, lesson := range lessons {
		lines = append(lines, "- "+lesson)
	}
	return renderSimplePDF(lines)
}

func renderSimplePDF(lines []string) []byte {
	wrapped := wrapPDFLines(lines, 88)
	if len(wrapped) == 0 {
		wrapped = []string{"R-SIEM Report", "No content available."}
	}
	const linesPerPage = 48
	pages := make([][]string, 0, (len(wrapped)+linesPerPage-1)/linesPerPage)
	for start := 0; start < len(wrapped); start += linesPerPage {
		end := start + linesPerPage
		if end > len(wrapped) {
			end = len(wrapped)
		}
		pages = append(pages, wrapped[start:end])
	}

	var out bytes.Buffer
	offsets := []int{}
	writeObj := func(id int, body string) {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", id, body)
	}
	pageIDs := make([]int, len(pages))
	contentIDs := make([]int, len(pages))
	for i := range pages {
		pageIDs[i] = 3 + i*2
		contentIDs[i] = 4 + i*2
	}
	fontID := 3 + len(pages)*2
	out.WriteString("%PDF-1.4\n")
	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	kids := make([]string, 0, len(pageIDs))
	for _, id := range pageIDs {
		kids = append(kids, fmt.Sprintf("%d 0 R", id))
	}
	writeObj(2, fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>", len(pageIDs), strings.Join(kids, " ")))
	for i, pageLines := range pages {
		content := pdfPageContent(pageLines)
		writeObj(pageIDs[i], fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents %d 0 R /Resources << /Font << /F1 %d 0 R >> >> >>", contentIDs[i], fontID))
		writeObj(contentIDs[i], fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content))
	}
	writeObj(fontID, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	xrefStart := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, off := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xrefStart)
	return out.Bytes()
}

func pdfPageContent(lines []string) string {
	var stream strings.Builder
	stream.WriteString("BT\n/F1 11 Tf\n14 TL\n50 790 Td\n")
	for i, line := range lines {
		if i == 0 {
			stream.WriteString("(" + escapePDFText(line) + ") Tj\n")
			stream.WriteString("0 -18 Td\n")
			continue
		}
		stream.WriteString("(" + escapePDFText(line) + ") Tj\n")
		stream.WriteString("0 -14 Td\n")
	}
	stream.WriteString("ET\n")
	return stream.String()
}

func wrapPDFLines(lines []string, maxChars int) []string {
	wrapped := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, " ")
		if line == "" {
			wrapped = append(wrapped, "")
			continue
		}
		indent := ""
		content := line
		if strings.HasPrefix(content, "- ") {
			indent = "- "
			content = strings.TrimPrefix(content, "- ")
		}
		width := maxChars - len(indent)
		if width < 20 {
			width = maxChars
		}
		for len([]rune(content)) > width {
			runes := []rune(content)
			split := width
			for i := width; i > 0; i-- {
				if runes[i-1] == ' ' {
					split = i - 1
					break
				}
			}
			part := strings.TrimSpace(string(runes[:split]))
			wrapped = append(wrapped, indent+part)
			content = strings.TrimSpace(string(runes[split:]))
			indent = "  "
			width = maxChars - len(indent)
			if width < 20 {
				width = maxChars
			}
		}
		if content != "" {
			wrapped = append(wrapped, indent+content)
		}
	}
	return wrapped
}

func escapePDFText(s string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "(", "\\(", ")", "\\)")
	return replacer.Replace(s)
}

func (a *app) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	windowMs := parseWindowMs(r.URL.Query().Get("window"), 24*time.Hour)
	nowMs := time.Now().UnixMilli()
	fromMs := nowMs - windowMs
	prevFromMs := fromMs - windowMs
	prevToMs := fromMs
	maxLatencySampleMs := int64(10 * time.Minute / time.Millisecond)

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
WHERE recv_ts_unix_ms >= $1
  AND event_ts_unix_ms > 0
  AND event_ts_unix_ms <= recv_ts_unix_ms
  AND recv_ts_unix_ms - event_ts_unix_ms <= $2
`, fromMs, maxLatencySampleMs).Scan(&p95); err == nil && p95.Valid {
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
	startBucket := (fromMs / bucketMs) * bucketMs
	endBucket := (nowMs / bucketMs) * bucketMs
	for ts := startBucket; ts <= endBucket; ts += bucketMs {
		if _, ok := m[ts]; ok {
			continue
		}
		m[ts] = &point{TS: ts}
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
		hay := strings.ToLower(strings.Join([]string{run.RunID, run.RuleID, run.PlaybookID, run.NodeID, run.SourceType, run.EventType, run.SrcIP, run.DstIP, run.User}, "|"))
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
SELECT event_ts_unix_ms, recv_ts_unix_ms, node_id, source_type, event_type, COALESCE(src_ip::text,''), COALESCE(dst_ip::text,''), COALESCE(user_name,''), COALESCE(severity,''), COALESCE(rule_id,''), event_idem_key
FROM normalized_events
WHERE recv_ts_unix_ms BETWEEN $1 AND $2
  AND (
    LOWER(COALESCE(user_name,'')) LIKE $3
    OR LOWER(COALESCE(src_ip::text,'')) LIKE $3
    OR LOWER(COALESCE(dst_ip::text,'')) LIKE $3
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
				if err := rows.Scan(&ev.EventTSUnixMs, &ev.RecvTSUnixMs, &ev.NodeID, &ev.SourceType, &ev.EventType, &ev.SrcIP, &ev.DstIP, &ev.UserName, &ev.Severity, &ev.RuleID, &ev.EventIdemKey); err == nil {
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
SELECT event_ts_unix_ms, recv_ts_unix_ms, node_id, source_type, event_type, COALESCE(src_ip::text,''), COALESCE(dst_ip::text,''), COALESCE(user_name,''), COALESCE(severity,''), COALESCE(rule_id,''), event_idem_key
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
		if err := rows.Scan(&ev.EventTSUnixMs, &ev.RecvTSUnixMs, &ev.NodeID, &ev.SourceType, &ev.EventType, &ev.SrcIP, &ev.DstIP, &ev.UserName, &ev.Severity, &ev.RuleID, &ev.EventIdemKey); err == nil {
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
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))
	fromMs := parseInt64(r.URL.Query().Get("from"), 0)
	toMs := parseInt64(r.URL.Query().Get("to"), 0)
	entries := a.collectAuditEntries(roleCtx, q, fromMs, toMs, 500)
	writeJSON(w, http.StatusOK, map[string]any{"items": entries, "count": len(entries)})
}

func (a *app) collectAuditEntries(roleCtx roleContext, q string, fromMs, toMs int64, limit int) []auditEntry {
	entries := make([]auditEntry, 0, 512)
	entries = append(entries, parseAuditLog(a.cfg.MasterLogPath, "master")...)
	entries = append(entries, parseAuditLog(a.cfg.UIAPILogPath, "ui-api")...)
	entries = append(entries, a.parseUIStateAudit()...)
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
	if strings.ToLower(roleCtx.Role) != "admin" {
		for i := range filtered {
			if filtered[i].Details != nil {
				filtered[i].Details = map[string]any{"summary": "restricted_to_admin"}
			}
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].TS > filtered[j].TS
	})
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return filtered
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

func (a *app) deriveLane(run incident, steps []stepResult) string {
	for _, st := range steps {
		lane := strings.ToUpper(strings.TrimSpace(st.Lane))
		if lane == "FAST" || lane == "STANDARD" {
			return lane
		}
	}
	switch strings.ToUpper(strings.TrimSpace(run.Lane)) {
	case "FAST", "STANDARD":
		return strings.ToUpper(strings.TrimSpace(run.Lane))
	}
	if strings.ToUpper(strings.TrimSpace(run.Status)) == "WAITING_APPROVAL" || run.ApprovalRequestedAtMs > 0 {
		return "FAST"
	}
	if severityRank(run.Severity) >= severityRank("high") {
		return "FAST"
	}
	if severityRank(run.Severity) > 0 {
		return "STANDARD"
	}
	switch a.playbookApprovalBy[strings.TrimSpace(run.PlaybookID)] {
	case "auto":
		return "STANDARD"
	case "required_for_high":
		return "FAST"
	case "required_for_critical":
		if severityRank(run.Severity) >= severityRank("critical") {
			return "FAST"
		}
		return "STANDARD"
	}
	return ""
}

func deriveIncidentConfidence(run incident) int {
	score := normalizeConfidence(run.ConfidenceScore)
	if score > 0 {
		return score
	}
	score = defaultConfidenceForSeverity(run.Severity)
	switch strings.ToLower(strings.TrimSpace(run.SourceType)) {
	case "auditd_exec":
		score += 8
	case "inotify":
		score += 7
	case "dns_packet":
		score += 6
	case "proc_net":
		score += 4
	case "host", "tail":
		score += 3
	}
	if strings.EqualFold(strings.TrimSpace(run.Lane), "FAST") {
		score += 6
	}
	user := strings.ToLower(strings.TrimSpace(run.User))
	if user != "" && user != "unknown" {
		score += 6
	}
	if strings.TrimSpace(run.ExecPath) != "" {
		score += 6
	}
	if strings.TrimSpace(run.Comm) != "" {
		score += 4
	}
	if strings.TrimSpace(run.Cmdline) != "" {
		score += 4
	}
	if strings.TrimSpace(run.DstIP) != "" {
		score += 3
	}
	if strings.EqualFold(strings.TrimSpace(run.EventType), "dns_query") {
		score += 6
	}
	if strings.EqualFold(strings.TrimSpace(run.ApprovalPolicyMode), "required") {
		score += 2
	}
	return normalizeConfidence(score)
}

func isTerminalIncidentStatus(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "SUCCEEDED", "FAILED_SAFE", "FAILED_TRANSIENT", "DENIED", "TIMED_OUT", "CLOSED", "CANCELLED":
		return true
	default:
		return false
	}
}

func incidentAgeDays(run incident, nowMs int64) int {
	if run.LastUpdatedAtUnixMs <= 0 || nowMs <= run.LastUpdatedAtUnixMs {
		return 0
	}
	return int((nowMs - run.LastUpdatedAtUnixMs) / int64((24*time.Hour)/time.Millisecond))
}

func incidentLifecycleState(run incident) string {
	status := strings.ToUpper(strings.TrimSpace(run.Status))
	switch status {
	case "WAITING_APPROVAL":
		return "pending_approval"
	case "MANUAL_REVIEW_REQUIRED":
		return "pending_manual_review"
	case "CREATED", "RUNNING":
		return "active"
	case "FAILED_SAFE", "FAILED_TRANSIENT":
		return "failed_safe"
	case "SUCCEEDED":
		return "resolved"
	case "DENIED", "TIMED_OUT", "CANCELLED", "CLOSED":
		return "closed_no_action"
	}
	switch strings.ToLower(strings.TrimSpace(run.ApprovalDecision)) {
	case "deny", "timeout":
		return "closed_no_action"
	}
	if isTerminalIncidentStatus(status) {
		return "resolved"
	}
	return "active"
}

func normalizeTimedOutApproval(run incident, nowMs int64) incident {
	if strings.ToUpper(strings.TrimSpace(run.Status)) != "WAITING_APPROVAL" {
		return run
	}
	if run.ApprovalRequestedAtMs <= 0 {
		return run
	}
	timeoutMs := run.ApprovalTimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = defaultApprovalTimeout
	}
	if nowMs < run.ApprovalRequestedAtMs+timeoutMs {
		return run
	}
	run.Status = "MANUAL_REVIEW_REQUIRED"
	run.ApprovalDecision = chooseNonEmpty("timeout", run.ApprovalDecision)
	run.OperatorAction = chooseNonEmpty("manual_review_required", run.OperatorAction)
	run.FailedSafeReason = chooseNonEmpty("approval_timeout", run.FailedSafeReason)
	if run.LastUpdatedAtUnixMs < run.ApprovalRequestedAtMs+timeoutMs {
		run.LastUpdatedAtUnixMs = run.ApprovalRequestedAtMs + timeoutMs
	}
	return run
}

func incidentEnvironmentClass(run incident) string {
	if env := strings.ToLower(strings.TrimSpace(run.AssetEnvironment)); env != "" {
		return env
	}
	hay := strings.ToLower(strings.Join([]string{
		run.User,
		run.Actor,
		run.ApprovalActor,
		run.Target,
		run.EventIdemKey,
	}, "|"))
	markers := []string{
		"demo_local",
		"demo_fast_local",
		"demo_std_local",
		"demo2",
		"smoke_",
		"verify_",
		"verify-",
		"ui_smoke",
		"ui-live-check",
		"auto_pressure",
		"pressure",
		"|demo|",
	}
	for _, marker := range markers {
		if strings.Contains(hay, marker) {
			return "demo_test"
		}
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(run.User)), "demo") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(run.User)), "smoke") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(run.Actor)), "verify") {
		return "demo_test"
	}
	return "operational"
}

func boolVal(v any, fallback bool) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		trimmed := strings.TrimSpace(strings.ToLower(t))
		switch trimmed {
		case "true", "1", "yes", "y":
			return true
		case "false", "0", "no", "n":
			return false
		}
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return n != 0
		}
	case float64:
		return t != 0
	case int:
		return t != 0
	case int64:
		return t != 0
	}
	return fallback
}

func knownServiceAccount(run incident) bool {
	if !run.IdentityServiceAccount {
		return false
	}
	user := strings.TrimSpace(strings.ToLower(run.User))
	if user == "" || user == "unknown" {
		return false
	}
	return true
}

func matchesRetentionRule(run incident, rule retentionRule) bool {
	if len(rule.EnvironmentIn) > 0 {
		matched := false
		for _, candidate := range rule.EnvironmentIn {
			if strings.EqualFold(strings.TrimSpace(candidate), run.EnvironmentClass) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(rule.LifecycleIn) > 0 {
		matched := false
		for _, candidate := range rule.LifecycleIn {
			if strings.EqualFold(strings.TrimSpace(candidate), run.LifecycleState) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(rule.AssetCriticalityIn) > 0 {
		matched := false
		for _, candidate := range rule.AssetCriticalityIn {
			if strings.EqualFold(strings.TrimSpace(candidate), run.AssetCriticality) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if rule.ServiceAccount != nil && knownServiceAccount(run) != *rule.ServiceAccount {
		return false
	}
	if rule.HighImpact != nil && incidentHighImpact(run) != *rule.HighImpact {
		return false
	}
	return true
}

func incidentHighImpact(run incident) bool {
	return severityRank(run.Severity) >= severityRank("high") ||
		severityRank(run.AssetCriticality) >= severityRank("high") ||
		knownServiceAccount(run) ||
		strings.EqualFold(run.PlaybookReversibility, "irreversible") ||
		strings.EqualFold(run.PlaybookReversibility, "partial") ||
		run.ApprovalRequestedAtMs > 0 ||
		run.ApprovalDecision != "" ||
		run.OperatorAction != "" ||
		run.FailedSafeReason != ""
}

func (a *app) applyIncidentRetentionPolicy(run incident, nowMs int64) incident {
	run.LifecycleState = incidentLifecycleState(run)
	run.EnvironmentClass = incidentEnvironmentClass(run)
	run.AgeDays = incidentAgeDays(run, nowMs)
	run.IdentityServiceAccount = knownServiceAccount(run)
	run.RetentionRuleID = ""
	run.RetentionClass = ""
	run.ArchiveAfterDays = 0
	run.PurgeAfterDays = 0
	run.Archived = false
	run.PurgeEligible = false

	isTerminal := isTerminalIncidentStatus(run.Status) || run.LifecycleState == "closed_no_action" || run.LifecycleState == "resolved" || run.LifecycleState == "failed_safe"
	for _, rule := range a.retentionRules {
		if !matchesRetentionRule(run, rule) {
			continue
		}
		run.RetentionRuleID = rule.ID
		run.RetentionClass = rule.Class
		run.ArchiveAfterDays = rule.ArchiveAfterDays
		run.PurgeAfterDays = rule.PurgeAfterDays
		break
	}
	if run.RetentionClass == "" {
		run.RetentionRuleID = "operational_standard_default"
		run.RetentionClass = "operational_standard"
		run.ArchiveAfterDays = 30
		run.PurgeAfterDays = 180
	}

	run.Archived = isTerminal && run.AgeDays >= run.ArchiveAfterDays
	run.PurgeEligible = run.EnvironmentClass == "demo_test" && isTerminal && run.AgeDays >= run.PurgeAfterDays
	return run
}

func normalizeConfidence(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func defaultConfidenceForSeverity(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 70
	case "high":
		return 58
	case "medium":
		return 46
	case "low":
		return 32
	case "info":
		return 20
	default:
		return 40
	}
}

func (a *app) deriveSeverity(run incident, created createdMeta) string {
	if sev := strings.ToLower(strings.TrimSpace(run.Severity)); sev != "" {
		return sev
	}
	if sev := strings.ToLower(strings.TrimSpace(created.Severity)); sev != "" {
		return sev
	}
	if sev := strings.ToLower(strings.TrimSpace(a.ruleSeverityByID[strings.TrimSpace(run.RuleID)])); sev != "" {
		return sev
	}
	switch {
	case strings.EqualFold(strings.TrimSpace(run.Status), "WAITING_APPROVAL"):
		return "high"
	case strings.Contains(strings.ToUpper(run.RuleID), "DECEPTION"), strings.Contains(strings.ToUpper(run.PlaybookID), "DECEPTION"):
		return "critical"
	case strings.Contains(strings.ToUpper(run.RuleID), "COUNT-PROCESS"), strings.Contains(strings.ToUpper(run.PlaybookID), "COUNT-PROCESS"):
		return "high"
	}
	return ""
}

func (a *app) loadState() ([]incident, map[string][]stepResult, map[string]createdMeta) {
	runsByID := map[string]incident{}
	purgedRunIDs := a.loadPurgedRunIDs()
	_ = scanJSONLines(a.cfg.RunsPath, func(obj map[string]any) {
		runID := strVal(obj["run_id"])
		if runID == "" {
			return
		}
		r := runsByID[runID]
		r.RunID = runID
		r.TriggerIdemKey = chooseNonEmpty(strVal(obj["trigger_idem_key"]), r.TriggerIdemKey)
		r.AlertKey = chooseNonEmpty(strVal(obj["alert_key"]), r.AlertKey)
		r.Status = chooseNonEmpty(strVal(obj["status"]), r.Status)
		r.RuleID = chooseNonEmpty(strVal(obj["rule_id"]), r.RuleID)
		r.PlaybookID = chooseNonEmpty(strVal(obj["playbook_id"]), r.PlaybookID)
		r.PlaybookVersion = chooseNonEmpty(strVal(obj["playbook_version"]), r.PlaybookVersion)
		r.Severity = chooseNonEmpty(strVal(obj["severity"]), r.Severity)
		r.ConfidenceScore = intVal(obj["confidence_score"], r.ConfidenceScore)
		r.Lane = chooseNonEmpty(strings.ToUpper(strVal(obj["lane"])), r.Lane)
		r.NodeID = chooseNonEmpty(strVal(obj["node_id"]), r.NodeID)
		r.AssetEnvironment = chooseNonEmpty(strVal(obj["asset_environment"]), r.AssetEnvironment)
		r.AssetCriticality = chooseNonEmpty(strVal(obj["asset_criticality"]), r.AssetCriticality)
		r.AssetOwner = chooseNonEmpty(strVal(obj["asset_owner"]), r.AssetOwner)
		r.AssetTeam = chooseNonEmpty(strVal(obj["asset_team"]), r.AssetTeam)
		r.AssetRole = chooseNonEmpty(strVal(obj["asset_role"]), r.AssetRole)
		r.SourceType = chooseNonEmpty(strVal(obj["source_type"]), r.SourceType)
		r.EventType = chooseNonEmpty(strVal(obj["event_type"]), r.EventType)
		r.SrcIP = chooseNonEmpty(strVal(obj["src_ip"]), r.SrcIP)
		r.DstIP = chooseNonEmpty(strVal(obj["dst_ip"]), r.DstIP)
		r.User = chooseNonEmpty(strVal(obj["user_name"]), r.User)
		r.User = chooseNonEmpty(strVal(obj["user"]), r.User)
		r.ExecPath = chooseNonEmpty(strVal(obj["exec_path"]), r.ExecPath)
		r.Comm = chooseNonEmpty(strVal(obj["comm"]), r.Comm)
		r.Cmdline = chooseNonEmpty(strVal(obj["cmdline"]), r.Cmdline)
		r.IdentityDisplayName = chooseNonEmpty(strVal(obj["identity_display_name"]), r.IdentityDisplayName)
		r.IdentityDepartment = chooseNonEmpty(strVal(obj["identity_department"]), r.IdentityDepartment)
		r.IdentityManager = chooseNonEmpty(strVal(obj["identity_manager"]), r.IdentityManager)
		r.IdentityPrivileged = boolVal(obj["identity_privileged"], r.IdentityPrivileged)
		r.IdentityServiceAccount = boolVal(obj["identity_service_account"], r.IdentityServiceAccount)
		r.Actor = chooseNonEmpty(strVal(obj["actor"]), r.Actor)
		r.Target = chooseNonEmpty(strVal(obj["target"]), r.Target)
		r.TargetAgentID = chooseNonEmpty(strVal(obj["target_agent_id"]), r.TargetAgentID)
		r.EventIdemKey = chooseNonEmpty(strVal(obj["event_idem_key"]), r.EventIdemKey)
		r.FailedSafeReason = chooseNonEmpty(strVal(obj["failed_safe_reason"]), r.FailedSafeReason)
		r.OperatorAction = chooseNonEmpty(strVal(obj["operator_action"]), r.OperatorAction)
		r.ApprovalPolicyMode = chooseNonEmpty(strVal(obj["approval_policy_mode"]), r.ApprovalPolicyMode)
		r.ApprovalPolicyRuleID = chooseNonEmpty(strVal(obj["approval_policy_rule_id"]), r.ApprovalPolicyRuleID)
		r.AllowlistRuleID = chooseNonEmpty(strVal(obj["allowlist_rule_id"]), r.AllowlistRuleID)
		r.ApprovalPolicyReason = chooseNonEmpty(strVal(obj["approval_policy_reason"]), r.ApprovalPolicyReason)
		r.PlaybookReversibility = chooseNonEmpty(strVal(obj["playbook_reversibility"]), r.PlaybookReversibility)
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
			RunID:            runID,
			StepID:           strVal(obj["step_id"]),
			StepIndex:        intVal(obj["step_index"], 0),
			StepKey:          strVal(obj["step_key"]),
			Status:           strVal(obj["status"]),
			ActionType:       strVal(obj["action_type"]),
			Lane:             strVal(obj["lane"]),
			Actor:            strVal(obj["actor"]),
			Attempt:          intVal(obj["attempt"], 0),
			FinishedAtMs:     int64Val(obj["finished_at_unix_ms"], 0),
			Target:           strVal(obj["target"]),
			TargetAgentID:    strVal(obj["target_agent_id"]),
			LastError:        strVal(obj["last_error"]),
			Receipt:          mapVal(obj["receipt"]),
			AllowlistRuleID:  strVal(obj["allowlist_rule_id"]),
			GuardrailRuleIDs: stringSliceVal(obj["guardrail_rule_ids"]),
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
				RuleID:                 strVal(obj["rule_id"]),
				PlaybookID:             strVal(obj["playbook_id"]),
				PlaybookVersion:        strVal(obj["playbook_version"]),
				Severity:               strVal(obj["severity"]),
				NodeID:                 strVal(obj["node_id"]),
				AssetEnvironment:       strVal(obj["asset_environment"]),
				AssetCriticality:       strVal(obj["asset_criticality"]),
				AssetOwner:             strVal(obj["asset_owner"]),
				AssetTeam:              strVal(obj["asset_team"]),
				AssetRole:              strVal(obj["asset_role"]),
				SourceType:             strVal(obj["source_type"]),
				EventType:              strVal(obj["event_type"]),
				SrcIP:                  strVal(obj["src_ip"]),
				DstIP:                  strVal(obj["dst_ip"]),
				User:                   chooseNonEmpty(strVal(obj["user"]), strVal(obj["user_name"])),
				ExecPath:               strVal(obj["exec_path"]),
				Comm:                   strVal(obj["comm"]),
				Cmdline:                strVal(obj["cmdline"]),
				IdentityDisplayName:    strVal(obj["identity_display_name"]),
				IdentityDepartment:     strVal(obj["identity_department"]),
				IdentityManager:        strVal(obj["identity_manager"]),
				IdentityPrivileged:     boolVal(obj["identity_privileged"], false),
				IdentityServiceAccount: boolVal(obj["identity_service_account"], false),
				TargetAgentID:          strVal(obj["target_agent_id"]),
				EventIdemKey:           strVal(obj["event_idem_key"]),
			}
			r := runsByID[runID]
			r.RunID = runID
			r.Status = chooseNonEmpty(strings.ToUpper(strVal(obj["status"])), r.Status)
			r.Status = chooseNonEmpty("CREATED", r.Status)
			r.RuleID = chooseNonEmpty(strVal(obj["rule_id"]), r.RuleID)
			r.PlaybookID = chooseNonEmpty(strVal(obj["playbook_id"]), r.PlaybookID)
			r.PlaybookVersion = chooseNonEmpty(strVal(obj["playbook_version"]), r.PlaybookVersion)
			r.Severity = chooseNonEmpty(strVal(obj["severity"]), r.Severity)
			r.NodeID = chooseNonEmpty(strVal(obj["node_id"]), r.NodeID)
			r.AssetEnvironment = chooseNonEmpty(strVal(obj["asset_environment"]), r.AssetEnvironment)
			r.AssetCriticality = chooseNonEmpty(strVal(obj["asset_criticality"]), r.AssetCriticality)
			r.AssetOwner = chooseNonEmpty(strVal(obj["asset_owner"]), r.AssetOwner)
			r.AssetTeam = chooseNonEmpty(strVal(obj["asset_team"]), r.AssetTeam)
			r.AssetRole = chooseNonEmpty(strVal(obj["asset_role"]), r.AssetRole)
			r.SourceType = chooseNonEmpty(strVal(obj["source_type"]), r.SourceType)
			r.EventType = chooseNonEmpty(strVal(obj["event_type"]), r.EventType)
			r.SrcIP = chooseNonEmpty(strVal(obj["src_ip"]), r.SrcIP)
			r.DstIP = chooseNonEmpty(strVal(obj["dst_ip"]), r.DstIP)
			r.User = chooseNonEmpty(strVal(obj["user_name"]), r.User)
			r.User = chooseNonEmpty(strVal(obj["user"]), r.User)
			r.ExecPath = chooseNonEmpty(strVal(obj["exec_path"]), r.ExecPath)
			r.Comm = chooseNonEmpty(strVal(obj["comm"]), r.Comm)
			r.Cmdline = chooseNonEmpty(strVal(obj["cmdline"]), r.Cmdline)
			r.IdentityDisplayName = chooseNonEmpty(strVal(obj["identity_display_name"]), r.IdentityDisplayName)
			r.IdentityDepartment = chooseNonEmpty(strVal(obj["identity_department"]), r.IdentityDepartment)
			r.IdentityManager = chooseNonEmpty(strVal(obj["identity_manager"]), r.IdentityManager)
			r.IdentityPrivileged = boolVal(obj["identity_privileged"], r.IdentityPrivileged)
			r.IdentityServiceAccount = boolVal(obj["identity_service_account"], r.IdentityServiceAccount)
			r.TargetAgentID = chooseNonEmpty(strVal(obj["target_agent_id"]), r.TargetAgentID)
			r.EventIdemKey = chooseNonEmpty(strVal(obj["event_idem_key"]), r.EventIdemKey)
			r.LastUpdatedAtUnixMs = int64Val(lastUpdatedMs, r.LastUpdatedAtUnixMs)
			if r.Source == "" {
				r.Source = "master_log"
			}
			runsByID[runID] = r
		case "response_run_waiting_approval":
			r := runsByID[runID]
			r.RunID = runID
			// Do not regress a timed-out/manual-review run back into waiting state.
			if strings.ToUpper(strings.TrimSpace(r.Status)) != "MANUAL_REVIEW_REQUIRED" {
				r.Status = "WAITING_APPROVAL"
			}
			r.RuleID = chooseNonEmpty(strVal(obj["rule_id"]), r.RuleID)
			r.PlaybookID = chooseNonEmpty(strVal(obj["playbook_id"]), r.PlaybookID)
			r.ApprovalTimeoutMs = int64Val(obj["timeout_ms"], r.ApprovalTimeoutMs)
			r.ApprovalRequestedAtMs = int64Val(logTsMs, r.ApprovalRequestedAtMs)
			r.LastUpdatedAtUnixMs = int64Val(lastUpdatedMs, r.LastUpdatedAtUnixMs)
			if r.Source == "" {
				r.Source = "master_log"
			}
			runsByID[runID] = r
		case "approval_policy_evaluated":
			r := runsByID[runID]
			r.RunID = runID
			r.RuleID = chooseNonEmpty(strVal(obj["rule_id"]), r.RuleID)
			r.PlaybookID = chooseNonEmpty(strVal(obj["playbook_id"]), r.PlaybookID)
			r.Severity = chooseNonEmpty(strVal(obj["severity"]), r.Severity)
			r.ConfidenceScore = intVal(obj["confidence_score"], r.ConfidenceScore)
			r.ApprovalPolicyMode = chooseNonEmpty(strVal(obj["approval_mode"]), r.ApprovalPolicyMode)
			r.ApprovalPolicyRuleID = chooseNonEmpty(strVal(obj["approval_rule_id"]), r.ApprovalPolicyRuleID)
			r.ApprovalPolicyReason = chooseNonEmpty(strVal(obj["reason"]), r.ApprovalPolicyReason)
			r.PlaybookReversibility = chooseNonEmpty(strVal(obj["reversibility"]), r.PlaybookReversibility)
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
				r.OperatorAction = chooseNonEmpty("manual_review_required", r.OperatorAction)
				r.FailedSafeReason = chooseNonEmpty("approval_timeout", r.FailedSafeReason)
			}
			r.ApprovalActor = chooseNonEmpty(strVal(obj["actor"]), r.ApprovalActor)
			r.LastUpdatedAtUnixMs = int64Val(lastUpdatedMs, r.LastUpdatedAtUnixMs)
			if r.Source == "" {
				r.Source = "master_log"
			}
			runsByID[runID] = r
		case "response_run_manual_review_required":
			r := runsByID[runID]
			r.RunID = runID
			r.Status = "MANUAL_REVIEW_REQUIRED"
			r.RuleID = chooseNonEmpty(strVal(obj["rule_id"]), r.RuleID)
			r.PlaybookID = chooseNonEmpty(strVal(obj["playbook_id"]), r.PlaybookID)
			r.FailedSafeReason = chooseNonEmpty(strVal(obj["reason"]), r.FailedSafeReason)
			r.FailedSafeReason = chooseNonEmpty("approval_timeout", r.FailedSafeReason)
			r.OperatorAction = chooseNonEmpty(strVal(obj["operator_action"]), r.OperatorAction)
			r.OperatorAction = chooseNonEmpty("manual_review_required", r.OperatorAction)
			r.ApprovalDecision = chooseNonEmpty("timeout", r.ApprovalDecision)
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
			r.ConfidenceScore = intVal(obj["confidence_score"], r.ConfidenceScore)
			r.Lane = chooseNonEmpty(strings.ToUpper(strVal(obj["lane"])), r.Lane)
			r.NodeID = chooseNonEmpty(strVal(obj["node_id"]), r.NodeID)
			r.AssetEnvironment = chooseNonEmpty(strVal(obj["asset_environment"]), r.AssetEnvironment)
			r.AssetCriticality = chooseNonEmpty(strVal(obj["asset_criticality"]), r.AssetCriticality)
			r.AssetOwner = chooseNonEmpty(strVal(obj["asset_owner"]), r.AssetOwner)
			r.AssetTeam = chooseNonEmpty(strVal(obj["asset_team"]), r.AssetTeam)
			r.AssetRole = chooseNonEmpty(strVal(obj["asset_role"]), r.AssetRole)
			r.SourceType = chooseNonEmpty(strVal(obj["source_type"]), r.SourceType)
			r.EventType = chooseNonEmpty(strVal(obj["event_type"]), r.EventType)
			r.SrcIP = chooseNonEmpty(strVal(obj["src_ip"]), r.SrcIP)
			r.DstIP = chooseNonEmpty(strVal(obj["dst_ip"]), r.DstIP)
			r.User = chooseNonEmpty(strVal(obj["user_name"]), r.User)
			r.User = chooseNonEmpty(strVal(obj["user"]), r.User)
			r.ExecPath = chooseNonEmpty(strVal(obj["exec_path"]), r.ExecPath)
			r.Comm = chooseNonEmpty(strVal(obj["comm"]), r.Comm)
			r.Cmdline = chooseNonEmpty(strVal(obj["cmdline"]), r.Cmdline)
			r.IdentityDisplayName = chooseNonEmpty(strVal(obj["identity_display_name"]), r.IdentityDisplayName)
			r.IdentityDepartment = chooseNonEmpty(strVal(obj["identity_department"]), r.IdentityDepartment)
			r.IdentityManager = chooseNonEmpty(strVal(obj["identity_manager"]), r.IdentityManager)
			r.IdentityPrivileged = boolVal(obj["identity_privileged"], r.IdentityPrivileged)
			r.IdentityServiceAccount = boolVal(obj["identity_service_account"], r.IdentityServiceAccount)
			r.Actor = chooseNonEmpty(strVal(obj["actor"]), r.Actor)
			r.Target = chooseNonEmpty(strVal(obj["target"]), r.Target)
			r.TargetAgentID = chooseNonEmpty(strVal(obj["target_agent_id"]), r.TargetAgentID)
			r.EventIdemKey = chooseNonEmpty(strVal(obj["event_idem_key"]), r.EventIdemKey)
			r.FailedSafeReason = chooseNonEmpty(strVal(obj["failed_safe_reason"]), r.FailedSafeReason)
			r.OperatorAction = chooseNonEmpty(strVal(obj["operator_action"]), r.OperatorAction)
			r.ApprovalPolicyMode = chooseNonEmpty(strVal(obj["approval_policy_mode"]), r.ApprovalPolicyMode)
			r.ApprovalPolicyRuleID = chooseNonEmpty(strVal(obj["approval_policy_rule_id"]), r.ApprovalPolicyRuleID)
			r.AllowlistRuleID = chooseNonEmpty(strVal(obj["allowlist_rule_id"]), r.AllowlistRuleID)
			r.ApprovalPolicyReason = chooseNonEmpty(strVal(obj["approval_policy_reason"]), r.ApprovalPolicyReason)
			r.PlaybookReversibility = chooseNonEmpty(strVal(obj["playbook_reversibility"]), r.PlaybookReversibility)
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
		case "response_run_rejected":
			r := runsByID[runID]
			r.RunID = runID
			r.Status = chooseNonEmpty(strings.ToUpper(strVal(obj["status"])), r.Status)
			r.Status = chooseNonEmpty("FAILED_SAFE", r.Status)
			r.RuleID = chooseNonEmpty(strVal(obj["rule_id"]), r.RuleID)
			r.PlaybookID = chooseNonEmpty(strVal(obj["playbook_id"]), r.PlaybookID)
			r.FailedSafeReason = chooseNonEmpty(strVal(obj["failed_safe_reason"]), r.FailedSafeReason)
			r.FailedSafeReason = chooseNonEmpty("policy_rejected", r.FailedSafeReason)
			r.AllowlistRuleID = chooseNonEmpty(strVal(obj["allowlist_rule_id"]), r.AllowlistRuleID)
			r.LastUpdatedAtUnixMs = int64Val(lastUpdatedMs, r.LastUpdatedAtUnixMs)
			if r.Source == "" {
				r.Source = "master_log"
			}
			runsByID[runID] = r
		}
	})

	runs := make([]incident, 0, len(runsByID))
	nowMs := time.Now().UnixMilli()
	for runID, v := range runsByID {
		if _, purged := purgedRunIDs[runID]; purged {
			continue
		}
		v = normalizeTimedOutApproval(v, nowMs)
		v = enrichIncidentFromCreatedMeta(v, created[runID])
		v = a.enrichIncidentFromInventory(v)
		v.Severity = chooseNonEmpty(a.deriveSeverity(v, created[runID]), v.Severity)
		v.Lane = chooseNonEmpty(a.deriveLane(v, stepsByRun[runID]), v.Lane)
		v.ConfidenceScore = deriveIncidentConfidence(v)
		v = a.applyIncidentRetentionPolicy(v, nowMs)
		v.IdentityWorkflowEligible, v.IdentityWorkflowReason = identityWorkflowEligibility(v)
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
	a.logger.Info("ui_user_upserted", "username", username, "role", role, "disabled", body.Disabled, "actor", roleFromRequest(r).Username)
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
	a.logger.Info("ui_user_disabled", "username", username, "actor", roleFromRequest(r).Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username, "disabled": true})
}

func (a *app) handleAdminUsersDelete(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(strings.ToLower(r.PathValue("id")))
	if username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id is required"})
		return
	}
	roleCtx := roleFromRequest(r)
	if strings.EqualFold(roleCtx.Username, username) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "cannot delete current user"})
		return
	}
	a.usersMu.Lock()
	user, exists := a.users[username]
	if !exists {
		a.usersMu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "user not found"})
		return
	}
	if !user.Disabled {
		a.usersMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "disable user before delete"})
		return
	}
	delete(a.users, username)
	a.usersMu.Unlock()
	if err := a.saveUsers(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	a.logger.Info("ui_user_deleted", "username", username, "actor", roleCtx.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username, "deleted": true})
}

func (a *app) handleAdminPurgeDemoTestIncidents(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OlderThanDays int    `json:"older_than_days"`
		DryRun        bool   `json:"dry_run"`
		Actor         string `json:"actor"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	roleCtx := roleFromRequest(r)
	actor := chooseNonEmpty(strings.TrimSpace(body.Actor), roleCtx.Username)
	runs, _, _ := a.loadState()
	candidates := make([]incident, 0, len(runs))
	for _, run := range runs {
		if run.EnvironmentClass != "demo_test" || !run.PurgeEligible {
			continue
		}
		if body.OlderThanDays > 0 && run.AgeDays < body.OlderThanDays {
			continue
		}
		candidates = append(candidates, run)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].LastUpdatedAtUnixMs == candidates[j].LastUpdatedAtUnixMs {
			return candidates[i].RunID < candidates[j].RunID
		}
		return candidates[i].LastUpdatedAtUnixMs < candidates[j].LastUpdatedAtUnixMs
	})
	if body.DryRun {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         true,
			"dry_run":    true,
			"count":      len(candidates),
			"items":      candidates,
			"older_than": body.OlderThanDays,
		})
		return
	}
	for _, run := range candidates {
		note := fmt.Sprintf("retention_class=%s age_days=%d purge_after_days=%d", run.RetentionClass, run.AgeDays, run.PurgeAfterDays)
		if err := a.appendUIStateRecord(a.purgedIncidentsStatePath(), uiStateRecord{
			TS:     time.Now().UTC().Format(time.RFC3339Nano),
			Action: "purge_demo_test",
			RunID:  run.RunID,
			Actor:  actor,
			Note:   note,
			Status: "purged",
		}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"dry_run":    false,
		"count":      len(candidates),
		"items":      candidates,
		"older_than": body.OlderThanDays,
		"actor":      actor,
	})
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

func (a *app) identityStatePath() string {
	return filepath.Join(a.cfg.UIStateDir, "identity_actions.jsonl")
}

func (a *app) purgedIncidentsStatePath() string {
	return filepath.Join(a.cfg.UIStateDir, "purged_incidents.jsonl")
}

func (a *app) uiStateIdempotencyKey(rec uiStateRecord) string {
	base := strings.Join([]string{
		strings.TrimSpace(rec.Action),
		strings.TrimSpace(rec.RunID),
		strings.TrimSpace(strings.ToLower(rec.Actor)),
		strings.TrimSpace(strings.ToLower(rec.Assignee)),
		strings.TrimSpace(rec.Note),
		strings.TrimSpace(rec.Status),
		strings.TrimSpace(strings.ToLower(rec.Method)),
		strings.TrimSpace(strings.ToLower(rec.Reference)),
		strings.TrimSpace(strings.ToLower(rec.Scope)),
		strings.TrimSpace(rec.Reason),
		strings.TrimSpace(rec.Result),
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
		"assignment":   "",
		"notes":        []map[string]any{},
		"reviewed":     false,
		"verification": map[string]any{"verified": false},
		"restore":      map[string]any{"restored": false},
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
	_ = scanJSONLines(a.identityStatePath(), func(obj map[string]any) {
		if strVal(obj["run_id"]) != runID {
			return
		}
		action := strVal(obj["action"])
		switch action {
		case "verify_user":
			out["verification"] = map[string]any{
				"verified":  true,
				"ts":        strVal(obj["ts"]),
				"actor":     strVal(obj["actor"]),
				"method":    strVal(obj["method"]),
				"reference": strVal(obj["reference"]),
				"notes":     strVal(obj["note"]),
				"status":    strVal(obj["status"]),
				"result":    strVal(obj["result"]),
			}
		case "restore_access":
			out["restore"] = map[string]any{
				"restored":  true,
				"ts":        strVal(obj["ts"]),
				"actor":     strVal(obj["actor"]),
				"scope":     strVal(obj["scope"]),
				"reason":    strVal(obj["reason"]),
				"reference": strVal(obj["reference"]),
				"status":    strVal(obj["status"]),
				"result":    strVal(obj["result"]),
			}
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
	_ = scanJSONLines(a.purgedIncidentsStatePath(), appendEntry)
	return entries
}

func (a *app) loadPurgedRunIDs() map[string]struct{} {
	out := map[string]struct{}{}
	_ = scanJSONLines(a.purgedIncidentsStatePath(), func(obj map[string]any) {
		if strVal(obj["action"]) != "purge_demo_test" {
			return
		}
		runID := strVal(obj["run_id"])
		if runID == "" {
			return
		}
		out[runID] = struct{}{}
	})
	return out
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
		case "approval_received", "approval_approved", "approval_denied", "approval_timed_out", "response_run_manual_review_required", "response_run_partial_completion", "ui_approval_published", "ui_user_upserted", "ui_user_disabled", "ui_user_deleted", "identity_verification_completed", "identity_verification_failed_safe", "identity_verification_failed", "auth_access_restored", "auth_restore_failed_safe", "auth_access_restore_failed":
			keep = true
		case "response_run_updated":
			status := strings.ToUpper(strVal(obj["status"]))
			keep = status == "FAILED_SAFE" || status == "FAILED_TRANSIENT" || status == "MANUAL_REVIEW_REQUIRED"
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

func floatVal(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		if n, err := t.Float64(); err == nil {
			return n
		}
	case string:
		if t == "" {
			return 0
		}
		if n, err := strconv.ParseFloat(t, 64); err == nil {
			return n
		}
	}
	return 0
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

func stringSliceVal(v any) []string {
	switch t := v.(type) {
	case []string:
		out := make([]string, 0, len(t))
		for _, s := range t {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s := strVal(item)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func buildURL(base string, p string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base + p
	}
	u.Path = p
	return u.String()
}
