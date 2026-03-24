package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"r-siem-agent/internal/config"
)

type modelEditorPatch struct {
	Enabled                      *bool   `json:"enabled,omitempty"`
	Severity                     *string `json:"severity,omitempty"`
	GroupBy                      *string `json:"group_by,omitempty"`
	WindowMs                     *int64  `json:"window_ms,omitempty"`
	Threshold                    *int    `json:"threshold,omitempty"`
	ApprovalMode                 *string `json:"approval_mode,omitempty"`
	MaxBlastRadius               *int    `json:"max_blast_radius,omitempty"`
	AutoMinConfidence            *int    `json:"auto_min_confidence,omitempty"`
	AutoMaxBlastRadius           *int    `json:"auto_max_blast_radius,omitempty"`
	AutoMaxSeverity              *string `json:"auto_max_severity,omitempty"`
	RequireApprovalForPrivileged *bool   `json:"require_approval_for_privileged,omitempty"`
	RequireApprovalForLocalSrc   *bool   `json:"require_approval_for_local_src,omitempty"`
	RequireIdentityContext       *bool   `json:"require_identity_context,omitempty"`
	DefaultContainmentDurationMs *int64  `json:"default_containment_duration_ms,omitempty"`
	MaxContainmentDurationMs     *int64  `json:"max_containment_duration_ms,omitempty"`
	Required                     *bool   `json:"required,omitempty"`
	Reason                       *string `json:"reason,omitempty"`
}

type modelEditorCurrent struct {
	Enabled                      *bool  `json:"enabled,omitempty"`
	Severity                     string `json:"severity,omitempty"`
	GroupBy                      string `json:"group_by,omitempty"`
	WindowMs                     *int64 `json:"window_ms,omitempty"`
	Threshold                    *int   `json:"threshold,omitempty"`
	ApprovalMode                 string `json:"approval_mode,omitempty"`
	MaxBlastRadius               *int   `json:"max_blast_radius,omitempty"`
	AutoMinConfidence            *int   `json:"auto_min_confidence,omitempty"`
	AutoMaxBlastRadius           *int   `json:"auto_max_blast_radius,omitempty"`
	AutoMaxSeverity              string `json:"auto_max_severity,omitempty"`
	RequireApprovalForPrivileged *bool  `json:"require_approval_for_privileged,omitempty"`
	RequireApprovalForLocalSrc   *bool  `json:"require_approval_for_local_src,omitempty"`
	RequireIdentityContext       *bool  `json:"require_identity_context,omitempty"`
	DefaultContainmentDurationMs *int64 `json:"default_containment_duration_ms,omitempty"`
	MaxContainmentDurationMs     *int64 `json:"max_containment_duration_ms,omitempty"`
	Required                     *bool  `json:"required,omitempty"`
	Reason                       string `json:"reason,omitempty"`
}

type modelEditorCatalogItem struct {
	Kind             string   `json:"kind"`
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Enabled          bool     `json:"enabled"`
	Severity         string   `json:"severity,omitempty"`
	ApprovalMode     string   `json:"approval_mode,omitempty"`
	Summary          string   `json:"summary,omitempty"`
	EditableFields   []string `json:"editable_fields,omitempty"`
	PendingProposals int      `json:"pending_proposals,omitempty"`
}

type modelEditorCatalogResponse struct {
	Items                 []modelEditorCatalogItem `json:"items"`
	Count                 int                      `json:"count"`
	RestartTargets        []modelRestartTargetView `json:"restart_targets,omitempty"`
	LiveReloadSupported   bool                     `json:"live_reload_supported"`
	EffectiveAfterRestart bool                     `json:"effective_after_restart"`
	Source                string                   `json:"source"`
}

type modelEditorDetailResponse struct {
	Kind                  string                             `json:"kind"`
	ID                    string                             `json:"id"`
	Title                 string                             `json:"title"`
	EditableFields        []string                           `json:"editable_fields"`
	Current               modelEditorCurrent                 `json:"current"`
	Rule                  *incidentLogicRuleResponse         `json:"rule,omitempty"`
	Playbook              *incidentLogicPlaybookResponse     `json:"playbook,omitempty"`
	ApprovalRule          *incidentLogicApprovalRuleResponse `json:"approval_rule,omitempty"`
	RestartTargets        []modelRestartTargetView           `json:"restart_targets,omitempty"`
	LiveReloadSupported   bool                               `json:"live_reload_supported"`
	EffectiveAfterRestart bool                               `json:"effective_after_restart"`
	Source                string                             `json:"source"`
}

type modelEditorValidationResponse struct {
	OK                    bool             `json:"ok"`
	Kind                  string           `json:"kind"`
	ID                    string           `json:"id"`
	Changes               modelEditorPatch `json:"changes"`
	Warnings              []string         `json:"warnings,omitempty"`
	LiveReloadSupported   bool             `json:"live_reload_supported"`
	EffectiveAfterRestart bool             `json:"effective_after_restart"`
}

type modelProposalRecord struct {
	ProposalID            string               `json:"proposal_id"`
	TS                    string               `json:"ts"`
	Kind                  string               `json:"kind"`
	ModelID               string               `json:"model_id"`
	Actor                 string               `json:"actor"`
	Action                string               `json:"action"`
	Status                string               `json:"status"`
	Summary               string               `json:"summary,omitempty"`
	Changes               modelEditorPatch     `json:"changes,omitempty"`
	Warnings              []string             `json:"warnings,omitempty"`
	BackupPath            string               `json:"backup_path,omitempty"`
	ApprovedBy            string               `json:"approved_by,omitempty"`
	RejectedBy            string               `json:"rejected_by,omitempty"`
	AppliedBy             string               `json:"applied_by,omitempty"`
	RestartTargets        []string             `json:"restart_targets,omitempty"`
	RestartResults        []modelRestartResult `json:"restart_results,omitempty"`
	EffectiveAfterRestart bool                 `json:"effective_after_restart,omitempty"`
	IdempotencyKey        string               `json:"idempotency_key,omitempty"`
}

type modelRestartTargetView struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
	Running     bool   `json:"running,omitempty"`
	PID         int    `json:"pid,omitempty"`
	PIDFile     string `json:"pid_file,omitempty"`
	LogFile     string `json:"log_file,omitempty"`
}

type modelRestartTargetSpec struct {
	ID          string
	Label       string
	Description string
	PIDFile     string
	LogFile     string
	Command     []string
}

type modelRestartResult struct {
	Target  string `json:"target"`
	OK      bool   `json:"ok"`
	PID     int    `json:"pid,omitempty"`
	LogFile string `json:"log_file,omitempty"`
	Error   string `json:"error,omitempty"`
}

type modelProposalView struct {
	ProposalID            string               `json:"proposal_id"`
	Kind                  string               `json:"kind"`
	ModelID               string               `json:"model_id"`
	Actor                 string               `json:"actor"`
	Summary               string               `json:"summary,omitempty"`
	Status                string               `json:"status"`
	CreatedAt             string               `json:"created_at"`
	ApprovedAt            string               `json:"approved_at,omitempty"`
	ApprovedBy            string               `json:"approved_by,omitempty"`
	RejectedAt            string               `json:"rejected_at,omitempty"`
	RejectedBy            string               `json:"rejected_by,omitempty"`
	AppliedAt             string               `json:"applied_at,omitempty"`
	AppliedBy             string               `json:"applied_by,omitempty"`
	Changes               modelEditorPatch     `json:"changes"`
	Warnings              []string             `json:"warnings,omitempty"`
	BackupPath            string               `json:"backup_path,omitempty"`
	RestartTargets        []string             `json:"restart_targets,omitempty"`
	RestartResults        []modelRestartResult `json:"restart_results,omitempty"`
	EffectiveAfterRestart bool                 `json:"effective_after_restart"`
}

type modelProposalsResponse struct {
	Items                 []modelProposalView      `json:"items"`
	Count                 int                      `json:"count"`
	RestartTargets        []modelRestartTargetView `json:"restart_targets,omitempty"`
	LiveReloadSupported   bool                     `json:"live_reload_supported"`
	EffectiveAfterRestart bool                     `json:"effective_after_restart"`
}

type modelEditorConfig struct {
	LogLevel         string                       `yaml:"log_level"`
	ListenAddr       string                       `yaml:"listen_addr"`
	Transport        config.MasterTransportConfig `yaml:"transport"`
	JetStream        config.JetStreamConfig       `yaml:"jetstream"`
	Consumer         config.ConsumerConfig        `yaml:"consumer"`
	DB               config.MasterDBConfig        `yaml:"db"`
	AckDelayMs       int                          `yaml:"ack_delay_ms"`
	AckDropRate      float64                      `yaml:"ack_drop_rate"`
	Collectors       map[string]any               `yaml:"collectors,omitempty"`
	Export           map[string]any               `yaml:"export,omitempty"`
	Incidents        map[string]any               `yaml:"incidents,omitempty"`
	ResponseTriggers map[string]any               `yaml:"response_triggers,omitempty"`
	ROE              map[string]any               `yaml:"roe,omitempty"`
	RCE              struct {
		Rules []struct {
			ID        string `yaml:"id"`
			Enabled   bool   `yaml:"enabled"`
			Kind      string `yaml:"kind"`
			Severity  string `yaml:"severity"`
			GroupBy   string `yaml:"group_by"`
			WindowMs  int64  `yaml:"window_ms"`
			Threshold int    `yaml:"threshold"`
			When      struct {
				Type   string         `yaml:"type"`
				Fields map[string]any `yaml:"fields"`
			} `yaml:"when"`
			Steps []struct {
				Type string `yaml:"type"`
			} `yaml:"steps"`
			Predicates []struct {
				Type   string         `yaml:"type"`
				Fields map[string]any `yaml:"fields"`
			} `yaml:"predicates"`
		} `yaml:"rules"`
	} `yaml:"rce"`
	Playbooks []struct {
		ID        string `yaml:"id"`
		Version   int    `yaml:"version"`
		Enabled   bool   `yaml:"enabled"`
		Selectors struct {
			RuleIDs []string `yaml:"rule_ids"`
		} `yaml:"selectors"`
		PolicyRequirements struct {
			Approval                     string `yaml:"approval"`
			MaxBlastRadius               int    `yaml:"max_blast_radius"`
			AutoMinConfidence            int    `yaml:"auto_min_confidence"`
			AutoMaxBlastRadius           int    `yaml:"auto_max_blast_radius"`
			AutoMaxSeverity              string `yaml:"auto_max_severity"`
			RequireApprovalForPrivileged bool   `yaml:"require_approval_for_privileged"`
			RequireApprovalForLocalSrc   bool   `yaml:"require_approval_for_local_src"`
			RequireIdentityContext       bool   `yaml:"require_identity_context"`
			DefaultContainmentDurationMs int64  `yaml:"default_containment_duration_ms"`
			MaxContainmentDurationMs     int64  `yaml:"max_containment_duration_ms"`
		} `yaml:"policy_requirements"`
		Steps []struct {
			Name          string         `yaml:"name"`
			ActionType    string         `yaml:"action_type"`
			Reversibility string         `yaml:"reversibility"`
			TimeoutMs     int64          `yaml:"timeout_ms"`
			Retries       int            `yaml:"retries"`
			BackoffMs     int64          `yaml:"backoff_ms"`
			TargetFrom    string         `yaml:"target_from"`
			Params        map[string]any `yaml:"params"`
		} `yaml:"steps"`
	} `yaml:"playbooks"`
	Policies struct {
		Approvals struct {
			TimeoutMs                int64 `yaml:"timeout_ms"`
			DefaultAutoMinConfidence int   `yaml:"default_auto_min_confidence"`
			Rules                    []struct {
				ID       string         `yaml:"id"`
				When     map[string]any `yaml:"when"`
				Decision struct {
					Required bool   `yaml:"required"`
					Reason   string `yaml:"reason"`
				} `yaml:"decision"`
			} `yaml:"rules"`
		} `yaml:"approvals"`
		Assets    any `yaml:"assets,omitempty"`
		Identity  any `yaml:"identity,omitempty"`
		Retention any `yaml:"retention,omitempty"`
	} `yaml:"policies"`
}

func allowedRuleSeverities() map[string]struct{} {
	return map[string]struct{}{"critical": {}, "high": {}, "medium": {}, "low": {}, "info": {}}
}

func allowedApprovalModes() map[string]struct{} {
	return map[string]struct{}{"auto": {}, "required": {}, "required_for_high": {}, "required_for_critical": {}}
}

func modelEditableFields(kind string) []string {
	switch kind {
	case "rule":
		return []string{"enabled", "severity", "group_by", "window_ms", "threshold"}
	case "playbook":
		return []string{"enabled", "approval_mode", "max_blast_radius", "auto_min_confidence", "auto_max_blast_radius", "auto_max_severity", "require_approval_for_privileged", "require_approval_for_local_src", "require_identity_context", "default_containment_duration_ms", "max_containment_duration_ms"}
	case "approval_rule":
		return []string{"required", "reason"}
	default:
		return nil
	}
}

func intPtr(v int) *int       { return &v }
func int64Ptr(v int64) *int64 { return &v }

func modelLogicPlaybookSteps(in []struct {
	Name          string         `yaml:"name"`
	ActionType    string         `yaml:"action_type"`
	Reversibility string         `yaml:"reversibility"`
	TimeoutMs     int64          `yaml:"timeout_ms"`
	Retries       int            `yaml:"retries"`
	BackoffMs     int64          `yaml:"backoff_ms"`
	TargetFrom    string         `yaml:"target_from"`
	Params        map[string]any `yaml:"params"`
}) []logicPlaybookStepDefinition {
	if len(in) == 0 {
		return nil
	}
	out := make([]logicPlaybookStepDefinition, 0, len(in))
	for _, step := range in {
		paramKeys := make([]string, 0, len(step.Params))
		for key := range step.Params {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			paramKeys = append(paramKeys, key)
		}
		sort.Strings(paramKeys)
		out = append(out, logicPlaybookStepDefinition{
			Name:          strings.TrimSpace(step.Name),
			ActionType:    strings.TrimSpace(step.ActionType),
			Reversibility: strings.TrimSpace(step.Reversibility),
			TimeoutMs:     step.TimeoutMs,
			Retries:       step.Retries,
			BackoffMs:     step.BackoffMs,
			TargetFrom:    strings.TrimSpace(step.TargetFrom),
			ParamKeys:     paramKeys,
		})
	}
	return out
}

func (a *app) modelProposalsStatePath() string {
	return filepath.Join(a.cfg.UIStateDir, "model_proposals.jsonl")
}

func (a *app) modelBackupsDir() string {
	return filepath.Join(a.cfg.UIStateDir, "model_backups")
}

func (a *app) modelEditorRepoRoot() string {
	masterDir := filepath.Dir(a.cfg.MasterConfig)
	if strings.EqualFold(filepath.Base(masterDir), "configs") {
		return filepath.Dir(masterDir)
	}
	if cwd, err := os.Getwd(); err == nil && strings.TrimSpace(cwd) != "" {
		return cwd
	}
	return "."
}

func (a *app) modelEditorMasterConfigForRestart() string {
	root := a.modelEditorRepoRoot()
	demoCfg := filepath.Join(root, "tmp", "master_lan_db.yaml")
	if _, err := os.Stat(demoCfg); err == nil {
		return "tmp/master_lan_db.yaml"
	}
	if rel, err := filepath.Rel(root, a.cfg.MasterConfig); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return a.cfg.MasterConfig
}

func (a *app) allowedModelRestartTargets() []modelRestartTargetSpec {
	root := a.modelEditorRepoRoot()
	masterCfg := a.modelEditorMasterConfigForRestart()
	return []modelRestartTargetSpec{
		{
			ID:          "master-roe",
			Label:       "master-roe",
			Description: "Response orchestration and DB/event persistence",
			PIDFile:     filepath.Join(root, ".pids", "master-roe.pid"),
			LogFile:     filepath.Join(root, "logs", "master-roe.log"),
			Command:     []string{"go", "run", "-mod=vendor", "./cmd/master-roe", "--config", masterCfg},
		},
		{
			ID:          "master-roe-worker",
			Label:       "master-roe-worker",
			Description: "FAST and STANDARD action execution worker",
			PIDFile:     filepath.Join(root, ".pids", "worker.pid"),
			LogFile:     filepath.Join(root, "logs", "worker.log"),
			Command:     []string{"go", "run", "-mod=vendor", "./cmd/master-roe-worker", "--config", masterCfg, "--lane", "BOTH"},
		},
		{
			ID:          "detector-v0",
			Label:       "detector-v0",
			Description: "Rule engine and trigger publication",
			PIDFile:     filepath.Join(root, ".pids", "detector.pid"),
			LogFile:     filepath.Join(root, "logs", "detector.log"),
			Command:     []string{"go", "run", "-mod=vendor", "./cmd/detector-v0", "--config", "configs/detector.yaml"},
		},
		{
			ID:          "investigation-enricher",
			Label:       "investigation-enricher",
			Description: "External intelligence enrichment worker",
			PIDFile:     filepath.Join(root, ".pids", "investigation-enricher.pid"),
			LogFile:     filepath.Join(root, "logs", "investigation-enricher.log"),
			Command:     []string{"./scripts/run_investigation_enricher.sh"},
		},
	}
}

func (a *app) allowedModelRestartTargetsView() []modelRestartTargetView {
	specs := a.allowedModelRestartTargets()
	out := make([]modelRestartTargetView, 0, len(specs))
	for _, spec := range specs {
		out = append(out, a.modelRestartTargetView(spec))
	}
	return out
}

func (a *app) modelRestartTargetView(spec modelRestartTargetSpec) modelRestartTargetView {
	view := modelRestartTargetView{
		ID:          spec.ID,
		Label:       spec.Label,
		Description: spec.Description,
		PIDFile:     spec.PIDFile,
		LogFile:     spec.LogFile,
		Status:      "unknown",
	}
	pid, err := readPIDFile(spec.PIDFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			view.Status = "missing_pid"
			return view
		}
		view.Status = "invalid_pid"
		return view
	}
	view.PID = pid
	proc, err := os.FindProcess(pid)
	if err != nil {
		view.Status = "stale_pid"
		return view
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		view.Status = "stale_pid"
		return view
	}
	view.Running = true
	view.Status = "running"
	return view
}

func (a *app) lookupModelRestartTarget(id string) (modelRestartTargetSpec, bool) {
	id = strings.TrimSpace(id)
	for _, spec := range a.allowedModelRestartTargets() {
		if spec.ID == id {
			return spec, true
		}
	}
	return modelRestartTargetSpec{}, false
}

func (a *app) normalizeRestartTargets(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, ok := a.lookupModelRestartTarget(id); !ok {
			return nil, fmt.Errorf("unsupported restart target: %s", id)
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

func readPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid pid file: %s", path)
	}
	return pid, nil
}

func stopPID(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	_ = proc.Signal(os.Interrupt)
	for i := 0; i < 20; i++ {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = proc.Kill()
	for i := 0; i < 10; i++ {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func (a *app) restartModelTarget(spec modelRestartTargetSpec) modelRestartResult {
	result := modelRestartResult{Target: spec.ID, LogFile: spec.LogFile}
	pid, err := readPIDFile(spec.PIDFile)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if err := stopPID(pid); err != nil {
		result.Error = err.Error()
		return result
	}
	if err := os.MkdirAll(filepath.Dir(spec.LogFile), 0o755); err != nil {
		result.Error = err.Error()
		return result
	}
	logf, err := os.OpenFile(spec.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer logf.Close()
	cmd := exec.Command(spec.Command[0], spec.Command[1:]...)
	cmd.Dir = a.modelEditorRepoRoot()
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(a.modelEditorRepoRoot(), ".cache", "go-build"))
	if err := cmd.Start(); err != nil {
		result.Error = err.Error()
		return result
	}
	newPID := cmd.Process.Pid
	if err := os.WriteFile(spec.PIDFile, []byte(strconv.Itoa(newPID)), 0o644); err != nil {
		result.Error = err.Error()
		return result
	}
	time.Sleep(1 * time.Second)
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		result.Error = fmt.Sprintf("restart failed: %v", err)
		return result
	}
	result.OK = true
	result.PID = newPID
	return result
}

func (a *app) reloadLogicCatalog() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ruleSeverityByID, a.playbookApprovalBy, a.retentionRules, a.defaultAssetEnv, a.assetByNodeID, a.assetByTargetAgent, a.identityByUser,
		a.logicRulesByID, a.logicPlaybooksByID, a.approvalRulesByID, a.approvalTimeoutMs, a.defaultAutoMinConf = loadDashboardHints(a.cfg.MasterConfig)
}

func loadModelEditorConfig(path string) (*modelEditorConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg modelEditorConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (a *app) currentModelState(kind, id string) (modelEditorCurrent, *incidentLogicRuleResponse, *incidentLogicPlaybookResponse, *incidentLogicApprovalRuleResponse, error) {
	cfg, err := loadModelEditorConfig(a.cfg.MasterConfig)
	if err != nil {
		return modelEditorCurrent{}, nil, nil, nil, err
	}
	switch kind {
	case "rule":
		for _, rule := range cfg.RCE.Rules {
			if strings.TrimSpace(rule.ID) != id {
				continue
			}
			current := modelEditorCurrent{
				Enabled:   boolPtr(rule.Enabled),
				Severity:  strings.TrimSpace(rule.Severity),
				GroupBy:   strings.TrimSpace(rule.GroupBy),
				WindowMs:  int64Ptr(rule.WindowMs),
				Threshold: intPtr(rule.Threshold),
			}
			logic := incidentLogicRuleResponse{
				ID:         id,
				Enabled:    rule.Enabled,
				Kind:       strings.TrimSpace(rule.Kind),
				Severity:   strings.TrimSpace(rule.Severity),
				GroupBy:    strings.TrimSpace(rule.GroupBy),
				WindowMs:   rule.WindowMs,
				Threshold:  rule.Threshold,
				WhenType:   strings.TrimSpace(rule.When.Type),
				Conditions: stringifyConditions(rule.When.Fields),
				Sequence:   extractSequenceTypes(rule.Steps),
				Predicates: extractPredicateSummaries(rule.Predicates),
			}
			return current, &logic, nil, nil, nil
		}
	case "playbook":
		for _, pb := range cfg.Playbooks {
			if strings.TrimSpace(pb.ID) != id {
				continue
			}
			current := modelEditorCurrent{
				Enabled:                      boolPtr(pb.Enabled),
				ApprovalMode:                 strings.TrimSpace(pb.PolicyRequirements.Approval),
				MaxBlastRadius:               intPtr(pb.PolicyRequirements.MaxBlastRadius),
				AutoMinConfidence:            intPtr(pb.PolicyRequirements.AutoMinConfidence),
				AutoMaxBlastRadius:           intPtr(pb.PolicyRequirements.AutoMaxBlastRadius),
				AutoMaxSeverity:              strings.TrimSpace(pb.PolicyRequirements.AutoMaxSeverity),
				RequireApprovalForPrivileged: boolPtr(pb.PolicyRequirements.RequireApprovalForPrivileged),
				RequireApprovalForLocalSrc:   boolPtr(pb.PolicyRequirements.RequireApprovalForLocalSrc),
				RequireIdentityContext:       boolPtr(pb.PolicyRequirements.RequireIdentityContext),
				DefaultContainmentDurationMs: int64Ptr(pb.PolicyRequirements.DefaultContainmentDurationMs),
				MaxContainmentDurationMs:     int64Ptr(pb.PolicyRequirements.MaxContainmentDurationMs),
			}
			logic := incidentLogicPlaybookResponse{
				ID:                           id,
				Version:                      pb.Version,
				Enabled:                      pb.Enabled,
				SelectorRuleIDs:              append([]string(nil), pb.Selectors.RuleIDs...),
				ApprovalMode:                 strings.TrimSpace(pb.PolicyRequirements.Approval),
				MaxBlastRadius:               pb.PolicyRequirements.MaxBlastRadius,
				AutoMinConfidence:            pb.PolicyRequirements.AutoMinConfidence,
				AutoMaxBlastRadius:           pb.PolicyRequirements.AutoMaxBlastRadius,
				AutoMaxSeverity:              strings.TrimSpace(pb.PolicyRequirements.AutoMaxSeverity),
				RequireApprovalForPrivileged: pb.PolicyRequirements.RequireApprovalForPrivileged,
				RequireApprovalForLocalSrc:   pb.PolicyRequirements.RequireApprovalForLocalSrc,
				RequireIdentityContext:       pb.PolicyRequirements.RequireIdentityContext,
				DefaultContainmentDurationMs: pb.PolicyRequirements.DefaultContainmentDurationMs,
				MaxContainmentDurationMs:     pb.PolicyRequirements.MaxContainmentDurationMs,
				Steps:                        buildIncidentLogicPlaybookSteps(modelLogicPlaybookSteps(pb.Steps)),
			}
			return current, nil, &logic, nil, nil
		}
	case "approval_rule":
		for _, rule := range cfg.Policies.Approvals.Rules {
			if strings.TrimSpace(rule.ID) != id {
				continue
			}
			current := modelEditorCurrent{
				Required: boolPtr(rule.Decision.Required),
				Reason:   strings.TrimSpace(rule.Decision.Reason),
			}
			logic := incidentLogicApprovalRuleResponse{
				ID:         id,
				Conditions: stringifyConditions(rule.When),
				Required:   rule.Decision.Required,
				Reason:     strings.TrimSpace(rule.Decision.Reason),
			}
			return current, nil, nil, &logic, nil
		}
	}
	return modelEditorCurrent{}, nil, nil, nil, fmt.Errorf("model not found")
}

func normalizeModelPatch(kind, id string, current modelEditorCurrent, patch modelEditorPatch) (modelEditorPatch, []string, error) {
	warnings := []string{"Applied config changes only affect running services after a controlled restart or clean start. Live hot reload is not supported."}
	trimString := func(v *string) *string {
		if v == nil {
			return nil
		}
		x := strings.TrimSpace(*v)
		return &x
	}
	patch.Severity = trimString(patch.Severity)
	patch.GroupBy = trimString(patch.GroupBy)
	patch.ApprovalMode = trimString(patch.ApprovalMode)
	patch.AutoMaxSeverity = trimString(patch.AutoMaxSeverity)
	patch.Reason = trimString(patch.Reason)
	switch kind {
	case "rule":
		if patch.Severity != nil {
			if _, ok := allowedRuleSeverities()[strings.ToLower(*patch.Severity)]; !ok {
				return modelEditorPatch{}, nil, fmt.Errorf("invalid severity for rule %s", id)
			}
			v := strings.ToLower(*patch.Severity)
			patch.Severity = &v
		}
		if patch.WindowMs != nil && *patch.WindowMs <= 0 {
			return modelEditorPatch{}, nil, fmt.Errorf("window_ms must be > 0")
		}
		if patch.Threshold != nil && *patch.Threshold <= 0 {
			return modelEditorPatch{}, nil, fmt.Errorf("threshold must be > 0")
		}
	case "playbook":
		if patch.ApprovalMode != nil {
			if _, ok := allowedApprovalModes()[strings.ToLower(*patch.ApprovalMode)]; !ok {
				return modelEditorPatch{}, nil, fmt.Errorf("invalid approval_mode for playbook %s", id)
			}
			v := strings.ToLower(*patch.ApprovalMode)
			patch.ApprovalMode = &v
		}
		if patch.MaxBlastRadius != nil && *patch.MaxBlastRadius < 0 {
			return modelEditorPatch{}, nil, fmt.Errorf("max_blast_radius must be >= 0")
		}
		if patch.AutoMinConfidence != nil && (*patch.AutoMinConfidence < 0 || *patch.AutoMinConfidence > 100) {
			return modelEditorPatch{}, nil, fmt.Errorf("auto_min_confidence must be between 0 and 100")
		}
		if patch.AutoMaxBlastRadius != nil && *patch.AutoMaxBlastRadius < 0 {
			return modelEditorPatch{}, nil, fmt.Errorf("auto_max_blast_radius must be >= 0")
		}
		if patch.AutoMaxSeverity != nil && *patch.AutoMaxSeverity != "" {
			if _, ok := allowedRuleSeverities()[strings.ToLower(*patch.AutoMaxSeverity)]; !ok {
				return modelEditorPatch{}, nil, fmt.Errorf("invalid auto_max_severity for playbook %s", id)
			}
			v := strings.ToLower(*patch.AutoMaxSeverity)
			patch.AutoMaxSeverity = &v
		}
		if patch.DefaultContainmentDurationMs != nil && *patch.DefaultContainmentDurationMs < 0 {
			return modelEditorPatch{}, nil, fmt.Errorf("default_containment_duration_ms must be >= 0")
		}
		if patch.MaxContainmentDurationMs != nil && *patch.MaxContainmentDurationMs < 0 {
			return modelEditorPatch{}, nil, fmt.Errorf("max_containment_duration_ms must be >= 0")
		}
	case "approval_rule":
		if patch.Reason != nil && patch.Required != nil && *patch.Required && strings.TrimSpace(*patch.Reason) == "" {
			return modelEditorPatch{}, nil, fmt.Errorf("reason is required when approval rule remains required")
		}
	default:
		return modelEditorPatch{}, nil, fmt.Errorf("unsupported model kind")
	}
	changed := modelEditorPatch{}
	if patch.Enabled != nil && (current.Enabled == nil || *patch.Enabled != *current.Enabled) {
		changed.Enabled = patch.Enabled
	}
	if patch.Severity != nil && strings.TrimSpace(current.Severity) != valueString(patch.Severity) {
		changed.Severity = patch.Severity
	}
	if patch.GroupBy != nil && strings.TrimSpace(current.GroupBy) != valueString(patch.GroupBy) {
		changed.GroupBy = patch.GroupBy
	}
	if patch.WindowMs != nil && (current.WindowMs == nil || *patch.WindowMs != *current.WindowMs) {
		changed.WindowMs = patch.WindowMs
	}
	if patch.Threshold != nil && (current.Threshold == nil || *patch.Threshold != *current.Threshold) {
		changed.Threshold = patch.Threshold
	}
	if patch.ApprovalMode != nil && strings.TrimSpace(current.ApprovalMode) != valueString(patch.ApprovalMode) {
		changed.ApprovalMode = patch.ApprovalMode
	}
	if patch.MaxBlastRadius != nil && (current.MaxBlastRadius == nil || *patch.MaxBlastRadius != *current.MaxBlastRadius) {
		changed.MaxBlastRadius = patch.MaxBlastRadius
	}
	if patch.AutoMinConfidence != nil && (current.AutoMinConfidence == nil || *patch.AutoMinConfidence != *current.AutoMinConfidence) {
		changed.AutoMinConfidence = patch.AutoMinConfidence
	}
	if patch.AutoMaxBlastRadius != nil && (current.AutoMaxBlastRadius == nil || *patch.AutoMaxBlastRadius != *current.AutoMaxBlastRadius) {
		changed.AutoMaxBlastRadius = patch.AutoMaxBlastRadius
	}
	if patch.AutoMaxSeverity != nil && strings.TrimSpace(current.AutoMaxSeverity) != valueString(patch.AutoMaxSeverity) {
		changed.AutoMaxSeverity = patch.AutoMaxSeverity
	}
	if patch.RequireApprovalForPrivileged != nil && (current.RequireApprovalForPrivileged == nil || *patch.RequireApprovalForPrivileged != *current.RequireApprovalForPrivileged) {
		changed.RequireApprovalForPrivileged = patch.RequireApprovalForPrivileged
	}
	if patch.RequireApprovalForLocalSrc != nil && (current.RequireApprovalForLocalSrc == nil || *patch.RequireApprovalForLocalSrc != *current.RequireApprovalForLocalSrc) {
		changed.RequireApprovalForLocalSrc = patch.RequireApprovalForLocalSrc
	}
	if patch.RequireIdentityContext != nil && (current.RequireIdentityContext == nil || *patch.RequireIdentityContext != *current.RequireIdentityContext) {
		changed.RequireIdentityContext = patch.RequireIdentityContext
	}
	if patch.DefaultContainmentDurationMs != nil && (current.DefaultContainmentDurationMs == nil || *patch.DefaultContainmentDurationMs != *current.DefaultContainmentDurationMs) {
		changed.DefaultContainmentDurationMs = patch.DefaultContainmentDurationMs
	}
	if patch.MaxContainmentDurationMs != nil && (current.MaxContainmentDurationMs == nil || *patch.MaxContainmentDurationMs != *current.MaxContainmentDurationMs) {
		changed.MaxContainmentDurationMs = patch.MaxContainmentDurationMs
	}
	if patch.Required != nil && (current.Required == nil || *patch.Required != *current.Required) {
		changed.Required = patch.Required
	}
	if patch.Reason != nil && strings.TrimSpace(current.Reason) != valueString(patch.Reason) {
		changed.Reason = patch.Reason
	}
	return changed, warnings, nil
}

func valueString(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

func patchIsEmpty(p modelEditorPatch) bool {
	return p.Enabled == nil && p.Severity == nil && p.GroupBy == nil && p.WindowMs == nil && p.Threshold == nil &&
		p.ApprovalMode == nil && p.MaxBlastRadius == nil && p.AutoMinConfidence == nil && p.AutoMaxBlastRadius == nil &&
		p.AutoMaxSeverity == nil && p.RequireApprovalForPrivileged == nil && p.RequireApprovalForLocalSrc == nil &&
		p.RequireIdentityContext == nil && p.DefaultContainmentDurationMs == nil && p.MaxContainmentDurationMs == nil &&
		p.Required == nil && p.Reason == nil
}

func validatePatchedConfig(path string, kind, id string, patch modelEditorPatch) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	updated, err := applyPatchToMasterConfig(data, kind, id, patch)
	if err != nil {
		return err
	}
	tmpDir := filepath.Join(os.TempDir(), "rsiem_model_editor_validate")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return err
	}
	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("master_validate_%d.yaml", time.Now().UnixNano()))
	defer os.Remove(tmpFile)
	if err := os.WriteFile(tmpFile, updated, 0o644); err != nil {
		return err
	}
	if _, err := config.LoadMaster(tmpFile); err != nil {
		return err
	}
	var hints dashboardHintsConfig
	if err := yaml.Unmarshal(updated, &hints); err != nil {
		return err
	}
	return nil
}

func applyPatchToMasterConfig(data []byte, kind, id string, patch modelEditorPatch) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, fmt.Errorf("invalid yaml document")
	}
	root := doc.Content[0]
	switch kind {
	case "rule":
		item, err := findRuleNode(root, id)
		if err != nil {
			return nil, err
		}
		applyScalarPatch(item, "enabled", patch.Enabled)
		applyScalarPatch(item, "severity", patch.Severity)
		applyScalarPatch(item, "group_by", patch.GroupBy)
		applyScalarPatch(item, "window_ms", patch.WindowMs)
		applyScalarPatch(item, "threshold", patch.Threshold)
	case "playbook":
		item, err := findPlaybookNode(root, id)
		if err != nil {
			return nil, err
		}
		applyScalarPatch(item, "enabled", patch.Enabled)
		policyNode, err := findMapValue(item, "policy_requirements")
		if err != nil {
			return nil, err
		}
		applyScalarPatch(policyNode, "approval", patch.ApprovalMode)
		applyScalarPatch(policyNode, "max_blast_radius", patch.MaxBlastRadius)
		applyScalarPatch(policyNode, "auto_min_confidence", patch.AutoMinConfidence)
		applyScalarPatch(policyNode, "auto_max_blast_radius", patch.AutoMaxBlastRadius)
		applyScalarPatch(policyNode, "auto_max_severity", patch.AutoMaxSeverity)
		applyScalarPatch(policyNode, "require_approval_for_privileged", patch.RequireApprovalForPrivileged)
		applyScalarPatch(policyNode, "require_approval_for_local_src", patch.RequireApprovalForLocalSrc)
		applyScalarPatch(policyNode, "require_identity_context", patch.RequireIdentityContext)
		applyScalarPatch(policyNode, "default_containment_duration_ms", patch.DefaultContainmentDurationMs)
		applyScalarPatch(policyNode, "max_containment_duration_ms", patch.MaxContainmentDurationMs)
	case "approval_rule":
		item, err := findApprovalRuleNode(root, id)
		if err != nil {
			return nil, err
		}
		decisionNode, err := findMapValue(item, "decision")
		if err != nil {
			return nil, err
		}
		applyScalarPatch(decisionNode, "required", patch.Required)
		applyScalarPatch(decisionNode, "reason", patch.Reason)
	default:
		return nil, fmt.Errorf("unsupported model kind")
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	_ = enc.Close()
	return out.Bytes(), nil
}

func findMapValue(node *yaml.Node, key string) (*yaml.Node, error) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping node for key %s", key)
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if strings.TrimSpace(node.Content[i].Value) == key {
			return node.Content[i+1], nil
		}
	}
	return nil, fmt.Errorf("missing key %s", key)
}

func findSeqItemByID(seq *yaml.Node, id string) (*yaml.Node, error) {
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("expected sequence node")
	}
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(item.Content); i += 2 {
			if strings.TrimSpace(item.Content[i].Value) == "id" && strings.TrimSpace(item.Content[i+1].Value) == id {
				return item, nil
			}
		}
	}
	return nil, fmt.Errorf("item %s not found", id)
}

func findRuleNode(root *yaml.Node, id string) (*yaml.Node, error) {
	rce, err := findMapValue(root, "rce")
	if err != nil {
		return nil, err
	}
	rules, err := findMapValue(rce, "rules")
	if err != nil {
		return nil, err
	}
	return findSeqItemByID(rules, id)
}

func findPlaybookNode(root *yaml.Node, id string) (*yaml.Node, error) {
	playbooks, err := findMapValue(root, "playbooks")
	if err != nil {
		return nil, err
	}
	return findSeqItemByID(playbooks, id)
}

func findApprovalRuleNode(root *yaml.Node, id string) (*yaml.Node, error) {
	policies, err := findMapValue(root, "policies")
	if err != nil {
		return nil, err
	}
	approvals, err := findMapValue(policies, "approvals")
	if err != nil {
		return nil, err
	}
	rules, err := findMapValue(approvals, "rules")
	if err != nil {
		return nil, err
	}
	return findSeqItemByID(rules, id)
}

func applyScalarPatch[T any](node *yaml.Node, key string, value *T) {
	if value == nil || node == nil || node.Kind != yaml.MappingNode {
		return
	}
	var rendered string
	tag := "!!str"
	switch v := any(*value).(type) {
	case bool:
		rendered = strconv.FormatBool(v)
		tag = "!!bool"
	case int:
		rendered = strconv.Itoa(v)
		tag = "!!int"
	case int64:
		rendered = strconv.FormatInt(v, 10)
		tag = "!!int"
	case string:
		rendered = v
	default:
		return
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if strings.TrimSpace(node.Content[i].Value) == key {
			node.Content[i+1].Kind = yaml.ScalarNode
			node.Content[i+1].Tag = tag
			node.Content[i+1].Value = rendered
			return
		}
	}
	node.Content = append(node.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: rendered},
	)
}

func (a *app) loadModelCatalog() ([]modelEditorCatalogItem, error) {
	cfg, err := loadModelEditorConfig(a.cfg.MasterConfig)
	if err != nil {
		return nil, err
	}
	proposalViews, _ := a.loadModelProposalViews()
	pendingByModel := map[string]int{}
	for _, proposal := range proposalViews {
		if proposal.Status == "pending_approval" || proposal.Status == "approved" {
			pendingByModel[proposal.Kind+":"+proposal.ModelID]++
		}
	}
	items := make([]modelEditorCatalogItem, 0, len(cfg.RCE.Rules)+len(cfg.Playbooks)+len(cfg.Policies.Approvals.Rules))
	for _, rule := range cfg.RCE.Rules {
		id := strings.TrimSpace(rule.ID)
		if id == "" {
			continue
		}
		items = append(items, modelEditorCatalogItem{
			Kind:             "rule",
			ID:               id,
			Title:            id,
			Enabled:          rule.Enabled,
			Severity:         strings.TrimSpace(rule.Severity),
			Summary:          fmt.Sprintf("%s rule, threshold %d, window %dms", strings.TrimSpace(rule.Kind), rule.Threshold, rule.WindowMs),
			EditableFields:   modelEditableFields("rule"),
			PendingProposals: pendingByModel["rule:"+id],
		})
	}
	for _, pb := range cfg.Playbooks {
		id := strings.TrimSpace(pb.ID)
		if id == "" {
			continue
		}
		items = append(items, modelEditorCatalogItem{
			Kind:             "playbook",
			ID:               id,
			Title:            id,
			Enabled:          pb.Enabled,
			ApprovalMode:     strings.TrimSpace(pb.PolicyRequirements.Approval),
			Summary:          fmt.Sprintf("v%d, %d steps, approval %s", pb.Version, len(pb.Steps), strings.TrimSpace(pb.PolicyRequirements.Approval)),
			EditableFields:   modelEditableFields("playbook"),
			PendingProposals: pendingByModel["playbook:"+id],
		})
	}
	for _, rule := range cfg.Policies.Approvals.Rules {
		id := strings.TrimSpace(rule.ID)
		if id == "" {
			continue
		}
		items = append(items, modelEditorCatalogItem{
			Kind:             "approval_rule",
			ID:               id,
			Title:            id,
			Enabled:          rule.Decision.Required,
			Summary:          strings.TrimSpace(rule.Decision.Reason),
			EditableFields:   modelEditableFields("approval_rule"),
			PendingProposals: pendingByModel["approval_rule:"+id],
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Kind == items[j].Kind {
			return items[i].ID < items[j].ID
		}
		return items[i].Kind < items[j].Kind
	})
	return items, nil
}

func (a *app) appendModelProposalRecord(rec modelProposalRecord) error {
	if strings.TrimSpace(rec.ProposalID) == "" {
		return fmt.Errorf("proposal_id is required")
	}
	if strings.TrimSpace(rec.IdempotencyKey) == "" {
		rec.IdempotencyKey = rec.ProposalID + ":" + rec.Action
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	path := a.modelProposalsStatePath()
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
	a.logger.Info("ui_model_proposal_event",
		"proposal_id", rec.ProposalID,
		"kind", rec.Kind,
		"model_id", rec.ModelID,
		"action", rec.Action,
		"actor", rec.Actor,
		"status", rec.Status,
	)
	return nil
}

func (a *app) loadModelProposalViews() ([]modelProposalView, error) {
	path := a.modelProposalsStatePath()
	viewsByID := map[string]modelProposalView{}
	err := scanJSONLines(path, func(obj map[string]any) {
		id := strings.TrimSpace(strVal(obj["proposal_id"]))
		if id == "" {
			return
		}
		view := viewsByID[id]
		if view.ProposalID == "" {
			view = modelProposalView{
				ProposalID:            id,
				Kind:                  strVal(obj["kind"]),
				ModelID:               strVal(obj["model_id"]),
				Actor:                 strVal(obj["actor"]),
				Summary:               strVal(obj["summary"]),
				Status:                strVal(obj["status"]),
				CreatedAt:             strVal(obj["ts"]),
				EffectiveAfterRestart: boolVal(obj["effective_after_restart"], true),
			}
		}
		switch action := strVal(obj["action"]); action {
		case "approve":
			view.Status = chooseNonEmpty(strVal(obj["status"]), "approved")
			view.ApprovedAt = strVal(obj["ts"])
			view.ApprovedBy = chooseNonEmpty(strVal(obj["approved_by"]), strVal(obj["actor"]))
		case "reject":
			view.Status = chooseNonEmpty(strVal(obj["status"]), "rejected")
			view.RejectedAt = strVal(obj["ts"])
			view.RejectedBy = chooseNonEmpty(strVal(obj["rejected_by"]), strVal(obj["actor"]))
		case "apply":
			view.Status = chooseNonEmpty(strVal(obj["status"]), "applied")
			view.AppliedAt = strVal(obj["ts"])
			view.AppliedBy = chooseNonEmpty(strVal(obj["applied_by"]), strVal(obj["actor"]))
			view.BackupPath = strVal(obj["backup_path"])
			if raw, err := json.Marshal(obj["restart_targets"]); err == nil {
				var targets []string
				if json.Unmarshal(raw, &targets) == nil {
					view.RestartTargets = targets
				}
			}
			if raw, err := json.Marshal(obj["restart_results"]); err == nil {
				var results []modelRestartResult
				if json.Unmarshal(raw, &results) == nil {
					view.RestartResults = results
				}
			}
		default:
			view.Status = chooseNonEmpty(strVal(obj["status"]), view.Status)
		}
		if raw, err := json.Marshal(obj["changes"]); err == nil {
			var patch modelEditorPatch
			if json.Unmarshal(raw, &patch) == nil {
				view.Changes = patch
			}
		}
		if raw, err := json.Marshal(obj["warnings"]); err == nil {
			var warnings []string
			if json.Unmarshal(raw, &warnings) == nil {
				view.Warnings = warnings
			}
		}
		viewsByID[id] = view
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	out := make([]modelProposalView, 0, len(viewsByID))
	for _, view := range viewsByID {
		out = append(out, view)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CreatedAt > out[j].CreatedAt
	})
	return out, nil
}

func (a *app) handleModelCatalog(w http.ResponseWriter, r *http.Request) {
	items, err := a.loadModelCatalog()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, modelEditorCatalogResponse{
		Items:                 items,
		Count:                 len(items),
		RestartTargets:        a.allowedModelRestartTargetsView(),
		LiveReloadSupported:   false,
		EffectiveAfterRestart: true,
		Source:                "master_config",
	})
}

func (a *app) handleModelDetail(w http.ResponseWriter, r *http.Request) {
	kind := strings.TrimSpace(r.PathValue("kind"))
	id := strings.TrimSpace(r.PathValue("id"))
	current, rule, playbook, approvalRule, err := a.currentModelState(kind, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, modelEditorDetailResponse{
		Kind:                  kind,
		ID:                    id,
		Title:                 id,
		EditableFields:        modelEditableFields(kind),
		Current:               current,
		Rule:                  rule,
		Playbook:              playbook,
		ApprovalRule:          approvalRule,
		RestartTargets:        a.allowedModelRestartTargetsView(),
		LiveReloadSupported:   false,
		EffectiveAfterRestart: true,
		Source:                "master_config",
	})
}

func decodeModelPatch(r *http.Request) (modelEditorPatch, string, error) {
	var body struct {
		Summary string           `json:"summary"`
		Changes modelEditorPatch `json:"changes"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		return modelEditorPatch{}, "", err
	}
	return body.Changes, strings.TrimSpace(body.Summary), nil
}

func decodeModelApplyRequest(r *http.Request) ([]string, error) {
	var body struct {
		RestartTargets []string `json:"restart_targets"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		return nil, err
	}
	return body.RestartTargets, nil
}

func (a *app) findModelProposal(proposalID string) (*modelProposalView, error) {
	proposals, err := a.loadModelProposalViews()
	if err != nil {
		return nil, err
	}
	for i := range proposals {
		if proposals[i].ProposalID == proposalID {
			return &proposals[i], nil
		}
	}
	return nil, nil
}

func (a *app) handleModelValidate(w http.ResponseWriter, r *http.Request) {
	kind := strings.TrimSpace(r.PathValue("kind"))
	id := strings.TrimSpace(r.PathValue("id"))
	current, _, _, _, err := a.currentModelState(kind, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	patch, _, err := decodeModelPatch(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	normalized, warnings, err := normalizeModelPatch(kind, id, current, patch)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if patchIsEmpty(normalized) {
		writeJSON(w, http.StatusOK, modelEditorValidationResponse{OK: true, Kind: kind, ID: id, Changes: modelEditorPatch{}, Warnings: append(warnings, "No changes detected relative to current config."), LiveReloadSupported: false, EffectiveAfterRestart: true})
		return
	}
	if err := validatePatchedConfig(a.cfg.MasterConfig, kind, id, normalized); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, modelEditorValidationResponse{OK: true, Kind: kind, ID: id, Changes: normalized, Warnings: warnings, LiveReloadSupported: false, EffectiveAfterRestart: true})
}

func (a *app) handleModelPropose(w http.ResponseWriter, r *http.Request) {
	kind := strings.TrimSpace(r.PathValue("kind"))
	id := strings.TrimSpace(r.PathValue("id"))
	roleCtx := roleFromRequest(r)
	current, _, _, _, err := a.currentModelState(kind, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	patch, summary, err := decodeModelPatch(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	normalized, warnings, err := normalizeModelPatch(kind, id, current, patch)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if patchIsEmpty(normalized) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no config changes to propose"})
		return
	}
	if err := validatePatchedConfig(a.cfg.MasterConfig, kind, id, normalized); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	proposalID := fmt.Sprintf("mdl_%d", time.Now().UnixNano())
	rec := modelProposalRecord{
		ProposalID:            proposalID,
		TS:                    time.Now().UTC().Format(time.RFC3339Nano),
		Kind:                  kind,
		ModelID:               id,
		Actor:                 roleCtx.Username,
		Action:                "propose",
		Status:                "pending_approval",
		Summary:               summary,
		Changes:               normalized,
		Warnings:              warnings,
		EffectiveAfterRestart: true,
		IdempotencyKey:        proposalID + ":propose",
	}
	if err := a.appendModelProposalRecord(rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	a.logger.Info("ui_model_change_proposed", "proposal_id", proposalID, "kind", kind, "model_id", id, "actor", roleCtx.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "proposal_id": proposalID, "kind": kind, "id": id, "changes": normalized, "warnings": warnings, "effective_after_restart": true})
}

func (a *app) handleModelApprove(w http.ResponseWriter, r *http.Request) {
	proposalID := strings.TrimSpace(r.PathValue("proposal_id"))
	roleCtx := roleFromRequest(r)
	proposal, err := a.findModelProposal(proposalID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if proposal == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "proposal not found"})
		return
	}
	if proposal.Status != "pending_approval" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "proposal is not awaiting approval"})
		return
	}
	if strings.EqualFold(strings.TrimSpace(proposal.Actor), strings.TrimSpace(roleCtx.Username)) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "dual control required: proposer cannot approve"})
		return
	}
	rec := modelProposalRecord{
		ProposalID:            proposalID,
		TS:                    time.Now().UTC().Format(time.RFC3339Nano),
		Kind:                  proposal.Kind,
		ModelID:               proposal.ModelID,
		Actor:                 roleCtx.Username,
		Action:                "approve",
		Status:                "approved",
		Summary:               proposal.Summary,
		Changes:               proposal.Changes,
		Warnings:              proposal.Warnings,
		ApprovedBy:            roleCtx.Username,
		EffectiveAfterRestart: true,
		IdempotencyKey:        proposalID + ":approve",
	}
	if err := a.appendModelProposalRecord(rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	a.logger.Info("ui_model_change_approved", "proposal_id", proposalID, "kind", proposal.Kind, "model_id", proposal.ModelID, "actor", roleCtx.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "proposal_id": proposalID, "status": "approved"})
}

func (a *app) handleModelReject(w http.ResponseWriter, r *http.Request) {
	proposalID := strings.TrimSpace(r.PathValue("proposal_id"))
	roleCtx := roleFromRequest(r)
	proposal, err := a.findModelProposal(proposalID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if proposal == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "proposal not found"})
		return
	}
	if proposal.Status != "pending_approval" && proposal.Status != "approved" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "proposal is not open"})
		return
	}
	rec := modelProposalRecord{
		ProposalID:            proposalID,
		TS:                    time.Now().UTC().Format(time.RFC3339Nano),
		Kind:                  proposal.Kind,
		ModelID:               proposal.ModelID,
		Actor:                 roleCtx.Username,
		Action:                "reject",
		Status:                "rejected",
		Summary:               proposal.Summary,
		Changes:               proposal.Changes,
		Warnings:              proposal.Warnings,
		RejectedBy:            roleCtx.Username,
		EffectiveAfterRestart: true,
		IdempotencyKey:        proposalID + ":reject",
	}
	if err := a.appendModelProposalRecord(rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	a.logger.Info("ui_model_change_rejected", "proposal_id", proposalID, "kind", proposal.Kind, "model_id", proposal.ModelID, "actor", roleCtx.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "proposal_id": proposalID, "status": "rejected"})
}

func (a *app) handleModelProposals(w http.ResponseWriter, _ *http.Request) {
	items, err := a.loadModelProposalViews()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, modelProposalsResponse{
		Items:                 items,
		Count:                 len(items),
		RestartTargets:        a.allowedModelRestartTargetsView(),
		LiveReloadSupported:   false,
		EffectiveAfterRestart: true,
	})
}

func (a *app) handleModelApply(w http.ResponseWriter, r *http.Request) {
	proposalID := strings.TrimSpace(r.PathValue("proposal_id"))
	roleCtx := roleFromRequest(r)
	restartTargets, err := decodeModelApplyRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	restartTargets, err = a.normalizeRestartTargets(restartTargets)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	proposal, err := a.findModelProposal(proposalID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if proposal == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "proposal not found"})
		return
	}
	if proposal.Status != "approved" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "proposal must be approved before apply"})
		return
	}
	if err := validatePatchedConfig(a.cfg.MasterConfig, proposal.Kind, proposal.ModelID, proposal.Changes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	data, err := os.ReadFile(a.cfg.MasterConfig)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	updated, err := applyPatchToMasterConfig(data, proposal.Kind, proposal.ModelID, proposal.Changes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	backupDir := a.modelBackupsDir()
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	backupPath := filepath.Join(backupDir, fmt.Sprintf("master_%s_%d.yaml", proposalID, time.Now().Unix()))
	if err := os.WriteFile(backupPath, data, 0o644); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	tmpPath := a.cfg.MasterConfig + ".tmp"
	if err := os.WriteFile(tmpPath, updated, 0o644); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if err := os.Rename(tmpPath, a.cfg.MasterConfig); err != nil {
		_ = os.Remove(tmpPath)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	a.reloadLogicCatalog()
	restartResults := make([]modelRestartResult, 0, len(restartTargets))
	for _, target := range restartTargets {
		spec, ok := a.lookupModelRestartTarget(target)
		if !ok {
			continue
		}
		restartResults = append(restartResults, a.restartModelTarget(spec))
	}
	rec := modelProposalRecord{
		ProposalID:            proposalID,
		TS:                    time.Now().UTC().Format(time.RFC3339Nano),
		Kind:                  proposal.Kind,
		ModelID:               proposal.ModelID,
		Actor:                 roleCtx.Username,
		Action:                "apply",
		Status:                "applied",
		Summary:               proposal.Summary,
		Changes:               proposal.Changes,
		Warnings:              proposal.Warnings,
		AppliedBy:             roleCtx.Username,
		RestartTargets:        restartTargets,
		RestartResults:        restartResults,
		BackupPath:            backupPath,
		EffectiveAfterRestart: true,
		IdempotencyKey:        proposalID + ":apply",
	}
	if err := a.appendModelProposalRecord(rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	a.logger.Info("ui_model_change_applied", "proposal_id", proposalID, "kind", proposal.Kind, "model_id", proposal.ModelID, "actor", roleCtx.Username, "backup_path", backupPath)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                      true,
		"proposal_id":             proposalID,
		"backup_path":             backupPath,
		"restart_targets":         restartTargets,
		"restart_results":         restartResults,
		"effective_after_restart": true,
		"live_reload_supported":   false,
	})
}
