package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultManualActionDurationMs = int64(2 * time.Hour / time.Millisecond)
)

type responseActionRecord struct {
	Version         int            `json:"version"`
	TS              string         `json:"ts"`
	Action          string         `json:"action"`
	ActionID        string         `json:"action_id"`
	ScopeType       string         `json:"scope_type"`
	RunID           string         `json:"run_id,omitempty"`
	NodeID          string         `json:"node_id,omitempty"`
	TargetAgentID   string         `json:"target_agent_id,omitempty"`
	Actor           string         `json:"actor"`
	ActionName      string         `json:"action_name"`
	Label           string         `json:"label"`
	Status          string         `json:"status"`
	StatusDetail    string         `json:"status_detail,omitempty"`
	ActionType      string         `json:"action_type"`
	CommandID       string         `json:"command_id,omitempty"`
	ClearCommandID  string         `json:"clear_command_id,omitempty"`
	Target          string         `json:"target,omitempty"`
	Direction       string         `json:"direction,omitempty"`
	Reason          string         `json:"reason,omitempty"`
	Reference       string         `json:"reference,omitempty"`
	DurationMs      int64          `json:"duration_ms,omitempty"`
	StartedAtUnixMs int64          `json:"started_at_unix_ms,omitempty"`
	ExpiresAtUnixMs int64          `json:"expires_at_unix_ms,omitempty"`
	ClearedAtUnixMs int64          `json:"cleared_at_unix_ms,omitempty"`
	ExecutionMode   string         `json:"execution_mode,omitempty"`
	ClearSupported  bool           `json:"clear_supported,omitempty"`
	Subject         string         `json:"subject,omitempty"`
	Result          string         `json:"result,omitempty"`
	ErrorClass      string         `json:"error_class,omitempty"`
	Details         map[string]any `json:"details,omitempty"`
	IdempotencyKey  string         `json:"idempotency_key,omitempty"`
}

type responseActionView struct {
	ActionID        string         `json:"action_id"`
	ScopeType       string         `json:"scope_type"`
	RunID           string         `json:"run_id,omitempty"`
	NodeID          string         `json:"node_id,omitempty"`
	TargetAgentID   string         `json:"target_agent_id,omitempty"`
	Actor           string         `json:"actor"`
	ActionName      string         `json:"action_name"`
	Label           string         `json:"label"`
	Status          string         `json:"status"`
	Bucket          string         `json:"bucket"`
	StatusDetail    string         `json:"status_detail,omitempty"`
	ActionType      string         `json:"action_type"`
	CommandID       string         `json:"command_id,omitempty"`
	Target          string         `json:"target,omitempty"`
	Direction       string         `json:"direction,omitempty"`
	Reason          string         `json:"reason,omitempty"`
	Reference       string         `json:"reference,omitempty"`
	DurationMs      int64          `json:"duration_ms,omitempty"`
	StartedAtUnixMs int64          `json:"started_at_unix_ms,omitempty"`
	ExpiresAtUnixMs int64          `json:"expires_at_unix_ms,omitempty"`
	ClearedAtUnixMs int64          `json:"cleared_at_unix_ms,omitempty"`
	ExecutionMode   string         `json:"execution_mode,omitempty"`
	ClearSupported  bool           `json:"clear_supported,omitempty"`
	Subject         string         `json:"subject,omitempty"`
	Result          string         `json:"result,omitempty"`
	ErrorClass      string         `json:"error_class,omitempty"`
	Details         map[string]any `json:"details,omitempty"`
	Source          string         `json:"source"`
}

type responseActionTemplate struct {
	ID              string
	Label           string
	Description     string
	ActionType      string
	CommandID       string
	ClearCommandID  string
	ExecutionMode   string
	DefaultDuration int64
	ClearSupported  bool
	IncidentOnly    bool
}

type responseActionCatalogEntry struct {
	ID                    string `json:"id"`
	Label                 string `json:"label"`
	Description           string `json:"description"`
	ActionType            string `json:"action_type"`
	CommandID             string `json:"command_id,omitempty"`
	ExecutionMode         string `json:"execution_mode"`
	DefaultDurationMs     int64  `json:"default_duration_ms"`
	ClearSupported        bool   `json:"clear_supported"`
	RequiresIncidentScope bool   `json:"requires_incident_scope,omitempty"`
	Available             bool   `json:"available"`
	UnavailableReason     string `json:"unavailable_reason,omitempty"`
}

type responseActionListResponse struct {
	ScopeType string                       `json:"scope_type"`
	ScopeID   string                       `json:"scope_id"`
	Items     []responseActionView         `json:"items"`
	Count     int                          `json:"count"`
	Buckets   map[string]int               `json:"buckets"`
	Available []responseActionCatalogEntry `json:"available_actions"`
	Source    string                       `json:"source"`
}

type responseActionFleetResponse struct {
	Items   []responseActionView `json:"items"`
	Count   int                  `json:"count"`
	Total   int                  `json:"total"`
	Page    int                  `json:"page"`
	Limit   int                  `json:"limit"`
	Buckets map[string]int       `json:"buckets"`
	Source  string               `json:"source"`
}

var responseActionTemplates = []responseActionTemplate{
	{
		ID:              "block_all_outgoing",
		Label:           "Block all outgoing traffic",
		Description:     "Host-scoped outbound network containment using nftables-backed enforcement with bounded expiry.",
		ActionType:      "network_block",
		ExecutionMode:   "enforced",
		DefaultDuration: defaultManualActionDurationMs,
		ClearSupported:  true,
	},
	{
		ID:              "block_all_incoming",
		Label:           "Block all incoming traffic",
		Description:     "Host-scoped inbound network containment using nftables-backed enforcement with bounded expiry.",
		ActionType:      "network_block",
		ExecutionMode:   "enforced",
		DefaultDuration: defaultManualActionDurationMs,
		ClearSupported:  true,
	},
	{
		ID:              "block_matching_connections",
		Label:           "Block matching destination",
		Description:     "Contain a matching destination IP/CIDR or DNS hostname from the incident or an analyst-supplied target. Supports early clear.",
		ActionType:      "network_block",
		ExecutionMode:   "enforced",
		DefaultDuration: defaultManualActionDurationMs,
		ClearSupported:  true,
	},
	{
		ID:              "quarantine_device",
		Label:           "Quarantine device",
		Description:     "Halt lateral movement from the device to incident-scoped internal targets. Expires automatically.",
		ActionType:      "agent_command",
		CommandID:       "halt_lateral_movement",
		ExecutionMode:   "enforced_or_marker",
		DefaultDuration: defaultManualActionDurationMs,
	},
	{
		ID:              "enforce_pattern_of_life",
		Label:           "Enforce pattern of life",
		Description:     "Contain suspicious process execution identity for a bounded duration. Supports early clear.",
		ActionType:      "agent_command",
		CommandID:       "contain_process_exec",
		ClearCommandID:  "restore_process_exec",
		ExecutionMode:   "enforced",
		DefaultDuration: defaultManualActionDurationMs,
		ClearSupported:  true,
		IncidentOnly:    true,
	},
}

func responseActionTemplateByID(id string) (responseActionTemplate, bool) {
	id = strings.TrimSpace(strings.ToLower(id))
	for _, item := range responseActionTemplates {
		if item.ID == id {
			return item, true
		}
	}
	return responseActionTemplate{}, false
}

func responseActionAvailability(scopeType string, template responseActionTemplate, run incident, nodeID string) (bool, string) {
	if scopeType == "endpoint" && template.IncidentOnly {
		return false, "requires incident context"
	}
	targetAgentID := chooseFirstResponseValue(strings.TrimSpace(run.TargetAgentID), strings.TrimSpace(nodeID), strings.TrimSpace(run.NodeID))
	if targetAgentID == "" {
		return false, "missing target agent context"
	}
	switch template.ID {
	case "enforce_pattern_of_life":
		if strings.TrimSpace(run.ExecPath) == "" && strings.TrimSpace(run.Comm) == "" {
			return false, "requires process context"
		}
	}
	return true, ""
}

func responseActionCatalog(scopeType string, run incident, nodeID string) []responseActionCatalogEntry {
	out := make([]responseActionCatalogEntry, 0, len(responseActionTemplates))
	for _, item := range responseActionTemplates {
		available, unavailableReason := responseActionAvailability(scopeType, item, run, nodeID)
		out = append(out, responseActionCatalogEntry{
			ID:                    item.ID,
			Label:                 item.Label,
			Description:           item.Description,
			ActionType:            item.ActionType,
			CommandID:             item.CommandID,
			ExecutionMode:         item.ExecutionMode,
			DefaultDurationMs:     item.DefaultDuration,
			ClearSupported:        item.ClearSupported,
			RequiresIncidentScope: item.IncidentOnly,
			Available:             available,
			UnavailableReason:     unavailableReason,
		})
	}
	return out
}

func (a *app) responseActionsStatePath() string {
	return filepath.Join(a.cfg.UIStateDir, "response_actions.jsonl")
}

func (a *app) responseActionIdempotencyKey(rec responseActionRecord) string {
	base := strings.Join([]string{
		strings.TrimSpace(rec.Action),
		strings.TrimSpace(rec.ActionID),
		strings.TrimSpace(rec.ScopeType),
		strings.TrimSpace(rec.RunID),
		strings.TrimSpace(rec.NodeID),
		strings.TrimSpace(rec.Actor),
		strings.TrimSpace(rec.Status),
		strings.TrimSpace(rec.ActionName),
		strings.TrimSpace(rec.Target),
		strings.TrimSpace(rec.CommandID),
		strings.TrimSpace(rec.Reference),
		strings.TrimSpace(rec.Reason),
	}, "|")
	sum := sha256Sum([]byte(base))
	return "uia." + hex.EncodeToString(sum[:12])
}

func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func (a *app) appendResponseActionRecord(rec responseActionRecord) error {
	rec.Version = 1
	if strings.TrimSpace(rec.TS) == "" {
		rec.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if strings.TrimSpace(rec.IdempotencyKey) == "" {
		rec.IdempotencyKey = a.responseActionIdempotencyKey(rec)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	path := a.responseActionsStatePath()
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
	a.logger.Info("ui_response_action_event",
		slog.String("action", rec.Action),
		slog.String("action_id", rec.ActionID),
		slog.String("run_id", rec.RunID),
		slog.String("node_id", rec.NodeID),
		slog.String("status", rec.Status),
		slog.String("actor", rec.Actor),
		slog.String("action_name", rec.ActionName),
	)
	return nil
}

func (a *app) loadActionRecords() []responseActionRecord {
	records := make([]responseActionRecord, 0, 64)
	_ = scanJSONLines(a.responseActionsStatePath(), func(obj map[string]any) {
		rec := responseActionRecord{
			Version:         int(intVal(obj["version"], 0)),
			TS:              strVal(obj["ts"]),
			Action:          strVal(obj["action"]),
			ActionID:        strVal(obj["action_id"]),
			ScopeType:       strVal(obj["scope_type"]),
			RunID:           strVal(obj["run_id"]),
			NodeID:          strVal(obj["node_id"]),
			TargetAgentID:   strVal(obj["target_agent_id"]),
			Actor:           strVal(obj["actor"]),
			ActionName:      strVal(obj["action_name"]),
			Label:           strVal(obj["label"]),
			Status:          strVal(obj["status"]),
			StatusDetail:    strVal(obj["status_detail"]),
			ActionType:      strVal(obj["action_type"]),
			CommandID:       strVal(obj["command_id"]),
			ClearCommandID:  strVal(obj["clear_command_id"]),
			Target:          strVal(obj["target"]),
			Direction:       strVal(obj["direction"]),
			Reason:          strVal(obj["reason"]),
			Reference:       strVal(obj["reference"]),
			DurationMs:      int64(intVal(obj["duration_ms"], 0)),
			StartedAtUnixMs: int64(intVal(obj["started_at_unix_ms"], 0)),
			ExpiresAtUnixMs: int64(intVal(obj["expires_at_unix_ms"], 0)),
			ClearedAtUnixMs: int64(intVal(obj["cleared_at_unix_ms"], 0)),
			ExecutionMode:   strVal(obj["execution_mode"]),
			ClearSupported:  boolVal(obj["clear_supported"], false),
			Subject:         strVal(obj["subject"]),
			Result:          strVal(obj["result"]),
			ErrorClass:      strVal(obj["error_class"]),
			Details:         mapVal(obj["details"]),
			IdempotencyKey:  strVal(obj["idempotency_key"]),
		}
		if rec.ActionID == "" {
			return
		}
		records = append(records, rec)
	})
	sort.SliceStable(records, func(i, j int) bool {
		ti := logTimeUnixMs(records[i].TS)
		tj := logTimeUnixMs(records[j].TS)
		if ti == tj {
			return records[i].ActionID < records[j].ActionID
		}
		return ti < tj
	})
	return records
}

func deriveActionBucket(status string, expiresAt, clearedAt int64) string {
	now := time.Now().UnixMilli()
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pending":
		return "pending"
	case "cleared":
		return "cleared"
	case "failed":
		return "failed"
	}
	if clearedAt > 0 {
		return "cleared"
	}
	if expiresAt > 0 && now >= expiresAt {
		return "expired"
	}
	return "active"
}

func actionViewFromRecord(rec responseActionRecord) responseActionView {
	status := strings.TrimSpace(rec.Status)
	if status == "" {
		status = "active"
	}
	bucket := deriveActionBucket(status, rec.ExpiresAtUnixMs, rec.ClearedAtUnixMs)
	if bucket == "expired" {
		status = "expired"
	}
	return responseActionView{
		ActionID:        rec.ActionID,
		ScopeType:       rec.ScopeType,
		RunID:           rec.RunID,
		NodeID:          rec.NodeID,
		TargetAgentID:   rec.TargetAgentID,
		Actor:           rec.Actor,
		ActionName:      rec.ActionName,
		Label:           rec.Label,
		Status:          status,
		Bucket:          bucket,
		StatusDetail:    rec.StatusDetail,
		ActionType:      rec.ActionType,
		CommandID:       rec.CommandID,
		Target:          rec.Target,
		Direction:       rec.Direction,
		Reason:          rec.Reason,
		Reference:       rec.Reference,
		DurationMs:      rec.DurationMs,
		StartedAtUnixMs: rec.StartedAtUnixMs,
		ExpiresAtUnixMs: rec.ExpiresAtUnixMs,
		ClearedAtUnixMs: rec.ClearedAtUnixMs,
		ExecutionMode:   rec.ExecutionMode,
		ClearSupported:  rec.ClearSupported,
		Subject:         rec.Subject,
		Result:          rec.Result,
		ErrorClass:      rec.ErrorClass,
		Details:         rec.Details,
		Source:          "ui_response_actions",
	}
}

func syntheticPendingActionViews(run incident, steps []stepResult) []responseActionView {
	status := strings.ToUpper(strings.TrimSpace(run.Status))
	if status != "WAITING_APPROVAL" && status != "MANUAL_REVIEW_REQUIRED" {
		return nil
	}
	items := make([]responseActionView, 0, len(steps))
	for _, step := range steps {
		if strings.TrimSpace(step.ActionType) == "" || strings.EqualFold(strings.TrimSpace(step.ActionType), "notify") {
			continue
		}
		items = append(items, responseActionView{
			ActionID:      "pending:" + step.StepID,
			ScopeType:     "incident",
			RunID:         run.RunID,
			NodeID:        run.NodeID,
			TargetAgentID: chooseNonEmpty(step.TargetAgentID, run.TargetAgentID),
			Actor:         step.Actor,
			ActionName:    "planned_" + strings.TrimSpace(step.ActionType),
			Label:         fmt.Sprintf("Pending %s", strings.ReplaceAll(strings.TrimSpace(step.ActionType), "_", " ")),
			Status:        "pending",
			Bucket:        "pending",
			ActionType:    step.ActionType,
			Target:        step.Target,
			Source:        "run_steps",
			Details: map[string]any{
				"step_id":    step.StepID,
				"step_index": step.StepIndex,
				"status":     run.Status,
			},
		})
	}
	return items
}

func mergeActionViews(records []responseActionRecord, scopeType, scopeID string) []responseActionView {
	latest := make(map[string]responseActionRecord)
	for _, rec := range records {
		if strings.TrimSpace(rec.ScopeType) != scopeType {
			continue
		}
		if scopeType == "incident" && strings.TrimSpace(rec.RunID) != scopeID {
			continue
		}
		if scopeType == "endpoint" && strings.TrimSpace(rec.NodeID) != scopeID {
			continue
		}
		prev, ok := latest[rec.ActionID]
		if !ok || logTimeUnixMs(rec.TS) >= logTimeUnixMs(prev.TS) {
			latest[rec.ActionID] = rec
		}
	}
	out := make([]responseActionView, 0, len(latest))
	for _, rec := range latest {
		out = append(out, actionViewFromRecord(rec))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].StartedAtUnixMs == out[j].StartedAtUnixMs {
			return out[i].ActionID < out[j].ActionID
		}
		return out[i].StartedAtUnixMs > out[j].StartedAtUnixMs
	})
	return out
}

func allActionViews(records []responseActionRecord, runs []incident, stepsByRun map[string][]stepResult) []responseActionView {
	latest := make(map[string]responseActionRecord)
	for _, rec := range records {
		prev, ok := latest[rec.ActionID]
		if !ok || logTimeUnixMs(rec.TS) >= logTimeUnixMs(prev.TS) {
			latest[rec.ActionID] = rec
		}
	}
	out := make([]responseActionView, 0, len(latest)+32)
	for _, rec := range latest {
		out = append(out, actionViewFromRecord(rec))
	}
	for _, run := range runs {
		out = append(out, syntheticPendingActionViews(run, stepsByRun[run.RunID])...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		left := out[i].StartedAtUnixMs
		if left == 0 {
			left = out[i].ClearedAtUnixMs
		}
		if left == 0 {
			left = out[i].ExpiresAtUnixMs
		}
		right := out[j].StartedAtUnixMs
		if right == 0 {
			right = out[j].ClearedAtUnixMs
		}
		if right == 0 {
			right = out[j].ExpiresAtUnixMs
		}
		if left == right {
			return out[i].ActionID < out[j].ActionID
		}
		return left > right
	})
	return out
}

func filterFleetActionViews(items []responseActionView, q url.Values) []responseActionView {
	scopeType := strings.ToLower(strings.TrimSpace(q.Get("scope_type")))
	bucket := strings.ToLower(strings.TrimSpace(q.Get("bucket")))
	runID := strings.TrimSpace(q.Get("run_id"))
	nodeID := strings.TrimSpace(q.Get("node_id"))
	actionName := strings.TrimSpace(q.Get("action_name"))
	query := strings.ToLower(strings.TrimSpace(q.Get("q")))
	if scopeType == "" && bucket == "" && runID == "" && nodeID == "" && actionName == "" && query == "" {
		return items
	}
	filtered := make([]responseActionView, 0, len(items))
	for _, item := range items {
		if scopeType != "" && strings.ToLower(strings.TrimSpace(item.ScopeType)) != scopeType {
			continue
		}
		if bucket != "" && strings.ToLower(strings.TrimSpace(item.Bucket)) != bucket {
			continue
		}
		if runID != "" && strings.TrimSpace(item.RunID) != runID {
			continue
		}
		if nodeID != "" && strings.TrimSpace(item.NodeID) != nodeID {
			continue
		}
		if actionName != "" && strings.TrimSpace(item.ActionName) != actionName {
			continue
		}
		if query != "" {
			hay := strings.ToLower(strings.Join([]string{
				item.ActionID,
				item.ScopeType,
				item.RunID,
				item.NodeID,
				item.Actor,
				item.ActionName,
				item.Label,
				item.Status,
				item.Target,
				item.Direction,
				item.Reason,
				item.Reference,
				item.Subject,
				item.Result,
			}, " "))
			if !strings.Contains(hay, query) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func paginateActionViews(items []responseActionView, page, limit int) ([]responseActionView, int, int) {
	total := len(items)
	if limit <= 0 {
		limit = 100
	}
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * limit
	if start >= total {
		return []responseActionView{}, total, page
	}
	end := start + limit
	if end > total {
		end = total
	}
	return items[start:end], total, page
}

func parsePositiveInt(raw string, fallback, minValue, maxValue int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		value = fallback
	}
	if value < minValue {
		value = minValue
	}
	if value > maxValue {
		value = maxValue
	}
	return value
}

func countActionBuckets(items []responseActionView) map[string]int {
	out := map[string]int{
		"pending": 0,
		"active":  0,
		"cleared": 0,
		"expired": 0,
		"failed":  0,
	}
	for _, item := range items {
		out[item.Bucket]++
	}
	return out
}

func (a *app) handleIncidentActions(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}
	runs, stepsByRun, _ := a.loadState()
	run := findIncidentByRunID(runs, runID)
	if run == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "run not found"})
		return
	}
	items := mergeActionViews(a.loadActionRecords(), "incident", runID)
	items = append(syntheticPendingActionViews(*run, stepsByRun[runID]), items...)
	catalogRun := *run
	writeJSON(w, http.StatusOK, responseActionListResponse{
		ScopeType: "incident",
		ScopeID:   runID,
		Items:     items,
		Count:     len(items),
		Buckets:   countActionBuckets(items),
		Available: responseActionCatalog("incident", catalogRun, strings.TrimSpace(catalogRun.NodeID)),
		Source:    "ui_response_actions+run_steps",
	})
}

func (a *app) handleEndpointActions(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("node_id"))
	if nodeID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing node_id"})
		return
	}
	items := mergeActionViews(a.loadActionRecords(), "endpoint", nodeID)
	writeJSON(w, http.StatusOK, responseActionListResponse{
		ScopeType: "endpoint",
		ScopeID:   nodeID,
		Items:     items,
		Count:     len(items),
		Buckets:   countActionBuckets(items),
		Available: responseActionCatalog("endpoint", incident{NodeID: nodeID, TargetAgentID: nodeID}, nodeID),
		Source:    "ui_response_actions",
	})
}

func (a *app) handleFleetActions(w http.ResponseWriter, r *http.Request) {
	runs, stepsByRun, _ := a.loadState()
	items := allActionViews(a.loadActionRecords(), runs, stepsByRun)
	filtered := filterFleetActionViews(items, r.URL.Query())
	page := parsePositiveInt(r.URL.Query().Get("page"), 1, 1, 100000)
	limit := parsePositiveInt(r.URL.Query().Get("limit"), 100, 1, 500)
	paged, total, page := paginateActionViews(filtered, page, limit)
	writeJSON(w, http.StatusOK, responseActionFleetResponse{
		Items:   paged,
		Count:   len(paged),
		Total:   total,
		Page:    page,
		Limit:   limit,
		Buckets: countActionBuckets(filtered),
		Source:  "ui_response_actions+run_steps",
	})
}

func (a *app) handleIncidentLaunchAction(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing run_id"})
		return
	}
	runs, _, created := a.loadState()
	run := findIncidentByRunID(runs, runID)
	if run == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "run not found"})
		return
	}
	enriched := enrichIncidentFromCreatedMeta(*run, created[runID])
	view, err := a.launchResponseAction(r, "incident", runID, enriched, strings.TrimSpace(enriched.NodeID))
	if err != nil {
		writeJSON(w, err.status, map[string]any{"error": err.message})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": view})
}

func (a *app) handleEndpointLaunchAction(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("node_id"))
	if nodeID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing node_id"})
		return
	}
	view, err := a.launchResponseAction(r, "endpoint", "", incident{NodeID: nodeID, TargetAgentID: nodeID}, nodeID)
	if err != nil {
		writeJSON(w, err.status, map[string]any{"error": err.message})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": view})
}

type responseActionHTTPError struct {
	status  int
	message string
}

func (a *app) launchResponseAction(r *http.Request, scopeType string, runID string, run incident, nodeID string) (responseActionView, *responseActionHTTPError) {
	roleCtx := roleFromRequest(r)
	var body struct {
		Actor         string `json:"actor"`
		ActionName    string `json:"action_name"`
		DurationMs    int64  `json:"duration_ms"`
		Reason        string `json:"reason"`
		Reference     string `json:"reference"`
		Target        string `json:"target"`
		TargetAgentID string `json:"target_agent_id"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		return responseActionView{}, &responseActionHTTPError{status: http.StatusBadRequest, message: err.Error()}
	}
	actor := chooseFirstResponseValue(strings.TrimSpace(body.Actor), roleCtx.Username, "ui")
	template, ok := responseActionTemplateByID(body.ActionName)
	if !ok {
		return responseActionView{}, &responseActionHTTPError{status: http.StatusBadRequest, message: "unsupported action_name"}
	}
	if available, reason := responseActionAvailability(scopeType, template, run, nodeID); !available {
		return responseActionView{}, &responseActionHTTPError{status: http.StatusConflict, message: reason}
	}
	durationMs := body.DurationMs
	if durationMs <= 0 {
		durationMs = template.DefaultDuration
	}
	if durationMs <= 0 {
		durationMs = defaultManualActionDurationMs
	}
	nowMs := time.Now().UnixMilli()
	actionID := fmt.Sprintf("uiact_%d", nowMs)
	targetAgentID := chooseFirstResponseValue(strings.TrimSpace(body.TargetAgentID), strings.TrimSpace(run.TargetAgentID), strings.TrimSpace(nodeID), strings.TrimSpace(run.NodeID))
	if targetAgentID == "" {
		return responseActionView{}, &responseActionHTTPError{status: http.StatusConflict, message: "missing target_agent_id"}
	}

	req, detailErr := buildResponseActionRequest(template, actionID, actor, runID, nodeID, targetAgentID, run, strings.TrimSpace(body.Target), durationMs, strings.TrimSpace(body.Reason), strings.TrimSpace(body.Reference))
	if detailErr != nil {
		return responseActionView{}, &responseActionHTTPError{status: http.StatusBadRequest, message: detailErr.Error()}
	}
	reply, err := a.requestAgentCommand(req.subject, req.command, 5*time.Second)
	if err != nil {
		return responseActionView{}, &responseActionHTTPError{status: http.StatusBadGateway, message: err.Error()}
	}
	record := responseActionRecord{
		TS:              time.Now().UTC().Format(time.RFC3339Nano),
		Action:          "launch",
		ActionID:        actionID,
		ScopeType:       scopeType,
		RunID:           runID,
		NodeID:          strings.TrimSpace(nodeID),
		TargetAgentID:   targetAgentID,
		Actor:           actor,
		ActionName:      template.ID,
		Label:           template.Label,
		Status:          "active",
		ActionType:      template.ActionType,
		CommandID:       template.CommandID,
		ClearCommandID:  template.ClearCommandID,
		Target:          req.displayTarget,
		Direction:       req.direction,
		Reason:          strings.TrimSpace(body.Reason),
		Reference:       strings.TrimSpace(body.Reference),
		DurationMs:      durationMs,
		StartedAtUnixMs: nowMs,
		ExpiresAtUnixMs: nowMs + durationMs,
		ExecutionMode:   req.executionMode,
		ClearSupported:  template.ClearSupported,
		Subject:         req.subject,
		Result:          strings.TrimSpace(reply.Stdout),
		ErrorClass:      strings.TrimSpace(reply.ErrorClass),
		Details:         req.details,
	}
	if !strings.EqualFold(strings.TrimSpace(reply.Status), "ok") {
		record.Status = "failed"
		record.StatusDetail = strings.TrimSpace(reply.Stderr)
		record.ExpiresAtUnixMs = 0
	}
	if template.ActionType == "agent_command" && template.CommandID == "halt_lateral_movement" {
		if strings.Contains(strings.ToLower(record.Result), "mode=marker") {
			record.ExecutionMode = "marker"
		}
	}
	if err := a.appendResponseActionRecord(record); err != nil {
		return responseActionView{}, &responseActionHTTPError{status: http.StatusInternalServerError, message: err.Error()}
	}
	return actionViewFromRecord(record), nil
}

type builtResponseActionRequest struct {
	command       agentCommandRequest
	subject       string
	displayTarget string
	direction     string
	executionMode string
	details       map[string]any
}

func buildResponseActionRequest(template responseActionTemplate, actionID, actor, runID, nodeID, targetAgentID string, run incident, overrideTarget string, durationMs int64, reason, reference string) (builtResponseActionRequest, error) {
	nowMs := time.Now().UnixMilli()
	req := builtResponseActionRequest{
		command: agentCommandRequest{
			RunID:         chooseFirstResponseValue(strings.TrimSpace(runID), fmt.Sprintf("ui_action_%d", nowMs)),
			StepID:        fmt.Sprintf("uiaction.%d", nowMs),
			Lane:          "FAST",
			ActionType:    template.ActionType,
			Target:        "",
			TargetAgentID: targetAgentID,
			Params: map[string]any{
				"actor":              actor,
				"node_id":            chooseFirstResponseValue(strings.TrimSpace(nodeID), strings.TrimSpace(run.NodeID)),
				"duration_ms":        durationMs,
				"reason":             reason,
				"reference":          reference,
				"response_action_id": actionID,
			},
		},
		subject:       defaultAgentCommandSub + "." + targetAgentID,
		executionMode: template.ExecutionMode,
		details: map[string]any{
			"action_id":       actionID,
			"node_id":         chooseFirstResponseValue(strings.TrimSpace(nodeID), strings.TrimSpace(run.NodeID)),
			"target_agent_id": targetAgentID,
		},
	}
	switch template.ID {
	case "block_all_outgoing":
		req.command.Target = "0.0.0.0/0"
		req.command.Params["direction"] = "egress"
		req.displayTarget = req.command.Target
		req.direction = "egress"
	case "block_all_incoming":
		req.command.Target = "0.0.0.0/0"
		req.command.Params["direction"] = "ingress"
		req.displayTarget = req.command.Target
		req.direction = "ingress"
	case "block_matching_connections":
		target := chooseFirstResponseValue(strings.TrimSpace(overrideTarget), strings.TrimSpace(run.DNSName), strings.TrimSpace(run.DstIP), strings.TrimSpace(run.Target))
		if target == "" {
			return builtResponseActionRequest{}, fmt.Errorf("block_matching_connections requires dst_ip, dns_name, or target")
		}
		target = strings.TrimSpace(target)
		req.command.ActionType = "network_block"
		req.command.Params["direction"] = "egress"
		if ip := strings.TrimSpace(strings.TrimSuffix(target, "/32")); net.ParseIP(ip) != nil {
			req.command.Target = ip
			req.displayTarget = ip
			req.details["dst_ip"] = ip
		} else if validHostname(target) {
			req.command.Target = strings.ToLower(target)
			req.command.Params["dns_name"] = strings.ToLower(target)
			req.displayTarget = strings.ToLower(target)
			req.details["dns_name"] = strings.ToLower(target)
			if ip := strings.TrimSpace(run.DstIP); ip != "" {
				req.command.Params["resolved_targets"] = ip
				req.details["resolved_targets"] = []string{ip}
			}
		} else if _, _, err := net.ParseCIDR(target); err == nil {
			req.command.Target = target
			req.displayTarget = target
			req.details["cidr"] = target
		} else {
			return builtResponseActionRequest{}, fmt.Errorf("block_matching_connections target must be an IP, CIDR, or DNS hostname")
		}
		req.direction = "egress"
	case "quarantine_device":
		req.command.ActionType = "agent_command"
		req.command.Target = chooseFirstResponseValue(strings.TrimSpace(run.DstIP), strings.TrimSpace(overrideTarget), strings.TrimSpace(run.Target), strings.TrimSpace(run.NodeID))
		req.command.Params["command"] = template.CommandID
		req.command.Params["protocol_family"] = chooseNonEmpty(strings.TrimSpace(run.ProtocolFamily), "host")
		if len(run.TopDestinations) > 0 {
			req.command.Params["top_destinations"] = strings.Join(run.TopDestinations, ",")
			req.details["top_destinations"] = append([]string(nil), run.TopDestinations...)
		}
		if run.DstIP != "" {
			req.command.Params["dst_ip"] = strings.TrimSpace(run.DstIP)
		}
		req.displayTarget = chooseFirstResponseValue(strings.TrimSpace(run.NodeID), strings.TrimSpace(nodeID))
	case "enforce_pattern_of_life":
		req.command.ActionType = "agent_command"
		req.command.Target = chooseFirstResponseValue(strings.TrimSpace(run.NodeID), strings.TrimSpace(nodeID))
		req.command.Params["command"] = template.CommandID
		req.command.Params["exec_path"] = strings.TrimSpace(run.ExecPath)
		req.command.Params["comm"] = strings.TrimSpace(run.Comm)
		req.command.Params["cmdline"] = strings.TrimSpace(run.Cmdline)
		req.command.Params["exec_sha256"] = strings.TrimSpace(run.ExecSHA256)
		if strings.TrimSpace(run.ExecPath) == "" && strings.TrimSpace(run.Comm) == "" {
			return builtResponseActionRequest{}, fmt.Errorf("enforce_pattern_of_life requires process context on the incident")
		}
		req.displayTarget = chooseFirstResponseValue(strings.TrimSpace(run.ExecPath), strings.TrimSpace(run.Comm), strings.TrimSpace(run.NodeID))
		req.details["exec_path"] = strings.TrimSpace(run.ExecPath)
		req.details["comm"] = strings.TrimSpace(run.Comm)
		req.details["cmdline"] = strings.TrimSpace(run.Cmdline)
		req.details["exec_sha256"] = strings.TrimSpace(run.ExecSHA256)
	default:
		return builtResponseActionRequest{}, fmt.Errorf("unsupported action")
	}
	req.details["reason"] = reason
	req.details["reference"] = reference
	req.details["target"] = req.displayTarget
	return req, nil
}

func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func (a *app) handleIncidentClearAction(w http.ResponseWriter, r *http.Request) {
	a.handleClearResponseAction(w, r, "incident")
}

func (a *app) handleEndpointClearAction(w http.ResponseWriter, r *http.Request) {
	a.handleClearResponseAction(w, r, "endpoint")
}

func (a *app) handleClearResponseAction(w http.ResponseWriter, r *http.Request, scopeType string) {
	scopeID := strings.TrimSpace(r.PathValue("run_id"))
	if scopeType == "endpoint" {
		scopeID = strings.TrimSpace(r.PathValue("node_id"))
	}
	actionID := strings.TrimSpace(r.PathValue("action_id"))
	if scopeID == "" || actionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing scope_id or action_id"})
		return
	}
	var latest *responseActionRecord
	for _, rec := range a.loadActionRecords() {
		if rec.ActionID != actionID || rec.ScopeType != scopeType {
			continue
		}
		if scopeType == "incident" && rec.RunID != scopeID {
			continue
		}
		if scopeType == "endpoint" && rec.NodeID != scopeID {
			continue
		}
		copyRec := rec
		latest = &copyRec
	}
	if latest == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "action not found"})
		return
	}
	if !latest.ClearSupported || (strings.TrimSpace(latest.ClearCommandID) == "" && latest.ActionType != "network_block") {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "selected action does not support manual clear"})
		return
	}
	var body struct {
		Actor     string `json:"actor"`
		Reason    string `json:"reason"`
		Reference string `json:"reference"`
	}
	_ = decodeJSONBody(r.Body, &body)
	actor := chooseFirstResponseValue(strings.TrimSpace(body.Actor), roleFromRequest(r).Username, "ui")
	target := strings.TrimSpace(latest.Target)
	req := agentCommandRequest{
		RunID:         chooseFirstResponseValue(strings.TrimSpace(latest.RunID), fmt.Sprintf("ui_clear_%d", time.Now().UnixMilli())),
		StepID:        fmt.Sprintf("uiaction.clear.%d", time.Now().UnixMilli()),
		Lane:          "FAST",
		ActionType:    "agent_command",
		Target:        target,
		TargetAgentID: latest.TargetAgentID,
		Params: map[string]any{
			"command":            latest.ClearCommandID,
			"containment_run_id": chooseFirstResponseValue(strings.TrimSpace(latest.RunID), actionID),
			"node_id":            latest.NodeID,
			"actor":              actor,
			"reason":             strings.TrimSpace(body.Reason),
			"reference":          strings.TrimSpace(body.Reference),
		},
	}
	if latest.ActionType == "network_block" {
		req.ActionType = "network_block"
		req.Params = map[string]any{
			"mode":               "clear",
			"direction":          latest.Direction,
			"node_id":            latest.NodeID,
			"actor":              actor,
			"reason":             strings.TrimSpace(body.Reason),
			"reference":          strings.TrimSpace(body.Reference),
			"response_action_id": latest.ActionID,
			"containment_run_id": chooseFirstResponseValue(strings.TrimSpace(latest.RunID), latest.ActionID),
		}
	}
	if latest.CommandID == "contain_destination_ip" {
		req.Params["dst_ip"] = target
	}
	if latest.CommandID == "contain_process_exec" {
		if v := stringMap(latest.Details, "exec_path"); v != "" {
			req.Params["exec_path"] = v
		}
		if v := stringMap(latest.Details, "comm"); v != "" {
			req.Params["comm"] = v
		}
	}
	reply, err := a.requestAgentCommand(defaultAgentCommandSub+"."+latest.TargetAgentID, req, 5*time.Second)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(reply.Status), "ok") {
		writeJSON(w, safeDeniedHTTPStatus(reply), map[string]any{"error": strings.TrimSpace(reply.Stderr), "error_class": reply.ErrorClass})
		return
	}
	nowMs := time.Now().UnixMilli()
	rec := responseActionRecord{
		TS:              time.Now().UTC().Format(time.RFC3339Nano),
		Action:          "clear",
		ActionID:        latest.ActionID,
		ScopeType:       latest.ScopeType,
		RunID:           latest.RunID,
		NodeID:          latest.NodeID,
		TargetAgentID:   latest.TargetAgentID,
		Actor:           actor,
		ActionName:      latest.ActionName,
		Label:           latest.Label,
		Status:          "cleared",
		StatusDetail:    strings.TrimSpace(body.Reason),
		ActionType:      latest.ActionType,
		CommandID:       latest.CommandID,
		ClearCommandID:  latest.ClearCommandID,
		Target:          latest.Target,
		Direction:       latest.Direction,
		Reason:          chooseFirstResponseValue(strings.TrimSpace(body.Reason), latest.Reason),
		Reference:       strings.TrimSpace(body.Reference),
		DurationMs:      latest.DurationMs,
		StartedAtUnixMs: latest.StartedAtUnixMs,
		ExpiresAtUnixMs: latest.ExpiresAtUnixMs,
		ClearedAtUnixMs: nowMs,
		ExecutionMode:   latest.ExecutionMode,
		ClearSupported:  latest.ClearSupported,
		Subject:         defaultAgentCommandSub + "." + latest.TargetAgentID,
		Result:          strings.TrimSpace(reply.Stdout),
		Details:         latest.Details,
	}
	if err := a.appendResponseActionRecord(rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": actionViewFromRecord(rec)})
}

func stringMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	return strings.TrimSpace(strVal(m[key]))
}

func chooseFirstResponseValue(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
