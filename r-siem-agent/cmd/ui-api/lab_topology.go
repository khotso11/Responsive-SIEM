package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultLabTopologyConfigPath = "configs/labs/eve_ng_soc_lab.yaml"
const defaultLabCollectorHost = "10.10.0.10"

type labTopologyFile struct {
	Provider   infrastructureProviderSpec  `yaml:"provider"`
	Lab        labTopologyLabSpec          `yaml:"lab"`
	Zones      []labTopologyZoneSpec       `yaml:"zones"`
	Nodes      []labTopologyNodeSpec       `yaml:"nodes"`
	Links      []labTopologyLinkSpec       `yaml:"links"`
	Collection []labTopologyCollectionSpec `yaml:"collection"`
	Signals    []labTopologySignalSpec     `yaml:"signals"`
}

type labTopologyLabSpec struct {
	ID          string `yaml:"id" json:"id"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	Status      string `yaml:"status" json:"status"`
	Version     string `yaml:"version,omitempty" json:"version,omitempty"`
}

type labTopologyZoneSpec struct {
	ID      string `yaml:"id" json:"id"`
	Name    string `yaml:"name" json:"name"`
	CIDR    string `yaml:"cidr" json:"cidr"`
	Purpose string `yaml:"purpose" json:"purpose"`
	Color   string `yaml:"color,omitempty" json:"color,omitempty"`
	Order   int    `yaml:"order,omitempty" json:"order,omitempty"`
}

type labTopologyServiceSpec struct {
	Name            string   `yaml:"name" json:"name"`
	Protocol        string   `yaml:"protocol" json:"protocol"`
	Port            int      `yaml:"port" json:"port"`
	Path            string   `yaml:"path,omitempty" json:"path,omitempty"`
	Exposure        string   `yaml:"exposure,omitempty" json:"exposure,omitempty"`
	ExpectedSources []string `yaml:"expected_sources,omitempty" json:"expected_sources,omitempty"`
	Notes           string   `yaml:"notes,omitempty" json:"notes,omitempty"`
}

type labTopologyNodeSpec struct {
	ID                string                   `yaml:"id" json:"id"`
	Label             string                   `yaml:"label" json:"label"`
	EveNodeName       string                   `yaml:"eve_node_name,omitempty" json:"eve_node_name,omitempty"`
	Role              string                   `yaml:"role" json:"role"`
	Zone              string                   `yaml:"zone" json:"zone"`
	OS                string                   `yaml:"os,omitempty" json:"os,omitempty"`
	State             string                   `yaml:"state,omitempty" json:"state,omitempty"`
	ServiceState      string                   `yaml:"service_state,omitempty" json:"service_state,omitempty"`
	IP                string                   `yaml:"ip,omitempty" json:"ip,omitempty"`
	IPs               []string                 `yaml:"ips,omitempty" json:"ips,omitempty"`
	PositionLeft      int                      `yaml:"position_left,omitempty" json:"position_left,omitempty"`
	PositionTop       int                      `yaml:"position_top,omitempty" json:"position_top,omitempty"`
	Notes             string                   `yaml:"notes,omitempty" json:"notes,omitempty"`
	Services          []labTopologyServiceSpec `yaml:"services,omitempty" json:"services,omitempty"`
	DataRoles         []string                 `yaml:"data_roles,omitempty" json:"data_roles,omitempty"`
	ExpectedBehaviors []string                 `yaml:"expected_behaviors,omitempty" json:"expected_behaviors,omitempty"`
	Connectivity      []string                 `yaml:"connectivity,omitempty" json:"connectivity,omitempty"`
	SourceRoles       []string                 `yaml:"source_roles,omitempty" json:"source_roles,omitempty"`
	ResponseTarget    bool                     `yaml:"response_target,omitempty" json:"response_target,omitempty"`
	LogSource         bool                     `yaml:"log_source,omitempty" json:"log_source,omitempty"`
	TrafficSource     bool                     `yaml:"traffic_source,omitempty" json:"traffic_source,omitempty"`
	AttackerSimulator bool                     `yaml:"attacker_simulator,omitempty" json:"attacker_simulator,omitempty"`
	Managed           bool                     `yaml:"managed,omitempty" json:"managed,omitempty"`
	Enabled           bool                     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

type labTopologyLinkSpec struct {
	ID        string   `yaml:"id" json:"id"`
	Label     string   `yaml:"label,omitempty" json:"label,omitempty"`
	Zone      string   `yaml:"zone,omitempty" json:"zone,omitempty"`
	Endpoints []string `yaml:"endpoints" json:"endpoints"`
	Kind      string   `yaml:"kind,omitempty" json:"kind,omitempty"`
}

type labTopologyCollectionSpec struct {
	NodeID     string   `yaml:"node_id" json:"node_id"`
	Collector  string   `yaml:"collector" json:"collector"`
	Transport  string   `yaml:"transport" json:"transport"`
	Endpoint   string   `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	SourceType string   `yaml:"source_type" json:"source_type"`
	EventTypes []string `yaml:"event_types,omitempty" json:"event_types,omitempty"`
	Notes      string   `yaml:"notes,omitempty" json:"notes,omitempty"`
	Required   bool     `yaml:"required,omitempty" json:"required,omitempty"`
	Status     string   `yaml:"status,omitempty" json:"status,omitempty"`
}

type labTopologySignalSpec struct {
	ID          string   `yaml:"id" json:"id"`
	Label       string   `yaml:"label" json:"label"`
	Description string   `yaml:"description" json:"description"`
	Severity    string   `yaml:"severity,omitempty" json:"severity,omitempty"`
	Status      string   `yaml:"status,omitempty" json:"status,omitempty"`
	Zone        string   `yaml:"zone,omitempty" json:"zone,omitempty"`
	NodeID      string   `yaml:"node_id,omitempty" json:"node_id,omitempty"`
	SourceNode  string   `yaml:"source_node,omitempty" json:"source_node,omitempty"`
	DstNode     string   `yaml:"dst_node,omitempty" json:"dst_node,omitempty"`
	SourceIP    string   `yaml:"source_ip,omitempty" json:"source_ip,omitempty"`
	DstIP       string   `yaml:"dst_ip,omitempty" json:"dst_ip,omitempty"`
	SourceTypes []string `yaml:"source_types,omitempty" json:"source_types,omitempty"`
	EventTypes  []string `yaml:"event_types,omitempty" json:"event_types,omitempty"`
	Protocols   []string `yaml:"protocols,omitempty" json:"protocols,omitempty"`
	Service     string   `yaml:"service,omitempty" json:"service,omitempty"`
}

type labTopologySummary struct {
	WindowFromUnixMs       int64 `json:"window_from_unix_ms"`
	WindowToUnixMs         int64 `json:"window_to_unix_ms"`
	ZoneCount              int   `json:"zone_count"`
	NodeCount              int   `json:"node_count"`
	ResponseTargetCount    int   `json:"response_target_count"`
	LogSourceCount         int   `json:"log_source_count"`
	TrafficSourceCount     int   `json:"traffic_source_count"`
	AttackerSimulatorCount int   `json:"attacker_simulator_count"`
	RecentEventCount       int   `json:"recent_event_count"`
	RecentIncidentCount    int   `json:"recent_incident_count"`
	RecentActionCount      int   `json:"recent_action_count"`
	ReachableNodeCount     int   `json:"reachable_node_count"`
	RunnableNodeCount      int   `json:"runnable_node_count"`
	ExpectedServiceCount   int   `json:"expected_service_count"`
}

type labTopologyZoneView struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	CIDR    string   `json:"cidr"`
	Purpose string   `json:"purpose"`
	Color   string   `json:"color,omitempty"`
	Order   int      `json:"order,omitempty"`
	NodeIDs []string `json:"node_ids,omitempty"`
}

type labTopologyNodeLive struct {
	Status            string   `json:"status"`
	ServiceState      string   `json:"service_state,omitempty"`
	LastSeenUnixMs    int64    `json:"last_seen_unix_ms,omitempty"`
	RecentEventCount  int      `json:"recent_event_count"`
	DetectionCount    int      `json:"detection_count"`
	IncidentCount     int      `json:"incident_count"`
	OpenIncidentCount int      `json:"open_incident_count"`
	ActiveActionCount int      `json:"active_action_count"`
	SeenSourceTypes   []string `json:"seen_source_types,omitempty"`
	SeenEventTypes    []string `json:"seen_event_types,omitempty"`
	SeenZones         []string `json:"seen_zones,omitempty"`
	RuntimeStatus     string   `json:"runtime_status,omitempty"`
	RuntimeDetail     string   `json:"runtime_detail,omitempty"`
}

type labTopologyNodeView struct {
	ID                string                   `json:"id"`
	Label             string                   `json:"label"`
	EveNodeName       string                   `json:"eve_node_name,omitempty"`
	Role              string                   `json:"role"`
	Zone              string                   `json:"zone"`
	OS                string                   `json:"os,omitempty"`
	State             string                   `json:"state,omitempty"`
	ServiceState      string                   `json:"service_state,omitempty"`
	IP                string                   `json:"ip,omitempty"`
	IPs               []string                 `json:"ips,omitempty"`
	PositionLeft      int                      `json:"position_left,omitempty"`
	PositionTop       int                      `json:"position_top,omitempty"`
	Notes             string                   `json:"notes,omitempty"`
	Services          []labTopologyServiceSpec `json:"services,omitempty"`
	DataRoles         []string                 `json:"data_roles,omitempty"`
	ExpectedBehaviors []string                 `json:"expected_behaviors,omitempty"`
	Connectivity      []string                 `json:"connectivity,omitempty"`
	SourceRoles       []string                 `json:"source_roles,omitempty"`
	ResponseTarget    bool                     `json:"response_target,omitempty"`
	LogSource         bool                     `json:"log_source,omitempty"`
	TrafficSource     bool                     `json:"traffic_source,omitempty"`
	AttackerSimulator bool                     `json:"attacker_simulator,omitempty"`
	Managed           bool                     `json:"managed,omitempty"`
	Enabled           bool                     `json:"enabled,omitempty"`
	ZoneName          string                   `json:"zone_name,omitempty"`
	ZoneCIDR          string                   `json:"zone_cidr,omitempty"`
	Live              labTopologyNodeLive      `json:"live"`
}

type labTopologyLinkView struct {
	ID        string   `json:"id"`
	Label     string   `json:"label,omitempty"`
	Zone      string   `json:"zone,omitempty"`
	Endpoints []string `json:"endpoints"`
	Kind      string   `json:"kind,omitempty"`
}

type labTopologyCollectionLive struct {
	RecentEventCount int   `json:"recent_event_count"`
	LastSeenUnixMs   int64 `json:"last_seen_unix_ms,omitempty"`
	Active           bool  `json:"active"`
}

type labTopologyCollectionView struct {
	NodeID     string                    `json:"node_id"`
	Collector  string                    `json:"collector"`
	Transport  string                    `json:"transport"`
	Endpoint   string                    `json:"endpoint,omitempty"`
	SourceType string                    `json:"source_type"`
	EventTypes []string                  `json:"event_types,omitempty"`
	Notes      string                    `json:"notes,omitempty"`
	Required   bool                      `json:"required,omitempty"`
	Status     string                    `json:"status,omitempty"`
	Live       labTopologyCollectionLive `json:"live"`
}

type labTopologySignalView struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Severity    string   `json:"severity,omitempty"`
	Status      string   `json:"status,omitempty"`
	Zone        string   `json:"zone,omitempty"`
	NodeID      string   `json:"node_id,omitempty"`
	SourceNode  string   `json:"source_node,omitempty"`
	DstNode     string   `json:"dst_node,omitempty"`
	SourceIP    string   `json:"source_ip,omitempty"`
	DstIP       string   `json:"dst_ip,omitempty"`
	SourceTypes []string `json:"source_types,omitempty"`
	EventTypes  []string `json:"event_types,omitempty"`
	Protocols   []string `json:"protocols,omitempty"`
	Service     string   `json:"service,omitempty"`
}

type labTopologyActivityItem struct {
	Kind       string `json:"kind"`
	TSUnixMs   int64  `json:"ts_unix_ms"`
	Label      string `json:"label"`
	Status     string `json:"status,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	NodeID     string `json:"node_id,omitempty"`
	SourceType string `json:"source_type,omitempty"`
	ActionID   string `json:"action_id,omitempty"`
	Zone       string `json:"zone,omitempty"`
}

type labTopologyResponse struct {
	Lab             labTopologyLabSpec                 `json:"lab"`
	Provider        infrastructureTopologyProviderView `json:"provider"`
	Zones           []labTopologyZoneView              `json:"zones"`
	Nodes           []labTopologyNodeView              `json:"nodes"`
	Links           []labTopologyLinkView              `json:"links"`
	Collection      []labTopologyCollectionView        `json:"collection"`
	Signals         []labTopologySignalView            `json:"signals"`
	Summary         labTopologySummary                 `json:"summary"`
	RecentEvents    []labEventView                     `json:"recent_events"`
	RecentIncidents []incident                         `json:"recent_incidents"`
	RecentActions   []responseActionView               `json:"recent_actions"`
	Activity        []labTopologyActivityItem          `json:"activity"`
	Source          string                             `json:"source"`
}

type labCatalogEntry struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Description         string `json:"description"`
	Status              string `json:"status"`
	ZoneCount           int    `json:"zone_count"`
	NodeCount           int    `json:"node_count"`
	ResponseTargetCount int    `json:"response_target_count"`
	LogSourceCount      int    `json:"log_source_count"`
	TrafficSourceCount  int    `json:"traffic_source_count"`
	RecentEventCount    int    `json:"recent_event_count"`
	LastSeenUnixMs      int64  `json:"last_seen_unix_ms,omitempty"`
	ConfigPath          string `json:"config_path,omitempty"`
}

type labCatalogResponse struct {
	Items  []labCatalogEntry `json:"items"`
	Count  int               `json:"count"`
	Source string            `json:"source"`
}

type labEventView struct {
	eventRow
	LabID                string `json:"lab_id"`
	LabName              string `json:"lab_name"`
	Zone                 string `json:"zone,omitempty"`
	SourceNodeID         string `json:"source_node_id,omitempty"`
	SourceNodeLabel      string `json:"source_node_label,omitempty"`
	SourceZone           string `json:"source_zone,omitempty"`
	SourceRole           string `json:"source_role,omitempty"`
	DestinationNodeID    string `json:"destination_node_id,omitempty"`
	DestinationNodeLabel string `json:"destination_node_label,omitempty"`
	DestinationZone      string `json:"destination_zone,omitempty"`
	DestinationRole      string `json:"destination_role,omitempty"`
	Service              string `json:"service,omitempty"`
	TrafficClass         string `json:"traffic_class,omitempty"`
	Expected             bool   `json:"expected,omitempty"`
	Suspicious           bool   `json:"suspicious,omitempty"`
	PolicyViolation      bool   `json:"policy_violation,omitempty"`
	Reconnaissance       bool   `json:"reconnaissance,omitempty"`
	Allowed              bool   `json:"allowed,omitempty"`
	SourceContext        string `json:"source_context,omitempty"`
	DestinationContext   string `json:"destination_context,omitempty"`
}

type labEventSearchResponse struct {
	Items            []labEventView `json:"items"`
	Count            int            `json:"count"`
	Total            int            `json:"total"`
	Page             int            `json:"page"`
	Limit            int            `json:"limit"`
	Sort             string         `json:"sort"`
	Source           string         `json:"source"`
	AvailableFilters []string       `json:"available_filters"`
	Query            any            `json:"query"`
}

type labEventSearchQuery struct {
	Q              string
	From           int64
	To             int64
	Zone           string
	NodeID         string
	SrcNodeID      string
	DstNodeID      string
	SourceType     string
	EventType      string
	Severity       string
	ProtocolFamily string
	Service        string
	TrafficClass   string
	RuleID         string
	Page           int
	Limit          int
	Sort           string
}

type labNodeIndex struct {
	NodeByID  map[string]labTopologyNodeSpec
	NodeByIP  map[string]labTopologyNodeSpec
	ZoneByID  map[string]labTopologyZoneSpec
	NodeZone  map[string]string
	ZoneNodes map[string][]string
}

func (a *app) handleLabCatalog(w http.ResponseWriter, r *http.Request) {
	fromMs := parseInt64(r.URL.Query().Get("from"), time.Now().Add(-1*time.Hour).UnixMilli())
	toMs := parseInt64(r.URL.Query().Get("to"), time.Now().UnixMilli())
	if fromMs > toMs {
		fromMs, toMs = toMs, fromMs
	}
	spec, path, err := loadLabTopologyFile(a.cfg.MasterConfig, a.cfg.LabConfig)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	resp, err := a.buildLabCatalog(r.Context(), spec, path, fromMs, toMs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *app) handleLabTopology(w http.ResponseWriter, r *http.Request) {
	labID := strings.TrimSpace(r.PathValue("lab_id"))
	fromMs := parseInt64(r.URL.Query().Get("from"), time.Now().Add(-1*time.Hour).UnixMilli())
	toMs := parseInt64(r.URL.Query().Get("to"), time.Now().UnixMilli())
	if fromMs > toMs {
		fromMs, toMs = toMs, fromMs
	}
	spec, _, err := loadLabTopologyFile(a.cfg.MasterConfig, a.cfg.LabConfig)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if labID != "" && !strings.EqualFold(labID, spec.Lab.ID) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "lab not found"})
		return
	}
	resp, err := a.buildLabTopology(r.Context(), spec, fromMs, toMs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *app) handleLabEvents(w http.ResponseWriter, r *http.Request) {
	labID := strings.TrimSpace(r.PathValue("lab_id"))
	spec, _, err := loadLabTopologyFile(a.cfg.MasterConfig, a.cfg.LabConfig)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if labID != "" && !strings.EqualFold(labID, spec.Lab.ID) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "lab not found"})
		return
	}
	req := parseLabEventSearchQuery(r.URL.Query(), time.Now())
	resp, err := a.searchLabEvents(r.Context(), spec, req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *app) handleLabIncidents(w http.ResponseWriter, r *http.Request) {
	labID := strings.TrimSpace(r.PathValue("lab_id"))
	spec, _, err := loadLabTopologyFile(a.cfg.MasterConfig, a.cfg.LabConfig)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if labID != "" && !strings.EqualFold(labID, spec.Lab.ID) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "lab not found"})
		return
	}
	fromMs := parseInt64(r.URL.Query().Get("from"), time.Now().Add(-24*time.Hour).UnixMilli())
	toMs := parseInt64(r.URL.Query().Get("to"), time.Now().UnixMilli())
	if fromMs > toMs {
		fromMs, toMs = toMs, fromMs
	}
	limit := int(parseInt64(r.URL.Query().Get("limit"), 50))
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	runs, _, _ := a.loadState()
	items := filterLabIncidents(spec, runs, fromMs, toMs, strings.TrimSpace(r.URL.Query().Get("node_id")), strings.TrimSpace(r.URL.Query().Get("zone")), strings.TrimSpace(r.URL.Query().Get("severity")), strings.TrimSpace(r.URL.Query().Get("status")))
	if len(items) > limit {
		items = items[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"count":  len(items),
		"total":  len(items),
		"from":   fromMs,
		"to":     toMs,
		"source": "lab+state",
	})
}

func (a *app) handleLabActions(w http.ResponseWriter, r *http.Request) {
	labID := strings.TrimSpace(r.PathValue("lab_id"))
	spec, _, err := loadLabTopologyFile(a.cfg.MasterConfig, a.cfg.LabConfig)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if labID != "" && !strings.EqualFold(labID, spec.Lab.ID) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "lab not found"})
		return
	}
	fromMs := parseInt64(r.URL.Query().Get("from"), time.Now().Add(-24*time.Hour).UnixMilli())
	toMs := parseInt64(r.URL.Query().Get("to"), time.Now().UnixMilli())
	if fromMs > toMs {
		fromMs, toMs = toMs, fromMs
	}
	limit := int(parseInt64(r.URL.Query().Get("limit"), 50))
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	runs, stepsByRun, _ := a.loadState()
	actions := allActionViews(a.loadActionRecords(), runs, stepsByRun)
	items := filterLabActions(spec, actions, fromMs, toMs, strings.TrimSpace(r.URL.Query().Get("node_id")), strings.TrimSpace(r.URL.Query().Get("status")), strings.TrimSpace(r.URL.Query().Get("action_name")))
	if len(items) > limit {
		items = items[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"count":  len(items),
		"total":  len(items),
		"from":   fromMs,
		"to":     toMs,
		"source": "lab+state",
	})
}

func (a *app) buildLabCatalog(ctx context.Context, spec labTopologyFile, configPath string, fromMs, toMs int64) (labCatalogResponse, error) {
	topology, err := a.buildLabTopology(ctx, spec, fromMs, toMs)
	if err != nil {
		return labCatalogResponse{}, err
	}
	entry := labCatalogEntry{
		ID:                  topology.Lab.ID,
		Name:                topology.Lab.Name,
		Description:         topology.Lab.Description,
		Status:              topology.Lab.Status,
		ZoneCount:           len(topology.Zones),
		NodeCount:           len(topology.Nodes),
		ResponseTargetCount: topology.Summary.ResponseTargetCount,
		LogSourceCount:      topology.Summary.LogSourceCount,
		TrafficSourceCount:  topology.Summary.TrafficSourceCount,
		RecentEventCount:    topology.Summary.RecentEventCount,
		LastSeenUnixMs:      newestEventUnixMs(topology.RecentEvents),
		ConfigPath:          configPath,
	}
	return labCatalogResponse{Items: []labCatalogEntry{entry}, Count: 1, Source: topology.Source}, nil
}

func (a *app) buildLabTopology(ctx context.Context, spec labTopologyFile, fromMs, toMs int64) (labTopologyResponse, error) {
	providerView := loadLabEveNGTopology(spec)
	runtimeView := fetchEveNGRuntime(ctx, spec.Provider)
	providerView.RuntimeStatus = runtimeView.Status
	providerView.RuntimeDetail = runtimeView.Detail
	providerView.RuntimeLastSyncMs = runtimeView.LastSyncMs

	nodesByID, nodesByIP, zonesByID, zoneNodes := buildLabNodeIndex(spec)
	events := a.loadLabTopologyEvents(ctx, spec, fromMs, toMs)
	runs, stepsByRun, _ := a.loadState()
	actions := allActionViews(a.loadActionRecords(), runs, stepsByRun)
	incidents := filterLabIncidents(spec, runs, fromMs, toMs, "", "", "", "")

	resp := labTopologyResponse{
		Lab:      spec.Lab,
		Provider: providerView,
		Source:   "lab+db+state+exports",
	}
	if a.db == nil {
		resp.Source = "lab+state+exports"
	}
	resp.Zones = buildLabZoneViews(spec, zoneNodes)
	resp.Nodes = buildLabNodeViews(spec, nodesByID, nodesByIP, zonesByID, events, incidents, actions, runtimeView)
	resp.Links = buildLabLinkViews(spec)
	resp.Collection = buildLabCollectionViews(spec, nodesByID, events)
	resp.Signals = buildLabSignalViews(spec)
	resp.RecentEvents = buildLabRecentEventViews(spec, events)
	resp.RecentIncidents = limitIncidents(incidents, 12)
	resp.RecentActions = limitActions(actions, 12)
	resp.Activity = buildLabActivity(spec, events, incidents, actions)
	resp.Summary = summarizeLabTopology(spec, resp.Nodes, events, incidents, actions, fromMs, toMs)
	return resp, nil
}

func loadLabTopologyFile(masterConfigPath, defaultPath string) (labTopologyFile, string, error) {
	path := defaultPath
	if v := strings.TrimSpace(os.Getenv("RSIEM_LAB_CONFIG_PATH")); v != "" {
		path = v
	}
	baseDir := filepath.Dir(strings.TrimSpace(masterConfigPath))
	if !filepath.IsAbs(path) {
		candidate := filepath.Join(baseDir, "labs", filepath.Base(path))
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return labTopologyFile{}, "", err
	}
	var spec labTopologyFile
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return labTopologyFile{}, "", err
	}
	spec = applyLabEnvOverrides(spec)
	return spec, path, nil
}

func applyLabEnvOverrides(spec labTopologyFile) labTopologyFile {
	if v := strings.TrimSpace(os.Getenv("RSIEM_LAB_UI_URL")); v != "" {
		spec.Provider.UIURL = v
	}
	if v := strings.TrimSpace(os.Getenv("RSIEM_LAB_API_BASE_URL")); v != "" {
		spec.Provider.APIBaseURL = v
	}
	if v := strings.TrimSpace(os.Getenv("RSIEM_LAB_API_LAB_PATH")); v != "" {
		spec.Provider.APILabPath = v
	}
	if v := strings.TrimSpace(os.Getenv("RSIEM_LAB_ALLOW_INSECURE_TLS")); v != "" {
		spec.Provider.AllowInsecureTLS = strings.EqualFold(v, "1") || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}
	if v := strings.TrimSpace(os.Getenv("RSIEM_LAB_TOPOLOGY_IMPORT_PATH")); v != "" {
		spec.Provider.TopologyImportPath = v
	}
	if v := strings.TrimSpace(os.Getenv("RSIEM_LAB_HOST_COLLECTOR_IP")); v != "" {
		for i := range spec.Collection {
			spec.Collection[i].Endpoint = rewriteLabCollectorEndpoint(spec.Collection[i].Endpoint, v)
		}
	}
	return spec
}

func rewriteLabCollectorEndpoint(endpoint, host string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return endpoint
	}
	if strings.Contains(endpoint, defaultLabCollectorHost) {
		return strings.ReplaceAll(endpoint, defaultLabCollectorHost, host)
	}
	return endpoint
}

func loadLabEveNGTopology(spec labTopologyFile) infrastructureTopologyProviderView {
	view := infrastructureTopologyProviderView{
		Kind:               spec.Provider.Kind,
		Name:               spec.Provider.Name,
		UIURL:              spec.Provider.UIURL,
		APIBaseURL:         spec.Provider.APIBaseURL,
		APILabPath:         spec.Provider.APILabPath,
		ProjectPath:        spec.Provider.ProjectPath,
		LabFile:            spec.Provider.LabFile,
		TopologyImportPath: spec.Provider.TopologyImportPath,
		Notes:              spec.Provider.Notes,
		SourceStatus:       "configured",
	}
	if strings.TrimSpace(view.UIURL) == "" && strings.TrimSpace(view.APIBaseURL) == "" {
		view.SourceStatus = "not_configured"
		view.SourceDetail = "lab provider urls not configured"
		return view
	}
	if strings.TrimSpace(view.APILabPath) == "" {
		view.SourceStatus = "not_configured"
		view.SourceDetail = "api_lab_path missing"
		return view
	}
	if status, detail := labCollectorOverrideStatus(spec); status != "" {
		view.SourceStatus = status
		view.SourceDetail = detail
	}
	if strings.TrimSpace(view.TopologyImportPath) != "" {
		path := view.TopologyImportPath
		if !filepath.IsAbs(path) {
			if cwd, err := os.Getwd(); err == nil && strings.TrimSpace(cwd) != "" {
				path = filepath.Join(cwd, path)
			}
		}
		if _, err := os.Stat(path); err == nil {
			view.SourceStatus = "import_available"
			view.SourceDetail = path
		} else {
			view.SourceStatus = "import_missing"
			view.SourceDetail = path
		}
		if status, detail := labCollectorOverrideStatus(spec); status != "" {
			view.SourceStatus = status
			if view.SourceDetail != "" {
				view.SourceDetail = view.SourceDetail + "; " + detail
			} else {
				view.SourceDetail = detail
			}
		}
	}
	return view
}

func labCollectorOverrideStatus(spec labTopologyFile) (string, string) {
	needsOverride := false
	check := func(value string) {
		if strings.Contains(value, defaultLabCollectorHost) {
			needsOverride = true
		}
	}
	check(spec.Provider.UIURL)
	check(spec.Provider.APIBaseURL)
	check(spec.Provider.APILabPath)
	for _, collection := range spec.Collection {
		check(collection.Endpoint)
	}
	for _, node := range spec.Nodes {
		check(node.IP)
		for _, ip := range node.IPs {
			check(ip)
		}
	}
	if !needsOverride {
		return "", ""
	}
	if strings.TrimSpace(os.Getenv("RSIEM_INFRA_HOST_COLLECTOR_IP")) != "" {
		return "", ""
	}
	return "needs_host_collector_ip", "set RSIEM_INFRA_HOST_COLLECTOR_IP to rewrite the logical collector anchor 10.10.0.10 to the real host IP reachable from EVE-NG"
}

func buildLabNodeIndex(spec labTopologyFile) (map[string]labTopologyNodeSpec, map[string]labTopologyNodeSpec, map[string]labTopologyZoneSpec, map[string][]string) {
	nodesByID := make(map[string]labTopologyNodeSpec, len(spec.Nodes))
	nodesByIP := make(map[string]labTopologyNodeSpec, len(spec.Nodes)*2)
	zonesByID := make(map[string]labTopologyZoneSpec, len(spec.Zones))
	zoneNodes := make(map[string][]string, len(spec.Zones))
	for _, zone := range spec.Zones {
		key := normalizeInventoryKey(zone.ID)
		if key == "" {
			continue
		}
		zonesByID[key] = zone
	}
	for _, node := range spec.Nodes {
		key := normalizeInventoryKey(node.ID)
		if key == "" {
			continue
		}
		nodesByID[key] = node
		zoneKey := normalizeInventoryKey(node.Zone)
		if zoneKey != "" {
			zoneNodes[zoneKey] = append(zoneNodes[zoneKey], node.ID)
		}
		for _, ip := range append([]string{node.IP}, node.IPs...) {
			ipKey := stripCIDRSuffix(ip)
			if ipKey == "" {
				continue
			}
			nodesByIP[ipKey] = node
		}
	}
	return nodesByID, nodesByIP, zonesByID, zoneNodes
}

func buildLabZoneViews(spec labTopologyFile, zoneNodes map[string][]string) []labTopologyZoneView {
	out := make([]labTopologyZoneView, 0, len(spec.Zones))
	for _, zone := range spec.Zones {
		out = append(out, labTopologyZoneView{
			ID:      zone.ID,
			Name:    zone.Name,
			CIDR:    zone.CIDR,
			Purpose: zone.Purpose,
			Color:   zone.Color,
			Order:   zone.Order,
			NodeIDs: append([]string(nil), zoneNodes[normalizeInventoryKey(zone.ID)]...),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order == out[j].Order {
			return out[i].ID < out[j].ID
		}
		return out[i].Order < out[j].Order
	})
	return out
}

func buildLabNodeViews(spec labTopologyFile, nodesByID map[string]labTopologyNodeSpec, nodesByIP map[string]labTopologyNodeSpec, zonesByID map[string]labTopologyZoneSpec, events []labEventView, incidents []incident, actions []responseActionView, runtimeView eveNGRuntimeView) []labTopologyNodeView {
	out := make([]labTopologyNodeView, 0, len(spec.Nodes))
	for _, node := range spec.Nodes {
		nodeKey := normalizeInventoryKey(node.ID)
		zoneKey := normalizeInventoryKey(node.Zone)
		zone := zonesByID[zoneKey]
		view := labTopologyNodeView{
			ID:                node.ID,
			Label:             chooseNonEmpty(node.Label, node.ID),
			EveNodeName:       node.EveNodeName,
			Role:              node.Role,
			Zone:              node.Zone,
			OS:                node.OS,
			State:             chooseNonEmpty(node.State, "unknown"),
			ServiceState:      chooseNonEmpty(node.ServiceState, "unknown"),
			IP:                node.IP,
			IPs:               append([]string(nil), node.IPs...),
			PositionLeft:      node.PositionLeft,
			PositionTop:       node.PositionTop,
			Notes:             node.Notes,
			Services:          append([]labTopologyServiceSpec(nil), node.Services...),
			DataRoles:         append([]string(nil), node.DataRoles...),
			ExpectedBehaviors: append([]string(nil), node.ExpectedBehaviors...),
			Connectivity:      append([]string(nil), node.Connectivity...),
			SourceRoles:       append([]string(nil), node.SourceRoles...),
			ResponseTarget:    node.ResponseTarget,
			LogSource:         node.LogSource,
			TrafficSource:     node.TrafficSource,
			AttackerSimulator: node.AttackerSimulator,
			Managed:           node.Managed,
			Enabled:           node.Enabled || !node.AttackerSimulator || node.State != "planned",
			ZoneName:          zone.Name,
			ZoneCIDR:          zone.CIDR,
		}
		if view.Label == "" {
			view.Label = node.ID
		}
		view.Live = summarizeLabNodeLive(spec, nodeKey, view, events, incidents, actions, runtimeView, nodesByID, nodesByIP)
		out = append(out, view)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PositionTop == out[j].PositionTop {
			return out[i].PositionLeft < out[j].PositionLeft
		}
		return out[i].PositionTop < out[j].PositionTop
	})
	return out
}

func buildLabLinkViews(spec labTopologyFile) []labTopologyLinkView {
	out := make([]labTopologyLinkView, 0, len(spec.Links))
	for _, link := range spec.Links {
		out = append(out, labTopologyLinkView{
			ID:        link.ID,
			Label:     link.Label,
			Zone:      link.Zone,
			Endpoints: append([]string(nil), link.Endpoints...),
			Kind:      link.Kind,
		})
	}
	return out
}

func buildLabCollectionViews(spec labTopologyFile, nodesByID map[string]labTopologyNodeSpec, events []labEventView) []labTopologyCollectionView {
	out := make([]labTopologyCollectionView, 0, len(spec.Collection))
	for _, item := range spec.Collection {
		key := normalizeInventoryKey(item.NodeID)
		node := nodesByID[key]
		recentCount := 0
		lastSeen := int64(0)
		for _, ev := range events {
			if matchesCollectionNode(item.NodeID, ev.SourceNodeID, ev.DestinationNodeID, ev.NodeID, ev.SrcIP, ev.DstIP, node) {
				recentCount++
				if ev.RecvTSUnixMs > lastSeen {
					lastSeen = ev.RecvTSUnixMs
				}
			}
		}
		out = append(out, labTopologyCollectionView{
			NodeID:     item.NodeID,
			Collector:  item.Collector,
			Transport:  item.Transport,
			Endpoint:   item.Endpoint,
			SourceType: item.SourceType,
			EventTypes: append([]string(nil), item.EventTypes...),
			Notes:      item.Notes,
			Required:   item.Required,
			Status:     item.Status,
			Live: labTopologyCollectionLive{
				RecentEventCount: recentCount,
				LastSeenUnixMs:   lastSeen,
				Active:           recentCount > 0,
			},
		})
	}
	return out
}

func buildLabSignalViews(spec labTopologyFile) []labTopologySignalView {
	out := make([]labTopologySignalView, 0, len(spec.Signals))
	for _, sig := range spec.Signals {
		out = append(out, labTopologySignalView{
			ID:          sig.ID,
			Label:       sig.Label,
			Description: sig.Description,
			Severity:    sig.Severity,
			Status:      sig.Status,
			Zone:        sig.Zone,
			NodeID:      sig.NodeID,
			SourceNode:  sig.SourceNode,
			DstNode:     sig.DstNode,
			SourceIP:    sig.SourceIP,
			DstIP:       sig.DstIP,
			SourceTypes: append([]string(nil), sig.SourceTypes...),
			EventTypes:  append([]string(nil), sig.EventTypes...),
			Protocols:   append([]string(nil), sig.Protocols...),
			Service:     sig.Service,
		})
	}
	return out
}

func buildLabRecentEventViews(spec labTopologyFile, events []labEventView) []labEventView {
	if len(events) == 0 {
		return nil
	}
	limit := 30
	if len(events) < limit {
		limit = len(events)
	}
	out := make([]labEventView, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, events[i])
	}
	return out
}

func summarizeLabTopology(spec labTopologyFile, nodes []labTopologyNodeView, events []labEventView, incidents []incident, actions []responseActionView, fromMs, toMs int64) labTopologySummary {
	summary := labTopologySummary{
		WindowFromUnixMs: fromMs,
		WindowToUnixMs:   toMs,
		ZoneCount:        len(spec.Zones),
		NodeCount:        len(spec.Nodes),
	}
	for _, node := range spec.Nodes {
		if node.ResponseTarget {
			summary.ResponseTargetCount++
		}
		if node.LogSource {
			summary.LogSourceCount++
		}
		if node.TrafficSource {
			summary.TrafficSourceCount++
		}
		if node.AttackerSimulator {
			summary.AttackerSimulatorCount++
		}
		for _, svc := range node.Services {
			if strings.TrimSpace(svc.Name) != "" {
				summary.ExpectedServiceCount++
			}
		}
	}
	for _, node := range nodes {
		if strings.EqualFold(node.Live.Status, "running") || strings.EqualFold(node.Live.Status, "reachable") {
			summary.ReachableNodeCount++
		}
		if node.State != "planned" {
			summary.RunnableNodeCount++
		}
	}
	summary.RecentEventCount = len(events)
	summary.RecentIncidentCount = len(incidents)
	summary.RecentActionCount = len(actions)
	return summary
}

func summarizeLabNodeLive(spec labTopologyFile, nodeKey string, view labTopologyNodeView, events []labEventView, incidents []incident, actions []responseActionView, runtimeView eveNGRuntimeView, nodesByID map[string]labTopologyNodeSpec, nodesByIP map[string]labTopologyNodeSpec) labTopologyNodeLive {
	live := labTopologyNodeLive{
		Status:       chooseNonEmpty(view.State, "unknown"),
		ServiceState: chooseNonEmpty(view.ServiceState, "unknown"),
	}
	seenSourceTypes := map[string]struct{}{}
	seenEventTypes := map[string]struct{}{}
	seenZones := map[string]struct{}{}
	for _, ev := range events {
		if !matchesLabNodeEvent(view, ev) {
			continue
		}
		live.RecentEventCount++
		if ev.RecvTSUnixMs > live.LastSeenUnixMs {
			live.LastSeenUnixMs = ev.RecvTSUnixMs
		}
		if ev.RuleID != "" {
			live.DetectionCount++
		}
		if ev.Zone != "" {
			seenZones[ev.Zone] = struct{}{}
		}
		if ev.SourceType != "" {
			seenSourceTypes[ev.SourceType] = struct{}{}
		}
		if ev.EventType != "" {
			seenEventTypes[ev.EventType] = struct{}{}
		}
	}
	for _, inc := range incidents {
		if matchesLabIncidentNode(view, inc, nodesByID, nodesByIP) {
			live.IncidentCount++
			if strings.EqualFold(inc.Status, "OPEN") || strings.EqualFold(inc.Status, "RUNNING") || strings.EqualFold(inc.Status, "WAITING_APPROVAL") {
				live.OpenIncidentCount++
			}
		}
	}
	for _, action := range actions {
		if matchesLabActionNode(view, action, nodesByID, nodesByIP) && strings.EqualFold(action.Bucket, "active") {
			live.ActiveActionCount++
		}
	}
	if runtimeView.Status != "" {
		live.RuntimeStatus = runtimeView.Status
		live.RuntimeDetail = runtimeView.Detail
		if live.Status == "unknown" {
			switch runtimeView.Status {
			case "connected":
				live.Status = "reachable"
			case "credentials_missing", "not_configured":
				if view.State == "" || view.State == "unknown" {
					live.Status = "configured"
				}
			}
		}
	}
	if len(live.SeenSourceTypes) == 0 {
		live.SeenSourceTypes = sortedKeysSet(seenSourceTypes)
	}
	if len(live.SeenEventTypes) == 0 {
		live.SeenEventTypes = sortedKeysSet(seenEventTypes)
	}
	if len(live.SeenZones) == 0 {
		live.SeenZones = sortedKeysSet(seenZones)
	}
	if live.Status == "unknown" && live.RecentEventCount > 0 {
		live.Status = "reachable"
	}
	return live
}

func matchesLabNodeEvent(node labTopologyNodeView, ev labEventView) bool {
	if strings.EqualFold(strings.TrimSpace(ev.NodeID), node.ID) || strings.EqualFold(strings.TrimSpace(ev.SourceNodeID), node.ID) || strings.EqualFold(strings.TrimSpace(ev.DestinationNodeID), node.ID) {
		return true
	}
	for _, ip := range append([]string{node.IP}, node.IPs...) {
		if sameIP(ev.SrcIP, ip) || sameIP(ev.DstIP, ip) {
			return true
		}
	}
	return false
}

func matchesLabIncidentNode(node labTopologyNodeView, inc incident, nodesByID map[string]labTopologyNodeSpec, nodesByIP map[string]labTopologyNodeSpec) bool {
	if strings.EqualFold(strings.TrimSpace(inc.NodeID), node.ID) || strings.EqualFold(strings.TrimSpace(inc.TargetAgentID), node.ID) {
		return true
	}
	for _, ip := range append([]string{node.IP}, node.IPs...) {
		if sameIP(inc.SrcIP, ip) || sameIP(inc.DstIP, ip) || sameIP(inc.Target, ip) {
			return true
		}
	}
	return false
}

func matchesLabActionNode(node labTopologyNodeView, action responseActionView, nodesByID map[string]labTopologyNodeSpec, nodesByIP map[string]labTopologyNodeSpec) bool {
	if strings.EqualFold(strings.TrimSpace(action.NodeID), node.ID) || strings.EqualFold(strings.TrimSpace(action.TargetAgentID), node.ID) {
		return true
	}
	for _, ip := range append([]string{node.IP}, node.IPs...) {
		if sameIP(action.Target, ip) {
			return true
		}
	}
	return false
}

func parseLabEventSearchQuery(values map[string][]string, now time.Time) labEventSearchQuery {
	q := labEventSearchQuery{
		Q:              strings.TrimSpace(firstQueryValue(values, "q")),
		From:           parseInt64(firstQueryValue(values, "from"), now.Add(-1*time.Hour).UnixMilli()),
		To:             parseInt64(firstQueryValue(values, "to"), now.UnixMilli()),
		Zone:           strings.TrimSpace(firstQueryValue(values, "zone")),
		NodeID:         strings.TrimSpace(firstQueryValue(values, "node_id")),
		SrcNodeID:      strings.TrimSpace(firstQueryValue(values, "src_node_id")),
		DstNodeID:      strings.TrimSpace(firstQueryValue(values, "dst_node_id")),
		SourceType:     strings.TrimSpace(firstQueryValue(values, "source_type")),
		EventType:      strings.TrimSpace(firstQueryValue(values, "event_type")),
		Severity:       strings.TrimSpace(firstQueryValue(values, "severity")),
		ProtocolFamily: strings.TrimSpace(firstQueryValue(values, "protocol_family")),
		Service:        strings.TrimSpace(firstQueryValue(values, "service")),
		TrafficClass:   strings.TrimSpace(firstQueryValue(values, "traffic_class")),
		RuleID:         strings.TrimSpace(firstQueryValue(values, "rule_id")),
		Page:           int(parseInt64(firstQueryValue(values, "page"), 1)),
		Limit:          int(parseInt64(firstQueryValue(values, "limit"), 200)),
		Sort:           strings.TrimSpace(firstQueryValue(values, "sort")),
	}
	if q.Page <= 0 {
		q.Page = 1
	}
	if q.Limit <= 0 {
		q.Limit = 200
	}
	if q.Limit > 1000 {
		q.Limit = 1000
	}
	switch q.Sort {
	case "recv_asc", "event_asc", "recv_desc", "event_desc":
	default:
		q.Sort = "recv_desc"
	}
	if q.From > q.To {
		q.From, q.To = q.To, q.From
	}
	return q
}

func firstQueryValue(values map[string][]string, key string) string {
	if values == nil {
		return ""
	}
	v := values[key]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func (a *app) searchLabEvents(ctx context.Context, spec labTopologyFile, req labEventSearchQuery) (labEventSearchResponse, error) {
	resp := labEventSearchResponse{
		Items:  []labEventView{},
		Count:  0,
		Total:  0,
		Page:   req.Page,
		Limit:  req.Limit,
		Sort:   req.Sort,
		Source: "lab+db",
		AvailableFilters: []string{
			"q",
			"from",
			"to",
			"zone",
			"node_id",
			"src_node_id",
			"dst_node_id",
			"source_type",
			"event_type",
			"severity",
			"protocol_family",
			"service",
			"traffic_class",
			"rule_id",
			"page",
			"limit",
			"sort",
		},
		Query: req,
	}
	events := a.loadLabTopologyEvents(ctx, spec, req.From, req.To)
	nodesByID, nodesByIP, zonesByID, _ := buildLabNodeIndex(spec)
	filtered := make([]labEventView, 0, len(events))
	for _, ev := range events {
		if !matchesLabEventQuery(ev, req, nodesByID, nodesByIP, zonesByID) {
			continue
		}
		filtered = append(filtered, ev)
	}
	resp.Total = len(filtered)
	start := (req.Page - 1) * req.Limit
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + req.Limit
	if end > len(filtered) {
		end = len(filtered)
	}
	resp.Items = filtered[start:end]
	resp.Count = len(resp.Items)
	return resp, nil
}

func matchesLabEventQuery(ev labEventView, req labEventSearchQuery, nodesByID map[string]labTopologyNodeSpec, nodesByIP map[string]labTopologyNodeSpec, zonesByID map[string]labTopologyZoneSpec) bool {
	if req.NodeID != "" && !strings.EqualFold(req.NodeID, ev.NodeID) && !strings.EqualFold(req.NodeID, ev.SourceNodeID) && !strings.EqualFold(req.NodeID, ev.DestinationNodeID) {
		return false
	}
	if req.SrcNodeID != "" && !strings.EqualFold(req.SrcNodeID, ev.SourceNodeID) {
		return false
	}
	if req.DstNodeID != "" && !strings.EqualFold(req.DstNodeID, ev.DestinationNodeID) {
		return false
	}
	if req.Zone != "" && !strings.EqualFold(req.Zone, ev.Zone) && !strings.EqualFold(req.Zone, ev.SourceZone) && !strings.EqualFold(req.Zone, ev.DestinationZone) {
		return false
	}
	if req.SourceType != "" && !strings.EqualFold(req.SourceType, ev.SourceType) {
		return false
	}
	if req.EventType != "" && !strings.EqualFold(req.EventType, ev.EventType) {
		return false
	}
	if req.Severity != "" && !strings.EqualFold(req.Severity, ev.Severity) {
		return false
	}
	if req.ProtocolFamily != "" && !strings.EqualFold(req.ProtocolFamily, ev.ProtocolFamily) {
		return false
	}
	if req.Service != "" && !strings.EqualFold(req.Service, ev.Service) {
		return false
	}
	if req.TrafficClass != "" && !strings.EqualFold(req.TrafficClass, ev.TrafficClass) {
		return false
	}
	if req.RuleID != "" && !strings.EqualFold(req.RuleID, ev.RuleID) {
		return false
	}
	if req.Q != "" {
		q := strings.ToLower(req.Q)
		fields := []string{
			ev.NodeID, ev.SourceNodeID, ev.SourceNodeLabel, ev.DestinationNodeID, ev.DestinationNodeLabel,
			ev.Zone, ev.SourceZone, ev.DestinationZone, ev.SourceRole, ev.DestinationRole, ev.Service,
			ev.EventType, ev.SourceType, ev.RuleID, ev.TrafficClass, ev.SrcIP, ev.DstIP, ev.RawLineSHA256,
		}
		matched := false
		for _, field := range fields {
			if strings.Contains(strings.ToLower(field), q) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (a *app) loadLabTopologyEvents(ctx context.Context, spec labTopologyFile, fromMs, toMs int64) []labEventView {
	if a.db == nil {
		return nil
	}
	rows, err := a.db.QueryContext(ctx, `
SELECT event_ts_unix_ms, recv_ts_unix_ms, node_id, source_type, event_type,
       COALESCE(src_ip::text,''), COALESCE(dst_ip::text,''), COALESCE(dst_port,0), COALESCE(protocol_family,''),
       COALESCE(user_name,''), COALESCE(severity,''), COALESCE(rule_id,''),
       COALESCE(exec_path,''), COALESCE(comm,''), COALESCE(cmdline,''), COALESCE(dns_name,''),
       COALESCE(file_sha256,''), COALESCE(exec_sha256,''), event_idem_key, COALESCE(raw_line_sha256,'')
FROM normalized_events
WHERE recv_ts_unix_ms BETWEEN $1 AND $2
ORDER BY recv_ts_unix_ms DESC
LIMIT 2000
`, fromMs, toMs)
	if err != nil {
		return nil
	}
	defer rows.Close()

	nodesByID, nodesByIP, zonesByID, _ := buildLabNodeIndex(spec)
	items := make([]labEventView, 0, 256)
	for rows.Next() {
		var ev eventRow
		if err := rows.Scan(
			&ev.EventTSUnixMs, &ev.RecvTSUnixMs, &ev.NodeID, &ev.SourceType, &ev.EventType,
			&ev.SrcIP, &ev.DstIP, &ev.DstPort, &ev.ProtocolFamily,
			&ev.UserName, &ev.Severity, &ev.RuleID,
			&ev.ExecPath, &ev.Comm, &ev.Cmdline, &ev.DNSName,
			&ev.FileSHA256, &ev.ExecSHA256, &ev.EventIdemKey, &ev.RawLineSHA256,
		); err != nil {
			continue
		}
		if !matchesLabEvent(spec, ev, nodesByID, nodesByIP, zonesByID) {
			continue
		}
		items = append(items, enrichLabEvent(spec, ev, nodesByID, nodesByIP, zonesByID))
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].RecvTSUnixMs == items[j].RecvTSUnixMs {
			return items[i].EventTSUnixMs > items[j].EventTSUnixMs
		}
		return items[i].RecvTSUnixMs > items[j].RecvTSUnixMs
	})
	return items
}

func matchesLabEvent(spec labTopologyFile, ev eventRow, nodesByID map[string]labTopologyNodeSpec, nodesByIP map[string]labTopologyNodeSpec, zonesByID map[string]labTopologyZoneSpec) bool {
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ev.RuleID)), "R-INFRA-") {
		return true
	}
	if matchesAnyLabNode(ev.NodeID, ev.SrcIP, ev.DstIP, nodesByID, nodesByIP) {
		return true
	}
	if ev.SourceType == "syslog" || ev.SourceType == "netflow_v5" || ev.SourceType == "snmp_trap" {
		return true
	}
	return false
}

func matchesAnyLabNode(nodeID, srcIP, dstIP string, nodesByID map[string]labTopologyNodeSpec, nodesByIP map[string]labTopologyNodeSpec) bool {
	if nodeID != "" {
		if _, ok := nodesByID[normalizeInventoryKey(nodeID)]; ok {
			return true
		}
	}
	if srcIP != "" {
		if _, ok := nodesByIP[stripCIDRSuffix(srcIP)]; ok {
			return true
		}
	}
	if dstIP != "" {
		if _, ok := nodesByIP[stripCIDRSuffix(dstIP)]; ok {
			return true
		}
	}
	return false
}

func enrichLabEvent(spec labTopologyFile, ev eventRow, nodesByID map[string]labTopologyNodeSpec, nodesByIP map[string]labTopologyNodeSpec, zonesByID map[string]labTopologyZoneSpec) labEventView {
	srcNode, srcNodeID, srcZone := resolveLabNode(ev.NodeID, ev.SrcIP, nodesByID, nodesByIP, zonesByID)
	dstNode, dstNodeID, dstZone := resolveLabNode("", ev.DstIP, nodesByID, nodesByIP, zonesByID)
	service, trafficClass, expected, suspicious, policyViolation, reconnaissance, allowed := classifyLabEvent(spec, ev, srcNode, dstNode, srcZone, dstZone)
	view := labEventView{
		eventRow:             ev,
		LabID:                spec.Lab.ID,
		LabName:              chooseNonEmpty(spec.Lab.Name, spec.Lab.ID),
		Zone:                 chooseNonEmpty(srcZone, dstZone),
		SourceNodeID:         srcNodeID,
		SourceNodeLabel:      srcNode.Label,
		SourceZone:           srcZone,
		SourceRole:           srcNode.Role,
		DestinationNodeID:    dstNodeID,
		DestinationNodeLabel: dstNode.Label,
		DestinationZone:      dstZone,
		DestinationRole:      dstNode.Role,
		Service:              service,
		TrafficClass:         trafficClass,
		Expected:             expected,
		Suspicious:           suspicious,
		PolicyViolation:      policyViolation,
		Reconnaissance:       reconnaissance,
		Allowed:              allowed,
		SourceContext:        nodeContextString(srcNode, srcZone),
		DestinationContext:   nodeContextString(dstNode, dstZone),
	}
	if view.Zone == "" {
		view.Zone = chooseNonEmpty(dstZone, srcZone)
	}
	return view
}

func resolveLabNode(nodeID, ip string, nodesByID map[string]labTopologyNodeSpec, nodesByIP map[string]labTopologyNodeSpec, zonesByID map[string]labTopologyZoneSpec) (labTopologyNodeSpec, string, string) {
	if nodeID != "" {
		if node, ok := nodesByID[normalizeInventoryKey(nodeID)]; ok {
			return node, node.ID, zoneNameFor(node.Zone, zonesByID)
		}
	}
	ip = stripCIDRSuffix(ip)
	if ip != "" {
		if node, ok := nodesByIP[ip]; ok {
			return node, node.ID, zoneNameFor(node.Zone, zonesByID)
		}
	}
	return labTopologyNodeSpec{}, "", ""
}

func zoneNameFor(zoneID string, zonesByID map[string]labTopologyZoneSpec) string {
	if zoneID == "" {
		return ""
	}
	if zone, ok := zonesByID[normalizeInventoryKey(zoneID)]; ok {
		if zone.Name != "" {
			return zone.Name
		}
		return zone.ID
	}
	return zoneID
}

func classifyLabEvent(spec labTopologyFile, ev eventRow, srcNode, dstNode labTopologyNodeSpec, srcZone, dstZone string) (service, trafficClass string, expected, suspicious, policyViolation, reconnaissance, allowed bool) {
	service = detectLabService(ev, dstNode, srcNode)
	trafficClass = "normal"
	allowed = true
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ev.RuleID)), "R-INFRA-") {
		suspicious = true
		trafficClass = "detected"
	}
	if isZoneLike(srcNode.Zone, "USERS") && isZoneLike(dstNode.Zone, "SERVERS") {
		policyViolation = true
		trafficClass = "east_west_policy_violation"
	}
	if isZoneLike(srcNode.Zone, "USERS") && isZoneLike(dstNode.Zone, "DMZ") && service == "http" {
		expected = true
		trafficClass = "expected_dmz_web"
	}
	if isZoneLike(srcNode.Zone, "WAN") && !isZoneLike(dstNode.Zone, "DMZ") && dstNode.ID != "" {
		policyViolation = true
		trafficClass = "untrusted_to_internal"
	}
	if ev.DstPort > 0 && isReconnaissancePort(ev.DstPort) {
		reconnaissance = true
		trafficClass = "reconnaissance"
	}
	if ev.SourceType == "netflow_v5" && ev.EventType == "netflow_flow" {
		reconnaissance = true
		if trafficClass == "normal" {
			trafficClass = "flow_telemetry"
		}
	}
	if ev.SourceType == "syslog" && strings.Contains(strings.ToLower(srcNode.Role), "firewall") {
		allowed = false
		if trafficClass == "normal" {
			trafficClass = "firewall_observation"
		}
	}
	if expected && !policyViolation && !reconnaissance {
		trafficClass = chooseNonEmpty(trafficClass, "expected")
	}
	if policyViolation || reconnaissance || suspicious {
		allowed = false
	}
	return
}

func detectLabService(ev eventRow, dstNode, srcNode labTopologyNodeSpec) string {
	if ev.DstPort == 8080 {
		return "http"
	}
	if ev.DstPort == 22 {
		return "ssh"
	}
	if ev.DstPort == 443 {
		return "https"
	}
	if strings.Contains(strings.ToLower(ev.EventType), "http") {
		return "http"
	}
	if strings.Contains(strings.ToLower(ev.SourceType), "syslog") {
		return "syslog"
	}
	if strings.Contains(strings.ToLower(ev.SourceType), "snmp") {
		return "snmp"
	}
	if strings.Contains(strings.ToLower(ev.SourceType), "netflow") {
		return "flow"
	}
	if len(dstNode.Services) > 0 {
		for _, svc := range dstNode.Services {
			if svc.Port > 0 && svc.Port == ev.DstPort {
				return strings.ToLower(strings.TrimSpace(svc.Name))
			}
		}
	}
	return ""
}

func isZoneLike(actual, expected string) bool {
	actual = strings.ToUpper(strings.TrimSpace(actual))
	expected = strings.ToUpper(strings.TrimSpace(expected))
	if actual == "" || expected == "" {
		return false
	}
	return actual == expected || strings.Contains(actual, expected)
}

func nodeContextString(node labTopologyNodeSpec, zone string) string {
	parts := make([]string, 0, 4)
	if node.ID != "" {
		parts = append(parts, node.ID)
	}
	if zone != "" {
		parts = append(parts, zone)
	}
	if node.Role != "" {
		parts = append(parts, node.Role)
	}
	if node.State != "" {
		parts = append(parts, node.State)
	}
	return strings.Join(parts, " | ")
}

func filterLabIncidents(spec labTopologyFile, runs []incident, fromMs, toMs int64, nodeID, zone, severity, status string) []incident {
	nodesByID, nodesByIP, zonesByID, _ := buildLabNodeIndex(spec)
	out := make([]incident, 0, len(runs))
	for _, run := range runs {
		if run.LastUpdatedAtUnixMs < fromMs || run.LastUpdatedAtUnixMs > toMs {
			continue
		}
		if nodeID != "" && !strings.EqualFold(nodeID, run.NodeID) && !strings.EqualFold(nodeID, run.TargetAgentID) {
			if !sameIP(run.SrcIP, nodeIPForNodeID(nodeID, nodesByID)) && !sameIP(run.DstIP, nodeIPForNodeID(nodeID, nodesByID)) && !sameIP(run.Target, nodeIPForNodeID(nodeID, nodesByID)) {
				continue
			}
		}
		if zone != "" && !incidentMatchesZone(run, zone, nodesByID, nodesByIP, zonesByID) {
			continue
		}
		if severity != "" && !strings.EqualFold(severity, run.Severity) {
			continue
		}
		if status != "" && !strings.EqualFold(status, run.Status) {
			continue
		}
		out = append(out, run)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].LastUpdatedAtUnixMs > out[j].LastUpdatedAtUnixMs
	})
	return out
}

func incidentMatchesZone(run incident, zone string, nodesByID map[string]labTopologyNodeSpec, nodesByIP map[string]labTopologyNodeSpec, zonesByID map[string]labTopologyZoneSpec) bool {
	for _, node := range nodesByID {
		if !strings.EqualFold(node.Zone, zone) {
			continue
		}
		if strings.EqualFold(run.NodeID, node.ID) || strings.EqualFold(run.TargetAgentID, node.ID) {
			return true
		}
		for _, ip := range append([]string{node.IP}, node.IPs...) {
			if sameIP(run.SrcIP, ip) || sameIP(run.DstIP, ip) || sameIP(run.Target, ip) {
				return true
			}
		}
	}
	return false
}

func filterLabActions(spec labTopologyFile, actions []responseActionView, fromMs, toMs int64, nodeID, status, actionName string) []responseActionView {
	nodesByID, nodesByIP, _, _ := buildLabNodeIndex(spec)
	out := make([]responseActionView, 0, len(actions))
	for _, action := range actions {
		if action.StartedAtUnixMs > 0 && action.StartedAtUnixMs < fromMs {
			continue
		}
		if action.StartedAtUnixMs > 0 && action.StartedAtUnixMs > toMs {
			continue
		}
		if nodeID != "" && !actionMatchesNode(action, nodeID, nodesByID, nodesByIP) {
			continue
		}
		if status != "" && !strings.EqualFold(status, action.Bucket) && !strings.EqualFold(status, action.Status) {
			continue
		}
		if actionName != "" && !strings.EqualFold(actionName, action.ActionName) {
			continue
		}
		out = append(out, action)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].StartedAtUnixMs > out[j].StartedAtUnixMs
	})
	return out
}

func actionMatchesNode(action responseActionView, nodeID string, nodesByID map[string]labTopologyNodeSpec, nodesByIP map[string]labTopologyNodeSpec) bool {
	if strings.EqualFold(action.NodeID, nodeID) || strings.EqualFold(action.TargetAgentID, nodeID) {
		return true
	}
	node, ok := nodesByID[normalizeInventoryKey(nodeID)]
	if !ok {
		return false
	}
	for _, ip := range append([]string{node.IP}, node.IPs...) {
		if sameIP(action.Target, ip) {
			return true
		}
	}
	return false
}

func matchesCollectionNode(nodeID, sourceNodeID, destinationNodeID, eventNodeID, srcIP, dstIP string, node labTopologyNodeSpec) bool {
	if strings.EqualFold(strings.TrimSpace(nodeID), strings.TrimSpace(node.ID)) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(sourceNodeID), strings.TrimSpace(node.ID)) || strings.EqualFold(strings.TrimSpace(destinationNodeID), strings.TrimSpace(node.ID)) || strings.EqualFold(strings.TrimSpace(eventNodeID), strings.TrimSpace(node.ID)) {
		return true
	}
	for _, ip := range append([]string{node.IP}, node.IPs...) {
		if sameIP(srcIP, ip) || sameIP(dstIP, ip) {
			return true
		}
	}
	return false
}

func nodeIPForNodeID(nodeID string, nodesByID map[string]labTopologyNodeSpec) string {
	node, ok := nodesByID[normalizeInventoryKey(nodeID)]
	if !ok {
		return ""
	}
	return stripCIDRSuffix(node.IP)
}

func buildLabActivity(spec labTopologyFile, events []labEventView, incidents []incident, actions []responseActionView) []labTopologyActivityItem {
	items := make([]labTopologyActivityItem, 0, 40)
	for _, ev := range events {
		items = append(items, labTopologyActivityItem{
			Kind:       "event",
			TSUnixMs:   ev.RecvTSUnixMs,
			Label:      activityLabelForLabEvent(ev),
			Status:     ev.TrafficClass,
			RuleID:     ev.RuleID,
			NodeID:     ev.NodeID,
			SourceType: ev.SourceType,
			Zone:       chooseNonEmpty(chooseNonEmpty(ev.Zone, ev.SourceZone), ev.DestinationZone),
		})
	}
	for _, inc := range incidents {
		items = append(items, labTopologyActivityItem{
			Kind:     "incident",
			TSUnixMs: inc.LastUpdatedAtUnixMs,
			Label:    fmt.Sprintf("%s: %s", inc.RunID, inc.RuleID),
			Status:   inc.Status,
			RuleID:   inc.RuleID,
			RunID:    inc.RunID,
			NodeID:   inc.NodeID,
		})
	}
	for _, action := range actions {
		items = append(items, labTopologyActivityItem{
			Kind:     "action",
			TSUnixMs: action.StartedAtUnixMs,
			Label:    action.Label,
			Status:   action.Status,
			NodeID:   action.NodeID,
			ActionID: action.ActionID,
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].TSUnixMs > items[j].TSUnixMs
	})
	if len(items) > 40 {
		items = items[:40]
	}
	return items
}

func activityLabelForLabEvent(ev labEventView) string {
	if ev.SourceNodeLabel != "" && ev.DestinationNodeLabel != "" {
		return fmt.Sprintf("%s -> %s %s", ev.SourceNodeLabel, ev.DestinationNodeLabel, chooseNonEmpty(ev.Service, ev.EventType))
	}
	if ev.SourceNodeLabel != "" {
		return fmt.Sprintf("%s %s", ev.SourceNodeLabel, chooseNonEmpty(ev.Service, ev.EventType))
	}
	return chooseNonEmpty(ev.EventType, ev.SourceType)
}

func newestEventUnixMs(events []labEventView) int64 {
	var out int64
	for _, ev := range events {
		if ev.RecvTSUnixMs > out {
			out = ev.RecvTSUnixMs
		}
	}
	return out
}

func limitIncidents(items []incident, limit int) []incident {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func limitActions(items []responseActionView, limit int) []responseActionView {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func sortedKeysSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func isReconnaissancePort(port int) bool {
	switch port {
	case 21, 22, 23, 25, 53, 80, 88, 110, 139, 143, 389, 443, 445, 8080, 8443, 1433, 1521, 3306, 3389, 5985, 5986:
		return true
	default:
		return false
	}
}
