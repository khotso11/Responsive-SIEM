package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultInfrastructureLabPath = "configs/labs/emulated_infrastructure_lab.yaml"
const defaultInfrastructureCollectorHost = "10.10.0.10"

type infrastructureLabFile struct {
	Provider        infrastructureProviderSpec           `yaml:"provider"`
	Lab             infrastructureLabSpec                `yaml:"lab"`
	ManagementPlane infrastructureManagementPlaneSpec    `yaml:"management_plane"`
	Networks        map[string]infrastructureNetworkSpec `yaml:"networks"`
	Nodes           []infrastructureNodeSpec             `yaml:"nodes"`
	Links           []infrastructureLinkSpec             `yaml:"links"`
	StartupSequence []infrastructureStartupStepSpec      `yaml:"startup_sequence"`
	Telemetry       []infrastructureTelemetryMappingSpec `yaml:"telemetry_mapping"`
	FirstSixTests   []infrastructureTestScenarioSpec     `yaml:"first_six_tests"`
}

type infrastructureProviderSpec struct {
	Kind               string `yaml:"kind" json:"kind"`
	Name               string `yaml:"name" json:"name"`
	UIURL              string `yaml:"ui_url" json:"ui_url"`
	APIBaseURL         string `yaml:"api_base_url" json:"api_base_url"`
	APILabPath         string `yaml:"api_lab_path" json:"api_lab_path"`
	UsernameEnv        string `yaml:"username_env" json:"username_env"`
	PasswordEnv        string `yaml:"password_env" json:"password_env"`
	AllowInsecureTLS   bool   `yaml:"allow_insecure_tls" json:"allow_insecure_tls"`
	ProjectPath        string `yaml:"project_path" json:"project_path"`
	LabFile            string `yaml:"lab_file" json:"lab_file"`
	TopologyImportPath string `yaml:"topology_import_path" json:"topology_import_path"`
	Notes              string `yaml:"notes" json:"notes"`
}

type infrastructureLabSpec struct {
	ID          string `yaml:"id" json:"id"`
	Description string `yaml:"description" json:"description"`
}

type infrastructureManagementPlaneSpec struct {
	Master infrastructureNodeSpec `yaml:"rsiem_master" json:"master"`
}

type infrastructureNetworkSpec struct {
	CIDR    string `yaml:"cidr" json:"cidr"`
	Purpose string `yaml:"purpose" json:"purpose"`
}

type infrastructureTelemetryExportSpec struct {
	Type        string `yaml:"type" json:"type"`
	Destination string `yaml:"destination,omitempty" json:"destination,omitempty"`
	Path        string `yaml:"path,omitempty" json:"path,omitempty"`
}

type infrastructureLinkSpec struct {
	ID        string   `yaml:"id" json:"id"`
	Label     string   `yaml:"label,omitempty" json:"label,omitempty"`
	Network   string   `yaml:"network,omitempty" json:"network,omitempty"`
	Endpoints []string `yaml:"endpoints" json:"endpoints"`
}

type infrastructureStartupStepSpec struct {
	Order          int    `yaml:"order" json:"order"`
	DeviceID       string `yaml:"device_id" json:"device_id"`
	EveNodeName    string `yaml:"eve_node_name,omitempty" json:"eve_node_name,omitempty"`
	DeviceType     string `yaml:"device_type,omitempty" json:"device_type,omitempty"`
	Image          string `yaml:"image,omitempty" json:"image,omitempty"`
	BootCommand    string `yaml:"boot_command,omitempty" json:"boot_command,omitempty"`
	ValidationHint string `yaml:"validation_hint,omitempty" json:"validation_hint,omitempty"`
}

type infrastructureNodeSpec struct {
	ID               string                              `yaml:"id,omitempty" json:"id,omitempty"`
	EveNodeName      string                              `yaml:"eve_node_name,omitempty" json:"eve_node_name,omitempty"`
	Hostname         string                              `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	Role             string                              `yaml:"role,omitempty" json:"role,omitempty"`
	OS               string                              `yaml:"os,omitempty" json:"os,omitempty"`
	IP               string                              `yaml:"ip,omitempty" json:"ip,omitempty"`
	MgmtIP           string                              `yaml:"mgmt_ip,omitempty" json:"mgmt_ip,omitempty"`
	DataIPs          []string                            `yaml:"data_ips,omitempty" json:"data_ips,omitempty"`
	AgentSupport     bool                                `yaml:"agent_support,omitempty" json:"agent_support,omitempty"`
	Services         []string                            `yaml:"services,omitempty" json:"services,omitempty"`
	CollectorTargets map[string]string                   `yaml:"collector_endpoints,omitempty" json:"collector_endpoints,omitempty"`
	TelemetryExports []infrastructureTelemetryExportSpec `yaml:"telemetry_exports,omitempty" json:"telemetry_exports,omitempty"`
	Note             string                              `yaml:"note,omitempty" json:"note,omitempty"`
}

type infrastructureTelemetryMappingSpec struct {
	Source           string   `yaml:"source" json:"source"`
	Exporters        []string `yaml:"exporters" json:"exporters"`
	CollectorBinary  string   `yaml:"collector_binary" json:"collector_binary"`
	CollectorConfig  string   `yaml:"collector_config" json:"collector_config"`
	SourceType       string   `yaml:"source_type" json:"source_type"`
	NATSStream       string   `yaml:"nats_stream" json:"nats_stream"`
	NATSSubject      string   `yaml:"nats_subject" json:"nats_subject"`
	ExpectedUseCases []string `yaml:"expected_use_cases" json:"expected_use_cases"`
}

type infrastructureTestScenarioSpec struct {
	ID             string   `yaml:"id" json:"id"`
	Telemetry      []string `yaml:"telemetry" json:"telemetry"`
	InitiatingNode string   `yaml:"initiating_node,omitempty" json:"initiating_node,omitempty"`
	TargetNode     string   `yaml:"target_node,omitempty" json:"target_node,omitempty"`
	TargetSegment  string   `yaml:"target_segment,omitempty" json:"target_segment,omitempty"`
	Objective      string   `yaml:"objective" json:"objective"`
	CommandHint    string   `yaml:"command_hint,omitempty" json:"command_hint,omitempty"`
	ExpectedRuleID string   `yaml:"expected_rule_id,omitempty" json:"expected_rule_id,omitempty"`
	SearchPivot    string   `yaml:"search_pivot,omitempty" json:"search_pivot,omitempty"`
}

type infrastructureTopologySummary struct {
	WindowFromUnixMs       int64 `json:"window_from_unix_ms"`
	WindowToUnixMs         int64 `json:"window_to_unix_ms"`
	NodeCount              int   `json:"node_count"`
	ManagedEndpointCount   int   `json:"managed_endpoint_count"`
	WindowsEndpointCount   int   `json:"windows_endpoint_count"`
	LiveNodeCount          int   `json:"live_node_count"`
	InfrastructureRuns     int   `json:"infrastructure_runs"`
	OpenInfrastructureRuns int   `json:"open_infrastructure_runs"`
	RecentEventCount       int   `json:"recent_event_count"`
	ActiveActionCount      int   `json:"active_action_count"`
	VerifiedBlockCount     int   `json:"verified_block_count"`
}

type infrastructureTopologyNodeLive struct {
	Status             string   `json:"status"`
	StatusReason       string   `json:"status_reason,omitempty"`
	RecentEventCount   int      `json:"recent_event_count"`
	DetectionCount     int      `json:"detection_count"`
	IncidentCount      int      `json:"incident_count"`
	OpenIncidentCount  int      `json:"open_incident_count"`
	ActiveActionCount  int      `json:"active_action_count"`
	VerifiedBlockCount int      `json:"verified_block_count"`
	LastSeenUnixMs     int64    `json:"last_seen_unix_ms,omitempty"`
	SeenSourceTypes    []string `json:"seen_source_types,omitempty"`
	SeenRuleIDs        []string `json:"seen_rule_ids,omitempty"`
	LatestRunID        string   `json:"latest_run_id,omitempty"`
	LatestActionID     string   `json:"latest_action_id,omitempty"`
	EveRuntimeStatus   string   `json:"eve_runtime_status,omitempty"`
	EveConsoleURL      string   `json:"eve_console_url,omitempty"`
	EveLastSyncUnixMs  int64    `json:"eve_last_sync_unix_ms,omitempty"`
}

type infrastructureTopologyNodeView struct {
	ID               string                              `json:"id"`
	Label            string                              `json:"label"`
	EveNodeName      string                              `json:"eve_node_name,omitempty"`
	EveNodeID        string                              `json:"eve_node_id,omitempty"`
	Role             string                              `json:"role"`
	OS               string                              `json:"os,omitempty"`
	IP               string                              `json:"ip,omitempty"`
	MgmtIP           string                              `json:"mgmt_ip,omitempty"`
	DataIPs          []string                            `json:"data_ips,omitempty"`
	Networks         []string                            `json:"networks,omitempty"`
	AgentSupport     bool                                `json:"agent_support,omitempty"`
	Services         []string                            `json:"services,omitempty"`
	TelemetryExports []infrastructureTelemetryExportSpec `json:"telemetry_exports,omitempty"`
	PositionLeft     int                                 `json:"position_left,omitempty"`
	PositionTop      int                                 `json:"position_top,omitempty"`
	Note             string                              `json:"note,omitempty"`
	Live             infrastructureTopologyNodeLive      `json:"live"`
}

type infrastructureTopologyProviderView struct {
	Kind               string `json:"kind"`
	Name               string `json:"name"`
	UIURL              string `json:"ui_url,omitempty"`
	APIBaseURL         string `json:"api_base_url,omitempty"`
	APILabPath         string `json:"api_lab_path,omitempty"`
	ProjectPath        string `json:"project_path,omitempty"`
	LabFile            string `json:"lab_file,omitempty"`
	TopologyImportPath string `json:"topology_import_path,omitempty"`
	SourceStatus       string `json:"source_status"`
	SourceDetail       string `json:"source_detail,omitempty"`
	RuntimeStatus      string `json:"runtime_status,omitempty"`
	RuntimeDetail      string `json:"runtime_detail,omitempty"`
	RuntimeLastSyncMs  int64  `json:"runtime_last_sync_unix_ms,omitempty"`
	Notes              string `json:"notes,omitempty"`
}

type infrastructureTopologyLinkView struct {
	ID             string   `json:"id"`
	Label          string   `json:"label,omitempty"`
	Network        string   `json:"network,omitempty"`
	Endpoints      []string `json:"endpoints"`
	ProviderSource string   `json:"provider_source,omitempty"`
}

type infrastructureTopologyStartupStepView struct {
	Order          int    `json:"order"`
	DeviceID       string `json:"device_id"`
	EveNodeName    string `json:"eve_node_name,omitempty"`
	DeviceType     string `json:"device_type,omitempty"`
	Image          string `json:"image,omitempty"`
	BootCommand    string `json:"boot_command,omitempty"`
	ValidationHint string `json:"validation_hint,omitempty"`
}

type infrastructureTopologyCollectorLive struct {
	RecentEventCount int   `json:"recent_event_count"`
	ActiveExporters  int   `json:"active_exporters"`
	LastSeenUnixMs   int64 `json:"last_seen_unix_ms,omitempty"`
}

type infrastructureTopologyCollectorView struct {
	Source           string                              `json:"source"`
	SourceType       string                              `json:"source_type"`
	CollectorBinary  string                              `json:"collector_binary"`
	CollectorConfig  string                              `json:"collector_config"`
	NATSStream       string                              `json:"nats_stream"`
	NATSSubject      string                              `json:"nats_subject"`
	Exporters        []string                            `json:"exporters"`
	ExpectedUseCases []string                            `json:"expected_use_cases"`
	Live             infrastructureTopologyCollectorLive `json:"live"`
}

type infrastructureTopologyTestLive struct {
	Status            string `json:"status"`
	IncidentCount     int    `json:"incident_count"`
	LastSeenUnixMs    int64  `json:"last_seen_unix_ms,omitempty"`
	LastRunID         string `json:"last_run_id,omitempty"`
	ActiveActionCount int    `json:"active_action_count"`
}

type infrastructureTopologyTestView struct {
	ID             string                         `json:"id"`
	Telemetry      []string                       `json:"telemetry"`
	InitiatingNode string                         `json:"initiating_node,omitempty"`
	TargetNode     string                         `json:"target_node,omitempty"`
	TargetSegment  string                         `json:"target_segment,omitempty"`
	Objective      string                         `json:"objective"`
	CommandHint    string                         `json:"command_hint,omitempty"`
	ExpectedRuleID string                         `json:"expected_rule_id,omitempty"`
	SearchPivot    string                         `json:"search_pivot,omitempty"`
	Live           infrastructureTopologyTestLive `json:"live"`
}

type infrastructureTopologyActivityItem struct {
	Kind       string `json:"kind"`
	TSUnixMs   int64  `json:"ts_unix_ms"`
	Label      string `json:"label"`
	Status     string `json:"status,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	NodeID     string `json:"node_id,omitempty"`
	SourceType string `json:"source_type,omitempty"`
	ActionID   string `json:"action_id,omitempty"`
}

type infrastructureTopologyResponse struct {
	Lab        infrastructureLabSpec                   `json:"lab"`
	Provider   infrastructureTopologyProviderView      `json:"provider"`
	Management infrastructureNodeSpec                  `json:"management"`
	Networks   map[string]infrastructureNetworkSpec    `json:"networks"`
	Summary    infrastructureTopologySummary           `json:"summary"`
	Nodes      []infrastructureTopologyNodeView        `json:"nodes"`
	Links      []infrastructureTopologyLinkView        `json:"links"`
	Startup    []infrastructureTopologyStartupStepView `json:"startup"`
	Collectors []infrastructureTopologyCollectorView   `json:"collectors"`
	Tests      []infrastructureTopologyTestView        `json:"tests"`
	Activity   []infrastructureTopologyActivityItem    `json:"activity"`
	Source     string                                  `json:"source"`
}

func (a *app) handleInfrastructureTopology(w http.ResponseWriter, r *http.Request) {
	fromMs := parseInt64(r.URL.Query().Get("from"), time.Now().Add(-1*time.Hour).UnixMilli())
	toMs := parseInt64(r.URL.Query().Get("to"), time.Now().UnixMilli())
	if fromMs > toMs {
		fromMs, toMs = toMs, fromMs
	}
	resp, err := a.buildInfrastructureTopology(r.Context(), fromMs, toMs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *app) buildInfrastructureTopology(ctx context.Context, fromMs, toMs int64) (infrastructureTopologyResponse, error) {
	spec, specPath, err := loadInfrastructureLabFile(a.cfg.MasterConfig, defaultInfrastructureLabPath)
	if err != nil {
		return infrastructureTopologyResponse{}, err
	}
	eveImport, providerView := loadEveNGTopology(spec, specPath)
	eveRuntime := fetchEveNGRuntime(ctx, spec.Provider)
	providerView.RuntimeStatus = eveRuntime.Status
	providerView.RuntimeDetail = eveRuntime.Detail
	providerView.RuntimeLastSyncMs = eveRuntime.LastSyncMs
	resp := infrastructureTopologyResponse{
		Lab:        spec.Lab,
		Provider:   providerView,
		Management: spec.ManagementPlane.Master,
		Networks:   spec.Networks,
		Source:     "lab+exports",
		Summary: infrastructureTopologySummary{
			WindowFromUnixMs: fromMs,
			WindowToUnixMs:   toMs,
		},
	}

	runs, stepsByRun, _ := a.loadState()
	actions := allActionViews(a.loadActionRecords(), runs, stepsByRun)
	infraRuns := make([]incident, 0, len(runs))
	for _, run := range runs {
		if isInfrastructureIncident(run) {
			infraRuns = append(infraRuns, run)
		}
	}
	events := a.loadInfrastructureTopologyEvents(ctx, fromMs, toMs)
	resp.Source = "lab+exports"
	if a.db != nil {
		resp.Source = "lab+db+exports"
	}

	nodeViews := make([]infrastructureTopologyNodeView, 0, len(spec.Nodes)+1)
	managementView := buildInfrastructureTopologyNodeView(spec.ManagementPlane.Master, spec.Networks, eveImport)
	managementView.Live = mergeEveRuntime(managementView.Live, managementView, eveRuntime)
	managementView.Live = summarizeInfrastructureNodeLive(managementView, infraRuns, events, actions)
	managementView.Live = mergeEveRuntime(managementView.Live, managementView, eveRuntime)
	nodeViews = append(nodeViews, managementView)
	for _, node := range spec.Nodes {
		view := buildInfrastructureTopologyNodeView(node, spec.Networks, eveImport)
		view.Live = summarizeInfrastructureNodeLive(view, infraRuns, events, actions)
		view.Live = mergeEveRuntime(view.Live, view, eveRuntime)
		nodeViews = append(nodeViews, view)
	}
	resp.Nodes = nodeViews
	if len(eveImport.Links) > 0 {
		resp.Links = append(resp.Links, eveImport.Links...)
	} else {
		for _, link := range spec.Links {
			resp.Links = append(resp.Links, infrastructureTopologyLinkView{
				ID:        link.ID,
				Label:     link.Label,
				Network:   link.Network,
				Endpoints: append([]string(nil), link.Endpoints...),
			})
		}
	}
	for _, step := range spec.StartupSequence {
		resp.Startup = append(resp.Startup, infrastructureTopologyStartupStepView{
			Order:          step.Order,
			DeviceID:       step.DeviceID,
			EveNodeName:    step.EveNodeName,
			DeviceType:     step.DeviceType,
			Image:          step.Image,
			BootCommand:    step.BootCommand,
			ValidationHint: step.ValidationHint,
		})
	}
	sort.SliceStable(resp.Startup, func(i, j int) bool { return resp.Startup[i].Order < resp.Startup[j].Order })

	collectorViews := make([]infrastructureTopologyCollectorView, 0, len(spec.Telemetry))
	for _, item := range spec.Telemetry {
		collectorViews = append(collectorViews, infrastructureTopologyCollectorView{
			Source:           item.Source,
			SourceType:       item.SourceType,
			CollectorBinary:  item.CollectorBinary,
			CollectorConfig:  item.CollectorConfig,
			NATSStream:       item.NATSStream,
			NATSSubject:      item.NATSSubject,
			Exporters:        append([]string(nil), item.Exporters...),
			ExpectedUseCases: append([]string(nil), item.ExpectedUseCases...),
			Live:             summarizeCollectorLive(item, nodeViews, events),
		})
	}
	resp.Collectors = collectorViews

	testViews := make([]infrastructureTopologyTestView, 0, len(spec.FirstSixTests))
	for _, item := range spec.FirstSixTests {
		testViews = append(testViews, infrastructureTopologyTestView{
			ID:             item.ID,
			Telemetry:      append([]string(nil), item.Telemetry...),
			InitiatingNode: item.InitiatingNode,
			TargetNode:     item.TargetNode,
			TargetSegment:  item.TargetSegment,
			Objective:      item.Objective,
			CommandHint:    item.CommandHint,
			ExpectedRuleID: item.ExpectedRuleID,
			SearchPivot:    item.SearchPivot,
			Live:           summarizeTestLive(item, infraRuns, actions),
		})
	}
	resp.Tests = testViews
	resp.Activity = summarizeInfrastructureActivity(infraRuns, events, actions)
	resp.Summary = summarizeInfrastructureTopology(nodeViews, infraRuns, events, actions, fromMs, toMs)
	return resp, nil
}

func loadInfrastructureLabFile(masterConfigPath, defaultPath string) (infrastructureLabFile, string, error) {
	path := defaultPath
	baseDir := filepath.Dir(strings.TrimSpace(masterConfigPath))
	candidate := filepath.Join(baseDir, "labs", "emulated_infrastructure_lab.yaml")
	if _, err := os.Stat(candidate); err == nil {
		path = candidate
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return infrastructureLabFile{}, "", err
	}
	var spec infrastructureLabFile
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return infrastructureLabFile{}, "", err
	}
	spec = applyInfrastructureEnvOverrides(spec)
	return spec, path, nil
}

func applyInfrastructureEnvOverrides(spec infrastructureLabFile) infrastructureLabFile {
	if v := strings.TrimSpace(os.Getenv("RSIEM_EVE_NG_UI_URL")); v != "" {
		spec.Provider.UIURL = v
	}
	if v := strings.TrimSpace(os.Getenv("RSIEM_EVE_NG_API_BASE_URL")); v != "" {
		spec.Provider.APIBaseURL = v
	}
	if v := strings.TrimSpace(os.Getenv("RSIEM_EVE_NG_API_LAB_PATH")); v != "" {
		spec.Provider.APILabPath = v
	}
	if v := strings.TrimSpace(os.Getenv("RSIEM_EVE_NG_PROJECT_PATH")); v != "" {
		spec.Provider.ProjectPath = v
	}
	if v := strings.TrimSpace(os.Getenv("RSIEM_EVE_NG_LAB_FILE")); v != "" {
		spec.Provider.LabFile = v
	}
	if v := strings.TrimSpace(os.Getenv("RSIEM_EVE_NG_TOPOLOGY_IMPORT_PATH")); v != "" {
		spec.Provider.TopologyImportPath = v
	}
	if v := strings.TrimSpace(os.Getenv("RSIEM_EVE_NG_ALLOW_INSECURE_TLS")); v != "" {
		spec.Provider.AllowInsecureTLS = strings.EqualFold(v, "1") || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}
	if v := strings.TrimSpace(os.Getenv("RSIEM_INFRA_HOST_COLLECTOR_IP")); v != "" {
		spec = applyInfrastructureCollectorHostOverride(spec, v)
	}
	return spec
}

func applyInfrastructureCollectorHostOverride(spec infrastructureLabFile, host string) infrastructureLabFile {
	host = strings.TrimSpace(host)
	if host == "" {
		return spec
	}
	spec.ManagementPlane.Master.IP = replaceLiteralHost(spec.ManagementPlane.Master.IP, defaultInfrastructureCollectorHost, host)
	spec.ManagementPlane.Master.MgmtIP = replaceLiteralHost(spec.ManagementPlane.Master.MgmtIP, defaultInfrastructureCollectorHost, host)
	for i, ip := range spec.ManagementPlane.Master.DataIPs {
		spec.ManagementPlane.Master.DataIPs[i] = replaceLiteralHost(ip, defaultInfrastructureCollectorHost, host)
	}
	for key, value := range spec.ManagementPlane.Master.CollectorTargets {
		spec.ManagementPlane.Master.CollectorTargets[key] = rewriteCollectorDestination(value, host)
	}
	for i := range spec.Nodes {
		spec.Nodes[i].IP = replaceLiteralHost(spec.Nodes[i].IP, defaultInfrastructureCollectorHost, host)
		spec.Nodes[i].MgmtIP = replaceLiteralHost(spec.Nodes[i].MgmtIP, defaultInfrastructureCollectorHost, host)
		for j, ip := range spec.Nodes[i].DataIPs {
			spec.Nodes[i].DataIPs[j] = replaceLiteralHost(ip, defaultInfrastructureCollectorHost, host)
		}
		for key, value := range spec.Nodes[i].CollectorTargets {
			spec.Nodes[i].CollectorTargets[key] = rewriteCollectorDestination(value, host)
		}
		for j, export := range spec.Nodes[i].TelemetryExports {
			spec.Nodes[i].TelemetryExports[j].Destination = rewriteCollectorDestination(export.Destination, host)
		}
	}
	for i := range spec.StartupSequence {
		spec.StartupSequence[i].BootCommand = replaceLiteralHost(spec.StartupSequence[i].BootCommand, defaultInfrastructureCollectorHost, host)
		spec.StartupSequence[i].ValidationHint = replaceLiteralHost(spec.StartupSequence[i].ValidationHint, defaultInfrastructureCollectorHost, host)
	}
	return spec
}

func rewriteCollectorDestination(destination, host string) string {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return destination
	}
	parsedHost, parsedPort, err := net.SplitHostPort(destination)
	if err == nil {
		if strings.TrimSpace(parsedHost) == defaultInfrastructureCollectorHost {
			return net.JoinHostPort(host, parsedPort)
		}
		return destination
	}
	return replaceLiteralHost(destination, defaultInfrastructureCollectorHost, host)
}

func replaceLiteralHost(value, oldHost, newHost string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	if strings.Contains(value, oldHost) {
		return strings.ReplaceAll(value, oldHost, newHost)
	}
	return value
}

func buildInfrastructureTopologyNodeView(spec infrastructureNodeSpec, networks map[string]infrastructureNetworkSpec, eveImport eveNGTopologyImport) infrastructureTopologyNodeView {
	label := strings.TrimSpace(spec.ID)
	if label == "" {
		label = strings.TrimSpace(spec.Hostname)
	}
	eveNode := eveImport.findNode(firstNonEmpty(strings.TrimSpace(spec.EveNodeName), strings.TrimSpace(spec.ID), strings.TrimSpace(spec.Hostname)))
	view := infrastructureTopologyNodeView{
		ID:               firstNonEmpty(strings.TrimSpace(spec.ID), strings.TrimSpace(spec.Hostname)),
		Label:            label,
		EveNodeName:      firstNonEmpty(strings.TrimSpace(spec.EveNodeName), eveNode.Name),
		EveNodeID:        eveNode.ID,
		Role:             strings.TrimSpace(spec.Role),
		OS:               strings.TrimSpace(spec.OS),
		IP:               stripCIDRSuffix(spec.IP),
		MgmtIP:           stripCIDRSuffix(spec.MgmtIP),
		DataIPs:          normalizeIPs(spec.DataIPs),
		Networks:         infrastructureNodeNetworks(spec, networks),
		AgentSupport:     spec.AgentSupport,
		Services:         append([]string(nil), spec.Services...),
		TelemetryExports: append([]infrastructureTelemetryExportSpec(nil), spec.TelemetryExports...),
		PositionLeft:     eveNode.Left,
		PositionTop:      eveNode.Top,
		Note:             strings.TrimSpace(spec.Note),
		Live:             infrastructureTopologyNodeLive{Status: "quiet", StatusReason: "No recent telemetry in selected window."},
	}
	if view.Label == "" {
		view.Label = view.ID
	}
	return view
}

type eveNGLabXML struct {
	XMLName  xml.Name         `xml:"lab"`
	Name     string           `xml:"name,attr"`
	Version  string           `xml:"version,attr"`
	Topology eveNGTopologyXML `xml:"topology"`
}

type eveNGTopologyXML struct {
	Nodes    []eveNGNodeXML    `xml:"nodes>node"`
	Networks []eveNGNetworkXML `xml:"networks>network"`
}

type eveNGNodeXML struct {
	ID         string              `xml:"id,attr"`
	Name       string              `xml:"name,attr"`
	Type       string              `xml:"type,attr"`
	Image      string              `xml:"image,attr"`
	Template   string              `xml:"template,attr"`
	Left       int                 `xml:"left,attr"`
	Top        int                 `xml:"top,attr"`
	Interfaces []eveNGInterfaceXML `xml:"interface"`
}

type eveNGInterfaceXML struct {
	ID        string `xml:"id,attr"`
	Name      string `xml:"name,attr"`
	NetworkID string `xml:"network_id,attr"`
}

type eveNGNetworkXML struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name,attr"`
}

type eveNGImportedNode struct {
	ID    string
	Name  string
	Type  string
	Image string
	Left  int
	Top   int
}

type eveNGTopologyImport struct {
	Nodes  map[string]eveNGImportedNode
	Links  []infrastructureTopologyLinkView
	Status string
	Detail string
}

type eveNGNodeRuntime struct {
	ID        string
	Name      string
	Status    string
	StatusRaw int
	URL       string
	Left      int
	Top       int
	Image     string
}

type eveNGRuntimeView struct {
	Status     string
	Detail     string
	LastSyncMs int64
	Nodes      map[string]eveNGNodeRuntime
}

type eveNGActionResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type eveNGNodeControlResult struct {
	NodeID        string `json:"node_id"`
	NodeName      string `json:"node_name,omitempty"`
	Action        string `json:"action"`
	RuntimeStatus string `json:"runtime_status,omitempty"`
	ConsoleURL    string `json:"console_url,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

func (e eveNGTopologyImport) findNode(name string) eveNGImportedNode {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return eveNGImportedNode{}
	}
	if node, ok := e.Nodes[key]; ok {
		return node
	}
	return eveNGImportedNode{}
}

func loadEveNGTopology(spec infrastructureLabFile, specPath string) (eveNGTopologyImport, infrastructureTopologyProviderView) {
	provider := infrastructureTopologyProviderView{
		Kind:               strings.TrimSpace(spec.Provider.Kind),
		Name:               strings.TrimSpace(spec.Provider.Name),
		UIURL:              strings.TrimSpace(spec.Provider.UIURL),
		APIBaseURL:         strings.TrimSpace(spec.Provider.APIBaseURL),
		APILabPath:         strings.TrimSpace(spec.Provider.APILabPath),
		ProjectPath:        strings.TrimSpace(spec.Provider.ProjectPath),
		LabFile:            strings.TrimSpace(spec.Provider.LabFile),
		TopologyImportPath: strings.TrimSpace(spec.Provider.TopologyImportPath),
		SourceStatus:       "not_configured",
		Notes:              strings.TrimSpace(spec.Provider.Notes),
	}
	if provider.Kind == "" {
		return eveNGTopologyImport{}, provider
	}
	provider.SourceStatus = "configured"
	if !strings.EqualFold(provider.Kind, "eve_ng") {
		provider.SourceDetail = "provider configured but not EVE-NG"
		return eveNGTopologyImport{}, provider
	}
	importPath := strings.TrimSpace(spec.Provider.TopologyImportPath)
	if importPath == "" {
		provider.SourceDetail = "topology import path not set"
		return eveNGTopologyImport{}, provider
	}
	if !filepath.IsAbs(importPath) {
		importPath = filepath.Join(filepath.Dir(specPath), importPath)
	}
	data, err := os.ReadFile(importPath)
	if err != nil {
		provider.SourceStatus = "configured"
		provider.SourceDetail = err.Error()
		return eveNGTopologyImport{}, provider
	}
	var lab eveNGLabXML
	if err := xml.Unmarshal(data, &lab); err != nil {
		provider.SourceStatus = "parse_error"
		provider.SourceDetail = err.Error()
		return eveNGTopologyImport{}, provider
	}
	netNames := make(map[string]string, len(lab.Topology.Networks))
	for _, network := range lab.Topology.Networks {
		netNames[strings.TrimSpace(network.ID)] = strings.TrimSpace(network.Name)
	}
	imported := eveNGTopologyImport{
		Nodes:  make(map[string]eveNGImportedNode, len(lab.Topology.Nodes)),
		Status: "imported",
		Detail: firstNonEmpty(strings.TrimSpace(lab.Name), strings.TrimSpace(spec.Provider.Name)),
	}
	for _, node := range lab.Topology.Nodes {
		imported.Nodes[strings.ToLower(strings.TrimSpace(node.Name))] = eveNGImportedNode{
			ID:    strings.TrimSpace(node.ID),
			Name:  strings.TrimSpace(node.Name),
			Type:  firstNonEmpty(strings.TrimSpace(node.Type), strings.TrimSpace(node.Template)),
			Image: strings.TrimSpace(node.Image),
			Left:  node.Left,
			Top:   node.Top,
		}
	}
	for _, network := range lab.Topology.Networks {
		endpoints := make([]string, 0, 4)
		for _, node := range lab.Topology.Nodes {
			for _, iface := range node.Interfaces {
				if strings.TrimSpace(iface.NetworkID) == strings.TrimSpace(network.ID) {
					endpoints = append(endpoints, strings.TrimSpace(node.Name))
					break
				}
			}
		}
		if len(endpoints) < 2 {
			continue
		}
		imported.Links = append(imported.Links, infrastructureTopologyLinkView{
			ID:             firstNonEmpty(strings.TrimSpace(network.ID), strings.TrimSpace(network.Name)),
			Label:          strings.TrimSpace(network.Name),
			Network:        firstNonEmpty(strings.TrimSpace(network.Name), netNames[strings.TrimSpace(network.ID)]),
			Endpoints:      endpoints,
			ProviderSource: "eve_ng_unl",
		})
	}
	sort.SliceStable(imported.Links, func(i, j int) bool { return imported.Links[i].ID < imported.Links[j].ID })
	provider.SourceStatus = "imported"
	provider.SourceDetail = importPath
	return imported, provider
}

func mergeEveRuntime(live infrastructureTopologyNodeLive, node infrastructureTopologyNodeView, runtime eveNGRuntimeView) infrastructureTopologyNodeLive {
	if len(runtime.Nodes) == 0 {
		return live
	}
	matchKeys := []string{
		strings.ToLower(strings.TrimSpace(node.EveNodeName)),
		strings.ToLower(strings.TrimSpace(node.Label)),
		strings.ToLower(strings.TrimSpace(node.ID)),
	}
	for _, key := range matchKeys {
		if key == "" {
			continue
		}
		if item, ok := runtime.Nodes[key]; ok {
			live.EveRuntimeStatus = item.Status
			live.EveConsoleURL = item.URL
			live.EveLastSyncUnixMs = runtime.LastSyncMs
			if live.Status == "quiet" && item.Status == "running" {
				live.Status = "telemetry_live"
				live.StatusReason = "Node is running in EVE-NG even if no recent telemetry is visible in the selected window."
			}
			return live
		}
	}
	if runtime.LastSyncMs > 0 {
		live.EveRuntimeStatus = "not_found"
		live.EveLastSyncUnixMs = runtime.LastSyncMs
	}
	return live
}

type eveAuthResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type eveNodesResponse struct {
	Status  string                         `json:"status"`
	Message string                         `json:"message"`
	Code    int                            `json:"code"`
	Data    map[string]eveNodeStatusRecord `json:"data"`
}

type eveNodeStatusRecord struct {
	ID     any    `json:"id"`
	Name   string `json:"name"`
	Status any    `json:"status"`
	URL    string `json:"url"`
	Left   any    `json:"left"`
	Top    any    `json:"top"`
	Image  string `json:"image"`
}

func fetchEveNGRuntime(ctx context.Context, provider infrastructureProviderSpec) eveNGRuntimeView {
	if !strings.EqualFold(strings.TrimSpace(provider.Kind), "eve_ng") {
		return eveNGRuntimeView{Status: "disabled", Detail: "provider is not eve_ng"}
	}
	baseURL := strings.TrimSpace(provider.APIBaseURL)
	labPath := strings.TrimSpace(provider.APILabPath)
	userEnv := strings.TrimSpace(provider.UsernameEnv)
	passEnv := strings.TrimSpace(provider.PasswordEnv)
	if baseURL == "" || labPath == "" || userEnv == "" || passEnv == "" {
		return eveNGRuntimeView{Status: "not_configured", Detail: "api_base_url, api_lab_path, username_env, or password_env missing"}
	}
	username := strings.TrimSpace(os.Getenv(userEnv))
	password := strings.TrimSpace(os.Getenv(passEnv))
	if username == "" || password == "" {
		return eveNGRuntimeView{Status: "credentials_missing", Detail: fmt.Sprintf("set %s and %s", userEnv, passEnv)}
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return eveNGRuntimeView{Status: "client_error", Detail: err.Error()}
	}
	client := &http.Client{
		Timeout: 8 * time.Second,
		Jar:     jar,
	}
	if strings.HasPrefix(strings.ToLower(baseURL), "https://") && provider.AllowInsecureTLS {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	return fetchEveNGRuntimeWithClient(ctx, provider, username, password, client)
}

func newEveNGClient(provider infrastructureProviderSpec) (*http.Client, string, string, string, error) {
	if !strings.EqualFold(strings.TrimSpace(provider.Kind), "eve_ng") {
		return nil, "", "", "", fmt.Errorf("provider is not eve_ng")
	}
	baseURL := strings.TrimSpace(provider.APIBaseURL)
	labPath := strings.TrimSpace(provider.APILabPath)
	userEnv := strings.TrimSpace(provider.UsernameEnv)
	passEnv := strings.TrimSpace(provider.PasswordEnv)
	if baseURL == "" || labPath == "" || userEnv == "" || passEnv == "" {
		return nil, "", "", "", fmt.Errorf("api_base_url, api_lab_path, username_env, or password_env missing")
	}
	username := strings.TrimSpace(os.Getenv(userEnv))
	password := strings.TrimSpace(os.Getenv(passEnv))
	if username == "" || password == "" {
		return nil, "", "", "", fmt.Errorf("set %s and %s", userEnv, passEnv)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, "", "", "", err
	}
	client := &http.Client{
		Timeout: 8 * time.Second,
		Jar:     jar,
	}
	if strings.HasPrefix(strings.ToLower(baseURL), "https://") && provider.AllowInsecureTLS {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	return client, username, password, baseURL, nil
}

func fetchEveNGRuntimeWithClient(ctx context.Context, provider infrastructureProviderSpec, username, password string, client *http.Client) eveNGRuntimeView {
	baseURL := strings.TrimSpace(provider.APIBaseURL)
	labPath := strings.TrimSpace(provider.APILabPath)
	if err := eveNGLogin(ctx, client, baseURL, username, password); err != nil {
		return eveNGRuntimeView{Status: "auth_failed", Detail: err.Error()}
	}
	nodesURL := strings.TrimRight(baseURL, "/") + "/api/labs/" + eveEncodeLabPath(labPath) + "/nodes"
	nodesReq, err := http.NewRequestWithContext(ctx, http.MethodGet, nodesURL, nil)
	if err != nil {
		return eveNGRuntimeView{Status: "request_error", Detail: err.Error()}
	}
	nodesReq.Header.Set("Content-Type", "application/json")
	nodesResp, err := client.Do(nodesReq)
	if err != nil {
		return eveNGRuntimeView{Status: "connect_error", Detail: err.Error()}
	}
	defer nodesResp.Body.Close()
	nodesBytes, _ := io.ReadAll(io.LimitReader(nodesResp.Body, 4<<20))
	var parsed eveNodesResponse
	if err := json.Unmarshal(nodesBytes, &parsed); err != nil {
		return eveNGRuntimeView{Status: "parse_error", Detail: err.Error()}
	}
	if nodesResp.StatusCode != http.StatusOK || !strings.EqualFold(parsed.Status, "success") {
		return eveNGRuntimeView{Status: "query_failed", Detail: firstNonEmpty(strings.TrimSpace(parsed.Message), nodesResp.Status)}
	}
	view := eveNGRuntimeView{
		Status:     "connected",
		Detail:     fmt.Sprintf("%d nodes", len(parsed.Data)),
		LastSyncMs: time.Now().UnixMilli(),
		Nodes:      make(map[string]eveNGNodeRuntime, len(parsed.Data)),
	}
	for _, node := range parsed.Data {
		name := strings.TrimSpace(node.Name)
		if name == "" {
			continue
		}
		view.Nodes[strings.ToLower(name)] = eveNGNodeRuntime{
			ID:        stringifyAny(node.ID),
			Name:      name,
			StatusRaw: intifyAny(node.Status),
			Status:    eveNodeStatusLabel(intifyAny(node.Status)),
			URL:       strings.TrimSpace(node.URL),
			Left:      intifyAny(node.Left),
			Top:       intifyAny(node.Top),
			Image:     strings.TrimSpace(node.Image),
		}
	}
	return view
}

func eveNGLogin(ctx context.Context, client *http.Client, baseURL, username, password string) error {
	loginBody := strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, username, password))
	loginReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/auth/login", loginBody)
	if err != nil {
		return err
	}
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp, err := client.Do(loginReq)
	if err != nil {
		return err
	}
	defer loginResp.Body.Close()
	loginBytes, _ := io.ReadAll(io.LimitReader(loginResp.Body, 1<<20))
	var login eveAuthResponse
	_ = json.Unmarshal(loginBytes, &login)
	if loginResp.StatusCode != http.StatusOK || !strings.EqualFold(login.Status, "success") {
		return fmt.Errorf("%s", firstNonEmpty(strings.TrimSpace(login.Message), strings.TrimSpace(string(loginBytes))))
	}
	return nil
}

func eveNGNodeAction(ctx context.Context, provider infrastructureProviderSpec, nodeID, action string) (eveNGNodeControlResult, error) {
	client, username, password, baseURL, err := newEveNGClient(provider)
	if err != nil {
		return eveNGNodeControlResult{}, err
	}
	return eveNGNodeActionWithClient(ctx, provider, username, password, client, baseURL, nodeID, action)
}

func eveNGNodeActionWithClient(ctx context.Context, provider infrastructureProviderSpec, username, password string, client *http.Client, baseURL, nodeID, action string) (eveNGNodeControlResult, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "start", "stop", "wipe":
	default:
		return eveNGNodeControlResult{}, fmt.Errorf("unsupported action %q", action)
	}
	if err := eveNGLogin(ctx, client, baseURL, username, password); err != nil {
		return eveNGNodeControlResult{}, err
	}
	actionURL := strings.TrimRight(baseURL, "/") + "/api/labs/" + eveEncodeLabPath(strings.TrimSpace(provider.APILabPath)) + "/nodes/" + neturl.PathEscape(strings.TrimSpace(nodeID)) + "/" + action
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, actionURL, nil)
	if err != nil {
		return eveNGNodeControlResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return eveNGNodeControlResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var parsed eveNGActionResponse
	_ = json.Unmarshal(body, &parsed)
	if resp.StatusCode != http.StatusOK || !strings.EqualFold(parsed.Status, "success") {
		return eveNGNodeControlResult{}, fmt.Errorf("%s", firstNonEmpty(strings.TrimSpace(parsed.Message), resp.Status, strings.TrimSpace(string(body))))
	}
	runtime := fetchEveNGRuntimeWithClient(ctx, provider, username, password, client)
	result := eveNGNodeControlResult{
		NodeID: strings.TrimSpace(nodeID),
		Action: action,
		Detail: firstNonEmpty(strings.TrimSpace(parsed.Message), "ok"),
	}
	for _, item := range runtime.Nodes {
		if item.ID == strings.TrimSpace(nodeID) {
			result.NodeName = item.Name
			result.RuntimeStatus = item.Status
			result.ConsoleURL = item.URL
			break
		}
	}
	return result, nil
}

func eveEncodeLabPath(path string) string {
	path = strings.TrimSpace(path)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, part := range parts {
		parts[i] = neturl.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func eveNodeStatusLabel(v int) string {
	switch v {
	case 2:
		return "running"
	case 1:
		return "building"
	default:
		return "stopped"
	}
}

func stringifyAny(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func intifyAny(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
	}
}

func (a *app) handleInfrastructureEveNodeAction(w http.ResponseWriter, r *http.Request) {
	spec, specPath, err := loadInfrastructureLabFile(a.cfg.MasterConfig, defaultInfrastructureLabPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	eveImport, providerView := loadEveNGTopology(spec, specPath)
	if !strings.EqualFold(strings.TrimSpace(spec.Provider.Kind), "eve_ng") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "eve_ng provider not configured"})
		return
	}
	nodeKey := strings.TrimSpace(r.PathValue("node_id"))
	action := strings.TrimSpace(r.PathValue("action"))
	if nodeKey == "" || action == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "node_id and action are required"})
		return
	}
	node := eveImport.findNode(nodeKey)
	if node.ID == "" {
		for _, candidate := range spec.Nodes {
			if strings.EqualFold(strings.TrimSpace(candidate.ID), nodeKey) || strings.EqualFold(strings.TrimSpace(candidate.Hostname), nodeKey) || strings.EqualFold(strings.TrimSpace(candidate.EveNodeName), nodeKey) {
				node = eveImport.findNode(firstNonEmpty(candidate.EveNodeName, candidate.ID, candidate.Hostname))
				break
			}
		}
	}
	if node.ID == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "topology node has no imported EVE node mapping"})
		return
	}
	result, err := eveNGNodeAction(r.Context(), spec.Provider, node.ID, action)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":    err.Error(),
			"provider": providerView,
			"node_id":  node.ID,
			"action":   action,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"node_key": nodeKey,
		"provider": providerView,
		"result":   result,
	})
}

func summarizeInfrastructureNodeLive(node infrastructureTopologyNodeView, runs []incident, events []eventRow, actions []responseActionView) infrastructureTopologyNodeLive {
	live := infrastructureTopologyNodeLive{Status: "quiet", StatusReason: "No recent telemetry in selected window."}
	sourceSet := map[string]struct{}{}
	ruleSet := map[string]struct{}{}
	for _, ev := range events {
		if !matchesInfrastructureNodeEvent(node, ev) {
			continue
		}
		live.RecentEventCount++
		if ev.RuleID != "" {
			live.DetectionCount++
			ruleSet[ev.RuleID] = struct{}{}
		}
		if ev.SourceType != "" {
			sourceSet[ev.SourceType] = struct{}{}
		}
		if ev.RecvTSUnixMs > live.LastSeenUnixMs {
			live.LastSeenUnixMs = ev.RecvTSUnixMs
		}
	}
	for _, run := range runs {
		if !matchesInfrastructureNodeRun(node, run) {
			continue
		}
		live.IncidentCount++
		if !isRunTerminal(run.Status) {
			live.OpenIncidentCount++
		}
		if run.RuleID != "" {
			ruleSet[run.RuleID] = struct{}{}
		}
		if run.LastUpdatedAtUnixMs > live.LastSeenUnixMs {
			live.LastSeenUnixMs = run.LastUpdatedAtUnixMs
			live.LatestRunID = run.RunID
		}
		if strings.EqualFold(strings.TrimSpace(run.RuleID), "R-INFRA-POST-CONTAINMENT-BLOCK-VERIFY") {
			live.VerifiedBlockCount++
		}
	}
	for _, action := range actions {
		if !matchesInfrastructureNodeAction(node, action) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(action.Bucket), "active") {
			live.ActiveActionCount++
		}
		if action.ActionID != "" && (action.StartedAtUnixMs > live.LastSeenUnixMs || action.ClearedAtUnixMs > live.LastSeenUnixMs) {
			live.LatestActionID = action.ActionID
		}
	}
	live.SeenSourceTypes = sortedKeys(sourceSet)
	live.SeenRuleIDs = sortedKeys(ruleSet)
	switch {
	case live.ActiveActionCount > 0:
		live.Status = "containment_active"
		live.StatusReason = "Bounded control-point response is active for this node or enforcement point."
	case live.OpenIncidentCount > 0:
		live.Status = "alerting"
		live.StatusReason = "Open incidents currently reference this node, its IPs, or its control role."
	case live.RecentEventCount > 0:
		live.Status = "telemetry_live"
		live.StatusReason = "Recent telemetry seen for this node or its adjacent control path."
	}
	return live
}

func summarizeCollectorLive(spec infrastructureTelemetryMappingSpec, nodes []infrastructureTopologyNodeView, events []eventRow) infrastructureTopologyCollectorLive {
	live := infrastructureTopologyCollectorLive{}
	activeExporters := map[string]struct{}{}
	for _, ev := range events {
		if !strings.EqualFold(strings.TrimSpace(ev.SourceType), strings.TrimSpace(spec.SourceType)) {
			continue
		}
		live.RecentEventCount++
		if ev.RecvTSUnixMs > live.LastSeenUnixMs {
			live.LastSeenUnixMs = ev.RecvTSUnixMs
		}
		for _, node := range nodes {
			if node.Role == "management" {
				continue
			}
			if !sliceContains(spec.Exporters, node.ID) {
				continue
			}
			if matchesInfrastructureNodeEvent(node, ev) {
				activeExporters[node.ID] = struct{}{}
			}
		}
	}
	live.ActiveExporters = len(activeExporters)
	if live.ActiveExporters == 0 && live.RecentEventCount > 0 {
		live.ActiveExporters = len(spec.Exporters)
	}
	return live
}

func summarizeTestLive(spec infrastructureTestScenarioSpec, runs []incident, actions []responseActionView) infrastructureTopologyTestLive {
	live := infrastructureTopologyTestLive{Status: "ready"}
	for _, run := range runs {
		if spec.ExpectedRuleID != "" && !strings.EqualFold(strings.TrimSpace(run.RuleID), strings.TrimSpace(spec.ExpectedRuleID)) {
			continue
		}
		live.IncidentCount++
		if run.LastUpdatedAtUnixMs > live.LastSeenUnixMs {
			live.LastSeenUnixMs = run.LastUpdatedAtUnixMs
			live.LastRunID = run.RunID
		}
	}
	for _, action := range actions {
		if spec.ExpectedRuleID == "R-INFRA-POST-CONTAINMENT-BLOCK-VERIFY" && action.ActionID != "" && strings.EqualFold(action.Bucket, "active") {
			live.ActiveActionCount++
		}
		if spec.ExpectedRuleID == "R-INFRA-EAST-WEST-FLOW-SCAN" || spec.ExpectedRuleID == "R-INFRA-NETWORK-ADMIN-LOGIN" {
			if strings.EqualFold(action.Bucket, "active") && strings.Contains(strings.ToLower(strings.TrimSpace(action.Reason)), "infra_") {
				live.ActiveActionCount++
			}
		}
	}
	if live.IncidentCount > 0 {
		live.Status = "observed"
	}
	if live.ActiveActionCount > 0 {
		live.Status = "responding"
	}
	if spec.ExpectedRuleID == "R-INFRA-POST-CONTAINMENT-BLOCK-VERIFY" && live.IncidentCount > 0 {
		live.Status = "verified"
	}
	return live
}

func summarizeInfrastructureActivity(runs []incident, events []eventRow, actions []responseActionView) []infrastructureTopologyActivityItem {
	items := make([]infrastructureTopologyActivityItem, 0, 24)
	for _, run := range runs {
		items = append(items, infrastructureTopologyActivityItem{
			Kind:       "incident",
			TSUnixMs:   run.LastUpdatedAtUnixMs,
			Label:      firstNonEmpty(run.PlaybookID, run.RuleID, run.RunID),
			Status:     run.Status,
			RuleID:     run.RuleID,
			RunID:      run.RunID,
			NodeID:     run.NodeID,
			SourceType: run.SourceType,
		})
	}
	for _, action := range actions {
		if action.StartedAtUnixMs == 0 && action.ClearedAtUnixMs == 0 && action.ExpiresAtUnixMs == 0 {
			continue
		}
		ts := action.StartedAtUnixMs
		if ts == 0 {
			ts = action.ClearedAtUnixMs
		}
		if ts == 0 {
			ts = action.ExpiresAtUnixMs
		}
		if !strings.Contains(strings.ToLower(strings.TrimSpace(action.Reason)), "infra_") && strings.TrimSpace(action.RunID) == "" {
			continue
		}
		items = append(items, infrastructureTopologyActivityItem{
			Kind:     "action",
			TSUnixMs: ts,
			Label:    firstNonEmpty(action.Label, action.ActionName, action.ActionID),
			Status:   action.Bucket,
			RunID:    action.RunID,
			NodeID:   firstNonEmpty(action.TargetAgentID, action.NodeID),
			ActionID: action.ActionID,
		})
	}
	for _, ev := range events {
		if !isInfrastructureEvent(ev) {
			continue
		}
		items = append(items, infrastructureTopologyActivityItem{
			Kind:       "event",
			TSUnixMs:   ev.RecvTSUnixMs,
			Label:      firstNonEmpty(ev.RuleID, ev.EventType, ev.SourceType),
			RuleID:     ev.RuleID,
			NodeID:     ev.NodeID,
			SourceType: ev.SourceType,
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].TSUnixMs == items[j].TSUnixMs {
			return items[i].Label < items[j].Label
		}
		return items[i].TSUnixMs > items[j].TSUnixMs
	})
	if len(items) > 24 {
		items = items[:24]
	}
	return items
}

func summarizeInfrastructureTopology(nodes []infrastructureTopologyNodeView, runs []incident, events []eventRow, actions []responseActionView, fromMs, toMs int64) infrastructureTopologySummary {
	summary := infrastructureTopologySummary{WindowFromUnixMs: fromMs, WindowToUnixMs: toMs}
	summary.NodeCount = len(nodes)
	for _, node := range nodes {
		if node.AgentSupport {
			summary.ManagedEndpointCount++
		}
		if strings.EqualFold(strings.TrimSpace(node.OS), "windows") {
			summary.WindowsEndpointCount++
		}
		if node.Live.RecentEventCount > 0 || node.Live.OpenIncidentCount > 0 || node.Live.ActiveActionCount > 0 {
			summary.LiveNodeCount++
		}
		summary.ActiveActionCount += node.Live.ActiveActionCount
		summary.VerifiedBlockCount += node.Live.VerifiedBlockCount
	}
	for _, run := range runs {
		summary.InfrastructureRuns++
		if !isRunTerminal(run.Status) {
			summary.OpenInfrastructureRuns++
		}
		if strings.EqualFold(strings.TrimSpace(run.RuleID), "R-INFRA-POST-CONTAINMENT-BLOCK-VERIFY") {
			summary.VerifiedBlockCount++
		}
	}
	summary.RecentEventCount = len(events)
	// active action count from nodes may double-count shared views; normalize here.
	active := 0
	for _, action := range actions {
		if strings.EqualFold(strings.TrimSpace(action.Bucket), "active") && (strings.Contains(strings.ToLower(strings.TrimSpace(action.Reason)), "infra_") || strings.TrimSpace(action.RunID) != "") {
			active++
		}
	}
	summary.ActiveActionCount = active
	return summary
}

func (a *app) loadInfrastructureTopologyEvents(ctx context.Context, fromMs, toMs int64) []eventRow {
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
  AND (
    COALESCE(rule_id,'') LIKE 'R-INFRA-%'
    OR COALESCE(source_type,'') IN ('syslog','netflow_v5','snmp_trap','auditd_exec','auditd_connect','proc_net','dns','inotify')
  )
ORDER BY recv_ts_unix_ms DESC
LIMIT 800
`, fromMs, toMs)
	if err != nil {
		return nil
	}
	defer rows.Close()
	items := make([]eventRow, 0, 256)
	for rows.Next() {
		var ev eventRow
		if err := rows.Scan(
			&ev.EventTSUnixMs, &ev.RecvTSUnixMs, &ev.NodeID, &ev.SourceType, &ev.EventType,
			&ev.SrcIP, &ev.DstIP, &ev.DstPort, &ev.ProtocolFamily,
			&ev.UserName, &ev.Severity, &ev.RuleID,
			&ev.ExecPath, &ev.Comm, &ev.Cmdline, &ev.DNSName,
			&ev.FileSHA256, &ev.ExecSHA256, &ev.EventIdemKey, &ev.RawLineSHA256,
		); err == nil {
			if isInfrastructureEvent(ev) {
				ev.Category = "infrastructure"
			}
			items = append(items, ev)
		}
	}
	return items
}

func matchesInfrastructureNodeRun(node infrastructureTopologyNodeView, run incident) bool {
	if strings.TrimSpace(node.ID) == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(run.NodeID), node.ID) || strings.EqualFold(strings.TrimSpace(run.TargetAgentID), node.ID) {
		return true
	}
	ips := infrastructureNodeIPsView(node)
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		if sameIP(run.SrcIP, ip) || sameIP(run.DstIP, ip) || sameIP(run.Target, ip) {
			return true
		}
	}
	return false
}

func matchesInfrastructureNodeEvent(node infrastructureTopologyNodeView, ev eventRow) bool {
	if strings.TrimSpace(node.ID) != "" && strings.EqualFold(strings.TrimSpace(ev.NodeID), node.ID) {
		return true
	}
	for _, ip := range infrastructureNodeIPsView(node) {
		if sameIP(ev.SrcIP, ip) || sameIP(ev.DstIP, ip) {
			return true
		}
	}
	return false
}

func matchesInfrastructureNodeAction(node infrastructureTopologyNodeView, action responseActionView) bool {
	if strings.TrimSpace(node.ID) == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(action.NodeID), node.ID) || strings.EqualFold(strings.TrimSpace(action.TargetAgentID), node.ID) {
		return true
	}
	for _, ip := range infrastructureNodeIPsView(node) {
		if sameIP(action.Target, ip) {
			return true
		}
	}
	return false
}

func infrastructureNodeNetworks(spec infrastructureNodeSpec, networks map[string]infrastructureNetworkSpec) []string {
	seen := map[string]struct{}{}
	for _, ip := range append([]string{spec.IP, spec.MgmtIP}, spec.DataIPs...) {
		parsed := net.ParseIP(stripCIDRSuffix(ip))
		if parsed == nil {
			continue
		}
		for name, network := range networks {
			_, block, err := net.ParseCIDR(strings.TrimSpace(network.CIDR))
			if err != nil || block == nil {
				continue
			}
			if block.Contains(parsed) {
				seen[name] = struct{}{}
			}
		}
	}
	return sortedKeys(seen)
}

func infrastructureNodeIPsView(node infrastructureTopologyNodeView) []string {
	out := make([]string, 0, 2+len(node.DataIPs))
	if node.IP != "" {
		out = append(out, stripCIDRSuffix(node.IP))
	}
	if node.MgmtIP != "" {
		out = append(out, stripCIDRSuffix(node.MgmtIP))
	}
	out = append(out, normalizeIPs(node.DataIPs)...)
	return out
}

func normalizeIPs(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = stripCIDRSuffix(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func stripCIDRSuffix(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	base, _, _ := strings.Cut(value, "/")
	return strings.TrimSpace(base)
}

func sameIP(left, right string) bool {
	left = stripCIDRSuffix(left)
	right = stripCIDRSuffix(right)
	return left != "" && right != "" && left == right
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		if strings.TrimSpace(key) != "" {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func sliceContains(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func isRunTerminal(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "SUCCEEDED", "FAILED_SAFE", "FAILED_TRANSIENT", "CLEARED", "EXPIRED", "REJECTED", "APPLIED":
		return true
	default:
		return false
	}
}
