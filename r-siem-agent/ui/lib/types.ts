export type Incident = {
  run_id: string;
  trigger_idem_key?: string;
  alert_key?: string;
  status: string;
  rule_id?: string;
  playbook_id?: string;
  playbook_version?: string;
  severity?: string;
  confidence_score?: number;
  lane?: string;
  node_id?: string;
  asset_environment?: string;
  asset_criticality?: string;
  asset_owner?: string;
  asset_team?: string;
  asset_role?: string;
  source_type?: string;
  event_type?: string;
  src_ip?: string;
  dst_ip?: string;
  dst_port?: number;
  protocol_family?: string;
  scan_fanout?: number;
  top_destinations?: string[];
  user_name?: string;
  exec_path?: string;
  comm?: string;
  cmdline?: string;
  file_sha256?: string;
  exec_sha256?: string;
  dns_name?: string;
  identity_display_name?: string;
  identity_department?: string;
  identity_manager?: string;
  identity_privileged?: boolean;
  identity_service_account?: boolean;
  target?: string;
  target_agent_id?: string;
  actor?: string;
  event_idem_key?: string;
  step_total?: number;
  step_succeeded_count?: number;
  step_failed_safe_count?: number;
  step_failed_transient_count?: number;
  failed_safe_reason?: string;
  operator_action?: string;
  approval_policy_mode?: string;
  approval_policy_rule_id?: string;
  allowlist_rule_id?: string;
  approval_policy_reason?: string;
  playbook_reversibility?: string;
  approval_decision?: string;
  approval_actor?: string;
  last_updated_at_unix_ms?: number;
  lifecycle_state?: string;
  environment_class?: string;
  retention_class?: string;
  retention_rule_id?: string;
  archive_after_days?: number;
  purge_after_days?: number;
  age_days?: number;
  archived?: boolean;
  purge_eligible?: boolean;
  identity_workflow_eligible?: boolean;
  identity_workflow_reason?: string;
  source?: string;
};

export type IncidentUIState = {
  assignment?: string;
  reviewed?: boolean;
  notes?: Array<{ ts: string; actor: string; note: string }>;
  verification?: {
    verified?: boolean;
    ts?: string;
    actor?: string;
    method?: string;
    reference?: string;
    notes?: string;
    status?: string;
    result?: string;
  };
  restore?: {
    restored?: boolean;
    ts?: string;
    actor?: string;
    scope?: string;
    reason?: string;
    reference?: string;
    status?: string;
    result?: string;
  };
};

export type IncidentListResponse = {
  items: Incident[];
  count: number;
  total?: number;
  page?: number;
  limit?: number;
  sort?: string;
  source: string;
};

export type IncidentDetailResponse = {
  run: Incident;
  steps: StepResult[];
  ui_state?: IncidentUIState;
  annotations?: AuditEntry[];
  source: string;
};

export type IncidentLogicRule = {
  id: string;
  enabled: boolean;
  kind: string;
  severity: string;
  group_by?: string;
  window_ms?: number;
  threshold?: number;
  when_type?: string;
  conditions?: string[];
  sequence?: string[];
  predicates?: string[];
};

export type IncidentLogicPlaybookStep = {
  name: string;
  action_type: string;
  reversibility?: string;
  timeout_ms?: number;
  retries?: number;
  backoff_ms?: number;
  target_from?: string;
  param_keys?: string[];
};

export type IncidentLogicPlaybook = {
  id: string;
  version?: number;
  enabled: boolean;
  selector_rule_ids?: string[];
  approval_mode?: string;
  max_blast_radius?: number;
  auto_min_confidence?: number;
  auto_max_blast_radius?: number;
  auto_max_severity?: string;
  require_approval_for_privileged?: boolean;
  require_approval_for_local_src?: boolean;
  require_identity_context?: boolean;
  default_containment_duration_ms?: number;
  max_containment_duration_ms?: number;
  steps?: IncidentLogicPlaybookStep[];
};

export type IncidentLogicApprovalRule = {
  id: string;
  conditions?: string[];
  required: boolean;
  reason?: string;
};

export type IncidentLogicPolicy = {
  approval_mode?: string;
  approval_rule_id?: string;
  approval_rule?: IncidentLogicApprovalRule;
  approval_reason?: string;
  playbook_reversibility?: string;
  allowlist_rule_id?: string;
  approval_timeout_ms?: number;
  default_auto_min_confidence?: number;
};

export type IncidentLogicScope = {
  node_id?: string;
  target_agent_id?: string;
  source_type?: string;
  event_type?: string;
  user_name?: string;
  src_ip?: string;
  dst_ip?: string;
  dst_port?: number;
  protocol_family?: string;
  top_destinations?: string[];
  comm?: string;
  exec_path?: string;
  cmdline?: string;
  dns_name?: string;
  target?: string;
  file_sha256?: string;
  exec_sha256?: string;
};

export type IncidentLogicResponse = {
  run_id: string;
  rule: IncidentLogicRule;
  playbook: IncidentLogicPlaybook;
  policy: IncidentLogicPolicy;
  scope: IncidentLogicScope;
  source: string;
};

export type ResponseHistoryItem = {
  ts_unix_ms: number;
  ts?: string;
  stage: string;
  label: string;
  status?: string;
  actor?: string;
  decision?: string;
  step_id?: string;
  step_index?: number;
  action_type?: string;
  lane?: string;
  details?: Record<string, unknown>;
  source: string;
};

export type ResponseHistoryResponse = {
  run_id: string;
  items: ResponseHistoryItem[];
  count: number;
  source: string;
};

export type ResponseActionCatalogEntry = {
  id: string;
  label: string;
  description: string;
  action_type: string;
  command_id?: string;
  execution_mode: string;
  default_duration_ms: number;
  clear_supported: boolean;
  requires_incident_scope?: boolean;
  available: boolean;
  unavailable_reason?: string;
};

export type ResponseActionView = {
  action_id: string;
  scope_type: "incident" | "endpoint";
  run_id?: string;
  node_id?: string;
  target_agent_id?: string;
  actor: string;
  action_name: string;
  label: string;
  status: string;
  bucket: "pending" | "active" | "cleared" | "expired" | "failed";
  status_detail?: string;
  action_type: string;
  command_id?: string;
  target?: string;
  direction?: string;
  reason?: string;
  reference?: string;
  duration_ms?: number;
  started_at_unix_ms?: number;
  expires_at_unix_ms?: number;
  cleared_at_unix_ms?: number;
  execution_mode?: string;
  clear_supported?: boolean;
  subject?: string;
  result?: string;
  error_class?: string;
  details?: Record<string, unknown>;
  source: string;
};

export type ResponseActionListResponse = {
  scope_type: "incident" | "endpoint";
  scope_id: string;
  items: ResponseActionView[];
  count: number;
  buckets: Record<string, number>;
  available_actions: ResponseActionCatalogEntry[];
  source: string;
};

export type ResponseActionFleetResponse = {
  items: ResponseActionView[];
  count: number;
  total: number;
  page: number;
  limit: number;
  buckets: Record<string, number>;
  source: string;
};

export type StepResult = {
  run_id: string;
  step_id: string;
  step_index: number;
  step_key?: string;
  status: string;
  action_type?: string;
  lane?: string;
  actor?: string;
  attempt?: number;
  finished_at_unix_ms?: number;
  target?: string;
  target_agent_id?: string;
  last_error?: string;
  receipt?: Record<string, unknown>;
  allowlist_rule_id?: string;
  guardrail_rule_ids?: string[];
};

export type EventRow = {
  event_ts_unix_ms: number;
  recv_ts_unix_ms: number;
  node_id: string;
  source_type: string;
  event_type: string;
  src_ip?: string;
  dst_ip?: string;
  dst_port?: number;
  protocol_family?: string;
  user_name?: string;
  severity?: string;
  rule_id?: string;
  exec_path?: string;
  comm?: string;
  cmdline?: string;
  dns_name?: string;
  file_sha256?: string;
  exec_sha256?: string;
  event_idem_key: string;
  raw_line_sha256?: string;
};

export type EndpointSummary = {
  node_id: string;
  last_seen_unix_ms: number;
  event_count_5m: number;
  event_count_1h: number;
  source_type_distribution: Record<string, number>;
  source_types?: string[];
  derived_from?: string;
};

export type NamedCount = {
  value: string;
  count: number;
};

export type EndpointDetailSummary = {
  node_id: string;
  window_from_unix_ms: number;
  window_to_unix_ms: number;
  first_seen_unix_ms?: number;
  last_seen_unix_ms?: number;
  total_events: number;
  detection_count: number;
  active_action_count: number;
  recent_run_count: number;
  source_type_distribution?: Record<string, number>;
  event_type_distribution?: Record<string, number>;
  severity_distribution?: Record<string, number>;
  top_users?: NamedCount[];
  top_rules?: NamedCount[];
  top_destinations?: NamedCount[];
  top_domains?: NamedCount[];
};

export type AuditEntry = {
  ts: string;
  msg: string;
  run_id?: string;
  actor?: string;
  decision?: string;
  status?: string;
  details?: Record<string, unknown>;
  source: string;
};

export type SearchResponse = {
  q: string;
  incidents: Incident[];
  events: EventRow[];
  count_incidents: number;
  count_events: number;
};

export type EventSearchQuery = {
  q?: string;
  from?: number;
  to?: number;
  node_id?: string;
  user_name?: string;
  src_ip?: string;
  dst_ip?: string;
  dst_port?: number;
  protocol_family?: string;
  source_type?: string;
  event_type?: string;
  rule_id?: string;
  severity?: string;
  comm?: string;
  exec_path?: string;
  cmdline?: string;
  dns_name?: string;
  file_sha256?: string;
  exec_sha256?: string;
  event_idem_key?: string;
  raw_line_sha256?: string;
  page?: number;
  limit?: number;
  sort?: "recv_desc" | "recv_asc" | "event_desc" | "event_asc";
};

export type EventSearchResponse = {
  items: EventRow[];
  count: number;
  total: number;
  page: number;
  limit: number;
  sort: string;
  source: string;
  available_filters: string[];
  query: EventSearchQuery & { from: number; to: number; page: number; limit: number; sort: string };
};

export type AuthUser = {
  username: string;
  role: "admin" | "analyst";
};

export type DashboardSummary = {
  window_ms: number;
  from_unix_ms: number;
  to_unix_ms: number;
  incidents_last_window: number;
  critical_incidents_last_window?: number;
  approvals_pending: number;
  failed_safe_count: number;
  endpoints_active: number;
  ingestion_rate_per_min: number;
  latency_p95_ms: number;
  total_events_last_window?: number;
  model_alerts_last_window?: number;
  mitre_tactics_processed?: Array<{
    tactic: string;
    count: number;
    high_critical: number;
    delta?: number;
  }>;
};

export type DashboardIncidentPoint = {
  ts_unix_ms: number;
  count: number;
  fast: number;
  standard: number;
  failed_safe: number;
};

export type EndpointGeoSummary = {
  node_id: string;
  last_seen_rfc3339: string;
  events_5m: number;
  events_1h: number;
  status: "active" | "warning" | "critical" | "unknown";
  source_dist: Record<string, number>;
  geo: {
    lat: number;
    lon: number;
    label?: string;
    source: "configured" | "derived" | "none";
  };
};

export type EndpointsGeoResponse = {
  window: string;
  generated_at: string;
  endpoints: EndpointGeoSummary[];
  count: number;
  source: string;
};

export type InvestigationObservable = {
  kind: string;
  value: string;
  role: string;
  source: string;
  created_at_unix_ms: number;
};

export type InvestigationProviderResult = {
  observable_kind: string;
  observable_value: string;
  provider: string;
  status: string;
  verdict: string;
  score: number;
  summary: string;
  evidence_url?: string;
  fetched_at_unix_ms?: number;
  expires_at_unix_ms?: number;
  data?: Record<string, unknown>;
};

export type InvestigationProviderSummary = {
  provider: string;
  status: string;
  verdict: string;
  score: number;
  summary: string;
  attempts: number;
  latency_ms: number;
  http_status: number;
  error_class: string;
  fetched_at_unix_ms?: number;
};

export type InvestigationJob = {
  job_id: string;
  run_id: string;
  status: string;
  requested_by: string;
  requested_at_unix_ms: number;
  completed_at_unix_ms?: number;
  refresh: boolean;
  error_text?: string;
};

export type InvestigationResponse = {
  run_id: string;
  observables: InvestigationObservable[];
  enrichments: InvestigationProviderResult[];
  summaries: InvestigationProviderSummary[];
  jobs: InvestigationJob[];
  source: string;
};

export type InvestigationProviderCatalogEntry = {
  provider: string;
  label: string;
  enabled: boolean;
  api_key_configured: boolean;
  env_var: string;
  supported_kinds: string[];
  last_status?: string;
  last_verdict?: string;
  last_summary?: string;
  last_fetched_at_unix_ms?: number;
};

export type InvestigationProvidersResponse = {
  items: InvestigationProviderCatalogEntry[];
  count: number;
  source: string;
};

export type EntityProfileSummary = {
  first_seen_unix_ms?: number;
  last_seen_unix_ms?: number;
  total_events: number;
  detections: number;
  nodes?: string[];
  source_types?: string[];
  event_types?: string[];
  rules?: string[];
};

export type EntityProfileResponse = {
  kind: string;
  value: string;
  summary: EntityProfileSummary;
  recent_events: EventRow[];
  recent_incidents: Incident[];
  count_events: number;
  count_incidents: number;
  source: string;
};

export type ModelKind = "rule" | "playbook" | "approval_rule";

export type ModelEditorPatch = {
  enabled?: boolean;
  severity?: string;
  group_by?: string;
  window_ms?: number;
  threshold?: number;
  approval_mode?: string;
  max_blast_radius?: number;
  auto_min_confidence?: number;
  auto_max_blast_radius?: number;
  auto_max_severity?: string;
  require_approval_for_privileged?: boolean;
  require_approval_for_local_src?: boolean;
  require_identity_context?: boolean;
  default_containment_duration_ms?: number;
  max_containment_duration_ms?: number;
  required?: boolean;
  reason?: string;
};

export type ModelEditorCurrent = ModelEditorPatch;

export type ModelRestartTarget = {
  id: string;
  label: string;
  description?: string;
  status?: string;
  running?: boolean;
  pid?: number;
  pid_file?: string;
  log_file?: string;
};

export type ModelCatalogItem = {
  kind: ModelKind;
  id: string;
  title: string;
  enabled: boolean;
  severity?: string;
  approval_mode?: string;
  summary?: string;
  editable_fields?: string[];
  pending_proposals?: number;
};

export type ModelCatalogResponse = {
  items: ModelCatalogItem[];
  count: number;
  restart_targets?: ModelRestartTarget[];
  live_reload_supported: boolean;
  effective_after_restart: boolean;
  source: string;
};

export type ModelDetailResponse = {
  kind: ModelKind;
  id: string;
  title: string;
  editable_fields: string[];
  current: ModelEditorCurrent;
  rule?: IncidentLogicRule;
  playbook?: IncidentLogicPlaybook;
  approval_rule?: IncidentLogicApprovalRule;
  restart_targets?: ModelRestartTarget[];
  live_reload_supported: boolean;
  effective_after_restart: boolean;
  source: string;
};

export type ModelValidationResponse = {
  ok: boolean;
  kind: ModelKind;
  id: string;
  changes: ModelEditorPatch;
  warnings?: string[];
  live_reload_supported: boolean;
  effective_after_restart: boolean;
};

export type ModelProposal = {
  proposal_id: string;
  kind: ModelKind;
  model_id: string;
  actor: string;
  summary?: string;
  status: string;
  created_at: string;
  approved_at?: string;
  approved_by?: string;
  rejected_at?: string;
  rejected_by?: string;
  applied_at?: string;
  applied_by?: string;
  changes: ModelEditorPatch;
  warnings?: string[];
  backup_path?: string;
  restart_targets?: string[];
  restart_results?: Array<{ target: string; ok: boolean; pid?: number; log_file?: string; error?: string }>;
  effective_after_restart: boolean;
};

export type ModelProposalsResponse = {
  items: ModelProposal[];
  count: number;
  restart_targets?: ModelRestartTarget[];
  live_reload_supported: boolean;
  effective_after_restart: boolean;
};
