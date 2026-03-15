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
  user_name?: string;
  severity?: string;
  rule_id?: string;
  event_idem_key: string;
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
