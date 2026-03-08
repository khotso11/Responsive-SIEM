export type Incident = {
  run_id: string;
  status: string;
  rule_id?: string;
  playbook_id?: string;
  playbook_version?: string;
  severity?: string;
  lane?: string;
  node_id?: string;
  source_type?: string;
  event_type?: string;
  src_ip?: string;
  user_name?: string;
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
  last_updated_at_unix_ms?: number;
  source?: string;
};

export type IncidentUIState = {
  assignment?: string;
  reviewed?: boolean;
  notes?: Array<{ ts: string; actor: string; note: string }>;
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
};

export type EventRow = {
  event_ts_unix_ms: number;
  recv_ts_unix_ms: number;
  node_id: string;
  source_type: string;
  event_type: string;
  src_ip?: string;
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
