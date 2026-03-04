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

export type IncidentListResponse = {
  items: Incident[];
  count: number;
  total?: number;
  page?: number;
  limit?: number;
  sort?: string;
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
