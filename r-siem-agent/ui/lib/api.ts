import {
  AuditEntry,
  AuthUser,
  DashboardIncidentPoint,
  DashboardSummary,
  EndpointsGeoResponse,
  EndpointDetailSummary,
  EndpointSummary,
  EventSearchQuery,
  EventSearchResponse,
  EventRow,
  EntityProfileResponse,
  Incident,
  IncidentDetailResponse,
  IncidentLogicResponse,
  IncidentListResponse,
  InvestigationProvidersResponse,
  InfrastructureTopologyResponse,
  InfrastructureEveNodeActionResponse,
  InvestigationResponse,
  ModelCatalogResponse,
  ModelDetailResponse,
  ModelEditorPatch,
  ModelProposalsResponse,
  ModelValidationResponse,
  ResponseHistoryResponse,
  ResponseActionFleetResponse,
  ResponseActionListResponse,
  SearchResponse,
  StepResult
} from "@/lib/types";
import { emitAuthRequired } from "@/lib/events";

const API_BASE = process.env.NEXT_PUBLIC_UI_API_BASE || "http://127.0.0.1:8090";
const API_KEY = process.env.NEXT_PUBLIC_UI_API_KEY || "dev-ui-key";
const TOKEN_KEY = "rsiem_ui_token";

export class UnauthorizedError extends Error {
  constructor(message = "Session expired. Please log in again.") {
    super(message);
    this.name = "UnauthorizedError";
  }
}

function authToken(): string {
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem(TOKEN_KEY) || "";
}

export function setAuthToken(token: string): void {
  if (typeof window === "undefined") return;
  if (token) {
    window.localStorage.setItem(TOKEN_KEY, token);
  } else {
    window.localStorage.removeItem(TOKEN_KEY);
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers || {});
  const token = authToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (!headers.has("Content-Type") && init?.method && init.method !== "GET") {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    cache: "no-store"
  });

  if (res.status === 401) {
    setAuthToken("");
    emitAuthRequired({ reason: "unauthorized" });
    let text = "";
    try {
      text = await res.text();
    } catch {
      text = "";
    }
    throw new UnauthorizedError(text ? `Session expired. ${text}` : "Session expired. Please log in again.");
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  return (await res.json()) as T;
}

export function isUnauthorizedError(err: unknown): boolean {
  return err instanceof UnauthorizedError || (err instanceof Error && err.name === "UnauthorizedError");
}

export async function login(username: string, password: string): Promise<{ ok: boolean; user: AuthUser; token: string }> {
  const res = await apiFetch<{ ok: boolean; user: AuthUser; token: string }>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password })
  });
  if (res.token) {
    setAuthToken(res.token);
  }
  return res;
}

export async function logout(): Promise<void> {
  try {
    await apiFetch<{ ok: boolean }>("/api/auth/logout", { method: "POST" });
  } finally {
    setAuthToken("");
  }
}

export async function me(): Promise<{ ok: boolean; user: AuthUser }> {
  return apiFetch("/api/auth/me");
}

export async function getDashboardSummary(window = "24h"): Promise<DashboardSummary> {
  return apiFetch(`/api/dashboard/summary?window=${encodeURIComponent(window)}`);
}

export async function getDashboardIncidentsSeries(window = "24h", bucket = "1h"): Promise<{ items: DashboardIncidentPoint[]; count: number }> {
  return apiFetch(`/api/dashboard/series/incidents?window=${encodeURIComponent(window)}&bucket=${encodeURIComponent(bucket)}`);
}

export async function getDashboardSeverity(window = "24h"): Promise<{ items: Array<{ severity: string; count: number }> }> {
  return apiFetch(`/api/dashboard/series/severity?window=${encodeURIComponent(window)}`);
}

export async function getDashboardLanes(window = "24h"): Promise<{ items: Array<{ lane: string; count: number }> }> {
  return apiFetch(`/api/dashboard/series/lanes?window=${encodeURIComponent(window)}`);
}

export async function getDashboardTopEntities(window = "1h"): Promise<{
  window_ms: number;
  src_ip: Array<{ value: string; count: number }>;
  user_name: Array<{ value: string; count: number }>;
  node_id: Array<{ value: string; count: number }>;
}> {
  return apiFetch(`/api/dashboard/top/entities?window=${encodeURIComponent(window)}`);
}

export async function getIncidents(query = ""): Promise<IncidentListResponse> {
  return apiFetch(`/api/incidents${query ? `?${query}` : ""}`);
}

export async function getIncident(runId: string): Promise<IncidentDetailResponse> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}`);
}

export async function getIncidentLogic(runId: string): Promise<IncidentLogicResponse> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/logic`);
}

export async function getIncidentResponseHistory(runId: string): Promise<ResponseHistoryResponse> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/response-history`);
}

export async function getIncidentActions(runId: string): Promise<ResponseActionListResponse> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/actions`);
}

export async function postIncidentAction(
  runId: string,
  body: { actor?: string; action_name: string; duration_ms?: number; reason?: string; reference?: string; target?: string; target_agent_id?: string }
): Promise<{ ok: boolean; action: any }> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/actions`, {
    method: "POST",
    body: JSON.stringify(body)
  });
}

export async function clearIncidentAction(
  runId: string,
  actionId: string,
  body: { actor?: string; reason?: string; reference?: string } = {}
): Promise<{ ok: boolean; action: any }> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/actions/${encodeURIComponent(actionId)}/clear`, {
    method: "POST",
    body: JSON.stringify(body)
  });
}

export async function downloadIncidentReport(runId: string, format: "json" | "html" | "pdf"): Promise<void> {
  const headers = new Headers();
  const token = authToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const res = await fetch(`${API_BASE}/api/incidents/${encodeURIComponent(runId)}/report?format=${encodeURIComponent(format)}`, {
    method: "GET",
    headers,
    cache: "no-store"
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `incident_report_${runId}.${format}`;
  anchor.click();
  window.URL.revokeObjectURL(url);
}

export async function downloadSOCOperationsReport(reportWindow: string, format: "json" | "html" | "pdf"): Promise<void> {
  const headers = new Headers();
  const token = authToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const res = await fetch(`${API_BASE}/api/reports/soc/operations?window=${encodeURIComponent(reportWindow)}&format=${encodeURIComponent(format)}`, {
    method: "GET",
    headers,
    cache: "no-store"
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `soc_operations_report_${reportWindow}.${format}`;
  anchor.click();
  window.URL.revokeObjectURL(url);
}

export async function getIncidentEvents(
  runId: string,
  opts?: { windowSeconds?: number; from?: number; to?: number; userName?: string; srcIP?: string; nodeID?: string; limit?: number }
): Promise<{ items: EventRow[]; count: number; source: string }> {
  const qs = new URLSearchParams();
  qs.set("window_seconds", String(opts?.windowSeconds ?? 600));
  if (opts?.from) qs.set("from", String(opts.from));
  if (opts?.to) qs.set("to", String(opts.to));
  if (opts?.userName) qs.set("user_name", opts.userName);
  if (opts?.srcIP) qs.set("src_ip", opts.srcIP);
  if (opts?.nodeID) qs.set("node_id", opts.nodeID);
  if (opts?.limit) qs.set("limit", String(opts.limit));
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/events?${qs.toString()}`);
}

export async function approveIncident(runId: string, decision: "approve" | "reject", actor: string): Promise<{ ok: boolean }> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/approve`, {
    method: "POST",
    body: JSON.stringify({ decision, actor })
  });
}

export async function rejectIncident(runId: string, actor: string): Promise<{ ok: boolean }> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/reject`, {
    method: "POST",
    body: JSON.stringify({ actor })
  });
}

export async function reissueIncident(
  runId: string,
  actor: string,
  reason?: string
): Promise<{ ok: boolean; previous_run_id: string; new_run_id?: string; trigger_idem_key: string; alert_key: string; lane: string }> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/reissue`, {
    method: "POST",
    body: JSON.stringify({ actor, reason })
  });
}

export async function verifyIncidentUser(
  runId: string,
  actor: string,
  verificationMethod: string,
  verificationReference: string,
  notes?: string
): Promise<{ ok: boolean; run_id: string; actor: string; verification_method: string; verification_reference: string; status: string }> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/verify-user`, {
    method: "POST",
    body: JSON.stringify({
      actor,
      verification_method: verificationMethod,
      verification_reference: verificationReference,
      notes: notes || ""
    })
  });
}

export async function restoreIncidentAccess(
  runId: string,
  actor: string,
  scope: "src_ip" | "user" | "both",
  reason: string,
  changeReference?: string
): Promise<{ ok: boolean; run_id: string; actor: string; scope: string; reason: string; change_reference?: string; status: string }> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/restore-access`, {
    method: "POST",
    body: JSON.stringify({
      actor,
      scope,
      reason,
      change_reference: changeReference || ""
    })
  });
}

export async function assignIncident(runId: string, assignee: string): Promise<{ ok: boolean }> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/assign`, {
    method: "POST",
    body: JSON.stringify({ assignee })
  });
}

export async function addIncidentNote(runId: string, note: string): Promise<{ ok: boolean }> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/notes`, {
    method: "POST",
    body: JSON.stringify({ note })
  });
}

export async function markIncidentReviewed(runId: string): Promise<{ ok: boolean }> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/review`, {
    method: "POST",
    body: JSON.stringify({})
  });
}

export async function getEndpoints(): Promise<{ items: EndpointSummary[]; count: number; source: string }> {
  return apiFetch("/api/endpoints");
}

export async function getEndpointsGeo(window = "1h"): Promise<EndpointsGeoResponse> {
  return apiFetch(`/api/endpoints/geo?window=${encodeURIComponent(window)}`);
}

export async function getEndpointEvents(nodeID: string, query = ""): Promise<{ items: EventRow[]; count: number; source: string }> {
  return apiFetch(`/api/endpoints/${encodeURIComponent(nodeID)}/events${query ? `?${query}` : ""}`);
}

export async function getEndpointSummary(nodeID: string, query = ""): Promise<{ summary: EndpointDetailSummary; source: string }> {
  return apiFetch(`/api/endpoints/${encodeURIComponent(nodeID)}/summary${query ? `?${query}` : ""}`);
}

export async function getEndpointRuns(nodeID: string, limit = 50): Promise<{ items: Incident[]; count: number; source: string }> {
  return apiFetch(`/api/endpoints/${encodeURIComponent(nodeID)}/runs?limit=${limit}`);
}

export async function getEndpointActions(nodeID: string): Promise<ResponseActionListResponse> {
  return apiFetch(`/api/endpoints/${encodeURIComponent(nodeID)}/actions`);
}

export async function getInfrastructureTopology(from?: number, to?: number): Promise<InfrastructureTopologyResponse> {
  const qs = new URLSearchParams();
  if (from) qs.set("from", String(from));
  if (to) qs.set("to", String(to));
  return apiFetch(`/api/infrastructure/topology${qs.toString() ? `?${qs.toString()}` : ""}`);
}

export async function postInfrastructureEveNodeAction(
  nodeID: string,
  action: "start" | "stop" | "wipe"
): Promise<InfrastructureEveNodeActionResponse> {
  return apiFetch(`/api/infrastructure/eve/nodes/${encodeURIComponent(nodeID)}/${encodeURIComponent(action)}`, {
    method: "POST",
    body: JSON.stringify({})
  });
}

export async function getFleetActions(query: Record<string, string | number | undefined> = {}): Promise<ResponseActionFleetResponse> {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && String(value).trim() !== "") {
      qs.set(key, String(value));
    }
  }
  return apiFetch(`/api/actions${qs.toString() ? `?${qs.toString()}` : ""}`);
}

export async function postEndpointAction(
  nodeID: string,
  body: { actor?: string; action_name: string; duration_ms?: number; reason?: string; reference?: string; target?: string; target_agent_id?: string }
): Promise<{ ok: boolean; action: any }> {
  return apiFetch(`/api/endpoints/${encodeURIComponent(nodeID)}/actions`, {
    method: "POST",
    body: JSON.stringify(body)
  });
}

export async function clearEndpointAction(
  nodeID: string,
  actionId: string,
  body: { actor?: string; reason?: string; reference?: string } = {}
): Promise<{ ok: boolean; action: any }> {
  return apiFetch(`/api/endpoints/${encodeURIComponent(nodeID)}/actions/${encodeURIComponent(actionId)}/clear`, {
    method: "POST",
    body: JSON.stringify(body)
  });
}

export async function getInvestigation(runId: string): Promise<InvestigationResponse> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/investigation`);
}

export async function getInvestigationProviders(): Promise<InvestigationProvidersResponse> {
  return apiFetch("/api/investigation/providers");
}

export async function refreshInvestigation(runId: string): Promise<{ ok: boolean; job_id: string; observables: number }> {
  return apiFetch(`/api/incidents/${encodeURIComponent(runId)}/investigation/refresh`, {
    method: "POST",
    body: JSON.stringify({})
  });
}

export async function postEndpointTargetedTest(
  nodeID: string,
  actor: string,
  targetAgentID?: string
): Promise<{ ok: boolean; run_id: string; step_id: string; node_id: string; target_agent_id: string; subject: string }> {
  return apiFetch(`/api/endpoints/${encodeURIComponent(nodeID)}/targeted-test`, {
    method: "POST",
    body: JSON.stringify({ actor, target_agent_id: targetAgentID || "" })
  });
}

export async function getAudit(query = ""): Promise<{ items: AuditEntry[]; count: number }> {
  return apiFetch(`/api/audit${query ? `?${query}` : ""}`);
}

export async function getSearch(query: string, from?: number, to?: number, limit = 50): Promise<SearchResponse> {
  const qs = new URLSearchParams();
  qs.set("q", query);
  qs.set("limit", String(limit));
  if (from) qs.set("from", String(from));
  if (to) qs.set("to", String(to));
  return apiFetch(`/api/search?${qs.toString()}`);
}

export async function getSearchEvents(query: EventSearchQuery = {}): Promise<EventSearchResponse> {
  const qs = new URLSearchParams();
  const entries: Array<[string, string | number | undefined]> = [
    ["q", query.q],
    ["from", query.from],
    ["to", query.to],
    ["category", query.category],
    ["node_id", query.node_id],
    ["user_name", query.user_name],
    ["src_ip", query.src_ip],
    ["dst_ip", query.dst_ip],
    ["dst_port", query.dst_port],
    ["protocol_family", query.protocol_family],
    ["source_type", query.source_type],
    ["event_type", query.event_type],
    ["rule_id", query.rule_id],
    ["severity", query.severity],
    ["comm", query.comm],
    ["exec_path", query.exec_path],
    ["cmdline", query.cmdline],
    ["dns_name", query.dns_name],
    ["file_sha256", query.file_sha256],
    ["exec_sha256", query.exec_sha256],
    ["event_idem_key", query.event_idem_key],
    ["raw_line_sha256", query.raw_line_sha256],
    ["page", query.page],
    ["limit", query.limit],
    ["sort", query.sort]
  ];
  for (const [key, value] of entries) {
    if (value !== undefined && value !== null && String(value).trim() !== "") {
      qs.set(key, String(value));
    }
  }
  return apiFetch(`/api/search/events${qs.toString() ? `?${qs.toString()}` : ""}`);
}

export async function getEntityIP(ip: string): Promise<EntityProfileResponse> {
  return apiFetch(`/api/entities/ip/${encodeURIComponent(ip)}`);
}

export async function getEntityUser(user: string): Promise<EntityProfileResponse> {
  return apiFetch(`/api/entities/user/${encodeURIComponent(user)}`);
}

export async function getArtifacts(
  prefix: string,
  opts?: { q?: string; page?: number; limit?: number }
): Promise<{ items: Array<{ path: string; is_dir: boolean; size: number; modified: string }>; count: number; total?: number; page?: number; limit?: number; has_more?: boolean }> {
  const qs = new URLSearchParams();
  qs.set("prefix", prefix);
  if (opts?.q) qs.set("q", opts.q);
  if (opts?.page) qs.set("page", String(opts.page));
  if (opts?.limit) qs.set("limit", String(opts.limit));
  return apiFetch(`/api/artifacts?${qs.toString()}`);
}

export async function getAdminUsers(): Promise<{ items: Array<{ username: string; role: string; disabled: boolean }>; count: number }> {
  return apiFetch("/api/users");
}

export async function getModels(): Promise<ModelCatalogResponse> {
  return apiFetch("/api/models");
}

export async function getModelDetail(kind: string, id: string): Promise<ModelDetailResponse> {
  return apiFetch(`/api/models/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`);
}

export async function validateModelChange(kind: string, id: string, changes: ModelEditorPatch, summary = ""): Promise<ModelValidationResponse> {
  return apiFetch(`/api/models/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/validate`, {
    method: "POST",
    body: JSON.stringify({ summary, changes })
  });
}

export async function proposeModelChange(kind: string, id: string, changes: ModelEditorPatch, summary = ""): Promise<{ ok: boolean; proposal_id: string; warnings?: string[] }> {
  return apiFetch(`/api/models/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/propose`, {
    method: "POST",
    body: JSON.stringify({ summary, changes })
  });
}

export async function getModelProposals(): Promise<ModelProposalsResponse> {
  return apiFetch("/api/models/proposals");
}

export async function approveModelProposal(proposalId: string): Promise<{ ok: boolean; proposal_id: string; status: string }> {
  return apiFetch(`/api/models/proposals/${encodeURIComponent(proposalId)}/approve`, {
    method: "POST",
    body: JSON.stringify({})
  });
}

export async function rejectModelProposal(proposalId: string): Promise<{ ok: boolean; proposal_id: string; status: string }> {
  return apiFetch(`/api/models/proposals/${encodeURIComponent(proposalId)}/reject`, {
    method: "POST",
    body: JSON.stringify({})
  });
}

export async function applyModelProposal(
  proposalId: string,
  restartTargets: string[] = []
): Promise<{
  ok: boolean;
  proposal_id: string;
  backup_path?: string;
  restart_targets?: string[];
  restart_results?: Array<{ target: string; ok: boolean; pid?: number; log_file?: string; error?: string }>;
  effective_after_restart: boolean;
  live_reload_supported: boolean;
}> {
  return apiFetch(`/api/models/proposals/${encodeURIComponent(proposalId)}/apply`, {
    method: "POST",
    body: JSON.stringify({ restart_targets: restartTargets })
  });
}

export async function upsertAdminUser(payload: { username: string; role: string; disabled?: boolean; password?: string }): Promise<{ ok: boolean }> {
  return apiFetch("/api/users", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function disableUser(username: string): Promise<{ ok: boolean; username: string; disabled: boolean }> {
  return apiFetch(`/api/users/${encodeURIComponent(username)}/disable`, {
    method: "POST",
    body: JSON.stringify({})
  });
}

export async function deleteUser(username: string): Promise<{ ok: boolean; username: string; deleted: boolean }> {
  return apiFetch(`/api/users/${encodeURIComponent(username)}/delete`, {
    method: "POST",
    body: JSON.stringify({})
  });
}

export async function purgeDemoTestIncidents(payload?: {
  older_than_days?: number;
  dry_run?: boolean;
  actor?: string;
}): Promise<{ ok: boolean; dry_run: boolean; count: number; items: Incident[]; older_than?: number; actor?: string }> {
  return apiFetch("/api/admin/incidents/purge_demo_test", {
    method: "POST",
    body: JSON.stringify(payload || {})
  });
}

export function getApiBase(): string {
  return API_BASE;
}

export function getApiKey(): string {
  return API_KEY;
}

export function getStreamURL(): string {
  const token = authToken();
  if (token) {
    return `${API_BASE}/api/stream?token=${encodeURIComponent(token)}`;
  }
  return `${API_BASE}/api/stream?api_key=${encodeURIComponent(API_KEY)}`;
}
