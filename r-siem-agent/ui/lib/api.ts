import {
  AuditEntry,
  AuthUser,
  DashboardIncidentPoint,
  DashboardSummary,
  EndpointsGeoResponse,
  EndpointSummary,
  EventRow,
  Incident,
  IncidentDetailResponse,
  IncidentListResponse,
  SearchResponse,
  StepResult
} from "@/lib/types";

const API_BASE = process.env.NEXT_PUBLIC_UI_API_BASE || "http://127.0.0.1:8090";
const API_KEY = process.env.NEXT_PUBLIC_UI_API_KEY || "dev-ui-key";
const TOKEN_KEY = "rsiem_ui_token";

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

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  return (await res.json()) as T;
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

export async function getEndpointRuns(nodeID: string, limit = 50): Promise<{ items: Incident[]; count: number; source: string }> {
  return apiFetch(`/api/endpoints/${encodeURIComponent(nodeID)}/runs?limit=${limit}`);
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
