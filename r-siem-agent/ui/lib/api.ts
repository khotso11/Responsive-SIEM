import { AuditEntry, EndpointSummary, EventRow, Incident, IncidentListResponse, SearchResponse, StepResult } from "@/lib/types";

const API_BASE = process.env.NEXT_PUBLIC_UI_API_BASE || "http://127.0.0.1:8090";
const API_KEY = process.env.NEXT_PUBLIC_UI_API_KEY || "dev-ui-key";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers || {});
  headers.set("X-API-Key", API_KEY);
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

export async function getIncidents(query = ""): Promise<IncidentListResponse> {
  return apiFetch(`/api/incidents${query ? `?${query}` : ""}`);
}

export async function getIncident(runId: string): Promise<{ run: Incident; steps: StepResult[]; source: string }> {
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

export async function getEndpoints(): Promise<{ items: EndpointSummary[]; count: number; source: string }> {
  return apiFetch("/api/endpoints");
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

export async function getArtifacts(prefix: string): Promise<{ items: Array<{ path: string; is_dir: boolean; size: number; modified: string }>; count: number }> {
  return apiFetch(`/api/artifacts?prefix=${encodeURIComponent(prefix)}`);
}

export function getApiBase(): string {
  return API_BASE;
}

export function getApiKey(): string {
  return API_KEY;
}

export function getStreamURL(): string {
  return `${API_BASE}/api/stream?api_key=${encodeURIComponent(API_KEY)}`;
}
