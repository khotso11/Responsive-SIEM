"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { getIncidents, me, purgeDemoTestIncidents } from "@/lib/api";
import { INCIDENT_MUTATED_EVENT, INCIDENTS_UPDATED_EVENT } from "@/lib/events";
import { AuthUser, Incident, IncidentListResponse } from "@/lib/types";
import { IncidentDrawer } from "@/components/incident-drawer";
import { EmptyState, ErrorState, LaneBadge, LoadingState, StatusBadge, unixMsToLocal } from "@/components/ui";

type SavedView = {
  name: string;
  view?: string;
  status?: string;
  lane?: string;
  severity?: string;
};

const DEFAULT_VIEWS: SavedView[] = [
  { name: "Triage", view: "active", status: "RUNNING" },
  { name: "FAST Pending", view: "active", lane: "FAST", status: "WAITING_APPROVAL" },
  { name: "Failed Safe", view: "active", status: "FAILED_SAFE" },
  { name: "Archived", view: "archived" },
  { name: "All", view: "all" }
];

function policyBadge(reason?: string): string {
  const value = (reason || "").toLowerCase();
  if (!value) return "";
  if (value.includes("missing_identity_context")) return "Identity context required";
  if (value.includes("privileged_identity")) return "Privileged identity review";
  if (value.includes("local_source")) return "Local source review";
  if (value.includes("irreversible")) return "Irreversible action";
  if (value.includes("degraded")) return "Degraded queue";
  if (value.includes("confidence_below_threshold")) return "Low confidence review";
  if (value.includes("auto_within_bounds")) return "Auto within bounds";
  if (value.includes("auto_below_high")) return "Auto below high";
  if (value.includes("auto_below_critical")) return "Auto below critical";
  if (value.includes("required")) return "Manual approval";
  return reason || "";
}

function lifecycleLabel(value?: string): string {
  switch ((value || "").toLowerCase()) {
    case "pending_approval":
      return "Pending approval";
    case "pending_manual_review":
      return "Pending manual review";
    case "active":
      return "Active";
    case "resolved":
      return "Resolved";
    case "failed_safe":
      return "Failed safe";
    case "closed_no_action":
      return "Closed without action";
    default:
      return value || "-";
  }
}

function criticalityTone(value?: string): string {
  switch ((value || "").toLowerCase()) {
    case "critical":
      return "border-rose-700/60 bg-rose-950/70 text-rose-200";
    case "high":
      return "border-amber-700/60 bg-amber-950/70 text-amber-200";
    case "medium":
      return "border-sky-700/60 bg-sky-950/70 text-sky-200";
    case "low":
      return "border-emerald-700/60 bg-emerald-950/70 text-emerald-200";
    default:
      return "border-ink-700/60 bg-ink-900/60 text-ink-200";
  }
}

function parseQueryTime(v: string | null): number | undefined {
  if (!v) return undefined;
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return n;
  const p = Date.parse(v);
  if (!Number.isNaN(p) && p > 0) return p;
  return undefined;
}

export default function IncidentsPage() {
  const searchParams = useSearchParams();
  const requestedRunID = (searchParams.get("open_run_id") || "").trim();
  const requestedTab = ((searchParams.get("open_tab") || "").trim().toLowerCase() as
    | "overview"
    | "steps"
    | "timeline"
    | "entities"
    | "evidence"
    | "actions"
    | "");
  const [toasts, setToasts] = useState<Array<{ id: number; tone: "success" | "error"; message: string }>>([]);
  const [items, setItems] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(50);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [hasLoadedOnce, setHasLoadedOnce] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [view, setView] = useState("active");
  const [status, setStatus] = useState("");
  const [lane, setLane] = useState("");
  const [severity, setSeverity] = useState("");
  const [lifecycle, setLifecycle] = useState("");
  const [environment, setEnvironment] = useState("");
  const [nodeID, setNodeID] = useState("");
  const [playbookID, setPlaybookID] = useState("");
  const [ruleID, setRuleID] = useState("");
  const [q, setQ] = useState(searchParams.get("gq") || "");
  const [sort, setSort] = useState("updated_desc");
  const [selectedRunID, setSelectedRunID] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [refreshNonce, setRefreshNonce] = useState(0);
  const [pendingPurge, setPendingPurge] = useState(false);
  const globalFrom = useMemo(() => parseQueryTime(searchParams.get("gfrom")), [searchParams]);
  const globalTo = useMemo(() => parseQueryTime(searchParams.get("gto")), [searchParams]);

  const pushToast = useCallback((tone: "success" | "error", message: string) => {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    setToasts((prev) => [...prev, { id, tone, message }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((toast) => toast.id !== id));
    }, 3500);
  }, []);

  useEffect(() => {
    const saved = localStorage.getItem("rsiem-saved-view");
    if (saved) {
      const parsed = JSON.parse(saved) as SavedView;
      setView(parsed.view || "active");
      setStatus(parsed.status || "");
      setLane(parsed.lane || "");
      setSeverity(parsed.severity || "");
    }
  }, []);

  useEffect(() => {
    setQ(searchParams.get("gq") || "");
  }, [searchParams]);

  useEffect(() => {
    if (!requestedRunID) return;
    setSelectedRunID(requestedRunID);
    setDrawerOpen(true);
  }, [requestedRunID]);

  const load = useCallback(() => {
    const params = new URLSearchParams();
    if (view) params.set("view", view);
    if (status) params.set("status", status);
    if (lane) params.set("lane", lane);
    if (severity) params.set("severity", severity);
    if (lifecycle) params.set("lifecycle", lifecycle);
    if (environment) params.set("environment", environment);
    if (nodeID) params.set("node_id", nodeID);
    if (playbookID) params.set("playbook_id", playbookID);
    if (ruleID) params.set("rule_id", ruleID);
    if (q) params.set("q", q);
    if (globalFrom) params.set("from", String(globalFrom));
    if (globalTo) params.set("to", String(globalTo));
    params.set("limit", String(limit));
    params.set("page", String(page));
    params.set("sort", sort);

    if (hasLoadedOnce) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);
    return Promise.all([getIncidents(params.toString()), me().catch(() => null)])
      .then(([res, meRes]: [IncidentListResponse, { ok: boolean; user: AuthUser } | null]) => {
        setItems(res.items || []);
        setTotal(res.total || res.count || 0);
        setAuthUser(meRes?.user || null);
        setHasLoadedOnce(true);
      })
      .catch((e) => setError(e.message || String(e)))
      .finally(() => {
        setLoading(false);
        setRefreshing(false);
      });
  }, [view, status, lane, severity, lifecycle, environment, nodeID, playbookID, ruleID, q, globalFrom, globalTo, page, limit, sort, hasLoadedOnce]);

  useEffect(() => {
    void load();
  }, [load, refreshNonce]);

  useEffect(() => {
    const onRefresh = () => setRefreshNonce((v) => v + 1);
    window.addEventListener(INCIDENTS_UPDATED_EVENT, onRefresh);
    window.addEventListener(INCIDENT_MUTATED_EVENT, onRefresh);
    return () => {
      window.removeEventListener(INCIDENTS_UPDATED_EVENT, onRefresh);
      window.removeEventListener(INCIDENT_MUTATED_EVENT, onRefresh);
    };
  }, []);

  const pages = useMemo(() => Math.max(1, Math.ceil(total / limit)), [total, limit]);

  const saveView = (view: SavedView) => {
    localStorage.setItem("rsiem-saved-view", JSON.stringify(view));
    setView(view.view || "active");
    setStatus(view.status || "");
    setLane(view.lane || "");
    setSeverity(view.severity || "");
    setPage(1);
  };

  const purgeArchivedDemoTest = async () => {
    try {
      const res = await purgeDemoTestIncidents({ actor: authUser?.username || "admin" });
      pushToast("success", `Purged ${res.count} archived demo/test incidents from the active UI state.`);
      setPendingPurge(false);
      setRefreshNonce((v) => v + 1);
    } catch (e) {
      pushToast("error", `Purge failed: ${(e as Error).message}`);
    }
  };

  return (
    <section className="flex h-full min-h-0 flex-col gap-4 overflow-auto">
      {toasts.length > 0 ? (
        <div className="fixed right-6 top-6 z-50 flex max-w-sm flex-col gap-2">
          {toasts.map((toast) => (
            <div
              key={toast.id}
              className={`rounded-lg border px-3 py-2 text-sm shadow-lg ${
                toast.tone === "success"
                  ? "border-emerald-700/60 bg-emerald-950/80 text-emerald-100"
                  : "border-rose-700/60 bg-rose-950/80 text-rose-100"
              }`}
            >
              {toast.message}
            </div>
          ))}
        </div>
      ) : null}

      {pendingPurge ? (
        <div className="fixed inset-0 z-40 bg-black/50">
          <div className="absolute inset-y-0 right-0 flex w-full max-w-md flex-col border-l border-ink-800 bg-ink-950 shadow-2xl">
            <div className="flex items-center justify-between border-b border-ink-800 px-4 py-3">
              <div>
                <h3 className="text-[16px] font-semibold">Purge Demo/Test Incidents</h3>
                <p className="text-xs text-ink-300">Only archived demo/test incidents older than the retention threshold will be masked from the UI.</p>
              </div>
              <button className="btn-secondary px-3 py-2 text-xs" onClick={() => setPendingPurge(false)}>
                Close
              </button>
            </div>
            <div className="flex flex-1 flex-col gap-4 px-4 py-4 text-sm text-ink-200">
              <p>
                This does not delete raw logs, exports, or DB evidence. It masks eligible demo/test incidents from the active UI and audit-facing incident state.
              </p>
              <p className="text-xs text-ink-300">Only terminal demo/test incidents older than the policy threshold are eligible.</p>
              <div className="mt-auto flex justify-end gap-2">
                <button className="btn-secondary px-3 py-2 text-xs" onClick={() => setPendingPurge(false)}>
                  Cancel
                </button>
                <button className="btn-danger px-3 py-2 text-xs" onClick={() => void purgeArchivedDemoTest()}>
                  Purge Eligible Demo/Test Incidents
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-[18px] font-semibold">Incident Queue</h2>
          <p className="text-[13px] text-ink-300">SOC queue with deterministic sort/paging, triage filters, and drawer investigation.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {refreshing ? (
            <div className="rounded border border-ink-700/80 bg-ink-900/60 px-2 py-1 text-[11px] text-ink-300">
              Refreshing...
            </div>
          ) : null}
          <select value={sort} onChange={(e) => setSort(e.target.value)} className="select-field py-1 text-xs">
            <option value="updated_desc">Updated desc</option>
            <option value="updated_asc">Updated asc</option>
            <option value="severity_desc">Severity desc</option>
            <option value="status_asc">Status asc</option>
          </select>
          <select value={view} onChange={(e) => setView(e.target.value)} className="select-field py-1 text-xs">
            <option value="active">Active</option>
            <option value="archived">Archived</option>
            <option value="all">All</option>
          </select>
          <select
            value={limit}
            onChange={(e) => {
              setLimit(Number(e.target.value) || 50);
              setPage(1);
            }}
            className="select-field py-1 text-xs"
          >
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
          {authUser?.role === "admin" ? (
            <button className="btn-danger px-3 py-1 text-xs" onClick={() => setPendingPurge(true)}>
              Purge demo/test
            </button>
          ) : null}
        </div>
      </div>

      <div className="sticky top-2 z-20 panel-elevated grid grid-cols-1 gap-2 p-2 md:grid-cols-10">
        <input className="input-field" placeholder="Search run/user/src/node/rule" value={q} onChange={(e) => setQ(e.target.value)} />
        <input className="input-field" placeholder="Status (WAITING_APPROVAL...)" value={status} onChange={(e) => setStatus(e.target.value)} />
        <input className="input-field" placeholder="Lane (FAST/STANDARD)" value={lane} onChange={(e) => setLane(e.target.value)} />
        <input className="input-field" placeholder="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)} />
        <input className="input-field" placeholder="Lifecycle (active/resolved...)" value={lifecycle} onChange={(e) => setLifecycle(e.target.value)} />
        <input className="input-field" placeholder="Environment (demo_test/operational)" value={environment} onChange={(e) => setEnvironment(e.target.value)} />
        <input className="input-field" placeholder="Node ID" value={nodeID} onChange={(e) => setNodeID(e.target.value)} />
        <input className="input-field" placeholder="Playbook ID" value={playbookID} onChange={(e) => setPlaybookID(e.target.value)} />
        <input className="input-field" placeholder="Rule ID" value={ruleID} onChange={(e) => setRuleID(e.target.value)} />
        <button
          onClick={() => {
            setView("active");
            setQ("");
            setStatus("");
            setLane("");
            setSeverity("");
            setLifecycle("");
            setEnvironment("");
            setNodeID("");
            setPlaybookID("");
            setRuleID("");
            setPage(1);
          }}
          className="btn-secondary"
        >
          Clear filters
        </button>
      </div>

      <div className="flex flex-wrap gap-2">
        {DEFAULT_VIEWS.map((v) => (
          <button key={v.name} className="btn-secondary px-3 py-1 text-xs" onClick={() => saveView(v)}>
            {v.name}
          </button>
        ))}
      </div>

      {loading && !hasLoadedOnce ? <LoadingState /> : null}
      {error && !items.length ? <ErrorState message={error} /> : null}
      {error && items.length > 0 ? (
        <div className="rounded border border-rose-900/80 bg-rose-950/30 px-3 py-2 text-sm text-rose-200">
          {error}
        </div>
      ) : null}
      {!loading && !error && items.length === 0 ? <EmptyState title="No incidents found" detail="Adjust filters or trigger deterministic events." /> : null}

      {!loading && !error && items.length > 0 ? (
        <div className="overflow-auto">
          <table className="min-w-full text-sm">
            <thead className="text-left">
              <tr>
                <th className="table-head p-2">Severity</th>
                <th className="table-head p-2">Run ID</th>
                <th className="table-head p-2">Status</th>
                <th className="table-head p-2">Lifecycle</th>
                <th className="table-head p-2">Lane</th>
                <th className="table-head p-2">Rule / Playbook</th>
                <th className="table-head p-2">Node</th>
                <th className="table-head p-2">Source</th>
                <th className="table-head p-2">Updated</th>
                <th className="table-head p-2">Approvals</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <tr
                  key={it.run_id}
                  className="cursor-pointer border-t border-ink-800/80 hover:bg-ink-800/30"
                  onClick={() => {
                    setSelectedRunID(it.run_id);
                    setDrawerOpen(true);
                  }}
                >
                  <td className="p-2">{it.severity || "-"}</td>
                  <td className="p-2">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedRunID(it.run_id);
                          setDrawerOpen(true);
                        }}
                        className="underline decoration-ink-600"
                      >
                        {it.run_id}
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          navigator.clipboard.writeText(it.run_id);
                        }}
                        className="btn-secondary px-1.5 py-0.5 text-[11px]"
                        title="Copy run_id"
                      >
                        copy
                      </button>
                      <Link
                        className="btn-secondary px-1.5 py-0.5 text-[11px]"
                        href={`/incidents/${encodeURIComponent(it.run_id)}`}
                        onClick={(e) => e.stopPropagation()}
                        title="Open dedicated detail page"
                      >
                        open
                      </Link>
                    </div>
                  </td>
                  <td className="p-2"><StatusBadge status={it.status} /></td>
                  <td className="p-2">
                    <div className="text-xs text-ink-200">{lifecycleLabel(it.lifecycle_state)}</div>
                    <div className="text-[11px] text-ink-400">{it.archived ? "archived" : "active set"}</div>
                  </td>
                  <td className="p-2"><LaneBadge lane={it.lane} /></td>
                  <td className="p-2">
                    <div className="font-medium">{it.rule_id || "-"}</div>
                    <div className="text-xs text-ink-300">{it.playbook_id || "-"}</div>
                  </td>
                  <td className="p-2">
                    <div className="font-medium">{it.node_id || "-"}</div>
                    <div className="mt-1 flex flex-wrap gap-1 text-[11px]">
                      {it.asset_environment ? (
                        <span className="rounded border border-ink-700/60 bg-ink-900/60 px-1.5 py-0.5 text-ink-200">
                          {it.asset_environment}
                        </span>
                      ) : null}
                      {it.asset_criticality ? (
                        <span className={`rounded border px-1.5 py-0.5 ${criticalityTone(it.asset_criticality)}`}>
                          {it.asset_criticality}
                        </span>
                      ) : null}
                    </div>
                    {it.asset_role ? <div className="text-[11px] text-ink-400">{it.asset_role}</div> : null}
                  </td>
                  <td className="p-2">
                    <div>{it.source_type || "-"}</div>
                    <div className="text-xs text-ink-300">{it.event_type || "-"}</div>
                    {(it.identity_display_name || it.user_name) ? (
                      <div className="mt-1 flex flex-wrap items-center gap-1 text-[11px]">
                        <span className="truncate text-ink-200">
                          {it.identity_display_name || it.user_name}
                          {it.identity_display_name && it.user_name ? ` (${it.user_name})` : ""}
                        </span>
                        {it.identity_service_account ? (
                          <span className="rounded border border-violet-700/60 bg-violet-950/70 px-1.5 py-0.5 text-violet-200">
                            svc
                          </span>
                        ) : null}
                        {it.identity_privileged ? (
                          <span className="rounded border border-amber-700/60 bg-amber-950/70 px-1.5 py-0.5 text-amber-200">
                            privileged
                          </span>
                        ) : null}
                      </div>
                    ) : null}
                    <div className="flex items-baseline gap-1 overflow-hidden text-[11px]">
                      <span className="shrink-0 text-ink-500">net:</span>
                      <span className="truncate font-mono text-ink-300">
                        {it.src_ip || "-"}{it.dst_ip ? ` -> ${it.dst_ip}` : ""}
                      </span>
                    </div>
                    {(it.comm || it.exec_path) ? (
                      <div className="flex items-baseline gap-1 overflow-hidden text-[11px]">
                        <span className="shrink-0 text-ink-500">proc:</span>
                        <span className="truncate font-mono text-ink-300">
                          {it.comm || it.exec_path}
                          {it.comm && it.exec_path ? ` (${it.exec_path})` : ""}
                        </span>
                      </div>
                    ) : null}
                  </td>
                  <td className="p-2">{unixMsToLocal(it.last_updated_at_unix_ms)}</td>
                  <td className="p-2">
                    {it.status?.toUpperCase() === "WAITING_APPROVAL" ? (
                      <div className="space-y-1">
                        <span className="rounded bg-rose-900 px-2 py-0.5 text-xs text-rose-300">needed</span>
                        {policyBadge(it.approval_policy_reason) ? (
                          <div className="text-[11px] text-ink-300">{policyBadge(it.approval_policy_reason)}</div>
                        ) : null}
                        <div className="text-[11px] text-ink-400">
                          conf {it.confidence_score ?? "-"} | {it.playbook_reversibility || "mixed"}
                        </div>
                        <div className="text-[11px] text-ink-400">
                          {it.environment_class || "operational"} | retain {it.archive_after_days ?? "-"}d/{it.purge_after_days ?? "-"}d
                        </div>
                        {it.retention_rule_id ? (
                          <div className="text-[11px] text-ink-500">retention: {it.retention_rule_id}</div>
                        ) : null}
                      </div>
                    ) : (
                      <div className="space-y-1">
                        <span className="text-xs text-ink-400">none</span>
                        {policyBadge(it.approval_policy_reason) ? (
                          <div className="text-[11px] text-ink-300">{policyBadge(it.approval_policy_reason)}</div>
                        ) : null}
                        <div className="text-[11px] text-ink-400">
                          {it.environment_class || "operational"} | retain {it.archive_after_days ?? "-"}d/{it.purge_after_days ?? "-"}d
                        </div>
                        {it.retention_rule_id ? (
                          <div className="text-[11px] text-ink-500">retention: {it.retention_rule_id}</div>
                        ) : null}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <div className="panel-elevated flex items-center justify-between px-3 py-2 text-xs text-ink-300">
        <div>
          total={total} page={page}/{pages}
        </div>
        <div className="flex items-center gap-2">
          <button
            className="btn-secondary px-2 py-1 text-xs disabled:opacity-50"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
          >
            Prev
          </button>
          <button
            className="btn-secondary px-2 py-1 text-xs disabled:opacity-50"
            onClick={() => setPage((p) => Math.min(pages, p + 1))}
            disabled={page >= pages}
          >
            Next
          </button>
        </div>
      </div>

      <IncidentDrawer
        runID={selectedRunID}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        fromMs={globalFrom}
        toMs={globalTo}
        initialTab={requestedTab || "overview"}
      />
    </section>
  );
}
