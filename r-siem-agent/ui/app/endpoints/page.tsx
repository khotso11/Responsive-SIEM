"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { clearEndpointAction, getEndpointActions, getEndpointEvents, getEndpointRuns, getEndpoints, getEndpointSummary, postEndpointAction, postEndpointTargetedTest } from "@/lib/api";
import { INCIDENT_MUTATED_EVENT, INCIDENTS_UPDATED_EVENT } from "@/lib/events";
import { EndpointDetailSummary, EndpointSummary, EventRow, Incident, ResponseActionListResponse, ResponseActionView } from "@/lib/types";
import { EmptyState, ErrorState, LaneBadge, LoadingState, StatusBadge, unixMsToLocal } from "@/components/ui";

const ACTION_DURATION_PRESETS: Array<{ label: string; value: number }> = [
  { label: "2 hours", value: 2 * 60 * 60 * 1000 },
  { label: "1 day", value: 24 * 60 * 60 * 1000 },
  { label: "30 days", value: 30 * 24 * 60 * 60 * 1000 },
  { label: "1 year", value: 365 * 24 * 60 * 60 * 1000 }
];

function humanDuration(value?: number): string {
  const ms = Number(value || 0);
  if (!Number.isFinite(ms) || ms <= 0) return "-";
  const hours = Math.round(ms / (60 * 60 * 1000));
  if (hours < 24) return `${hours}h`;
  const days = Math.round(hours / 24);
  if (days < 365) return `${days}d`;
  return `${Math.round(days / 365)}y`;
}

function eligibilityTone(available: boolean): string {
  return available
    ? "border-emerald-700/60 bg-emerald-950/20 text-emerald-100"
    : "border-amber-700/60 bg-amber-950/20 text-amber-100";
}

function actionBuckets(items?: ResponseActionView[]) {
  const out: Record<string, ResponseActionView[]> = { pending: [], active: [], cleared: [], expired: [], failed: [] };
  for (const item of items || []) {
    const key = (item.bucket || "active").toLowerCase();
    if (!out[key]) out[key] = [];
    out[key].push(item);
  }
  return out;
}

function parseQueryTime(v: string | null): number | undefined {
  if (!v) return undefined;
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return n;
  const p = Date.parse(v);
  if (!Number.isNaN(p) && p > 0) return p;
  return undefined;
}

function matchesActionTarget(event: EventRow, action: ResponseActionView): boolean {
  const target = String(action.target || "").trim().toLowerCase();
  const dnsTarget = String(action.details?.dns_name || "").trim().toLowerCase();
  const ipTarget = String(action.details?.dst_ip || "").trim();
  const execPath = typeof action.details?.exec_path === "string" ? action.details.exec_path : "";
  const comm = typeof action.details?.comm === "string" ? action.details.comm : "";
  switch (action.action_name) {
    case "block_all_outgoing":
      return Boolean(event.dst_ip);
    case "block_all_incoming":
      return Boolean(event.src_ip);
    case "block_matching_connections":
      return Boolean(
        (target && (event.dst_ip === target || (event.dns_name || "").toLowerCase() === target)) ||
        (dnsTarget && (event.dns_name || "").toLowerCase() === dnsTarget) ||
        (ipTarget && event.dst_ip === ipTarget)
      );
    case "enforce_pattern_of_life":
      return Boolean(
        (execPath && event.exec_path === execPath) ||
        (comm && event.comm === comm)
      );
    case "quarantine_device":
      return true;
    default:
      return false;
  }
}

function actionPhaseForEvent(event: EventRow, actions: ResponseActionView[]): Array<{ label: string; tone: string }> {
  const ts = event.recv_ts_unix_ms || 0;
  const phases: Array<{ label: string; tone: string }> = [];
  for (const action of actions) {
    if (!matchesActionTarget(event, action)) continue;
    const start = action.started_at_unix_ms || 0;
    const end = action.cleared_at_unix_ms || action.expires_at_unix_ms || 0;
    if (start > 0 && ts < start) {
      phases.push({ label: `before ${action.label}`, tone: "rounded-full border border-ink-700 bg-ink-900/60 px-2 py-0.5 text-[10px] text-ink-200" });
    } else if (start > 0 && (end === 0 || ts <= end)) {
      phases.push({ label: `during ${action.label}`, tone: "rounded-full border border-amber-700/70 bg-amber-950/40 px-2 py-0.5 text-[10px] text-amber-100" });
    } else if (end > 0 && ts > end) {
      phases.push({ label: `after ${action.label}`, tone: "rounded-full border border-emerald-700/70 bg-emerald-950/40 px-2 py-0.5 text-[10px] text-emerald-100" });
    }
  }
  return phases.slice(0, 2);
}

export default function EndpointsPage() {
  const searchParams = useSearchParams();
  const [items, setItems] = useState<EndpointSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [hasLoadedOnce, setHasLoadedOnce] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<EndpointSummary | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [nodeSummary, setNodeSummary] = useState<EndpointDetailSummary | null>(null);
  const [nodeEvents, setNodeEvents] = useState<EventRow[]>([]);
  const [nodeRuns, setNodeRuns] = useState<Incident[]>([]);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [actionMsg, setActionMsg] = useState("");
  const [actor, setActor] = useState("soc.analyst");
  const [nodeActions, setNodeActions] = useState<ResponseActionListResponse | null>(null);
  const [endpointActionName, setEndpointActionName] = useState("block_all_outgoing");
  const [endpointActionDurationMs, setEndpointActionDurationMs] = useState<number>(ACTION_DURATION_PRESETS[0].value);
  const [endpointActionReason, setEndpointActionReason] = useState("");
  const [endpointActionReference, setEndpointActionReference] = useState("");
  const [endpointActionTarget, setEndpointActionTarget] = useState("");
  const [eventFocus, setEventFocus] = useState("");
  const [endpointActionBusy, setEndpointActionBusy] = useState(false);

  const fromMs = useMemo(() => parseQueryTime(searchParams.get("gfrom")), [searchParams]);
  const toMs = useMemo(() => parseQueryTime(searchParams.get("gto")), [searchParams]);

  const load = useCallback(async () => {
    if (hasLoadedOnce) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);
    try {
      const res = await getEndpoints();
      setItems(res.items || []);
      setHasLoadedOnce(true);
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [hasLoadedOnce]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const onRefresh = () => {
      void load();
    };
    window.addEventListener(INCIDENTS_UPDATED_EVENT, onRefresh);
    window.addEventListener(INCIDENT_MUTATED_EVENT, onRefresh);
    return () => {
      window.removeEventListener(INCIDENTS_UPDATED_EVENT, onRefresh);
      window.removeEventListener(INCIDENT_MUTATED_EVENT, onRefresh);
    };
  }, [load]);

  const openDrawer = async (node: EndpointSummary) => {
    setSelectedNode(node);
    setDrawerOpen(true);
    setDrawerLoading(true);
    setActionMsg("");
    setEventFocus("");
    setNodeSummary(null);
    try {
      const qs = new URLSearchParams();
      if (fromMs) qs.set("from", String(fromMs));
      if (toMs) qs.set("to", String(toMs));
      qs.set("limit", "300");
      const [summaryRes, evRes, runRes, actionRes] = await Promise.all([
        getEndpointSummary(node.node_id, qs.toString()),
        getEndpointEvents(node.node_id, qs.toString()),
        getEndpointRuns(node.node_id, 120),
        getEndpointActions(node.node_id)
      ]);
      setNodeSummary(summaryRes.summary || null);
      setNodeEvents(evRes.items || []);
      setNodeRuns(runRes.items || []);
      setNodeActions(actionRes);
      if ((actionRes.available_actions || []).length > 0) {
        const first = actionRes.available_actions.find((item) => item.available) || actionRes.available_actions[0];
        setEndpointActionName(first?.id || "");
        setEndpointActionDurationMs(first?.default_duration_ms || ACTION_DURATION_PRESETS[0].value);
      }
    } catch (e) {
      setActionMsg(`Failed loading node details: ${(e as Error).message}`);
      setNodeSummary(null);
      setNodeEvents([]);
      setNodeRuns([]);
      setNodeActions(null);
    } finally {
      setDrawerLoading(false);
    }
  };

  const doTargetedTest = async () => {
    if (!selectedNode) return;
    try {
      const res = await postEndpointTargetedTest(selectedNode.node_id, actor, selectedNode.node_id);
      setActionMsg(`Targeted test published run_id=${res.run_id} step_id=${res.step_id}`);
    } catch (e) {
      setActionMsg(`Targeted test failed: ${(e as Error).message}`);
    }
  };

  const activity = useMemo(() => {
    if (!nodeEvents.length) return [] as Array<{ label: string; value: number }>;
    const byMinute = new Map<string, number>();
    for (const ev of nodeEvents) {
      const ts = new Date(ev.recv_ts_unix_ms || 0);
      const label = `${ts.getHours().toString().padStart(2, "0")}:${ts.getMinutes().toString().padStart(2, "0")}`;
      byMinute.set(label, (byMinute.get(label) || 0) + 1);
    }
    const out = [...byMinute.entries()].map(([label, value]) => ({ label, value }));
    out.sort((a, b) => a.label.localeCompare(b.label));
    return out.slice(-24);
  }, [nodeEvents]);

  const activityMax = Math.max(1, ...activity.map((x) => x.value));
  const nodeActionGroups = useMemo(() => actionBuckets(nodeActions?.items), [nodeActions?.items]);
  const selectedEndpointAction = useMemo(
    () =>
      nodeActions?.available_actions?.find((item) => item.id === endpointActionName) ||
      nodeActions?.available_actions?.find((item) => item.available) ||
      nodeActions?.available_actions?.[0] ||
      null,
    [endpointActionName, nodeActions?.available_actions]
  );
  const actionItems = nodeActions?.items || [];
  const filteredNodeEvents = useMemo(() => {
    const needle = eventFocus.trim().toLowerCase();
    if (!needle) return nodeEvents;
    return nodeEvents.filter((ev) =>
      [
        ev.source_type,
        ev.event_type,
        ev.rule_id,
        ev.user_name,
        ev.src_ip,
        ev.dst_ip,
        ev.protocol_family,
        ev.comm,
        ev.exec_path,
        ev.cmdline,
        ev.dns_name,
        ev.file_sha256,
        ev.exec_sha256
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle))
    );
  }, [eventFocus, nodeEvents]);

  const launchEndpointAction = async () => {
    if (!selectedNode || !selectedEndpointAction) return;
    if (!selectedEndpointAction.available) {
      setActionMsg(selectedEndpointAction.unavailable_reason || "Selected action is not available for this endpoint.");
      return;
    }
    try {
      setEndpointActionBusy(true);
      await postEndpointAction(selectedNode.node_id, {
        actor,
        action_name: selectedEndpointAction.id,
        duration_ms: endpointActionDurationMs,
        reason: endpointActionReason.trim(),
        reference: endpointActionReference.trim(),
        target: endpointActionTarget.trim(),
        target_agent_id: selectedNode.node_id
      });
      setActionMsg(`Endpoint action launched: ${selectedEndpointAction.label}`);
      setEndpointActionReason("");
      setEndpointActionReference("");
      setEndpointActionTarget("");
      setNodeActions(await getEndpointActions(selectedNode.node_id));
    } catch (e) {
      setActionMsg(`Endpoint action failed: ${(e as Error).message}`);
    } finally {
      setEndpointActionBusy(false);
    }
  };

  const clearNodeAction = async (actionID: string) => {
    if (!selectedNode) return;
    try {
      setEndpointActionBusy(true);
      await clearEndpointAction(selectedNode.node_id, actionID, {
        actor,
        reason: endpointActionReason.trim() || "manual clear from endpoint workspace",
        reference: endpointActionReference.trim()
      });
      setActionMsg(`Endpoint action cleared: ${actionID}`);
      setNodeActions(await getEndpointActions(selectedNode.node_id));
    } catch (e) {
      setActionMsg(`Clear failed: ${(e as Error).message}`);
    } finally {
      setEndpointActionBusy(false);
    }
  };

  return (
    <section className="flex h-full min-h-0 flex-col gap-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-[18px] font-semibold">Endpoints</h2>
          <p className="text-[13px] text-ink-300">Endpoint posture with activity rates and source distribution. Select a node to investigate.</p>
        </div>
        {refreshing ? (
          <div className="rounded border border-ink-700/80 bg-ink-900/60 px-2 py-1 text-[11px] text-ink-300">
            Refreshing...
          </div>
        ) : null}
      </div>

      {loading && !hasLoadedOnce ? <LoadingState /> : null}
      {error && !items.length ? <ErrorState message={error} /> : null}
      {error && items.length > 0 ? (
        <div className="rounded border border-rose-900/80 bg-rose-950/30 px-3 py-2 text-sm text-rose-200">
          {error}
        </div>
      ) : null}
      {!loading && !error && items.length === 0 ? <EmptyState title="No endpoint activity" /> : null}

      {!loading && !error && items.length > 0 ? (
        <div className="overflow-auto">
          <table className="min-w-full text-sm">
            <thead className="text-left">
              <tr>
                <th className="table-head p-2">Node</th>
                <th className="table-head p-2">Last seen</th>
                <th className="table-head p-2">Events (5m)</th>
                <th className="table-head p-2">Events (1h)</th>
                <th className="table-head p-2">Source distribution</th>
              </tr>
            </thead>
            <tbody>
              {items.map((ep) => (
                <tr key={ep.node_id} className="cursor-pointer border-t border-ink-800/80 hover:bg-ink-800/30" onClick={() => openDrawer(ep)}>
                  <td className="p-2 font-medium">
                    <button className="underline decoration-ink-600">{ep.node_id}</button>
                  </td>
                  <td className="p-2">{unixMsToLocal(ep.last_seen_unix_ms)}</td>
                  <td className="p-2">{ep.event_count_5m}</td>
                  <td className="p-2">{ep.event_count_1h}</td>
                  <td className="p-2">
                    {Object.keys(ep.source_type_distribution || {}).length === 0 ? (
                      <span className="text-ink-400">-</span>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {Object.entries(ep.source_type_distribution).map(([k, v]) => (
                          <span key={k} className="badge-info">{k}:{v}</span>
                        ))}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {drawerOpen && selectedNode ? (
        <div className="fixed inset-0 z-40 bg-black/50">
          <div className="absolute right-0 top-0 h-full w-full max-w-4xl overflow-auto border-l border-ink-700 bg-ink-950 p-4">
            <div className="mb-3 flex items-center justify-between">
              <div>
                <h3 className="text-[18px] font-semibold">Endpoint Workspace</h3>
                <p className="text-xs text-ink-300">node_id: {selectedNode.node_id}</p>
              </div>
              <button className="btn-secondary" onClick={() => setDrawerOpen(false)}>
                Close
              </button>
            </div>

            <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-4">
              <div className="panel-elevated p-3 text-sm">
                <div className="text-xs text-ink-300">Last seen</div>
                <div className="font-medium">{unixMsToLocal(selectedNode.last_seen_unix_ms)}</div>
              </div>
              <div className="panel-elevated p-3 text-sm">
                <div className="text-xs text-ink-300">Events 5m / 1h</div>
                <div className="font-medium">{selectedNode.event_count_5m} / {selectedNode.event_count_1h}</div>
              </div>
              <div className="panel-elevated p-3 text-sm">
                <div className="text-xs text-ink-300">Source distribution</div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {Object.entries(selectedNode.source_type_distribution || {}).map(([k, v]) => (
                    <span key={k} className="badge-info">{k}:{v}</span>
                  ))}
                </div>
              </div>
              <div className="panel-elevated p-3 text-sm">
                <div className="text-xs text-ink-300">Active actions / recent runs</div>
                <div className="font-medium">{nodeActions?.buckets?.active || 0} / {nodeRuns.length}</div>
              </div>
            </div>

            <div className="panel-elevated mb-4 p-3">
              <h4 className="mb-2 text-sm font-semibold">Targeted Action Test</h4>
              <div className="flex flex-wrap items-center gap-2">
                <input
                  value={actor}
                  onChange={(e) => setActor(e.target.value)}
                  className="input-field"
                  placeholder="actor"
                />
                <button className="btn-primary" onClick={doTargetedTest}>
                  Publish harmless targeted test
                </button>
              </div>
              {actionMsg ? <p className="mt-2 text-xs text-ink-300">{actionMsg}</p> : null}
            </div>

              <div className="panel-elevated mb-4 p-3">
                <div className="mb-2 flex items-center justify-between gap-2">
                  <h4 className="text-sm font-semibold">Response Actions</h4>
                <div className="flex flex-wrap gap-2 text-[11px] text-ink-300">
                  <span className="badge-info">pending:{nodeActions?.buckets?.pending || 0}</span>
                  <span className="badge-info">active:{nodeActions?.buckets?.active || 0}</span>
                  <span className="badge-info">cleared:{nodeActions?.buckets?.cleared || 0}</span>
                  <span className="badge-info">expired:{nodeActions?.buckets?.expired || 0}</span>
                </div>
              </div>
              <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                <select
                  value={selectedEndpointAction?.id || endpointActionName}
                  onChange={(e) => {
                    const nextID = e.target.value;
                    setEndpointActionName(nextID);
                    const next = nodeActions?.available_actions?.find((item) => item.id === nextID);
                    if (next?.default_duration_ms) setEndpointActionDurationMs(next.default_duration_ms);
                  }}
                  className="input-field w-full"
                >
                  {(nodeActions?.available_actions || []).map((item) => (
                    <option key={item.id} value={item.id} disabled={!item.available}>
                      {item.label}{item.available ? "" : " (unavailable)"}
                    </option>
                  ))}
                </select>
                <select value={String(endpointActionDurationMs)} onChange={(e) => setEndpointActionDurationMs(Number(e.target.value))} className="input-field w-full">
                  {ACTION_DURATION_PRESETS.map((preset) => (
                    <option key={preset.label} value={preset.value}>
                      {preset.label}
                    </option>
                  ))}
                </select>
              </div>
              {selectedEndpointAction ? (
                <div className="mt-2 rounded border border-ink-800 bg-ink-900/40 px-3 py-2 text-xs text-ink-300">
                  <div className="font-medium text-ink-100">{selectedEndpointAction.label}</div>
                  <div>{selectedEndpointAction.description}</div>
                  <div className="mt-1 flex flex-wrap gap-2">
                    <span className="badge-info">mode:{selectedEndpointAction.execution_mode}</span>
                    <span className="badge-info">clear:{selectedEndpointAction.clear_supported ? "supported" : "expiry only"}</span>
                    <span className="badge-info">default:{humanDuration(selectedEndpointAction.default_duration_ms)}</span>
                  </div>
                  {!selectedEndpointAction.available ? (
                    <div className="mt-2 rounded border border-amber-700/50 bg-amber-950/20 px-2 py-1 text-amber-100">
                      {selectedEndpointAction.unavailable_reason || "This action is not available for this endpoint."}
                    </div>
                  ) : null}
                </div>
              ) : null}
              {(nodeActions?.available_actions || []).length > 0 ? (
                <div className="mt-2 grid gap-2 lg:grid-cols-2">
                  {(nodeActions?.available_actions || []).map((item) => (
                    <div
                      key={item.id}
                      className={`rounded border px-3 py-2 text-xs ${item.id === selectedEndpointAction?.id ? "border-cyan-600 bg-cyan-950/20" : "border-ink-800 bg-ink-900/40"}`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="font-medium text-ink-100">{item.label}</div>
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.22em] ${eligibilityTone(item.available)}`}>
                          {item.available ? "Eligible" : "Not Eligible"}
                        </span>
                      </div>
                      <div className="mt-1 text-ink-300">{item.description}</div>
                      {!item.available && item.unavailable_reason ? (
                        <div className="mt-2 text-amber-100">{item.unavailable_reason}</div>
                      ) : null}
                    </div>
                  ))}
                </div>
              ) : null}
              <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
                <input value={endpointActionTarget} onChange={(e) => setEndpointActionTarget(e.target.value)} className="input-field mt-2 w-full md:col-span-1" placeholder="optional target override: IP, CIDR, or dns name" />
                <input value={endpointActionReference} onChange={(e) => setEndpointActionReference(e.target.value)} className="input-field mt-2 w-full md:col-span-1" placeholder="change / case reference" />
                <input value={endpointActionReason} onChange={(e) => setEndpointActionReason(e.target.value)} className="input-field mt-2 w-full md:col-span-1" placeholder="operator reason" />
              </div>
              <button disabled={endpointActionBusy || !selectedEndpointAction || !selectedEndpointAction.available} className="btn-primary mt-2 disabled:opacity-60" onClick={launchEndpointAction}>
                Launch Endpoint Action
              </button>
            </div>

            {drawerLoading ? <LoadingState /> : null}
            {!drawerLoading ? (
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.3fr_1fr]">
                <div className="panel-elevated p-3">
                  <h4 className="mb-2 text-sm font-semibold">Device Summary</h4>
                  {activity.length === 0 ? <EmptyState title="No activity buckets" /> : null}
                  {activity.length > 0 ? (
                    <div className="mb-3 flex items-end gap-1 rounded border border-ink-700/70 bg-ink-900/40 p-2">
                      {activity.map((b) => {
                        const h = Math.max(8, Math.round((b.value / activityMax) * 68));
                        return <div key={b.label} className="w-3 rounded-t bg-cyan-400/90" style={{ height: `${h}px` }} title={`${b.label}: ${b.value}`} />;
                      })}
                    </div>
                  ) : null}

                  <div className="mb-3 grid grid-cols-2 gap-2 text-xs">
                    <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-2">
                      <div className="text-ink-400">Events in window</div>
                      <div className="mt-1 text-lg font-semibold">{nodeSummary?.total_events ?? nodeEvents.length}</div>
                    </div>
                    <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-2">
                      <div className="text-ink-400">Detections</div>
                      <div className="mt-1 text-lg font-semibold">{nodeSummary?.detection_count ?? nodeRuns.length}</div>
                    </div>
                    <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-2">
                      <div className="text-ink-400">Active actions</div>
                      <div className="mt-1 text-lg font-semibold">{nodeSummary?.active_action_count ?? nodeActions?.buckets?.active ?? 0}</div>
                    </div>
                    <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-2">
                      <div className="text-ink-400">Recent runs</div>
                      <div className="mt-1 text-lg font-semibold">{nodeSummary?.recent_run_count ?? nodeRuns.length}</div>
                    </div>
                  </div>

                  {nodeSummary ? (
                    <div className="mb-4 grid gap-3 lg:grid-cols-2">
                      <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-3 text-xs">
                        <div className="mb-2 text-ink-400">Top destinations</div>
                        <div className="space-y-1">
                          {(nodeSummary.top_destinations || []).length === 0 ? <div className="text-ink-500">No destination IPs in window.</div> : null}
                          {(nodeSummary.top_destinations || []).map((item) => (
                            <div key={item.value} className="flex items-center justify-between gap-2">
                              <span className="truncate text-ink-100">{item.value}</span>
                              <span className="text-ink-400">{item.count}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-3 text-xs">
                        <div className="mb-2 text-ink-400">Top domains</div>
                        <div className="space-y-1">
                          {(nodeSummary.top_domains || []).length === 0 ? <div className="text-ink-500">No DNS targets in window.</div> : null}
                          {(nodeSummary.top_domains || []).map((item) => (
                            <div key={item.value} className="flex items-center justify-between gap-2">
                              <span className="truncate text-ink-100">{item.value}</span>
                              <span className="text-ink-400">{item.count}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-3 text-xs">
                        <div className="mb-2 text-ink-400">Top users</div>
                        <div className="space-y-1">
                          {(nodeSummary.top_users || []).length === 0 ? <div className="text-ink-500">No attributed users in window.</div> : null}
                          {(nodeSummary.top_users || []).map((item) => (
                            <div key={item.value} className="flex items-center justify-between gap-2">
                              <span className="truncate text-ink-100">{item.value}</span>
                              <span className="text-ink-400">{item.count}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-3 text-xs">
                        <div className="mb-2 text-ink-400">Top rules</div>
                        <div className="space-y-1">
                          {(nodeSummary.top_rules || []).length === 0 ? <div className="text-ink-500">No rules matched in window.</div> : null}
                          {(nodeSummary.top_rules || []).map((item) => (
                            <div key={item.value} className="flex items-center justify-between gap-2">
                              <span className="truncate text-ink-100">{item.value}</span>
                              <span className="text-ink-400">{item.count}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  ) : null}

                  <h4 className="mb-2 text-sm font-semibold">Device Event Logs</h4>
                  <div className="mb-2 flex items-center gap-2">
                    <input
                      value={eventFocus}
                      onChange={(e) => setEventFocus(e.target.value)}
                      className="input-field w-full"
                      placeholder="Filter by rule, IP, dns name, process, or hash"
                    />
                    <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-2 text-xs text-ink-300">
                      {filteredNodeEvents.length} rows
                    </div>
                  </div>
                  {filteredNodeEvents.length === 0 ? <EmptyState title="No events in selected window" /> : null}
                  {filteredNodeEvents.length > 0 ? (
                    <div className="max-h-[420px] overflow-auto text-xs">
                      <table className="min-w-[82rem]">
                        <thead className="text-left">
                          <tr>
                            <th className="table-head p-1.5">Time</th>
                            <th className="table-head p-1.5">Source/Event</th>
                            <th className="table-head p-1.5">Rule/User</th>
                            <th className="table-head p-1.5">Network</th>
                            <th className="table-head p-1.5">Process</th>
                            <th className="table-head p-1.5">Evidence</th>
                            <th className="table-head p-1.5">Action lens</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredNodeEvents.map((ev) => {
                            const phases = actionPhaseForEvent(ev, actionItems);
                            return (
                            <tr key={`${ev.event_idem_key}-${ev.recv_ts_unix_ms}`} className="border-t border-ink-800/80">
                              <td className="p-1.5">{unixMsToLocal(ev.recv_ts_unix_ms)}</td>
                              <td className="p-1.5">
                                <div className="font-medium text-ink-100">{ev.source_type}/{ev.event_type}</div>
                                <div className="text-ink-400">{ev.event_idem_key}</div>
                              </td>
                              <td className="p-1.5">
                                <div>{ev.rule_id || "-"}</div>
                                <div className="text-ink-400">{ev.user_name || "-"}</div>
                              </td>
                              <td className="p-1.5">
                                <div>{[ev.src_ip || "-", ev.dst_ip || "-"].join(" -> ")}</div>
                                <div className="text-ink-400">{[ev.dst_port ? String(ev.dst_port) : "-", ev.protocol_family || "-"].join(" / ")}</div>
                              </td>
                              <td className="p-1.5">
                                <div>{ev.comm || ev.exec_path || "-"}</div>
                                <div className="max-w-[20rem] truncate text-ink-400">{ev.cmdline || "-"}</div>
                              </td>
                              <td className="p-1.5">
                                <div>{ev.dns_name || "-"}</div>
                                <div className="max-w-[16rem] truncate text-ink-400">{ev.file_sha256 || ev.exec_sha256 || ev.raw_line_sha256 || "-"}</div>
                              </td>
                              <td className="p-1.5">
                                {phases.length === 0 ? <span className="text-ink-500">No matching action window</span> : null}
                                {phases.length > 0 ? (
                                  <div className="flex flex-wrap gap-1">
                                    {phases.map((phase) => (
                                      <span key={`${ev.event_idem_key}-${phase.label}`} className={phase.tone}>{phase.label}</span>
                                    ))}
                                  </div>
                                ) : null}
                              </td>
                            </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  ) : null}
                </div>

                <div className="panel-elevated p-3">
                  <h4 className="mb-2 text-sm font-semibold">Recent Runs Affecting Node</h4>
                  {nodeRuns.length === 0 ? <EmptyState title="No runs for this node" /> : null}
                  {nodeRuns.length > 0 ? (
                    <div className="max-h-[420px] space-y-2 overflow-auto">
                      {nodeRuns.map((run) => (
                        <div key={run.run_id} className="rounded border border-ink-700 p-2 text-xs">
                          <div className="mb-1 flex items-center justify-between gap-2">
                            <span className="font-medium">{run.run_id}</span>
                            <StatusBadge status={run.status} />
                          </div>
                          <div className="mb-1 flex items-center gap-2">
                            <LaneBadge lane={run.lane} />
                            <span>{run.rule_id || "-"}</span>
                          </div>
                          <div className="text-ink-300">{unixMsToLocal(run.last_updated_at_unix_ms)}</div>
                        </div>
                      ))}
                    </div>
                  ) : null}

                  <h4 className="mb-3 mt-4 text-sm font-semibold">Action Lifecycle</h4>
                  {(["active", "pending", "cleared", "expired", "failed"] as const).map((bucket) => (
                    <div key={bucket} className="mb-3">
                      <div className="mb-1 text-xs uppercase tracking-[0.22em] text-ink-400">{bucket}</div>
                      {(nodeActionGroups[bucket] || []).length === 0 ? (
                        <div className="rounded border border-ink-800 bg-ink-900/30 px-3 py-2 text-xs text-ink-400">No {bucket} actions.</div>
                      ) : (
                        <div className="space-y-2">
                          {(nodeActionGroups[bucket] || []).map((item) => (
                            <div key={item.action_id} className="rounded border border-ink-700 bg-ink-900/40 px-3 py-2 text-xs">
                              <div className="flex items-center justify-between gap-2">
                                <span className="font-medium">{item.label}</span>
                                <StatusBadge status={item.status} />
                              </div>
                              <div className="mt-1 text-ink-300">{item.target || selectedNode.node_id} • {item.execution_mode || item.action_type}</div>
                              <div className="mt-1 text-ink-400">
                                {item.started_at_unix_ms ? unixMsToLocal(item.started_at_unix_ms) : "-"} • expires {item.expires_at_unix_ms ? unixMsToLocal(item.expires_at_unix_ms) : "-"} • {humanDuration(item.duration_ms)}
                              </div>
                              {item.clear_supported && item.bucket === "active" ? (
                                <button disabled={endpointActionBusy} className="btn-secondary mt-2 disabled:opacity-60" onClick={() => clearNodeAction(item.action_id)}>
                                  Clear Action
                                </button>
                              ) : null}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </section>
  );
}
