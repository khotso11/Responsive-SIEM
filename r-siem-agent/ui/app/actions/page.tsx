"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  clearEndpointAction,
  clearIncidentAction,
  getEndpointActions,
  getFleetActions,
  getIncidentActions,
  postEndpointAction,
  postIncidentAction
} from "@/lib/api";
import { INCIDENT_MUTATED_EVENT, INCIDENTS_UPDATED_EVENT } from "@/lib/events";
import { ResponseActionCatalogEntry, ResponseActionFleetResponse, ResponseActionListResponse, ResponseActionView } from "@/lib/types";
import { EmptyState, ErrorState, LoadingState, unixMsToLocal } from "@/components/ui";

function tone(bucket?: string): string {
  switch ((bucket || "").toLowerCase()) {
    case "pending":
      return "border-amber-700/60 bg-amber-950/20 text-amber-100";
    case "active":
      return "border-cyan-700/60 bg-cyan-950/20 text-cyan-100";
    case "cleared":
      return "border-emerald-700/60 bg-emerald-950/20 text-emerald-100";
    case "expired":
      return "border-fuchsia-700/60 bg-fuchsia-950/20 text-fuchsia-100";
    case "failed":
      return "border-rose-700/60 bg-rose-950/20 text-rose-100";
    default:
      return "border-ink-700/60 bg-ink-900/70 text-ink-200";
  }
}

function humanDuration(ms?: number): string {
  const value = Number(ms || 0);
  if (!Number.isFinite(value) || value <= 0) return "-";
  const hours = Math.round(value / 3_600_000);
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

export default function ActionsPage() {
  const [data, setData] = useState<ResponseActionFleetResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [bucket, setBucket] = useState("");
  const [scopeType, setScopeType] = useState("");
  const [page, setPage] = useState(1);
  const [actor, setActor] = useState("analyst");
  const [launchScopeType, setLaunchScopeType] = useState<"incident" | "endpoint">("incident");
  const [launchScopeID, setLaunchScopeID] = useState("");
  const [availableActions, setAvailableActions] = useState<ResponseActionCatalogEntry[]>([]);
  const [selectedActionName, setSelectedActionName] = useState("");
  const [durationMs, setDurationMs] = useState(2 * 60 * 60 * 1000);
  const [reason, setReason] = useState("");
  const [reference, setReference] = useState("");
  const [target, setTarget] = useState("");
  const [actionBusy, setActionBusy] = useState(false);
  const [actionMsg, setActionMsg] = useState("");

  const load = useCallback(async (opts?: { page?: number }) => {
    const nextPage = opts?.page || page;
    if (!data) setLoading(true);
    setError(null);
    try {
      const res = await getFleetActions({
        q: query.trim() || undefined,
        bucket: bucket || undefined,
        scope_type: scopeType || undefined,
        page: nextPage,
        limit: 100
      });
      setData(res);
      setPage(res.page || nextPage);
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setLoading(false);
    }
  }, [bucket, data, page, query, scopeType]);

  useEffect(() => {
    void load({ page: 1 });
  }, [load]);

  useEffect(() => {
    const reload = () => void load({ page });
    window.addEventListener(INCIDENTS_UPDATED_EVENT, reload);
    window.addEventListener(INCIDENT_MUTATED_EVENT, reload);
    return () => {
      window.removeEventListener(INCIDENTS_UPDATED_EVENT, reload);
      window.removeEventListener(INCIDENT_MUTATED_EVENT, reload);
    };
  }, [load, page]);

  const items = data?.items || [];
  const totalPages = Math.max(1, Math.ceil((data?.total || 0) / Math.max(1, data?.limit || 100)));

  const bucketCards = useMemo(() => [
    { key: "pending", label: "Pending", value: data?.buckets?.pending || 0 },
    { key: "active", label: "Active", value: data?.buckets?.active || 0 },
    { key: "cleared", label: "Cleared", value: data?.buckets?.cleared || 0 },
    { key: "expired", label: "Expired", value: data?.buckets?.expired || 0 },
    { key: "failed", label: "Failed", value: data?.buckets?.failed || 0 }
  ], [data?.buckets]);

  const selectedAction = useMemo(
    () =>
      availableActions.find((item) => item.id === selectedActionName) ||
      availableActions.find((item) => item.available) ||
      availableActions[0] ||
      null,
    [availableActions, selectedActionName]
  );

  const loadScopeCatalog = useCallback(async () => {
    const scopeID = launchScopeID.trim();
    if (!scopeID) {
      setAvailableActions([]);
      setSelectedActionName("");
      setActionMsg("Enter an incident run ID or endpoint node ID first.");
      return;
    }
    setActionMsg("");
    try {
      const res: ResponseActionListResponse =
        launchScopeType === "incident" ? await getIncidentActions(scopeID) : await getEndpointActions(scopeID);
      setAvailableActions(res.available_actions || []);
      const first = res.available_actions?.find((item) => item.available) || res.available_actions?.[0];
      setSelectedActionName(first?.id || "");
      setDurationMs(first?.default_duration_ms || 2 * 60 * 60 * 1000);
    } catch (e) {
      setAvailableActions([]);
      setSelectedActionName("");
      setActionMsg(`Failed loading scope actions: ${(e as Error).message}`);
    }
  }, [launchScopeID, launchScopeType]);

  useEffect(() => {
    setAvailableActions([]);
    setSelectedActionName("");
    setActionMsg("");
  }, [launchScopeType]);

  useEffect(() => {
    if (!selectedAction) return;
    setDurationMs(selectedAction.default_duration_ms || 2 * 60 * 60 * 1000);
  }, [selectedAction?.id]);

  const launchAction = async () => {
    const scopeID = launchScopeID.trim();
    if (!scopeID || !selectedAction) {
      setActionMsg("Load a valid scope and select an action first.");
      return;
    }
    if (!selectedAction.available) {
      setActionMsg(selectedAction.unavailable_reason || "Selected action is not available for this scope.");
      return;
    }
    try {
      setActionBusy(true);
      if (launchScopeType === "incident") {
        await postIncidentAction(scopeID, {
          actor,
          action_name: selectedAction.id,
          duration_ms: durationMs,
          reason: reason.trim(),
          reference: reference.trim(),
          target: target.trim()
        });
      } else {
        await postEndpointAction(scopeID, {
          actor,
          action_name: selectedAction.id,
          duration_ms: durationMs,
          reason: reason.trim(),
          reference: reference.trim(),
          target: target.trim(),
          target_agent_id: scopeID
        });
      }
      setActionMsg(`Action launched: ${selectedAction.label}`);
      setReason("");
      setReference("");
      setTarget("");
      await load({ page: 1 });
      await loadScopeCatalog();
    } catch (e) {
      setActionMsg(`Launch failed: ${(e as Error).message}`);
    } finally {
      setActionBusy(false);
    }
  };

  const clearAction = async (item: ResponseActionView) => {
    if (!item.clear_supported) return;
    try {
      setActionBusy(true);
      if (item.scope_type === "incident" && item.run_id) {
        await clearIncidentAction(item.run_id, item.action_id, {
          actor,
          reason: reason.trim() || "manual clear from actions page",
          reference: reference.trim()
        });
      } else if (item.scope_type === "endpoint" && item.node_id) {
        await clearEndpointAction(item.node_id, item.action_id, {
          actor,
          reason: reason.trim() || "manual clear from actions page",
          reference: reference.trim()
        });
      } else {
        throw new Error("Action scope is missing its run or node identifier");
      }
      setActionMsg(`Action cleared: ${item.action_id}`);
      await load({ page });
      if (launchScopeID.trim() && ((item.scope_type === "incident" && item.run_id === launchScopeID.trim()) || (item.scope_type === "endpoint" && item.node_id === launchScopeID.trim()))) {
        await loadScopeCatalog();
      }
    } catch (e) {
      setActionMsg(`Clear failed: ${(e as Error).message}`);
    } finally {
      setActionBusy(false);
    }
  };

  return (
    <section className="flex h-full min-h-0 flex-col gap-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="section-kicker">Fleet Response Actions</p>
          <h2 className="text-[18px] font-semibold text-ink-100">Actions</h2>
          <p className="text-[13px] text-ink-300">One ledger for incident-scoped and endpoint-scoped controls across the fleet.</p>
        </div>
      </div>

      <div className="rounded-2xl border border-ink-800 bg-ink-900/80 p-4">
        <div className="mb-3">
          <h3 className="text-sm font-semibold text-ink-100">Launch and Clear from Fleet Ledger</h3>
          <p className="text-xs text-ink-300">Operate on an incident run ID or endpoint node ID directly from this page.</p>
        </div>
        <div className="grid gap-3 xl:grid-cols-[140px_1fr_140px_140px]">
          <select className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm" value={launchScopeType} onChange={(e) => setLaunchScopeType(e.target.value as "incident" | "endpoint")}>
            <option value="incident">Incident</option>
            <option value="endpoint">Endpoint</option>
          </select>
          <input
            className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm outline-none focus:border-cyan-500"
            placeholder={launchScopeType === "incident" ? "run_id" : "node_id"}
            value={launchScopeID}
            onChange={(e) => setLaunchScopeID(e.target.value)}
          />
          <input
            className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm outline-none focus:border-cyan-500"
            placeholder="actor"
            value={actor}
            onChange={(e) => setActor(e.target.value)}
          />
          <button className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm font-medium text-ink-100" onClick={() => void loadScopeCatalog()}>
            Load Scope
          </button>
        </div>
        <div className="mt-3 grid gap-3 xl:grid-cols-[220px_180px_1fr_1fr_1fr_140px]">
          <select
            className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm"
            value={selectedActionName}
            onChange={(e) => setSelectedActionName(e.target.value)}
            disabled={availableActions.length === 0}
          >
              <option value="">{availableActions.length ? "Select action" : "No actions loaded"}</option>
              {availableActions.map((item) => (
              <option key={item.id} value={item.id} disabled={!item.available}>
                {item.label}{item.available ? "" : " (unavailable)"}
              </option>
            ))}
          </select>
          <select className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm" value={String(durationMs)} onChange={(e) => setDurationMs(Number(e.target.value))}>
            <option value={2 * 60 * 60 * 1000}>2 hours</option>
            <option value={24 * 60 * 60 * 1000}>1 day</option>
            <option value={30 * 24 * 60 * 60 * 1000}>30 days</option>
            <option value={365 * 24 * 60 * 60 * 1000}>1 year</option>
          </select>
          <input
            className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm outline-none focus:border-cyan-500"
            placeholder="reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          <input
            className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm outline-none focus:border-cyan-500"
            placeholder="reference"
            value={reference}
            onChange={(e) => setReference(e.target.value)}
          />
          <input
            className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm outline-none focus:border-cyan-500"
            placeholder="target override (optional)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
          <button className="rounded-lg bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50" disabled={actionBusy || !selectedAction || !selectedAction.available} onClick={() => void launchAction()}>
            Launch
          </button>
        </div>
        {selectedAction ? (
          <p className="mt-2 text-xs text-ink-300">
            {selectedAction.description} Mode: <span className="text-ink-100">{selectedAction.execution_mode}</span>.
          </p>
        ) : null}
        {availableActions.length > 0 ? (
          <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {availableActions.map((item) => (
              <div
                key={item.id}
                className={`rounded-lg border px-3 py-2 text-xs ${item.id === selectedAction?.id ? "border-cyan-600 bg-cyan-950/20" : "border-ink-800 bg-ink-950/40"}`}
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
        {selectedAction && !selectedAction.available ? (
          <div className="mt-2 rounded border border-amber-700/50 bg-amber-950/20 px-3 py-2 text-xs text-amber-100">
            {selectedAction.unavailable_reason || "This action is not available for the selected scope."}
          </div>
        ) : null}
        {actionMsg ? <div className="mt-3 rounded border border-ink-700/80 bg-ink-950/60 px-3 py-2 text-sm text-ink-200">{actionMsg}</div> : null}
      </div>

      <div className="grid gap-3 md:grid-cols-5">
        {bucketCards.map((card) => (
          <div key={card.key} className={`rounded-xl border px-4 py-3 ${tone(card.key)}`}>
            <div className="text-[11px] uppercase tracking-[0.28em] text-current/80">{card.label}</div>
            <div className="mt-2 text-2xl font-semibold">{card.value}</div>
          </div>
        ))}
      </div>

      <div className="rounded-2xl border border-ink-800 bg-ink-900/80 p-4">
        <div className="grid gap-3 xl:grid-cols-[2fr_180px_180px_120px]">
          <input
            className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm outline-none focus:border-cyan-500"
            placeholder="Search action id, label, node, run, target, reason"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void load({ page: 1 });
            }}
          />
          <select className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm" value={bucket} onChange={(e) => setBucket(e.target.value)}>
            <option value="">All buckets</option>
            <option value="pending">Pending</option>
            <option value="active">Active</option>
            <option value="cleared">Cleared</option>
            <option value="expired">Expired</option>
            <option value="failed">Failed</option>
          </select>
          <select className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm" value={scopeType} onChange={(e) => setScopeType(e.target.value)}>
            <option value="">All scopes</option>
            <option value="incident">Incident</option>
            <option value="endpoint">Endpoint</option>
          </select>
          <button className="rounded-lg bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950" onClick={() => void load({ page: 1 })}>
            Refresh
          </button>
        </div>
      </div>

      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {!loading && !error && items.length === 0 ? (
        <EmptyState title="No response actions found" detail="Launch an incident or endpoint action to populate the fleet action ledger." />
      ) : null}

      {!loading && !error && items.length > 0 ? (
        <div className="rounded-2xl border border-ink-800 bg-ink-900/80 p-4">
          <div className="mb-3 flex items-center justify-between text-xs text-ink-300">
            <span>Showing {data?.count || 0} of {data?.total || 0} actions.</span>
            <span>Page {page} / {totalPages}</span>
          </div>
          <div className="overflow-auto">
            <table className="min-w-[88rem] text-sm">
              <thead>
                <tr>
                  <th className="table-head p-2 text-left">Action</th>
                  <th className="table-head p-2 text-left">Scope</th>
                  <th className="table-head p-2 text-left">Lifecycle</th>
                  <th className="table-head p-2 text-left">Target</th>
                  <th className="table-head p-2 text-left">Duration</th>
                  <th className="table-head p-2 text-left">Actor</th>
                  <th className="table-head p-2 text-left">Operate</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item: ResponseActionView) => (
                  <tr key={`${item.scope_type}:${item.action_id}`} className="border-t border-ink-800/80 align-top">
                    <td className="p-2">
                      <div className="font-medium text-ink-100">{item.label}</div>
                      <div className="text-xs text-ink-400">{item.action_name}</div>
                      <div className="mt-1 text-xs text-ink-500">{item.action_id}</div>
                    </td>
                    <td className="p-2 text-ink-200">
                      <div>{item.scope_type}</div>
                      <div className="text-xs text-ink-400">{item.node_id || "-"}</div>
                    </td>
                    <td className="p-2">
                      <span className={`inline-flex rounded-full border px-2 py-1 text-xs font-medium ${tone(item.bucket)}`}>{item.bucket.toUpperCase()}</span>
                      <div className="mt-2 text-xs text-ink-300">{item.execution_mode || "-"}</div>
                      <div className="mt-1 text-xs text-ink-500">started {unixMsToLocal(item.started_at_unix_ms)}</div>
                      <div className="text-xs text-ink-500">expires {unixMsToLocal(item.expires_at_unix_ms)}</div>
                    </td>
                    <td className="p-2 text-ink-200">
                      <div>{item.target || "-"}</div>
                      <div className="text-xs text-ink-400">{item.direction || "-"}</div>
                      <div className="mt-1 text-xs text-ink-500 break-all">{item.reason || "-"}</div>
                    </td>
                    <td className="p-2 text-ink-200">
                      <div>{humanDuration(item.duration_ms)}</div>
                      <div className="text-xs text-ink-400">{item.clear_supported ? "clearable" : "no manual clear"}</div>
                    </td>
                    <td className="p-2 text-ink-200">
                      <div>{item.actor || "-"}</div>
                      <div className="text-xs text-ink-400 break-all">{item.reference || "-"}</div>
                    </td>
                    <td className="p-2 text-sm">
                      <div className="flex flex-col gap-1">
                        {item.run_id ? (
                          <Link className="text-cyan-300 underline decoration-cyan-700 underline-offset-2" href={`/open_run_id=${encodeURIComponent(item.run_id)}`}>
                            Open incident
                          </Link>
                        ) : null}
                        {item.node_id ? (
                          <Link className="text-cyan-300 underline decoration-cyan-700 underline-offset-2" href={`/endpoints?node_id=${encodeURIComponent(item.node_id)}`}>
                            View node
                          </Link>
                        ) : null}
                        {item.clear_supported && item.bucket === "active" ? (
                          <button
                            className="rounded-lg border border-ink-700 bg-ink-950/70 px-2 py-1 text-left text-amber-200 disabled:opacity-50"
                            disabled={actionBusy}
                            onClick={() => void clearAction(item)}
                          >
                            Clear action
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-4 flex items-center justify-end gap-2">
            <button
              className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm disabled:opacity-40"
              disabled={page <= 1}
              onClick={() => void load({ page: page - 1 })}
            >
              Previous
            </button>
            <button
              className="rounded-lg border border-ink-700 bg-ink-950/70 px-3 py-2 text-sm disabled:opacity-40"
              disabled={page >= totalPages}
              onClick={() => void load({ page: page + 1 })}
            >
              Next
            </button>
          </div>
        </div>
      ) : null}
    </section>
  );
}
