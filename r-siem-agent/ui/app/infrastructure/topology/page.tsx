"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getInfrastructureTopology, postInfrastructureEveNodeAction } from "@/lib/api";
import { INCIDENT_MUTATED_EVENT, INCIDENTS_UPDATED_EVENT } from "@/lib/events";
import {
  InfrastructureCollector,
  InfrastructureTopologyLink,
  InfrastructureTopologyNode,
  InfrastructureTopologyResponse,
  InfrastructureTopologyTest
} from "@/lib/types";
import { infrastructureBadgeClass, infrastructureLabel } from "@/lib/infrastructure";
import { EmptyState, ErrorState, LoadingState, unixMsToLocal } from "@/components/ui";

function parseQueryTime(v: string | null): number | undefined {
  if (!v) return undefined;
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return n;
  const p = Date.parse(v);
  if (!Number.isNaN(p) && p > 0) return p;
  return undefined;
}

function toneForNodeStatus(status?: string): string {
  switch ((status || "").toLowerCase()) {
    case "containment_active":
      return "border-rose-700/60 bg-rose-950/35 text-rose-100";
    case "alerting":
      return "border-amber-700/60 bg-amber-950/35 text-amber-100";
    case "telemetry_live":
      return "border-cyan-700/60 bg-cyan-950/35 text-cyan-100";
    default:
      return "border-ink-700/60 bg-ink-900/60 text-ink-200";
  }
}

function eveNodeCardTone(runtimeStatus?: string, liveStatus?: string): string {
  switch ((runtimeStatus || "").toLowerCase()) {
    case "running":
      return "border-emerald-600/80 bg-gradient-to-br from-emerald-950/40 to-cyan-950/20 shadow-[0_0_0_1px_rgba(16,185,129,0.18)]";
    case "building":
      return "border-amber-600/80 bg-gradient-to-br from-amber-950/35 to-ink-950/25 shadow-[0_0_0_1px_rgba(245,158,11,0.14)]";
    case "stopped":
      return "border-rose-800/70 bg-gradient-to-br from-rose-950/30 to-ink-950/25";
    case "not_found":
      return "border-fuchsia-800/70 bg-gradient-to-br from-fuchsia-950/20 to-ink-950/25";
  }
  switch ((liveStatus || "").toLowerCase()) {
    case "containment_active":
      return "border-rose-700/80 bg-gradient-to-br from-rose-950/35 to-ink-950/25";
    case "alerting":
      return "border-amber-700/80 bg-gradient-to-br from-amber-950/30 to-ink-950/25";
    case "telemetry_live":
      return "border-cyan-700/80 bg-gradient-to-br from-cyan-950/30 to-ink-950/25";
    default:
      return "border-ink-800 bg-ink-950/30";
  }
}

function toneForTestStatus(status?: string): string {
  switch ((status || "").toLowerCase()) {
    case "verified":
      return "border-emerald-700/60 bg-emerald-950/35 text-emerald-100";
    case "responding":
      return "border-cyan-700/60 bg-cyan-950/35 text-cyan-100";
    case "observed":
      return "border-amber-700/60 bg-amber-950/35 text-amber-100";
    default:
      return "border-ink-700/60 bg-ink-900/60 text-ink-200";
  }
}

function providerStatusTone(status?: string): string {
  switch ((status || "").toLowerCase()) {
    case "imported":
      return "border-emerald-700/60 bg-emerald-950/35 text-emerald-100";
    case "configured":
      return "border-amber-700/60 bg-amber-950/35 text-amber-100";
    case "parse_error":
      return "border-rose-700/60 bg-rose-950/35 text-rose-100";
    default:
      return "border-ink-700/60 bg-ink-900/60 text-ink-200";
  }
}

function eveRuntimeTone(status?: string): string {
  switch ((status || "").toLowerCase()) {
    case "running":
    case "connected":
      return "border-emerald-700/60 bg-emerald-950/35 text-emerald-100";
    case "building":
    case "configured":
      return "border-amber-700/60 bg-amber-950/35 text-amber-100";
    case "auth_failed":
    case "connect_error":
    case "query_failed":
    case "parse_error":
      return "border-rose-700/60 bg-rose-950/35 text-rose-100";
    default:
      return "border-ink-700/60 bg-ink-900/60 text-ink-200";
  }
}

function activityTone(kind?: string): string {
  switch ((kind || "").toLowerCase()) {
    case "incident":
      return "border-amber-700/60 bg-amber-950/20 text-amber-100";
    case "action":
      return "border-rose-700/60 bg-rose-950/20 text-rose-100";
    default:
      return "border-cyan-700/60 bg-cyan-950/20 text-cyan-100";
  }
}

function statusLabel(status?: string): string {
  return (status || "quiet").replaceAll("_", " ");
}

function zoneTitle(name: string): string {
  switch (name) {
    case "management":
      return "Management Plane";
    case "user_lan":
      return "User LAN";
    case "server_lan":
      return "Server LAN";
    case "dmz":
      return "DMZ";
    case "red_team":
      return "Red Team";
    default:
      return name.replaceAll("_", " ");
  }
}

function zoneTone(name: string): string {
  switch (name) {
    case "management":
      return "border-cyan-800/70 bg-cyan-950/20";
    case "red_team":
      return "border-rose-800/70 bg-rose-950/20";
    case "dmz":
      return "border-fuchsia-800/70 bg-fuchsia-950/20";
    case "server_lan":
      return "border-emerald-800/70 bg-emerald-950/20";
    case "user_lan":
      return "border-sky-800/70 bg-sky-950/20";
    default:
      return "border-ink-800/70 bg-ink-950/20";
  }
}

function nodeRoleLabel(role?: string): string {
  return (role || "node").replaceAll("_", " ");
}

function linkState(endpoints: InfrastructureTopologyNode[]): { label: string; tone: string } {
  const runtimeStates = endpoints.map((node) => (node.live.eve_runtime_status || "").toLowerCase()).filter(Boolean);
  const running = runtimeStates.filter((item) => item === "running").length;
  const stopped = runtimeStates.filter((item) => item === "stopped").length;
  const building = runtimeStates.filter((item) => item === "building").length;
  if (running > 0 && stopped === 0 && building === 0) {
    return { label: "live", tone: "border-emerald-700/70 bg-emerald-950/25 text-emerald-100" };
  }
  if (running > 0 || building > 0) {
    return { label: "partial", tone: "border-amber-700/70 bg-amber-950/25 text-amber-100" };
  }
  if (stopped > 0) {
    return { label: "down", tone: "border-rose-700/70 bg-rose-950/25 text-rose-100" };
  }
  return { label: "unknown", tone: "border-ink-700/70 bg-ink-900/60 text-ink-200" };
}

function commandToSearchHref(test: InfrastructureTopologyTest): string {
  if (test.expected_rule_id) {
    return `/search?category=infrastructure&rule_id=${encodeURIComponent(test.expected_rule_id)}`;
  }
  return "/search?category=infrastructure";
}

function NodeCard({
  node,
  selected,
  onSelect
}: {
  node: InfrastructureTopologyNode;
  selected: boolean;
  onSelect: (nodeID: string) => void;
}) {
  return (
    <button
      onClick={() => onSelect(node.id)}
      className={`w-full rounded-2xl border p-3 text-left transition ${selected ? "border-cyan-400/90 shadow-[0_0_0_1px_rgba(34,211,238,0.32)]" : "hover:border-ink-700"} ${eveNodeCardTone(node.live.eve_runtime_status, node.live.status)}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-ink-100">{node.label}</div>
          <div className="mt-1 text-[11px] uppercase tracking-[0.18em] text-ink-400">{nodeRoleLabel(node.role)}</div>
          {node.eve_node_name ? <div className="mt-1 text-[11px] text-cyan-300">EVE node {node.eve_node_name}</div> : null}
        </div>
        <div className="flex flex-col items-end gap-1">
          <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${toneForNodeStatus(node.live.status)}`}>
            {statusLabel(node.live.status)}
          </span>
          {node.live.eve_runtime_status ? (
            <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${eveRuntimeTone(node.live.eve_runtime_status)}`}>
              eve {statusLabel(node.live.eve_runtime_status)}
            </span>
          ) : null}
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-ink-300">
        {node.os ? <span className="rounded border border-ink-700/70 bg-ink-900/70 px-2 py-1">{node.os}</span> : null}
        {node.agent_support ? <span className="rounded border border-emerald-700/60 bg-emerald-950/20 px-2 py-1 text-emerald-100">agent</span> : null}
        {node.mgmt_ip ? <span className="rounded border border-ink-700/70 bg-ink-900/70 px-2 py-1">mgmt {node.mgmt_ip}</span> : null}
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-ink-300">
        <div className="rounded border border-ink-800/80 bg-ink-950/40 px-2 py-2">
          <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Events</div>
          <div className="mt-1 text-sm font-semibold text-ink-100">{node.live.recent_event_count}</div>
        </div>
        <div className="rounded border border-ink-800/80 bg-ink-950/40 px-2 py-2">
          <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Actions</div>
          <div className="mt-1 text-sm font-semibold text-ink-100">{node.live.active_action_count}</div>
        </div>
      </div>
    </button>
  );
}

function LinkCard({
  link,
  nodesByKey,
  onSelect
}: {
  link: InfrastructureTopologyLink;
  nodesByKey: Map<string, InfrastructureTopologyNode>;
  onSelect: (nodeID: string) => void;
}) {
  const endpoints = link.endpoints
    .map((endpoint) => nodesByKey.get(endpoint.toLowerCase()))
    .filter((node): node is InfrastructureTopologyNode => Boolean(node));
  const state = linkState(endpoints);
  return (
    <div className={`rounded-2xl border p-3 ${state.tone}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="font-medium">{link.label || link.id}</div>
        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${state.tone}`}>{state.label}</span>
      </div>
      <div className="mt-1 text-[11px] uppercase tracking-[0.18em] opacity-80">{link.network || "-"}</div>
      <div className="mt-3 flex flex-wrap gap-2 text-xs">
        {link.endpoints.map((endpoint) => {
          const node = nodesByKey.get(endpoint.toLowerCase());
          return (
            <button
              key={endpoint}
              onClick={() => node && onSelect(node.id)}
              className={`rounded border px-2 py-1 ${node ? "border-ink-700/70 bg-ink-950/40 hover:border-cyan-500/60" : "border-ink-800/80 bg-ink-950/20"}`}
            >
              {endpoint}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function CollectorCard({ item }: { item: InfrastructureCollector }) {
  return (
    <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-ink-100">{item.source}</div>
          <div className="mt-1 text-xs text-ink-400">{item.collector_binary}</div>
        </div>
        <span className="rounded-full border border-cyan-700/60 bg-cyan-950/30 px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] text-cyan-100">
          {item.source_type}
        </span>
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-ink-300">
        <div className="rounded border border-ink-800/80 bg-ink-950/40 px-2 py-2">
          <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Recent events</div>
          <div className="mt-1 text-sm font-semibold text-ink-100">{item.live.recent_event_count}</div>
        </div>
        <div className="rounded border border-ink-800/80 bg-ink-950/40 px-2 py-2">
          <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Active exporters</div>
          <div className="mt-1 text-sm font-semibold text-ink-100">{item.live.active_exporters}/{item.exporters.length}</div>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-ink-300">
        {item.expected_use_cases.map((useCase) => (
          <span key={useCase} className="rounded border border-ink-700/70 bg-ink-900/60 px-2 py-1">
            {useCase.replaceAll("_", " ")}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function InfrastructureTopologyPage() {
  const searchParams = useSearchParams();
  const [data, setData] = useState<InfrastructureTopologyResponse | null>(null);
  const [selectedNodeID, setSelectedNodeID] = useState("");
  const [sideTab, setSideTab] = useState<"node" | "collectors" | "eve">("node");
  const [loading, setLoading] = useState(true);
  const [hasLoadedOnce, setHasLoadedOnce] = useState(false);
  const hasLoadedOnceRef = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [controlBusy, setControlBusy] = useState<"" | "start" | "stop" | "wipe">("");
  const [controlMessage, setControlMessage] = useState<string>("");
  const [controlError, setControlError] = useState<string>("");
  const globalFrom = useMemo(() => parseQueryTime(searchParams.get("gfrom")), [searchParams]);
  const globalTo = useMemo(() => parseQueryTime(searchParams.get("gto")), [searchParams]);

  const load = useCallback(async () => {
    if (!hasLoadedOnceRef.current) setLoading(true);
    setError(null);
    try {
      const res = await getInfrastructureTopology(globalFrom, globalTo);
      setData(res);
      hasLoadedOnceRef.current = true;
      setHasLoadedOnce(true);
      setSelectedNodeID((current) => current || res.nodes[0]?.id || "");
    } catch (err) {
      setError((err as Error).message || String(err));
    } finally {
      setLoading(false);
    }
  }, [globalFrom, globalTo]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const onRefresh = () => void load();
    window.addEventListener(INCIDENTS_UPDATED_EVENT, onRefresh);
    window.addEventListener(INCIDENT_MUTATED_EVENT, onRefresh);
    const interval = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        void load();
      }
    }, 15000);
    return () => {
      window.removeEventListener(INCIDENTS_UPDATED_EVENT, onRefresh);
      window.removeEventListener(INCIDENT_MUTATED_EVENT, onRefresh);
      window.clearInterval(interval);
    };
  }, [load]);

  const selectedNode = useMemo(
    () => data?.nodes.find((node) => node.id === selectedNodeID) || data?.nodes[0] || null,
    [data?.nodes, selectedNodeID]
  );

  const managementNodes = useMemo(() => data?.nodes.filter((node) => node.networks?.includes("management") || node.role === "management") || [], [data?.nodes]);
  const backboneNodes = useMemo(
    () => data?.nodes.filter((node) => ["router", "firewall_gateway", "switch_segment", "attacker_simulation"].includes(node.role)) || [],
    [data?.nodes]
  );
  const zoneNodes = useMemo(() => {
    const zones = ["user_lan", "server_lan", "dmz", "red_team"] as const;
    return Object.fromEntries(
      zones.map((zone) => [zone, (data?.nodes || []).filter((node) => node.networks?.includes(zone) && !backboneNodes.some((item) => item.id === node.id))])
    ) as Record<string, InfrastructureTopologyNode[]>;
  }, [backboneNodes, data?.nodes]);
  const nodesByLookup = useMemo(() => {
    const items = new Map<string, InfrastructureTopologyNode>();
    for (const node of data?.nodes || []) {
      for (const key of [node.id, node.label, node.eve_node_name]) {
        const normalized = (key || "").trim().toLowerCase();
        if (normalized) items.set(normalized, node);
      }
    }
    return items;
  }, [data?.nodes]);

  const runNodeControl = useCallback(
    async (action: "start" | "stop" | "wipe") => {
      if (!selectedNode?.eve_node_id) return;
      setControlBusy(action);
      setControlError("");
      setControlMessage("");
      try {
        const res = await postInfrastructureEveNodeAction(selectedNode.id, action);
        setControlMessage(`${res.result.action} completed for ${res.result.node_name || selectedNode.label} (${res.result.runtime_status || "unknown"})`);
        await load();
      } catch (err) {
        setControlError((err as Error).message || String(err));
      } finally {
        setControlBusy("");
      }
    },
    [load, selectedNode]
  );

  return (
    <section className="flex h-full min-h-0 flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-[11px] uppercase tracking-[0.24em] text-cyan-300">Infrastructure Topology</div>
          <h2 className="mt-1 text-[24px] font-semibold tracking-tight">Infrastructure Topology</h2>
          <p className="mt-1 max-w-4xl text-[13px] text-ink-300">
            Topology imported from the EVE-NG lab file and enriched with live incidents, telemetry, collectors, and controlled response activity.
          </p>
        </div>
        <div className="flex flex-wrap gap-2 text-xs">
          <Link className="btn-secondary px-3 py-2 text-xs" href="/infrastructure">Infrastructure Queue</Link>
          <Link className="btn-secondary px-3 py-2 text-xs" href="/infrastructure/runbook">EVE-NG Runbook</Link>
          <Link className="btn-secondary px-3 py-2 text-xs" href="/search?category=infrastructure">Search Infrastructure</Link>
          <Link className="btn-secondary px-3 py-2 text-xs" href="/actions?scope_type=incident&q=infra_">Response Actions</Link>
          <button className="btn-secondary px-3 py-2 text-xs" onClick={() => void load()}>Refresh</button>
        </div>
      </div>

      {loading && !hasLoadedOnce ? <LoadingState /> : null}
      {error && !data ? <ErrorState message={error} /> : null}
      {!loading && !error && !data ? <EmptyState title="No topology data" detail="The infrastructure topology API returned no data." /> : null}

      {data ? (
        <>
          <div className="grid grid-cols-2 gap-2 xl:grid-cols-6">
            <div className="panel-elevated p-3">
              <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Nodes</div>
              <div className="mt-2 text-[24px] font-semibold text-ink-100">{data.summary.node_count}</div>
            </div>
            <div className="panel-elevated p-3">
              <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Live nodes</div>
              <div className="mt-2 text-[24px] font-semibold text-cyan-100">{data.summary.live_node_count}</div>
            </div>
            <div className="panel-elevated p-3">
              <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Infra runs</div>
              <div className="mt-2 text-[24px] font-semibold text-ink-100">{data.summary.infrastructure_runs}</div>
            </div>
            <div className="panel-elevated p-3">
              <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Open runs</div>
              <div className="mt-2 text-[24px] font-semibold text-amber-100">{data.summary.open_infrastructure_runs}</div>
            </div>
            <div className="panel-elevated p-3">
              <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Active controls</div>
              <div className="mt-2 text-[24px] font-semibold text-rose-100">{data.summary.active_action_count}</div>
            </div>
            <div className="panel-elevated p-3">
              <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Verified blocks</div>
              <div className="mt-2 text-[24px] font-semibold text-emerald-100">{data.summary.verified_block_count}</div>
            </div>
          </div>

          <div className="panel-elevated p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">EVE-NG Lab Source</div>
                <div className="mt-1 text-lg font-semibold text-ink-100">{data.provider.name || "EVE-NG lab"}</div>
                <div className="mt-1 text-sm text-ink-300">
                  The topology model is sourced from the imported EVE-NG lab file, then overlaid with live R-SIEM incidents, collectors, events, and response actions.
                </div>
              </div>
              <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${providerStatusTone(data.provider.source_status)}`}>
                {statusLabel(data.provider.source_status)}
              </span>
            </div>
            <div className="mt-4 grid gap-3 lg:grid-cols-4">
              <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
                <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Provider</div>
                <div className="mt-1 text-sm font-semibold text-ink-100">{data.provider.kind || "-"}</div>
              </div>
              <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
                <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">EVE UI</div>
                <div className="mt-1 break-all text-sm text-ink-100">{data.provider.ui_url || "-"}</div>
              </div>
              <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
                <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Lab file</div>
                <div className="mt-1 break-all text-sm text-ink-100">{data.provider.lab_file || "-"}</div>
              </div>
              <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
                <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Imported topology</div>
                <div className="mt-1 break-all text-sm text-ink-100">{data.provider.source_detail || data.provider.topology_import_path || "-"}</div>
              </div>
            </div>
            <div className="mt-3 grid gap-3 lg:grid-cols-3">
              <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
                <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Runtime status</div>
                <div className={`mt-2 inline-flex rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${eveRuntimeTone(data.provider.runtime_status)}`}>
                  {statusLabel(data.provider.runtime_status)}
                </div>
              </div>
              <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
                <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">API base</div>
                <div className="mt-1 break-all text-sm text-ink-100">{data.provider.api_base_url || "-"}</div>
              </div>
              <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
                <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">API lab path</div>
                <div className="mt-1 break-all text-sm text-ink-100">{data.provider.api_lab_path || "-"}</div>
              </div>
            </div>
            {data.provider.runtime_detail ? (
              <div className="mt-3 rounded-2xl border border-ink-800 bg-ink-950/20 p-3 text-sm text-ink-300">{data.provider.runtime_detail}</div>
            ) : null}
            {data.provider.notes ? (
              <div className="mt-3 rounded-2xl border border-ink-800 bg-ink-950/20 p-3 text-sm text-ink-300">{data.provider.notes}</div>
            ) : null}
          </div>

          <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.45fr)_minmax(22rem,0.8fr)]">
            <div className="flex min-h-0 flex-col gap-4">
              <div className="panel-elevated p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">Topology Canvas</div>
                    <div className="mt-1 text-sm text-ink-300">View the imported lab structure, telemetry exporters, and where bounded enforcement is applied.</div>
                  </div>
                  <div className="rounded border border-ink-800 bg-ink-950/30 px-3 py-2 text-xs text-ink-300">
                    Window: {unixMsToLocal(data.summary.window_from_unix_ms)} to {unixMsToLocal(data.summary.window_to_unix_ms)}
                  </div>
                </div>

                <div className="mt-4 flex flex-col gap-4">
                  <div className={`rounded-3xl border p-4 ${zoneTone("management")}`}>
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300">{zoneTitle("management")}</div>
                        <div className="mt-1 text-sm text-ink-300">Control plane, UI, detector, ROE, NATS, and database services.</div>
                      </div>
                      <div className="text-xs text-ink-300">{data.management.mgmt_ip || data.management.ip || "-"}</div>
                    </div>
                    <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                      {managementNodes.map((node) => (
                        <NodeCard key={node.id} node={node} selected={selectedNode?.id === node.id} onSelect={(nodeID) => setSelectedNodeID(nodeID)} />
                      ))}
                      <div className="rounded-2xl border border-ink-800 bg-ink-950/30 p-3 text-sm text-ink-300">
                        <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300">Collector Endpoints</div>
                        <div className="mt-3 grid gap-2 text-xs sm:grid-cols-3">
                          {Object.entries(data.management.collector_endpoints || {}).map(([key, value]) => (
                            <div key={key} className="rounded border border-ink-800/80 bg-ink-950/40 px-2 py-2">
                              <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">{key.replaceAll("_", " ")}</div>
                              <div className="mt-1 font-mono text-ink-100">{value}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="grid gap-4 xl:grid-cols-4">
                    {backboneNodes.map((node) => (
                      <div key={node.id} className={`rounded-3xl border p-4 ${zoneTone(node.role === "attacker_simulation" ? "red_team" : "management")}`}>
                        <div className="mb-3 text-[11px] uppercase tracking-[0.18em] text-ink-400">{nodeRoleLabel(node.role)}</div>
                        <NodeCard node={node} selected={selectedNode?.id === node.id} onSelect={(nodeID) => setSelectedNodeID(nodeID)} />
                      </div>
                    ))}
                  </div>

                  <div className="rounded-3xl border border-ink-800 bg-ink-950/25 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300">Live Link State</div>
                        <div className="mt-1 text-sm text-ink-300">Link cards are colored from imported EVE topology endpoints and current runtime state.</div>
                      </div>
                      <div className="text-xs text-ink-400">{data.links.length} imported links</div>
                    </div>
                    <div className="mt-4 grid gap-3 xl:grid-cols-3">
                      {data.links.map((link) => (
                        <LinkCard key={link.id} link={link} nodesByKey={nodesByLookup} onSelect={(nodeID) => setSelectedNodeID(nodeID)} />
                      ))}
                    </div>
                  </div>

                  <div className="grid gap-4 xl:grid-cols-4">
                    {(["red_team", "user_lan", "server_lan", "dmz"] as const).map((zone) => (
                      <div key={zone} className={`rounded-3xl border p-4 ${zoneTone(zone)}`}>
                        <div className="flex items-center justify-between gap-3">
                          <div>
                            <div className="text-[11px] uppercase tracking-[0.18em] text-ink-200">{zoneTitle(zone)}</div>
                            <div className="mt-1 text-xs text-ink-400">{data.networks[zone]?.cidr || "-"}</div>
                          </div>
                          <div className="text-[11px] text-ink-400">{zoneNodes[zone]?.length || 0} nodes</div>
                        </div>
                        <div className="mt-3 flex flex-col gap-3">
                          {(zoneNodes[zone] || []).map((node) => (
                            <NodeCard key={node.id} node={node} selected={selectedNode?.id === node.id} onSelect={(nodeID) => setSelectedNodeID(nodeID)} />
                          ))}
                          {!zoneNodes[zone]?.length ? (
                            <div className="rounded-2xl border border-dashed border-ink-700/70 px-3 py-6 text-center text-xs text-ink-500">
                              No nodes defined for this segment.
                            </div>
                          ) : null}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                <div className="panel-elevated p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">Scenario Runbook</div>
                      <div className="mt-1 text-sm text-ink-300">Exact verifier commands you can run in the terminal while this topology page is open.</div>
                    </div>
                    <Link className="btn-secondary px-3 py-2 text-xs" href="/search?category=infrastructure">Open Search</Link>
                  </div>
                  <div className="mt-4 grid gap-3">
                    {data.tests.map((test) => (
                      <div key={test.id} className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div>
                            <div className="text-sm font-semibold text-ink-100">{test.id}</div>
                            <div className="mt-1 text-xs text-ink-300">{test.objective}</div>
                          </div>
                          <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${toneForTestStatus(test.live.status)}`}>
                            {statusLabel(test.live.status)}
                          </span>
                        </div>
                        <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-ink-300">
                          {test.telemetry.map((item) => (
                            <span key={item} className="rounded border border-ink-700/70 bg-ink-900/60 px-2 py-1">{item}</span>
                          ))}
                        </div>
                        <div className="mt-3 grid gap-2 text-xs text-ink-300 sm:grid-cols-2">
                          <div className="rounded border border-ink-800/80 bg-ink-950/40 px-2 py-2">
                            <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Run in terminal</div>
                            <div className="mt-1 font-mono text-ink-100">{test.command_hint || "-"}</div>
                          </div>
                          <div className="rounded border border-ink-800/80 bg-ink-950/40 px-2 py-2">
                            <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Expected rule</div>
                            <div className="mt-1 text-ink-100">{test.expected_rule_id || "-"}</div>
                          </div>
                        </div>
                        <div className="mt-3 flex flex-wrap gap-2 text-xs">
                          <Link className="btn-secondary px-3 py-2 text-xs" href={commandToSearchHref(test)}>Search pivot</Link>
                          {test.expected_rule_id ? (
                            <Link className="btn-secondary px-3 py-2 text-xs" href={`/incidents?category=infrastructure&rule_id=${encodeURIComponent(test.expected_rule_id)}`}>
                              Incident queue
                            </Link>
                          ) : null}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="panel-elevated p-4">
                  <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">Live Activity</div>
                  <div className="mt-1 text-sm text-ink-300">Most recent infrastructure incidents, actions, and telemetry in the selected window.</div>
                  <div className="mt-4 flex max-h-[34rem] flex-col gap-2 overflow-auto">
                    {data.activity.map((item, idx) => (
                      <div key={`${item.kind}-${item.run_id || item.action_id || item.ts_unix_ms}-${idx}`} className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3 text-sm">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${activityTone(item.kind)}`}>{item.kind}</span>
                            {item.rule_id ? <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${infrastructureBadgeClass(item.rule_id)}`}>{infrastructureLabel(item.rule_id)}</span> : null}
                          </div>
                          <div className="text-xs text-ink-400">{unixMsToLocal(item.ts_unix_ms)}</div>
                        </div>
                        <div className="mt-2 font-medium text-ink-100">{item.label}</div>
                        <div className="mt-1 text-xs text-ink-300">
                          {item.run_id ? `run ${item.run_id}` : item.action_id ? `action ${item.action_id}` : item.node_id || item.source_type || "-"}
                        </div>
                      </div>
                    ))}
                    {data.activity.length === 0 ? <EmptyState title="No recent activity" detail="Run one of the infrastructure verifier scripts to populate this stream." /> : null}
                  </div>
                </div>
              </div>
            </div>

            <div className="flex min-h-0 flex-col gap-4">
              <div className="panel-elevated p-4">
                <div className="flex flex-wrap gap-2 text-xs">
                  {([
                    { id: "node", label: "Selected Node" },
                    { id: "collectors", label: "Collectors" },
                    { id: "eve", label: "EVE-NG Bring-up" }
                  ] as const).map((tab) => (
                    <button
                      key={tab.id}
                      className={`rounded px-3 py-1.5 ${sideTab === tab.id ? "bg-cyan-600 text-white" : "bg-ink-800 text-ink-200 hover:bg-ink-700"}`}
                      onClick={() => setSideTab(tab.id)}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>

                {sideTab === "node" ? (
                  <div className="mt-4">
                    {selectedNode ? (
                      <>
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <div className="text-lg font-semibold text-ink-100">{selectedNode.label}</div>
                            <div className="mt-1 text-[11px] uppercase tracking-[0.18em] text-ink-400">{nodeRoleLabel(selectedNode.role)}</div>
                          </div>
                          <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${toneForNodeStatus(selectedNode.live.status)}`}>
                            {statusLabel(selectedNode.live.status)}
                          </span>
                        </div>
                        <div className="mt-2 text-sm text-ink-300">{selectedNode.live.status_reason || "-"}</div>
                        <div className="mt-4 grid grid-cols-2 gap-2 text-xs text-ink-300">
                          <div className="rounded border border-ink-800/80 bg-ink-950/40 px-3 py-3">
                            <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Incidents</div>
                            <div className="mt-1 text-lg font-semibold text-ink-100">{selectedNode.live.incident_count}</div>
                            <div className="text-[11px] text-ink-400">open {selectedNode.live.open_incident_count}</div>
                          </div>
                          <div className="rounded border border-ink-800/80 bg-ink-950/40 px-3 py-3">
                            <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Recent events</div>
                            <div className="mt-1 text-lg font-semibold text-ink-100">{selectedNode.live.recent_event_count}</div>
                            <div className="text-[11px] text-ink-400">detections {selectedNode.live.detection_count}</div>
                          </div>
                          <div className="rounded border border-ink-800/80 bg-ink-950/40 px-3 py-3">
                            <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Active controls</div>
                            <div className="mt-1 text-lg font-semibold text-ink-100">{selectedNode.live.active_action_count}</div>
                            <div className="text-[11px] text-ink-400">verified {selectedNode.live.verified_block_count}</div>
                          </div>
                          <div className="rounded border border-ink-800/80 bg-ink-950/40 px-3 py-3">
                            <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Last seen</div>
                            <div className="mt-1 text-sm font-semibold text-ink-100">{unixMsToLocal(selectedNode.live.last_seen_unix_ms)}</div>
                            <div className="text-[11px] text-ink-400">run {selectedNode.live.latest_run_id || "-"}</div>
                          </div>
                        </div>
                        <div className="mt-4 rounded-2xl border border-ink-800 bg-ink-950/20 p-3 text-sm text-ink-300">
                          <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300">Addresses and networks</div>
                          <div className="mt-3 flex flex-wrap gap-2 text-xs">
                            {selectedNode.eve_node_name ? <span className="rounded border border-cyan-700/60 bg-cyan-950/20 px-2 py-1 text-cyan-100">eve {selectedNode.eve_node_name}</span> : null}
                            {selectedNode.eve_node_id ? <span className="rounded border border-cyan-700/60 bg-cyan-950/20 px-2 py-1 text-cyan-100">node id {selectedNode.eve_node_id}</span> : null}
                            {selectedNode.live.eve_runtime_status ? <span className={`rounded border px-2 py-1 ${eveRuntimeTone(selectedNode.live.eve_runtime_status)}`}>runtime {statusLabel(selectedNode.live.eve_runtime_status)}</span> : null}
                            {selectedNode.ip ? <span className="rounded border border-ink-700/70 bg-ink-900/60 px-2 py-1">ip {selectedNode.ip}</span> : null}
                            {selectedNode.mgmt_ip ? <span className="rounded border border-ink-700/70 bg-ink-900/60 px-2 py-1">mgmt {selectedNode.mgmt_ip}</span> : null}
                            {(selectedNode.data_ips || []).map((ip) => (
                              <span key={ip} className="rounded border border-ink-700/70 bg-ink-900/60 px-2 py-1">{ip}</span>
                            ))}
                            {(selectedNode.networks || []).map((network) => (
                              <span key={network} className="rounded border border-cyan-700/60 bg-cyan-950/20 px-2 py-1 text-cyan-100">{zoneTitle(network)}</span>
                            ))}
                          </div>
                        </div>
                        {(selectedNode.position_left || selectedNode.position_top) ? (
                          <div className="mt-4 rounded-2xl border border-ink-800 bg-ink-950/20 p-3 text-sm text-ink-300">
                            <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300">EVE layout position</div>
                            <div className="mt-2 text-xs text-ink-200">left {selectedNode.position_left || 0}, top {selectedNode.position_top || 0}</div>
                          </div>
                        ) : null}
                        {selectedNode.live.eve_console_url ? (
                          <div className="mt-4 rounded-2xl border border-ink-800 bg-ink-950/20 p-3 text-sm text-ink-300">
                            <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300">EVE console</div>
                            <div className="mt-2 break-all text-xs text-ink-200">{selectedNode.live.eve_console_url}</div>
                          </div>
                        ) : null}
                        {selectedNode.eve_node_id ? (
                          <div className="mt-4 rounded-2xl border border-ink-800 bg-ink-950/20 p-3 text-sm text-ink-300">
                            <div className="flex items-center justify-between gap-3">
                              <div>
                                <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300">EVE node controls</div>
                                <div className="mt-1 text-xs text-ink-400">Admin-only runtime controls against the EVE host.</div>
                              </div>
                              <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${eveRuntimeTone(selectedNode.live.eve_runtime_status)}`}>
                                {statusLabel(selectedNode.live.eve_runtime_status)}
                              </span>
                            </div>
                            <div className="mt-3 flex flex-wrap gap-2 text-xs">
                              <button className="btn-secondary px-3 py-2 text-xs disabled:opacity-50" disabled={Boolean(controlBusy)} onClick={() => void runNodeControl("start")}>
                                {controlBusy === "start" ? "Starting..." : "Start"}
                              </button>
                              <button className="btn-secondary px-3 py-2 text-xs disabled:opacity-50" disabled={Boolean(controlBusy)} onClick={() => void runNodeControl("stop")}>
                                {controlBusy === "stop" ? "Stopping..." : "Stop"}
                              </button>
                              <button className="btn-secondary px-3 py-2 text-xs disabled:opacity-50" disabled={Boolean(controlBusy)} onClick={() => void runNodeControl("wipe")}>
                                {controlBusy === "wipe" ? "Wiping..." : "Wipe"}
                              </button>
                            </div>
                            {controlMessage ? <div className="mt-3 rounded border border-emerald-700/60 bg-emerald-950/25 px-3 py-2 text-xs text-emerald-100">{controlMessage}</div> : null}
                            {controlError ? <div className="mt-3 rounded border border-rose-700/60 bg-rose-950/25 px-3 py-2 text-xs text-rose-100">{controlError}</div> : null}
                          </div>
                        ) : null}
                        <div className="mt-4 rounded-2xl border border-ink-800 bg-ink-950/20 p-3 text-sm text-ink-300">
                          <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300">Telemetry exports</div>
                          <div className="mt-3 flex flex-col gap-2 text-xs">
                            {(selectedNode.telemetry_exports || []).map((item) => (
                              <div key={`${item.type}-${item.destination || item.path || ""}`} className="rounded border border-ink-800/80 bg-ink-950/40 px-2 py-2">
                                <div className="font-medium text-ink-100">{item.type}</div>
                                <div className="mt-1 text-ink-300">{item.destination || item.path || "local collector"}</div>
                              </div>
                            ))}
                            {!(selectedNode.telemetry_exports || []).length ? <div className="text-ink-500">No explicit telemetry exports in lab spec.</div> : null}
                          </div>
                        </div>
                        <div className="mt-4 flex flex-wrap gap-2 text-xs">
                          <Link className="btn-secondary px-3 py-2 text-xs" href={`/search?node_id=${encodeURIComponent(selectedNode.id)}&category=infrastructure`}>Search node</Link>
                          {selectedNode.agent_support ? <Link className="btn-secondary px-3 py-2 text-xs" href={`/endpoints?node=${encodeURIComponent(selectedNode.id)}`}>Endpoint view</Link> : null}
                          {selectedNode.live.latest_run_id ? <Link className="btn-secondary px-3 py-2 text-xs" href={`/incidents?category=infrastructure&open_run_id=${encodeURIComponent(selectedNode.live.latest_run_id)}`}>Open latest incident</Link> : null}
                        </div>
                      </>
                    ) : (
                      <EmptyState title="No node selected" detail="Select a topology node to inspect its live state." />
                    )}
                  </div>
                ) : null}

                {sideTab === "collectors" ? (
                  <div className="mt-4 flex flex-col gap-3">
                    {data.collectors.map((collector) => (
                      <CollectorCard key={collector.source} item={collector} />
                    ))}
                  </div>
                ) : null}

                {sideTab === "eve" ? (
                  <div className="mt-4 flex flex-col gap-4">
                    <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
                      <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300">Bring-up sequence</div>
                      <div className="mt-2 space-y-3">
                        {data.startup.map((step) => (
                          <div key={`${step.order}-${step.device_id}`} className="rounded border border-ink-800/80 bg-ink-950/40 p-3">
                            <div className="flex items-start justify-between gap-2">
                              <div>
                                <div className="font-medium text-ink-100">{step.order}. {step.device_id}</div>
                                <div className="mt-1 text-[11px] uppercase tracking-[0.18em] text-ink-400">
                                  {step.device_type || "device"}{step.eve_node_name ? ` • eve ${step.eve_node_name}` : ""}
                                </div>
                              </div>
                              {step.image ? <span className="rounded border border-ink-700/70 bg-ink-900/60 px-2 py-1 text-[11px] text-ink-200">{step.image}</span> : null}
                            </div>
                            {step.boot_command ? <div className="mt-2 text-xs text-ink-200">{step.boot_command}</div> : null}
                            {step.validation_hint ? <div className="mt-2 text-[11px] text-cyan-100">{step.validation_hint}</div> : null}
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
                      <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300">Imported link map</div>
                      <div className="mt-2 space-y-3">
                        {data.links.map((link) => (
                          <div key={link.id}>
                            <LinkCard link={link} nodesByKey={nodesByLookup} onSelect={(nodeID) => setSelectedNodeID(nodeID)} />
                            {link.provider_source ? <div className="mt-1 text-[11px] text-cyan-200">source {link.provider_source}</div> : null}
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3 text-sm text-ink-300">
                      <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300">Topology provenance</div>
                      <div className="mt-2 text-xs text-ink-300">
                        The boxes on this page are the R-SIEM operational overlay. The lab source, device order, and imported link map come from the EVE-NG provider definition and `.unl` topology import.
                      </div>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>
        </>
      ) : null}
    </section>
  );
}
