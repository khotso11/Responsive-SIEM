"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { getLabActions, getLabEvents, getLabIncidents, getLabTopology } from "@/lib/api";
import { EmptyState, ErrorState, LoadingState, unixMsToLocal } from "@/components/ui";
import { Incident, LabActivity, LabEventView, LabTopologyResponse, ResponseActionView } from "@/lib/types";

const DEFAULT_LAB_ID = "eve-ng-soc-lab-v1";

function parseQueryTime(v: string | null, fallback: number): number {
  if (!v) return fallback;
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return n;
  const p = Date.parse(v);
  if (!Number.isNaN(p) && p > 0) return p;
  return fallback;
}

function toneForTrafficClass(value?: string): string {
  switch ((value || "").toLowerCase()) {
    case "expected_dmz_web":
    case "expected":
      return "border-emerald-700/60 bg-emerald-950/40 text-emerald-100";
    case "reconnaissance":
    case "detected":
    case "firewall_observation":
      return "border-amber-700/60 bg-amber-950/40 text-amber-100";
    case "east_west_policy_violation":
    case "untrusted_to_internal":
      return "border-rose-700/60 bg-rose-950/40 text-rose-100";
    case "flow_telemetry":
      return "border-cyan-700/60 bg-cyan-950/40 text-cyan-100";
    default:
      return "border-slate-700/60 bg-slate-950/40 text-slate-100";
  }
}

function statusTone(value?: string): string {
  switch ((value || "").toLowerCase()) {
    case "running":
    case "reachable":
    case "active":
    case "expected":
      return "border-emerald-700/60 bg-emerald-950/30 text-emerald-100";
    case "planned":
    case "configured":
      return "border-cyan-700/60 bg-cyan-950/30 text-cyan-100";
    case "limited":
    case "unknown":
    case "suspicious":
      return "border-amber-700/60 bg-amber-950/30 text-amber-100";
    case "unavailable":
    case "blocked":
    case "policy_violation":
      return "border-rose-700/60 bg-rose-950/30 text-rose-100";
    default:
      return "border-slate-700/60 bg-slate-950/30 text-slate-100";
  }
}

function kvClass(label: string, value: string): string {
  return `${label}: ${value || "-"}`;
}

export default function LabPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const labID = (searchParams.get("lab_id") || DEFAULT_LAB_ID).trim();
  const windowFrom = parseQueryTime(searchParams.get("gfrom"), Date.now() - 24 * 60 * 60 * 1000);
  const windowTo = parseQueryTime(searchParams.get("gto"), Date.now());

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [topology, setTopology] = useState<LabTopologyResponse | null>(null);
  const [events, setEvents] = useState<LabEventView[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [actions, setActions] = useState<ResponseActionView[]>([]);
  const [q, setQ] = useState(searchParams.get("q") || "");
  const [zone, setZone] = useState(searchParams.get("zone") || "");
  const [nodeID, setNodeID] = useState(searchParams.get("node_id") || "");
  const [srcNodeID, setSrcNodeID] = useState(searchParams.get("src_node_id") || "");
  const [dstNodeID, setDstNodeID] = useState(searchParams.get("dst_node_id") || "");
  const [sourceType, setSourceType] = useState(searchParams.get("source_type") || "");
  const [eventType, setEventType] = useState(searchParams.get("event_type") || "");
  const [severity, setSeverity] = useState(searchParams.get("severity") || "");
  const [protocolFamily, setProtocolFamily] = useState(searchParams.get("protocol_family") || "");
  const [service, setService] = useState(searchParams.get("service") || "");
  const [trafficClass, setTrafficClass] = useState(searchParams.get("traffic_class") || "");

  useEffect(() => {
    setQ(searchParams.get("q") || "");
    setZone(searchParams.get("zone") || "");
    setNodeID(searchParams.get("node_id") || "");
    setSrcNodeID(searchParams.get("src_node_id") || "");
    setDstNodeID(searchParams.get("dst_node_id") || "");
    setSourceType(searchParams.get("source_type") || "");
    setEventType(searchParams.get("event_type") || "");
    setSeverity(searchParams.get("severity") || "");
    setProtocolFamily(searchParams.get("protocol_family") || "");
    setService(searchParams.get("service") || "");
    setTrafficClass(searchParams.get("traffic_class") || "");
  }, [searchParams.toString()]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const query = {
        from: windowFrom,
        to: windowTo,
        q: q || undefined,
        zone: zone || undefined,
        node_id: nodeID || undefined,
        src_node_id: srcNodeID || undefined,
        dst_node_id: dstNodeID || undefined,
        source_type: sourceType || undefined,
        event_type: eventType || undefined,
        severity: severity || undefined,
        protocol_family: protocolFamily || undefined,
        service: service || undefined,
        traffic_class: trafficClass || undefined,
        page: 1,
        limit: 200,
        sort: "recv_desc" as const
      };
      const [topologyRes, eventsRes, incidentsRes, actionsRes] = await Promise.all([
        getLabTopology(labID, windowFrom, windowTo),
        getLabEvents(labID, query),
        getLabIncidents(labID, {
          from: windowFrom,
          to: windowTo,
          node_id: nodeID || undefined,
          zone: zone || undefined,
          severity: severity || undefined,
          status: undefined,
          limit: 20
        }),
        getLabActions(labID, {
          from: windowFrom,
          to: windowTo,
          node_id: nodeID || undefined,
          status: undefined,
          action_name: undefined,
          limit: 20
        })
      ]);
      setTopology(topologyRes);
      setEvents(eventsRes.items || []);
      setIncidents((incidentsRes.items || []) as Incident[]);
      setActions((actionsRes.items || []) as ResponseActionView[]);
    } catch (e) {
      setError((e as Error).message || String(e));
      setTopology(null);
      setEvents([]);
      setIncidents([]);
      setActions([]);
    } finally {
      setLoading(false);
    }
  }, [windowFrom, windowTo, q, zone, nodeID, srcNodeID, dstNodeID, sourceType, eventType, severity, protocolFamily, service, trafficClass, labID]);

  useEffect(() => {
    void load();
  }, [load]);

  const applyFilters = () => {
    const params = new URLSearchParams(searchParams.toString());
    params.set("lab_id", labID);
    if (q.trim()) params.set("q", q.trim());
    else params.delete("q");
    if (zone.trim()) params.set("zone", zone.trim());
    else params.delete("zone");
    if (nodeID.trim()) params.set("node_id", nodeID.trim());
    else params.delete("node_id");
    if (srcNodeID.trim()) params.set("src_node_id", srcNodeID.trim());
    else params.delete("src_node_id");
    if (dstNodeID.trim()) params.set("dst_node_id", dstNodeID.trim());
    else params.delete("dst_node_id");
    if (sourceType.trim()) params.set("source_type", sourceType.trim());
    else params.delete("source_type");
    if (eventType.trim()) params.set("event_type", eventType.trim());
    else params.delete("event_type");
    if (severity.trim()) params.set("severity", severity.trim());
    else params.delete("severity");
    if (protocolFamily.trim()) params.set("protocol_family", protocolFamily.trim());
    else params.delete("protocol_family");
    if (service.trim()) params.set("service", service.trim());
    else params.delete("service");
    if (trafficClass.trim()) params.set("traffic_class", trafficClass.trim());
    else params.delete("traffic_class");
    router.push(`?${params.toString()}`, { scroll: false });
  };

  const resetFilters = () => {
    setQ("");
    setZone("");
    setNodeID("");
    setSrcNodeID("");
    setDstNodeID("");
    setSourceType("");
    setEventType("");
    setSeverity("");
    setProtocolFamily("");
    setService("");
    setTrafficClass("");
    router.push(`?lab_id=${encodeURIComponent(labID)}`, { scroll: false });
  };

  const currentTopology = topology;
  const zones = currentTopology?.zones || [];
  const nodes = currentTopology?.nodes || [];
  const signals = currentTopology?.signals || [];
  const collections = currentTopology?.collection || [];
  const activity = currentTopology?.activity || [];

  const groupNodesByZone = useMemo(() => {
    const map = new Map<string, typeof nodes>();
    for (const zoneItem of zones) {
      map.set(zoneItem.id, []);
    }
    for (const node of nodes) {
      const key = node.zone || "";
      if (!map.has(key)) map.set(key, []);
      map.get(key)?.push(node);
    }
    return map;
  }, [nodes, zones]);

  const selectedZoneLabel = useMemo(() => zones.find((item) => item.id === zone)?.name || zone || "All zones", [zones, zone]);

  return (
    <div className="space-y-6 p-4 md:p-6">
      <div className="rounded-2xl border border-slate-800 bg-gradient-to-br from-slate-950 via-slate-950 to-cyan-950/30 p-5 shadow-xl shadow-cyan-950/20">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="text-[11px] uppercase tracking-[0.28em] text-cyan-200/80">Lab / Topology</div>
            <h1 className="mt-2 text-3xl font-semibold text-white">{currentTopology?.lab.name || "Emulated SOC Lab"}</h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-300">{currentTopology?.lab.description || "Lab topology and event ledger for the EVE-NG segmented network."}</p>
            <div className="mt-4 flex flex-wrap gap-2 text-xs text-slate-200">
              <span className="rounded-full border border-cyan-800/60 bg-cyan-950/50 px-3 py-1">{currentTopology?.lab.id || labID}</span>
              <span className="rounded-full border border-slate-700/60 bg-slate-950/60 px-3 py-1">{currentTopology?.lab.status || "unknown"}</span>
              <span className="rounded-full border border-slate-700/60 bg-slate-950/60 px-3 py-1">{selectedZoneLabel}</span>
              <span className="rounded-full border border-slate-700/60 bg-slate-950/60 px-3 py-1">{events.length} matching events</span>
            </div>
            {currentTopology?.provider?.source_status ? (
              <div className={`mt-3 inline-flex flex-wrap items-center gap-2 rounded-xl border px-3 py-2 text-xs ${statusTone(currentTopology.provider.source_status)}`}>
                <span className="font-semibold uppercase tracking-[0.18em]">{currentTopology.provider.source_status}</span>
                <span>{currentTopology.provider.source_detail || currentTopology.provider.notes || "Topology source status reported by backend."}</span>
              </div>
            ) : null}
          </div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:min-w-[32rem]">
            {[
              { label: "Nodes", value: currentTopology?.summary.node_count || nodes.length },
              { label: "Zones", value: currentTopology?.summary.zone_count || zones.length },
              { label: "Recent incidents", value: currentTopology?.summary.recent_incident_count || incidents.length },
              { label: "Recent actions", value: currentTopology?.summary.recent_action_count || actions.length }
            ].map((item) => (
              <div key={item.label} className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                <div className="text-[11px] uppercase tracking-[0.22em] text-slate-400">{item.label}</div>
                <div className="mt-1 text-2xl font-semibold text-white">{item.value}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">Event Filters</h2>
            <p className="text-xs text-slate-400">Filter by lab, zone, node pair, service, protocol, severity, and traffic classification.</p>
          </div>
          <div className="flex gap-2">
            <button className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200" onClick={resetFilters}>Reset</button>
            <button className="rounded-lg bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950" onClick={applyFilters}>Apply</button>
          </div>
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3 xl:grid-cols-6">
          <FilterField label="Query" value={q} onChange={setQ} />
          <FilterField label="Zone" value={zone} onChange={setZone} placeholder="users | dmz | servers | wan" />
          <FilterField label="Node" value={nodeID} onChange={setNodeID} placeholder="FW-EDGE-1" />
          <FilterField label="Src Node" value={srcNodeID} onChange={setSrcNodeID} placeholder="USR-WS-1" />
          <FilterField label="Dst Node" value={dstNodeID} onChange={setDstNodeID} placeholder="DMZ-WEB-1" />
          <FilterField label="Source Type" value={sourceType} onChange={setSourceType} placeholder="syslog | netflow_v5" />
          <FilterField label="Event Type" value={eventType} onChange={setEventType} placeholder="netflow_flow | auth" />
          <FilterField label="Severity" value={severity} onChange={setSeverity} placeholder="high | medium" />
          <FilterField label="Protocol" value={protocolFamily} onChange={setProtocolFamily} placeholder="tcp | icmp" />
          <FilterField label="Service" value={service} onChange={setService} placeholder="http | firewall" />
          <FilterField label="Traffic Class" value={trafficClass} onChange={setTrafficClass} placeholder="expected_dmz_web" />
        </div>
      </div>

      {error ? <ErrorState message={error} /> : null}
      {loading ? <LoadingState /> : null}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {[
          { label: "Response targets", value: currentTopology?.summary.response_target_count || 0, tone: "text-cyan-100" },
          { label: "Log sources", value: currentTopology?.summary.log_source_count || 0, tone: "text-emerald-100" },
          { label: "Traffic sources", value: currentTopology?.summary.traffic_source_count || 0, tone: "text-amber-100" },
          { label: "Attacker simulators", value: currentTopology?.summary.attacker_simulator_count || 0, tone: "text-rose-100" },
          { label: "Reachable nodes", value: currentTopology?.summary.reachable_node_count || 0, tone: "text-sky-100" },
          { label: "Expected services", value: currentTopology?.summary.expected_service_count || 0, tone: "text-violet-100" }
        ].map((item) => (
          <div key={item.label} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
            <div className="text-[11px] uppercase tracking-[0.22em] text-slate-400">{item.label}</div>
            <div className={`mt-2 text-3xl font-semibold ${item.tone}`}>{item.value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="mb-3 text-lg font-semibold text-white">Zone Layout</h2>
          <div className="space-y-4">
            {zones.map((zoneItem) => (
              <div key={zoneItem.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold text-white">{zoneItem.name}</div>
                    <div className="text-xs text-slate-400">{zoneItem.cidr}</div>
                  </div>
                  <div className="rounded-full border border-slate-700 bg-slate-950 px-2.5 py-1 text-[10px] uppercase tracking-[0.22em] text-slate-300">
                    {zoneItem.purpose}
                  </div>
                </div>
                <div className="mt-3 grid gap-2 md:grid-cols-2">
                  {(groupNodesByZone.get(zoneItem.id) || []).map((node) => (
                    <button
                      key={node.id}
                      className="rounded-lg border border-slate-800 bg-slate-950/80 p-3 text-left transition hover:border-cyan-700/70"
                      onClick={() => setNodeID(node.id)}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="font-medium text-white">{node.label}</div>
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${statusTone(node.live?.status)}`}>
                          {node.live?.status || "unknown"}
                        </span>
                      </div>
                      <div className="mt-1 text-xs text-slate-400">{node.role}</div>
                      <div className="mt-2 text-xs text-slate-200">{node.ip || "-"}</div>
                      <div className="mt-2 flex flex-wrap gap-1">
                        {node.response_target ? <span className="rounded-full border border-cyan-800/60 bg-cyan-950/60 px-2 py-0.5 text-[10px] text-cyan-100">response target</span> : null}
                        {node.log_source ? <span className="rounded-full border border-emerald-800/60 bg-emerald-950/60 px-2 py-0.5 text-[10px] text-emerald-100">log source</span> : null}
                        {node.traffic_source ? <span className="rounded-full border border-amber-800/60 bg-amber-950/60 px-2 py-0.5 text-[10px] text-amber-100">traffic source</span> : null}
                        {node.attacker_simulator ? <span className="rounded-full border border-rose-800/60 bg-rose-950/60 px-2 py-0.5 text-[10px] text-rose-100">attacker</span> : null}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
            <h2 className="mb-3 text-lg font-semibold text-white">Node Drill-Down</h2>
            {nodes
              .filter((node) => !nodeID || node.id === nodeID)
              .slice(0, 1)
              .map((node) => (
                <div key={node.id} className="space-y-3">
                  <div className="flex flex-wrap gap-2 text-xs">
                    <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200">{node.id}</span>
                    <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200">{node.zone_name || node.zone}</span>
                    <span className={`rounded-full border px-2 py-1 ${statusTone(node.live?.status)}`}>{node.live?.status || node.state || "unknown"}</span>
                    <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200">{node.live?.recent_event_count || 0} events</span>
                    <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200">{node.live?.incident_count || 0} incidents</span>
                  </div>
                  <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                    <InfoRow label="Role" value={node.role} />
                    <InfoRow label="Service State" value={node.service_state || node.live?.service_state || "-"} />
                    <InfoRow label="IP" value={node.ip || "-"} />
                    <InfoRow label="Observed last seen" value={node.live?.last_seen_unix_ms ? unixMsToLocal(node.live.last_seen_unix_ms) : "-"} />
                  </div>
                  <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
                    <div className="mb-2 text-xs uppercase tracking-[0.22em] text-slate-400">Services</div>
                    <div className="flex flex-wrap gap-2">
                      {(node.services || []).map((svc) => (
                        <span key={`${node.id}-${svc.name}-${svc.port}`} className={`rounded-full border px-2 py-1 text-xs ${toneForTrafficClass(svc.exposure || svc.name)}`}>
                          {svc.name}:{svc.port}/{svc.protocol}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm text-slate-300">
                    {node.notes || "No node notes configured."}
                  </div>
                </div>
              ))}
            {!nodeID && nodes.length > 0 ? (
              <p className="text-sm text-slate-400">Select a node from the zone layout to drill into its context.</p>
            ) : null}
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
            <h2 className="mb-3 text-lg font-semibold text-white">Collection Mappings</h2>
            <div className="space-y-2">
              {collections.map((item) => (
                <div key={`${item.node_id}-${item.collector}-${item.source_type}`} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm">
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-medium text-white">{item.node_id}</div>
                    <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${statusTone(item.status)}`}>{item.status || "unknown"}</span>
                  </div>
                  <div className="mt-1 text-slate-300">{item.collector} via {item.transport} {item.endpoint ? `-> ${item.endpoint}` : ""}</div>
                  <div className="mt-1 text-xs text-slate-400">{item.notes || item.source_type}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4 xl:col-span-2">
          <h2 className="mb-3 text-lg font-semibold text-white">Recent Lab Events</h2>
          {events.length === 0 ? <EmptyState title="No lab events in the current window" detail="Generate ICMP, HTTP, syslog, or flow activity to populate this tray." /> : null}
          {events.length > 0 ? (
            <div className="overflow-auto">
              <table className="min-w-full text-xs">
                <thead>
                  <tr className="text-left text-slate-400">
                    <th className="px-2 py-2">Time</th>
                    <th className="px-2 py-2">Node</th>
                    <th className="px-2 py-2">Pair</th>
                    <th className="px-2 py-2">Source</th>
                    <th className="px-2 py-2">Event</th>
                    <th className="px-2 py-2">Service</th>
                    <th className="px-2 py-2">Traffic</th>
                    <th className="px-2 py-2">Severity</th>
                    <th className="px-2 py-2">Rule</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev) => (
                    <tr key={`${ev.event_idem_key}-${ev.recv_ts_unix_ms}`} className="border-t border-slate-800/80">
                      <td className="px-2 py-2 text-slate-300">{unixMsToLocal(ev.recv_ts_unix_ms)}</td>
                      <td className="px-2 py-2">
                        <button className="text-cyan-200 hover:text-cyan-100" onClick={() => setNodeID(ev.source_node_id || ev.node_id)}>
                          {ev.source_node_label || ev.node_id}
                        </button>
                      </td>
                      <td className="px-2 py-2 text-slate-300">
                        <div>{ev.source_zone || "-"} {"->"} {ev.destination_zone || "-"}</div>
                        <div className="text-[10px] text-slate-500">{ev.destination_node_label || ev.dst_ip || "-"}</div>
                      </td>
                      <td className="px-2 py-2 text-slate-300">{ev.source_type}</td>
                      <td className="px-2 py-2 text-slate-200">{ev.event_type}</td>
                      <td className="px-2 py-2 text-slate-200">{ev.service || "-"}</td>
                      <td className="px-2 py-2">
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${toneForTrafficClass(ev.traffic_class)}`}>
                          {ev.traffic_class || "normal"}
                        </span>
                      </td>
                      <td className="px-2 py-2 text-slate-300">{ev.severity || "-"}</td>
                      <td className="px-2 py-2 text-slate-300">{ev.rule_id || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>

        <div className="space-y-4">
          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
            <h2 className="mb-3 text-lg font-semibold text-white">Signals</h2>
            <div className="space-y-2">
              {signals.map((signal) => (
                <div key={signal.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-medium text-white">{signal.label}</div>
                    <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${statusTone(signal.status)}`}>{signal.severity || signal.status || "ready"}</span>
                  </div>
                  <div className="mt-1 text-xs text-slate-400">{signal.description}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
            <h2 className="mb-3 text-lg font-semibold text-white">Recent Incidents</h2>
            {incidents.length === 0 ? <EmptyState title="No lab incidents yet" detail="Detected lab activity will appear here when the existing detection logic fires." /> : null}
            <div className="space-y-2">
              {incidents.map((incident) => (
                <Link key={incident.run_id} href={`/incidents/${encodeURIComponent(incident.run_id)}`} className="block rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm transition hover:border-cyan-700/70">
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-medium text-white">{incident.rule_id || incident.run_id}</div>
                    <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${statusTone(incident.status)}`}>{incident.status}</span>
                  </div>
                  <div className="mt-1 text-xs text-slate-400">{incident.node_id || "-"} {incident.asset_role ? `• ${incident.asset_role}` : ""}</div>
                  <div className="mt-1 text-xs text-slate-300">{incident.severity || "-"} / {incident.source_type || "-"}</div>
                </Link>
              ))}
            </div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
            <h2 className="mb-3 text-lg font-semibold text-white">Recent Actions</h2>
            {actions.length === 0 ? <EmptyState title="No lab response actions" /> : null}
            <div className="space-y-2">
              {actions.map((action) => (
                <div key={action.action_id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm">
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-medium text-white">{action.label}</div>
                    <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${statusTone(action.status)}`}>{action.bucket}</span>
                  </div>
                  <div className="mt-1 text-xs text-slate-400">{action.node_id || action.target_agent_id || "-"}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
            <h2 className="mb-3 text-lg font-semibold text-white">Activity</h2>
            <div className="space-y-2">
              {activity.slice(0, 16).map((item) => (
                <div key={`${item.kind}-${item.ts_unix_ms}-${item.label}`} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm">
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-medium text-white">{item.label}</div>
                    <span className="rounded-full border border-slate-700 bg-slate-950 px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] text-slate-300">{item.kind}</span>
                  </div>
                  <div className="mt-1 text-xs text-slate-400">{unixMsToLocal(item.ts_unix_ms)} {item.zone ? `• ${item.zone}` : ""}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function FilterField({
  label,
  value,
  onChange,
  placeholder
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="space-y-1 text-xs text-slate-300">
      <div className="uppercase tracking-[0.22em] text-slate-400">{label}</div>
      <input
        className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none ring-0 placeholder:text-slate-500 focus:border-cyan-700"
        value={value}
        placeholder={placeholder || label}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-sm">
      <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">{label}</div>
      <div className="mt-1 text-slate-100">{value || "-"}</div>
    </div>
  );
}
