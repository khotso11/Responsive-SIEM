"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getIncidents, getSearchEvents } from "@/lib/api";
import { INCIDENT_MUTATED_EVENT, INCIDENTS_UPDATED_EVENT } from "@/lib/events";
import { infrastructureBadgeClass, infrastructureDescription, infrastructureLabel, isInfrastructureIncident } from "@/lib/infrastructure";
import { EventRow, Incident, IncidentListResponse } from "@/lib/types";
import { EmptyState, ErrorState, LaneBadge, LoadingState, StatusBadge, unixMsToLocal } from "@/components/ui";

function parseQueryTime(v: string | null): number | undefined {
  if (!v) return undefined;
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return n;
  const p = Date.parse(v);
  if (!Number.isNaN(p) && p > 0) return p;
  return undefined;
}

function countBy<T extends string>(items: T[]): Array<{ key: string; count: number }> {
  const counts = new Map<string, number>();
  for (const item of items) {
    const key = (item || "").trim() || "-";
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => (b.count === a.count ? a.key.localeCompare(b.key) : b.count - a.count));
}

export default function InfrastructurePage() {
  const searchParams = useSearchParams();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [hasLoadedOnce, setHasLoadedOnce] = useState(false);
  const hasLoadedOnceRef = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const globalFrom = useMemo(() => parseQueryTime(searchParams.get("gfrom")), [searchParams]);
  const globalTo = useMemo(() => parseQueryTime(searchParams.get("gto")), [searchParams]);

  const load = useCallback(async () => {
    if (!hasLoadedOnceRef.current) setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set("category", "infrastructure");
      params.set("view", "active");
      params.set("limit", "12");
      params.set("sort", "updated_desc");
      if (globalFrom) params.set("from", String(globalFrom));
      if (globalTo) params.set("to", String(globalTo));
      const [incidentRes, eventRes] = await Promise.all([
        getIncidents(params.toString()),
        getSearchEvents({
          category: "infrastructure",
          from: globalFrom,
          to: globalTo,
          limit: 50,
          page: 1,
          sort: "recv_desc"
        })
      ]);
      const infraIncidents = (incidentRes as IncidentListResponse).items.filter((item) => isInfrastructureIncident(item));
      setIncidents(infraIncidents);
      setEvents(eventRes.items || []);
      hasLoadedOnceRef.current = true;
      setHasLoadedOnce(true);
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
    return () => {
      window.removeEventListener(INCIDENTS_UPDATED_EVENT, onRefresh);
      window.removeEventListener(INCIDENT_MUTATED_EVENT, onRefresh);
    };
  }, [load]);

  const pendingApprovals = useMemo(() => incidents.filter((item) => item.status?.toUpperCase() === "WAITING_APPROVAL").length, [incidents]);
  const verifiedBlocks = useMemo(() => incidents.filter((item) => item.rule_id === "R-INFRA-POST-CONTAINMENT-BLOCK-VERIFY").length, [incidents]);
  const sourceBreakdown = useMemo(() => countBy(events.map((item) => item.source_type || "-")).slice(0, 4), [events]);
  const ruleBreakdown = useMemo(() => countBy(incidents.map((item) => item.rule_id || "-")).slice(0, 6), [incidents]);

  return (
    <section className="flex h-full min-h-0 flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-[11px] uppercase tracking-[0.22em] text-cyan-300">Infrastructure Operations</div>
          <h2 className="mt-1 text-[22px] font-semibold tracking-tight">Infrastructure Monitoring</h2>
          <p className="mt-1 text-[13px] text-ink-300">
            Infrastructure incidents and telemetry from syslog, NetFlow, and SNMP collectors, including bounded gateway-backed containment where configured.
          </p>
        </div>
        <div className="flex flex-wrap gap-2 text-xs">
          <Link className="btn-secondary px-3 py-2 text-xs" href="/infrastructure/topology">
            Open Topology
          </Link>
          <Link className="btn-secondary px-3 py-2 text-xs" href="/infrastructure/runbook">
            EVE-NG Runbook
          </Link>
          <Link className="btn-secondary px-3 py-2 text-xs" href="/search?category=infrastructure">
            Search Infrastructure
          </Link>
          <Link className="btn-secondary px-3 py-2 text-xs" href="/incidents?category=infrastructure">
            View Infrastructure Incidents
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 xl:grid-cols-4">
        <div className="panel-elevated p-3">
          <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Visible infra incidents</div>
          <div className="mt-2 text-[24px] font-semibold text-ink-100">{incidents.length}</div>
        </div>
        <div className="panel-elevated p-3">
          <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Pending approvals</div>
          <div className="mt-2 text-[24px] font-semibold text-amber-200">{pendingApprovals}</div>
        </div>
        <div className="panel-elevated p-3">
          <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Recent infra events</div>
          <div className="mt-2 text-[24px] font-semibold text-ink-100">{events.length}</div>
        </div>
        <div className="panel-elevated p-3">
          <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Block verified</div>
          <div className="mt-2 text-[24px] font-semibold text-emerald-200">{verifiedBlocks}</div>
        </div>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,0.75fr)]">
        <div className="panel-elevated flex min-h-0 flex-col overflow-hidden p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">Infrastructure Incident Queue</div>
              <div className="mt-1 text-sm text-ink-300">Rules and playbooks from the infrastructure detection slice.</div>
            </div>
            <div className="flex gap-2 text-xs">
              <Link className="btn-secondary px-3 py-2 text-xs" href="/search?category=infrastructure&source_type=syslog">Syslog</Link>
              <Link className="btn-secondary px-3 py-2 text-xs" href="/search?category=infrastructure&source_type=netflow_v5&event_type=netflow_flow">NetFlow</Link>
              <Link className="btn-secondary px-3 py-2 text-xs" href="/search?category=infrastructure&source_type=snmp_trap&event_type=snmp_trap">SNMP</Link>
            </div>
          </div>

          {loading && !hasLoadedOnce ? <LoadingState /> : null}
          {error && !incidents.length ? <ErrorState message={error} /> : null}
          {!loading && !error && incidents.length === 0 ? <EmptyState title="No infrastructure incidents" detail="Trigger syslog, NetFlow, or SNMP proofs to populate this queue." /> : null}

          {!loading && !error && incidents.length > 0 ? (
            <div className="mt-4 min-h-[20rem] flex-1 overflow-auto rounded-2xl border border-ink-800 bg-ink-950/20">
              <table className="min-w-full text-sm">
                <thead className="text-left">
                  <tr>
                    <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Rule</th>
                    <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Run</th>
                    <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Status</th>
                    <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Lane</th>
                    <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Source</th>
                    <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((item) => (
                    <tr key={item.run_id} className="border-t border-ink-800/80">
                      <td className="p-2">
                        <div className="font-medium text-ink-100">{item.rule_id || "-"}</div>
                        <div className="mt-1">
                          <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${infrastructureBadgeClass(item.rule_id)}`}>
                            {infrastructureLabel(item.rule_id)}
                          </span>
                        </div>
                        <div className="mt-2 text-[11px] text-ink-400">{infrastructureDescription(item.rule_id)}</div>
                      </td>
                      <td className="p-2">
                        <Link className="font-mono text-xs text-cyan-100 underline decoration-cyan-800/70" href={`/incidents?category=infrastructure&open_run_id=${encodeURIComponent(item.run_id)}&open_tab=overview`}>
                          {item.run_id}
                        </Link>
                        <div className="mt-1 text-[11px] text-ink-400">{item.playbook_id || "-"}</div>
                      </td>
                      <td className="p-2"><StatusBadge status={item.status} /></td>
                      <td className="p-2"><LaneBadge lane={item.lane} /></td>
                      <td className="p-2 text-xs text-ink-300">
                        <div>{item.source_type || "-"}</div>
                        <div className="mt-1">{item.event_type || "-"}</div>
                        <div className="mt-1">{item.target_agent_id ? `gateway ${item.target_agent_id}` : "notify-only / no gateway target"}</div>
                      </td>
                      <td className="p-2 text-xs text-ink-300">{unixMsToLocal(item.last_updated_at_unix_ms)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>

        <div className="flex min-h-0 flex-col gap-4">
          <div className="panel-elevated p-4">
            <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">Coverage</div>
            <div className="mt-3 space-y-3 text-sm">
              <div>
                <div className="text-ink-100">Source coverage</div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {sourceBreakdown.map((item) => (
                    <span key={item.key} className="rounded border border-ink-700/70 bg-ink-900/60 px-2 py-1 text-xs text-ink-200">
                      {item.key}: {item.count}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <div className="text-ink-100">Rule coverage</div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {ruleBreakdown.map((item) => (
                    <span key={item.key} className={`rounded border px-2 py-1 text-xs ${infrastructureBadgeClass(item.key)}`}>
                      {item.key}: {item.count}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="panel-elevated flex min-h-0 flex-col overflow-hidden p-4">
            <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">Recent Infrastructure Telemetry</div>
            <div className="mt-1 text-sm text-ink-300">Latest normalized infrastructure events available for search pivots.</div>
            <div className="mt-4 min-h-[18rem] flex-1 overflow-auto rounded-2xl border border-ink-800 bg-ink-950/20">
              <table className="min-w-full text-sm">
                <thead className="text-left">
                  <tr>
                    <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Received</th>
                    <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Source</th>
                    <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Rule</th>
                    <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Network</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => (
                    <tr key={`${event.event_idem_key}-${event.recv_ts_unix_ms}`} className="border-t border-ink-800/80">
                      <td className="p-2 text-xs text-ink-300">{unixMsToLocal(event.recv_ts_unix_ms)}</td>
                      <td className="p-2 text-xs text-ink-300">
                        <div>{event.source_type}</div>
                        <div className="mt-1">{event.event_type}</div>
                      </td>
                      <td className="p-2">
                        <div className="text-xs text-ink-100">{event.rule_id || "-"}</div>
                        {event.rule_id ? (
                          <div className="mt-1">
                            <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.18em] ${infrastructureBadgeClass(event.rule_id)}`}>
                              {infrastructureLabel(event.rule_id)}
                            </span>
                          </div>
                        ) : null}
                      </td>
                      <td className="p-2 text-xs text-ink-300">
                        <div>{event.src_ip || "-"}{event.dst_ip ? ` -> ${event.dst_ip}` : ""}</div>
                        <div className="mt-1">{event.dst_port ? `${event.dst_port}` : "-"}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
