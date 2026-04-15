"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  approveIncident,
  downloadSOCOperationsReport,
  getAudit,
  getDashboardIncidentsSeries,
  getDashboardLanes,
  getDashboardSeverity,
  getDashboardSummary,
  getDashboardTopEntities,
  getEndpointEvents,
  getEndpointRuns,
  getEndpointsGeo,
  getIncidents,
  me,
  rejectIncident
} from "@/lib/api";
import { INCIDENT_MUTATED_EVENT, INCIDENTS_UPDATED_EVENT, emitIncidentMutated, emitIncidentsUpdated } from "@/lib/events";
import { AuditEntry, AuthUser, DashboardIncidentPoint, DashboardSummary, EndpointGeoSummary, EventRow, Incident } from "@/lib/types";
import { EmptyState, ErrorState, LaneBadge, LoadingState, StatusBadge, unixMsToLocal } from "@/components/ui";
import { IncidentDrawer } from "@/components/incident-drawer";
import { GeoPostureMap } from "@/components/geo-posture-map";

function MiniBars({ data, colorClass }: { data: Array<{ label: string; value: number }>; colorClass: string }) {
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <div className="space-y-2">
      {data.map((d) => (
        <div key={d.label} className="space-y-1">
          <div className="flex items-center justify-between text-xs text-ink-300">
            <span className="truncate pr-2">{d.label}</span>
            <span>{d.value}</span>
          </div>
          <div className="h-2 rounded bg-ink-800/90">
            <div className={`h-2 rounded ${colorClass}`} style={{ width: `${Math.max(4, (d.value / max) * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function parseRange(windowQ: string | null): string {
  const v = (windowQ || "").toLowerCase();
  if (["15m", "1h", "24h", "7d"].includes(v)) return v;
  return "24h";
}

function seriesBucketForRange(range: string): string {
  switch (range) {
    case "15m":
      return "1m";
    case "1h":
      return "5m";
    case "7d":
      return "6h";
    case "24h":
    default:
      return "1h";
  }
}

function seriesLabelForRange(range: string, tsUnixMs: number): string {
  const date = new Date(tsUnixMs);
  if (range === "7d") {
    return `${date.toLocaleDateString([], { month: "2-digit", day: "2-digit" })} ${date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  }
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function parseQueryTime(v: string | null): number | undefined {
  if (!v) return undefined;
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return n;
  const p = Date.parse(v);
  if (!Number.isNaN(p) && p > 0) return p;
  return undefined;
}

function statusBadge(status: string): string {
  const s = status.toLowerCase();
  if (s === "active") return "badge-good";
  if (s === "warning") return "badge-warn";
  if (s === "critical") return "badge-bad";
  return "badge-info";
}

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

function isValidLatLon(lat: unknown, lon: unknown): lat is number {
  if (typeof lat !== "number" || typeof lon !== "number") return false;
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return false;
  return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

function isLocatedEndpoint(ep: EndpointGeoSummary): boolean {
  const src = (ep.geo?.source || "").trim().toLowerCase();
  if (!(src === "configured" || src === "explicit" || src === "manual")) return false;
  return isValidLatLon(ep.geo?.lat, ep.geo?.lon);
}

function EndpointDrawer({
  endpoint,
  events,
  runs,
  loading,
  onClose
}: {
  endpoint: EndpointGeoSummary | null;
  events: EventRow[];
  runs: Incident[];
  loading: boolean;
  onClose: () => void;
}) {
  if (!endpoint) return null;
  return (
    <div className="fixed inset-0 z-40 bg-black/50">
      <div className="absolute right-0 top-0 h-full w-full max-w-3xl overflow-auto border-l border-ink-700 bg-ink-950 p-4">
        <div className="mb-3 flex items-center justify-between">
          <div>
            <h3 className="text-[18px] font-semibold">Endpoint Detail</h3>
            <p className="text-xs text-ink-300">{endpoint.node_id}</p>
          </div>
          <button className="btn-secondary" onClick={onClose}>Close</button>
        </div>

        <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-4">
          <div className="panel-elevated p-3 text-sm"><div className="text-xs text-ink-300">Status</div><div className="mt-1"><span className={statusBadge(endpoint.status)}>{endpoint.status.toUpperCase()}</span></div></div>
          <div className="panel-elevated p-3 text-sm"><div className="text-xs text-ink-300">Last seen</div><div className="font-medium">{endpoint.last_seen_rfc3339 || "-"}</div></div>
          <div className="panel-elevated p-3 text-sm"><div className="text-xs text-ink-300">Events 5m / 1h</div><div className="font-medium">{endpoint.events_5m} / {endpoint.events_1h}</div></div>
          <div className="panel-elevated p-3 text-sm"><div className="text-xs text-ink-300">Geo source</div><div className="font-medium">{endpoint.geo?.source || "none"}</div></div>
        </div>

        {loading ? <LoadingState /> : null}
        {!loading ? (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="panel-elevated p-3">
              <h4 className="mb-2 text-sm font-semibold">Recent Events</h4>
              {events.length === 0 ? <EmptyState title="No recent events" /> : null}
              {events.length > 0 ? (
                <div className="max-h-[440px] overflow-auto text-xs">
                  <table className="min-w-full">
                    <thead>
                      <tr>
                        <th className="table-head p-1.5 text-left">Time</th>
                        <th className="table-head p-1.5 text-left">Type</th>
                        <th className="table-head p-1.5 text-left">User</th>
                        <th className="table-head p-1.5 text-left">src_ip</th>
                      </tr>
                    </thead>
                    <tbody>
                      {events.map((ev) => (
                        <tr key={`${ev.event_idem_key}-${ev.recv_ts_unix_ms}`} className="border-t border-ink-800/80">
                          <td className="p-1.5">{unixMsToLocal(ev.recv_ts_unix_ms)}</td>
                          <td className="p-1.5">{ev.source_type}/{ev.event_type}</td>
                          <td className="p-1.5">{ev.user_name || "-"}</td>
                          <td className="p-1.5">{ev.src_ip || "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </div>

            <div className="panel-elevated p-3">
              <h4 className="mb-2 text-sm font-semibold">Recent Runs</h4>
              {runs.length === 0 ? <EmptyState title="No runs for endpoint" /> : null}
              {runs.length > 0 ? (
                <div className="max-h-[440px] space-y-2 overflow-auto">
                  {runs.map((run) => (
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
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const searchParams = useSearchParams();
  const range = parseRange(searchParams.get("grange"));

  const [loading, setLoading] = useState(true);
  const [hasLoadedOnce, setHasLoadedOnce] = useState(false);
  const hasLoadedOnceRef = useRef(false);
  const [error, setError] = useState("");
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [series, setSeries] = useState<DashboardIncidentPoint[]>([]);
  const [severity, setSeverity] = useState<Array<{ severity: string; count: number }>>([]);
  const [lanes, setLanes] = useState<Array<{ lane: string; count: number }>>([]);
  const [top, setTop] = useState<{ src_ip: Array<{ value: string; count: number }>; user_name: Array<{ value: string; count: number }>; node_id: Array<{ value: string; count: number }> }>({
    src_ip: [],
    user_name: [],
    node_id: []
  });
  const [liveIncidents, setLiveIncidents] = useState<Incident[]>([]);
  const [auditItems, setAuditItems] = useState<AuditEntry[]>([]);
  const [selectedRunID, setSelectedRunID] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [actionBusyRun, setActionBusyRun] = useState("");
  const [refreshNonce, setRefreshNonce] = useState(0);

  const [geoEndpoints, setGeoEndpoints] = useState<EndpointGeoSummary[]>([]);
  const [geoGeneratedAt, setGeoGeneratedAt] = useState("");
  const [collapsedPosture, setCollapsedPosture] = useState(false);
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [useSiteAggregate, setUseSiteAggregate] = useState(false);

  const [selectedEndpoint, setSelectedEndpoint] = useState<EndpointGeoSummary | null>(null);
  const [endpointEvents, setEndpointEvents] = useState<EventRow[]>([]);
  const [endpointRuns, setEndpointRuns] = useState<Incident[]>([]);
  const [endpointLoading, setEndpointLoading] = useState(false);

  const fromMs = useMemo(() => parseQueryTime(searchParams.get("gfrom")), [searchParams]);
  const toMs = useMemo(() => parseQueryTime(searchParams.get("gto")), [searchParams]);

  const load = useCallback(async () => {
    if (!hasLoadedOnceRef.current) {
      setLoading(true);
    }
    setError("");
    try {
      const [s, i, sev, lane, t, inc, audit, geo] = await Promise.all([
        getDashboardSummary("24h"),
        getDashboardIncidentsSeries(range, seriesBucketForRange(range)),
        getDashboardSeverity(range),
        getDashboardLanes(range),
        getDashboardTopEntities(range === "7d" ? "24h" : "1h"),
        getIncidents("limit=20&sort=updated_desc"),
        getAudit("limit=20"),
        getEndpointsGeo("1h")
      ]);
      setSummary(s);
      setSeries(i.items || []);
      setSeverity(sev.items || []);
      setLanes(lane.items || []);
      setTop({ src_ip: t.src_ip || [], user_name: t.user_name || [], node_id: t.node_id || [] });
      setLiveIncidents(inc.items || []);
      setAuditItems(audit.items || []);
      setGeoEndpoints(geo.endpoints || []);
      setGeoGeneratedAt(geo.generated_at || "");
      hasLoadedOnceRef.current = true;
      setHasLoadedOnce(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [range]);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      if (cancelled) return;
      await load();
    };
    run();
    const t = setInterval(run, 15000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
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

  useEffect(() => {
    let cancelled = false;
    me()
      .then((res) => {
        if (!cancelled) setAuthUser(res.user);
      })
      .catch(() => {
        if (!cancelled) setAuthUser(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const trendBars = useMemo(() => {
    return series.map((p) => ({
      label: seriesLabelForRange(range, p.ts_unix_ms),
      value: p.count
    }));
  }, [range, series]);
  const locatedEndpoints = useMemo(() => geoEndpoints.filter(isLocatedEndpoint), [geoEndpoints]);
  const unlocated = useMemo(() => geoEndpoints.filter((x) => !isLocatedEndpoint(x)), [geoEndpoints]);
  const activeEndpointsCount = useMemo(() => geoEndpoints.filter((x) => x.status === "active").length, [geoEndpoints]);
  const criticalEndpointsCount = useMemo(() => geoEndpoints.filter((x) => x.status === "critical").length, [geoEndpoints]);
  const locatedEndpointsCount = locatedEndpoints.length;
  const unlocatedEndpointsCount = unlocated.length;
  const timelineMax = Math.max(1, ...trendBars.map((x) => x.value));

  const siteAggregate = useMemo(() => {
    const lat = Number(process.env.NEXT_PUBLIC_UI_SITE_LAT || "");
    const lon = Number(process.env.NEXT_PUBLIC_UI_SITE_LON || "");
    const label = (process.env.NEXT_PUBLIC_UI_SITE_LABEL || "").trim();
    if (!isValidLatLon(lat, lon)) return null;
    return { lat, lon, label: label || "Site aggregate (unlocated)" };
  }, []);

  const openEndpoint = async (nodeID: string) => {
    const ep = geoEndpoints.find((x) => x.node_id === nodeID) || null;
    setSelectedEndpoint(ep);
    if (!ep) return;
    setEndpointLoading(true);
    try {
      const qs = new URLSearchParams();
      if (fromMs) qs.set("from", String(fromMs));
      if (toMs) qs.set("to", String(toMs));
      qs.set("limit", "200");
      const [evRes, runRes] = await Promise.all([
        getEndpointEvents(ep.node_id, qs.toString()),
        getEndpointRuns(ep.node_id, 100)
      ]);
      setEndpointEvents(evRes.items || []);
      setEndpointRuns(runRes.items || []);
    } catch (e) {
      setError((e as Error).message);
      setEndpointEvents([]);
      setEndpointRuns([]);
    } finally {
      setEndpointLoading(false);
    }
  };

  const quickDecision = async (runID: string, decision: "approve" | "reject") => {
    setActionBusyRun(runID);
    try {
      if (decision === "approve") {
        await approveIncident(runID, "approve", "dashboard.quick");
      } else {
        await rejectIncident(runID, "dashboard.quick");
      }
      await load();
      emitIncidentMutated(runID);
      emitIncidentsUpdated({ runID });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setActionBusyRun("");
    }
  };

  return (
    <section className="flex h-full min-h-0 flex-col gap-4">
      <div>
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-[18px] font-semibold">Dashboard</h2>
            <p className="text-[13px] text-ink-300">Geo posture, live incidents, entity spotlight, and response pressure in one view.</p>
          </div>
          <div className="flex items-center gap-2">
            <button className="btn-secondary px-2 py-1 text-xs" onClick={() => void downloadSOCOperationsReport(range, "pdf")}>
              SOC PDF
            </button>
            <button className="btn-secondary px-2 py-1 text-xs" onClick={() => void downloadSOCOperationsReport(range, "html")}>
              SOC HTML
            </button>
          </div>
        </div>
      </div>

      {loading && !hasLoadedOnce ? <LoadingState /> : null}
      {error && !summary ? <ErrorState message={error} /> : null}
      {error && summary ? (
        <div className="rounded border border-rose-900/80 bg-rose-950/30 px-3 py-2 text-sm text-rose-200">
          {error}
        </div>
      ) : null}

      {summary ? (
        <>
          <div className="panel-elevated flex min-h-[560px] flex-col overflow-hidden border-ink-700/80">
            <div className="flex items-center justify-between border-b border-ink-700/80 px-4 py-3">
              <div>
                <h3 className="text-[16px] font-semibold">Geo Posture Map</h3>
                <p className="text-xs text-ink-300">Truthful basemap posture view: only configured endpoint geolocation is plotted.</p>
              </div>
              <div className="flex items-center gap-2">
                <button className="btn-secondary px-2 py-1 text-xs" onClick={() => setCollapsedPosture((v) => !v)}>
                  {collapsedPosture ? "Show Posture" : "Hide Posture"}
                </button>
              </div>
            </div>

            <div className="grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[330px_1fr]">
              {!collapsedPosture ? (
                <aside className="overflow-auto border-b border-r border-ink-700/80 bg-ink-900/50 p-4 lg:border-b-0">
                  <div className="mb-3 text-[11px] uppercase tracking-[0.08em] text-ink-400">Posture Panel</div>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="panel p-3"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Total Events (24h)</div><div className="text-xl font-semibold">{summary.total_events_last_window || 0}</div></div>
                    <div className="panel p-3"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Model Alerts (24h)</div><div className="text-xl font-semibold">{summary.model_alerts_last_window || 0}</div></div>
                    <div className="panel p-3"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Incidents (24h)</div><div className="text-xl font-semibold">{summary.incidents_last_window}</div></div>
                    <div className="panel p-3"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Critical (24h)</div><div className="text-xl font-semibold text-rose-300">{summary.critical_incidents_last_window || 0}</div></div>
                    <div className="panel p-3"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Active Endpoints</div><div className="text-xl font-semibold text-emerald-300">{activeEndpointsCount}</div></div>
                    <div className="panel p-3"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Critical Endpoints</div><div className="text-xl font-semibold text-rose-300">{criticalEndpointsCount}</div></div>
                    <div className="panel p-3"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Located Endpoints</div><div className="text-xl font-semibold text-cyan-300">{locatedEndpointsCount}</div></div>
                    <div className="panel p-3"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Unlocated Endpoints</div><div className="text-xl font-semibold text-slate-300">{unlocatedEndpointsCount}</div></div>
                  </div>

                  <div className="mt-3 rounded border border-ink-700/80 bg-ink-900/50 p-2 text-xs text-ink-300">
                    <span className="font-medium text-ink-100">Unlocated endpoints:</span> {unlocatedEndpointsCount}
                  </div>

                  {authUser?.role === "admin" && siteAggregate ? (
                    <div className="mt-3 rounded border border-ink-700/80 bg-ink-900/50 p-2 text-xs text-ink-300">
                      <label className="flex cursor-pointer items-start gap-2">
                        <input
                          type="checkbox"
                          checked={useSiteAggregate}
                          onChange={(e) => setUseSiteAggregate(e.target.checked)}
                          className="mt-0.5"
                        />
                        <span>
                          Use Configured Site Location for Unlocated Endpoints
                          <span className="ml-1 text-[11px] text-ink-400">(default OFF)</span>
                        </span>
                      </label>
                    </div>
                  ) : null}

                  <div className="mt-4">
                    <div className="mb-2 text-[11px] uppercase tracking-[0.08em] text-ink-400">MITRE Tactics Processed</div>
                    <div className="grid grid-cols-1 gap-2">
                      {(summary.mitre_tactics_processed || []).slice(0, 6).map((t) => (
                        <div key={t.tactic} className="panel flex items-center justify-between p-2 text-xs">
                          <div>
                            <div className="font-medium text-ink-100">{t.tactic}</div>
                            <div className="text-ink-300">High/Critical: {t.high_critical}</div>
                          </div>
                          <div className="text-right">
                            <div className="text-lg font-semibold">{t.count}</div>
                            {typeof t.delta === "number" ? <div className={`text-[11px] ${t.delta >= 0 ? "text-emerald-300" : "text-rose-300"}`}>{t.delta >= 0 ? "+" : ""}{t.delta}</div> : null}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {unlocated.length > 0 ? (
                    <div className="mt-4">
                      <div className="mb-1 text-[11px] uppercase tracking-[0.08em] text-ink-400">Unknown Location</div>
                      <div className="max-h-24 overflow-auto text-xs text-ink-300">
                        {unlocated.map((u) => <div key={u.node_id}>{u.node_id}</div>)}
                      </div>
                    </div>
                  ) : null}
                </aside>
              ) : null}

              <GeoPostureMap
                endpoints={geoEndpoints}
                generatedAt={geoGeneratedAt}
                onSelectEndpoint={openEndpoint}
                probeHover={searchParams.get("geo_hover_probe") === "1"}
                useSiteAggregateForUnlocated={useSiteAggregate}
                siteAggregate={siteAggregate}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 md:grid-cols-6">
            <div className="panel-elevated p-4"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Incidents ({range})</div><div className="text-[24px] font-semibold">{summary.incidents_last_window}</div></div>
            <div className="panel-elevated p-4"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Approvals Pending</div><div className="text-[24px] font-semibold">{summary.approvals_pending}</div></div>
            <div className="panel-elevated p-4"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Failed Safe</div><div className="text-[24px] font-semibold text-rose-300">{summary.failed_safe_count}</div></div>
            <div className="panel-elevated p-4"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Active Endpoints</div><div className="text-[24px] font-semibold">{summary.endpoints_active}</div></div>
            <div className="panel-elevated p-4"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">Ingest Rate / 5m</div><div className="text-[24px] font-semibold">{summary.ingestion_rate_per_min.toFixed(1)}</div></div>
            <div className="panel-elevated p-4"><div className="text-[11px] uppercase tracking-[0.08em] text-ink-400">p95 Latency (ms)</div><div className="text-[24px] font-semibold text-emerald-300">{summary.latency_p95_ms}</div></div>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.2fr_1.5fr_1fr]">
            <div className="space-y-4">
              <div className="panel-elevated p-4">
                <h3 className="mb-2 text-[16px] font-semibold">Threat Trend (24h)</h3>
                {trendBars.length === 0 ? <EmptyState title="No trend data" /> : <MiniBars data={trendBars} colorClass="bg-cyan-400" />}
              </div>
              <div className="panel-elevated p-4">
                <h3 className="mb-2 text-[16px] font-semibold">Severity Mix</h3>
                <MiniBars data={severity.map((s) => ({ label: s.severity, value: s.count }))} colorClass="bg-fuchsia-400" />
              </div>
            </div>

            <div className="panel-elevated p-4">
              <div className="mb-3">
                <h3 className="text-[16px] font-semibold">Threat Tray</h3>
                <p className="text-xs text-ink-300">Analyst-facing queue of live runs, approvals, and one-click pivots into the investigation workspace.</p>
              </div>
              {liveIncidents.length === 0 ? <EmptyState title="No incidents" /> : null}
              <div className="max-h-[620px] space-y-2 overflow-auto">
                {liveIncidents.map((run) => (
                  <div key={run.run_id} className="rounded-lg border border-ink-700 bg-ink-900/40 p-3 text-[13px]">
                    <div className="mb-1 flex items-center justify-between gap-2">
                      <button
                        className="font-medium underline decoration-ink-600"
                        onClick={() => {
                          setSelectedRunID(run.run_id);
                          setDrawerOpen(true);
                        }}
                      >
                        {run.run_id}
                      </button>
                      <StatusBadge status={run.status} />
                    </div>
                    <div className="grid grid-cols-2 gap-1 text-[12px] text-ink-300">
                      <div>{run.rule_id || "-"}</div>
                      <div>{run.playbook_id || "-"}</div>
                      <div>{run.node_id || "-"}</div>
                      <div>{unixMsToLocal(run.last_updated_at_unix_ms)}</div>
                      <div className="col-span-2 flex items-baseline gap-1 overflow-hidden text-[11px]">
                        <span className="shrink-0 text-ink-500">net:</span>
                        <span className="truncate font-mono text-ink-200">
                          {run.src_ip || "-"}{run.dst_ip ? ` -> ${run.dst_ip}` : ""}
                        </span>
                      </div>
                      {(run.comm || run.exec_path) ? (
                        <div className="col-span-2 flex items-baseline gap-1 overflow-hidden text-[11px]">
                          <span className="shrink-0 text-ink-500">proc:</span>
                          <span className="truncate font-mono text-ink-200">
                            {run.comm || run.exec_path}
                            {run.comm && run.exec_path ? ` (${run.exec_path})` : ""}
                          </span>
                        </div>
                      ) : null}
                    </div>
                    {policyBadge(run.approval_policy_reason) ? (
                      <div className="mt-2">
                        <span className="rounded-full border border-ink-700 bg-ink-800/70 px-2 py-0.5 text-[11px] text-ink-200">
                          {policyBadge(run.approval_policy_reason)}
                        </span>
                        <span className="ml-2 text-[11px] text-ink-400">
                          conf {run.confidence_score ?? "-"} | {run.playbook_reversibility || "mixed"}
                        </span>
                      </div>
                    ) : null}
                    <div className="mt-2 flex flex-wrap gap-2">
                      <button className="btn-secondary px-2 py-1 text-xs" onClick={() => { setSelectedRunID(run.run_id); setDrawerOpen(true); }}>Open</button>
                      {run.status?.toUpperCase() === "WAITING_APPROVAL" ? (
                        <>
                          <button disabled={actionBusyRun === run.run_id} className="btn-primary px-2 py-1 text-xs disabled:opacity-60" onClick={() => quickDecision(run.run_id, "approve")}>Approve</button>
                          <button disabled={actionBusyRun === run.run_id} className="btn-danger px-2 py-1 text-xs disabled:opacity-60" onClick={() => quickDecision(run.run_id, "reject")}>Reject</button>
                        </>
                      ) : null}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-4">
              <div className="panel-elevated p-4">
                <h3 className="mb-2 text-[16px] font-semibold">Entity Spotlight: src_ip</h3>
                <MiniBars data={top.src_ip.map((x) => ({ label: x.value, value: x.count }))} colorClass="bg-violet-400" />
              </div>
              <div className="panel-elevated p-4">
                <h3 className="mb-2 text-[16px] font-semibold">Top Users</h3>
                <MiniBars data={top.user_name.map((x) => ({ label: x.value, value: x.count }))} colorClass="bg-amber-400" />
              </div>
              <div className="panel-elevated p-4">
                <h3 className="mb-2 text-[16px] font-semibold">Top Nodes</h3>
                <MiniBars data={top.node_id.map((x) => ({ label: x.value, value: x.count }))} colorClass="bg-emerald-400" />
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.3fr_1fr]">
            <div className="panel-elevated p-4">
              <h3 className="mb-2 text-[16px] font-semibold">Lane Distribution + Timeline Strip</h3>
              <div className="mb-3 grid grid-cols-1 gap-4 md:grid-cols-2">
                <MiniBars data={lanes.map((l) => ({ label: l.lane, value: l.count }))} colorClass="bg-cyan-400" />
                <div>
                  <div className="mb-1 text-xs text-ink-300">Window density ({range})</div>
                  <div className="flex items-end gap-1 rounded border border-ink-700/70 bg-ink-900/40 p-2">
                    {trendBars.length === 0 ? <span className="text-xs text-ink-400">No timeline data</span> : null}
                    {trendBars.map((b) => {
                      const h = Math.max(8, Math.round((b.value / timelineMax) * 72));
                      return <div key={b.label} className="w-3 rounded-t bg-cyan-400/90" style={{ height: `${h}px` }} title={`${b.label}: ${b.value}`} />;
                    })}
                  </div>
                </div>
              </div>
            </div>

            <div className="panel-elevated p-4">
              <h3 className="mb-2 text-[16px] font-semibold">Recent Audit Events</h3>
              {auditItems.length === 0 ? <EmptyState title="No audit events" /> : null}
              <div className="max-h-[240px] space-y-2 overflow-auto">
                {auditItems.slice(0, 12).map((entry, idx) => (
                  <div key={`${entry.ts}-${entry.run_id || idx}`} className="rounded-lg border border-ink-700/80 bg-ink-900/40 p-2 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium">{entry.msg}</span>
                      <span className="text-ink-400">{entry.ts}</span>
                    </div>
                    <div className="mt-1 text-ink-300">run={entry.run_id || "-"} actor={entry.actor || "-"}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      ) : null}

      <IncidentDrawer runID={selectedRunID} open={drawerOpen} onClose={() => setDrawerOpen(false)} />
      <EndpointDrawer endpoint={selectedEndpoint} events={endpointEvents} runs={endpointRuns} loading={endpointLoading} onClose={() => setSelectedEndpoint(null)} />
    </section>
  );
}
