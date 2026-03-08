"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { getIncidents } from "@/lib/api";
import { INCIDENT_MUTATED_EVENT, INCIDENTS_UPDATED_EVENT } from "@/lib/events";
import { Incident, IncidentListResponse } from "@/lib/types";
import { IncidentDrawer } from "@/components/incident-drawer";
import { EmptyState, ErrorState, LaneBadge, LoadingState, StatusBadge, unixMsToLocal } from "@/components/ui";

type SavedView = {
  name: string;
  status?: string;
  lane?: string;
  severity?: string;
};

const DEFAULT_VIEWS: SavedView[] = [
  { name: "Triage", status: "RUNNING" },
  { name: "FAST Pending", lane: "FAST", status: "WAITING_APPROVAL" },
  { name: "Failed Safe", status: "FAILED_SAFE" },
  { name: "All" }
];

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
  const [items, setItems] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(50);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [lane, setLane] = useState("");
  const [severity, setSeverity] = useState("");
  const [nodeID, setNodeID] = useState("");
  const [playbookID, setPlaybookID] = useState("");
  const [ruleID, setRuleID] = useState("");
  const [q, setQ] = useState(searchParams.get("gq") || "");
  const [sort, setSort] = useState("updated_desc");
  const [selectedRunID, setSelectedRunID] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [refreshNonce, setRefreshNonce] = useState(0);
  const globalFrom = useMemo(() => parseQueryTime(searchParams.get("gfrom")), [searchParams]);
  const globalTo = useMemo(() => parseQueryTime(searchParams.get("gto")), [searchParams]);

  useEffect(() => {
    const saved = localStorage.getItem("rsiem-saved-view");
    if (saved) {
      const parsed = JSON.parse(saved) as SavedView;
      setStatus(parsed.status || "");
      setLane(parsed.lane || "");
      setSeverity(parsed.severity || "");
    }
  }, []);

  useEffect(() => {
    setQ(searchParams.get("gq") || "");
  }, [searchParams]);

  const load = useCallback(() => {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    if (lane) params.set("lane", lane);
    if (severity) params.set("severity", severity);
    if (nodeID) params.set("node_id", nodeID);
    if (playbookID) params.set("playbook_id", playbookID);
    if (ruleID) params.set("rule_id", ruleID);
    if (q) params.set("q", q);
    if (globalFrom) params.set("from", String(globalFrom));
    if (globalTo) params.set("to", String(globalTo));
    params.set("limit", String(limit));
    params.set("page", String(page));
    params.set("sort", sort);

    setLoading(true);
    setError(null);
    return getIncidents(params.toString())
      .then((res: IncidentListResponse) => {
        setItems(res.items || []);
        setTotal(res.total || res.count || 0);
      })
      .catch((e) => setError(e.message || String(e)))
      .finally(() => setLoading(false));
  }, [status, lane, severity, nodeID, playbookID, ruleID, q, globalFrom, globalTo, page, limit, sort]);

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
    setStatus(view.status || "");
    setLane(view.lane || "");
    setSeverity(view.severity || "");
    setPage(1);
  };

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-[18px] font-semibold">Incident Queue</h2>
          <p className="text-[13px] text-ink-300">SOC queue with deterministic sort/paging, triage filters, and drawer investigation.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <select value={sort} onChange={(e) => setSort(e.target.value)} className="select-field py-1 text-xs">
            <option value="updated_desc">Updated desc</option>
            <option value="updated_asc">Updated asc</option>
            <option value="severity_desc">Severity desc</option>
            <option value="status_asc">Status asc</option>
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
        </div>
      </div>

      <div className="sticky top-2 z-20 panel-elevated grid grid-cols-1 gap-2 p-2 md:grid-cols-8">
        <input className="input-field" placeholder="Search run/user/src/node/rule" value={q} onChange={(e) => setQ(e.target.value)} />
        <input className="input-field" placeholder="Status (WAITING_APPROVAL...)" value={status} onChange={(e) => setStatus(e.target.value)} />
        <input className="input-field" placeholder="Lane (FAST/STANDARD)" value={lane} onChange={(e) => setLane(e.target.value)} />
        <input className="input-field" placeholder="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)} />
        <input className="input-field" placeholder="Node ID" value={nodeID} onChange={(e) => setNodeID(e.target.value)} />
        <input className="input-field" placeholder="Playbook ID" value={playbookID} onChange={(e) => setPlaybookID(e.target.value)} />
        <input className="input-field" placeholder="Rule ID" value={ruleID} onChange={(e) => setRuleID(e.target.value)} />
        <button
          onClick={() => {
            setQ("");
            setStatus("");
            setLane("");
            setSeverity("");
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

      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {!loading && !error && items.length === 0 ? <EmptyState title="No incidents found" detail="Adjust filters or trigger deterministic events." /> : null}

      {!loading && !error && items.length > 0 ? (
        <div className="overflow-auto">
          <table className="min-w-full text-sm">
            <thead className="text-left">
              <tr>
                <th className="table-head p-2">Severity</th>
                <th className="table-head p-2">Run ID</th>
                <th className="table-head p-2">Status</th>
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
                  <td className="p-2"><LaneBadge lane={it.lane} /></td>
                  <td className="p-2">
                    <div className="font-medium">{it.rule_id || "-"}</div>
                    <div className="text-xs text-ink-300">{it.playbook_id || "-"}</div>
                  </td>
                  <td className="p-2">{it.node_id || "-"}</td>
                  <td className="p-2">
                    <div>{it.source_type || "-"}</div>
                    <div className="text-xs text-ink-300">{it.event_type || "-"}</div>
                  </td>
                  <td className="p-2">{unixMsToLocal(it.last_updated_at_unix_ms)}</td>
                  <td className="p-2">
                    {it.status?.toUpperCase() === "WAITING_APPROVAL" ? (
                      <span className="rounded bg-rose-900 px-2 py-0.5 text-xs text-rose-300">needed</span>
                    ) : (
                      <span className="text-xs text-ink-400">none</span>
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
      />
    </section>
  );
}
