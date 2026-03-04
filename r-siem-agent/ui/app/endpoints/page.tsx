"use client";

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { getEndpointEvents, getEndpointRuns, getEndpoints, postEndpointTargetedTest } from "@/lib/api";
import { EndpointSummary, EventRow, Incident } from "@/lib/types";
import { EmptyState, ErrorState, LaneBadge, LoadingState, StatusBadge, unixMsToLocal } from "@/components/ui";

function parseQueryTime(v: string | null): number | undefined {
  if (!v) return undefined;
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return n;
  const p = Date.parse(v);
  if (!Number.isNaN(p) && p > 0) return p;
  return undefined;
}

export default function EndpointsPage() {
  const searchParams = useSearchParams();
  const [items, setItems] = useState<EndpointSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<EndpointSummary | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [nodeEvents, setNodeEvents] = useState<EventRow[]>([]);
  const [nodeRuns, setNodeRuns] = useState<Incident[]>([]);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [actionMsg, setActionMsg] = useState("");
  const [actor, setActor] = useState("soc.analyst");

  const fromMs = useMemo(() => parseQueryTime(searchParams.get("gfrom")), [searchParams]);
  const toMs = useMemo(() => parseQueryTime(searchParams.get("gto")), [searchParams]);

  useEffect(() => {
    setLoading(true);
    getEndpoints()
      .then((res) => setItems(res.items || []))
      .catch((e) => setError(e.message || String(e)))
      .finally(() => setLoading(false));
  }, []);

  const openDrawer = async (node: EndpointSummary) => {
    setSelectedNode(node);
    setDrawerOpen(true);
    setDrawerLoading(true);
    setActionMsg("");
    try {
      const qs = new URLSearchParams();
      if (fromMs) qs.set("from", String(fromMs));
      if (toMs) qs.set("to", String(toMs));
      qs.set("limit", "200");
      const [evRes, runRes] = await Promise.all([getEndpointEvents(node.node_id, qs.toString()), getEndpointRuns(node.node_id, 100)]);
      setNodeEvents(evRes.items || []);
      setNodeRuns(runRes.items || []);
    } catch (e) {
      setActionMsg(`Failed loading node details: ${(e as Error).message}`);
      setNodeEvents([]);
      setNodeRuns([]);
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

  return (
    <section className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Endpoints</h2>
        <p className="text-sm text-ink-300">Node posture with event-rate telemetry and source distribution. Click a row for endpoint workspace.</p>
      </div>

      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {!loading && !error && items.length === 0 ? <EmptyState title="No endpoint activity" /> : null}

      {!loading && !error && items.length > 0 ? (
        <div className="overflow-auto">
          <table className="min-w-full text-sm">
            <thead className="text-left text-ink-300">
              <tr>
                <th className="p-2">Node</th>
                <th className="p-2">Last seen</th>
                <th className="p-2">Events (5m)</th>
                <th className="p-2">Events (1h)</th>
                <th className="p-2">Source distribution</th>
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
                          <span key={k} className="rounded bg-ink-800 px-2 py-0.5 text-xs">{k}:{v}</span>
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
                <h3 className="text-lg font-semibold">Endpoint Detail</h3>
                <p className="text-xs text-ink-300">node_id: {selectedNode.node_id}</p>
              </div>
              <button className="rounded bg-ink-800 px-3 py-2 text-sm hover:bg-ink-700" onClick={() => setDrawerOpen(false)}>
                Close
              </button>
            </div>

            <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-3">
              <div className="rounded border border-ink-800 p-3 text-sm">
                <div className="text-xs text-ink-300">Last seen</div>
                <div className="font-medium">{unixMsToLocal(selectedNode.last_seen_unix_ms)}</div>
              </div>
              <div className="rounded border border-ink-800 p-3 text-sm">
                <div className="text-xs text-ink-300">Events 5m / 1h</div>
                <div className="font-medium">{selectedNode.event_count_5m} / {selectedNode.event_count_1h}</div>
              </div>
              <div className="rounded border border-ink-800 p-3 text-sm">
                <div className="text-xs text-ink-300">Source distribution</div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {Object.entries(selectedNode.source_type_distribution || {}).map(([k, v]) => (
                    <span key={k} className="rounded bg-ink-800 px-2 py-0.5 text-xs">{k}:{v}</span>
                  ))}
                </div>
              </div>
            </div>

            <div className="mb-4 rounded border border-ink-800 p-3">
              <h4 className="mb-2 text-sm font-semibold">Targeted Action Test</h4>
              <div className="flex flex-wrap items-center gap-2">
                <input
                  value={actor}
                  onChange={(e) => setActor(e.target.value)}
                  className="rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm"
                  placeholder="actor"
                />
                <button className="rounded bg-ink-700 px-3 py-2 text-sm hover:bg-ink-600" onClick={doTargetedTest}>
                  Publish harmless targeted test
                </button>
              </div>
              {actionMsg ? <p className="mt-2 text-xs text-ink-300">{actionMsg}</p> : null}
            </div>

            {drawerLoading ? <LoadingState /> : null}
            {!drawerLoading ? (
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="rounded border border-ink-800 p-3">
                  <h4 className="mb-2 text-sm font-semibold">Recent Events</h4>
                  {nodeEvents.length === 0 ? <EmptyState title="No events in selected window" /> : null}
                  {nodeEvents.length > 0 ? (
                    <div className="max-h-[420px] overflow-auto text-xs">
                      <table className="min-w-full">
                        <thead className="text-left text-ink-300">
                          <tr>
                            <th className="p-1.5">Time</th>
                            <th className="p-1.5">Source/Event</th>
                            <th className="p-1.5">User</th>
                            <th className="p-1.5">src_ip</th>
                          </tr>
                        </thead>
                        <tbody>
                          {nodeEvents.map((ev) => (
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

                <div className="rounded border border-ink-800 p-3">
                  <h4 className="mb-2 text-sm font-semibold">Recent Runs Affecting Node</h4>
                  {nodeRuns.length === 0 ? <EmptyState title="No runs for this node" /> : null}
                  {nodeRuns.length > 0 ? (
                    <div className="max-h-[420px] space-y-2 overflow-auto">
                      {nodeRuns.map((run) => (
                        <div key={run.run_id} className="rounded border border-ink-800 p-2 text-xs">
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
      ) : null}
    </section>
  );
}
