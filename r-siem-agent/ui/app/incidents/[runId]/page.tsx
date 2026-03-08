"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { approveIncident, getArtifacts, getIncident, getIncidentEvents } from "@/lib/api";
import { EventRow, Incident, StepResult } from "@/lib/types";
import { EmptyState, ErrorState, LaneBadge, LoadingState, StatusBadge, ValueRow, unixMsToLocal } from "@/components/ui";

export default function IncidentDetailPage({ params }: { params: { runId: string } }) {
  const runID = decodeURIComponent(params.runId);
  const [run, setRun] = useState<Incident | null>(null);
  const [steps, setSteps] = useState<StepResult[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [artifacts, setArtifacts] = useState<Array<{ path: string; is_dir: boolean; size: number; modified: string }>>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actor, setActor] = useState("khotso");
  const [approvalBusy, setApprovalBusy] = useState(false);
  const [approvalMsg, setApprovalMsg] = useState("");

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const detail = await getIncident(runID);
      setRun(detail.run);
      setSteps(detail.steps || []);
      const ev = await getIncidentEvents(runID, { windowSeconds: 900 });
      setEvents(ev.items || []);
      const collected: Array<{ path: string; is_dir: boolean; size: number; modified: string }> = [];
      for (let p = 1; p <= 3; p++) {
        const art = await getArtifacts("demo_artifacts", { q: "/fr04/", page: p, limit: 200 });
        collected.push(...(art.items || []));
        if (!art.has_more) break;
      }
      setArtifacts(collected.filter((a) => a.path.includes("/fr04/") || a.path.endsWith("chain_of_custody.json") || a.path.endsWith("capture.pcap")));
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runID]);

  const canApprove = useMemo(() => {
    if (!run) return false;
    return (run.status || "").toUpperCase() === "WAITING_APPROVAL";
  }, [run]);

  const doDecision = async (decision: "approve" | "reject") => {
    if (!run) return;
    setApprovalBusy(true);
    setApprovalMsg("");
    try {
      await approveIncident(run.run_id, decision, actor);
      setApprovalMsg(`Decision sent: ${decision}`);
      await load();
    } catch (e) {
      setApprovalMsg(`Decision failed: ${(e as Error).message || String(e)}`);
    } finally {
      setApprovalBusy(false);
    }
  };

  return (
    <section className="space-y-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-xs text-ink-300">
            <Link className="underline" href="/incidents">Incidents</Link> / <span>{runID}</span>
          </div>
          <h2 className="text-lg font-semibold">Incident Detail</h2>
        </div>
      </div>

      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {!loading && !error && !run ? <EmptyState title="Run not found" /> : null}

      {!loading && run ? (
        <>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="rounded-lg border border-ink-700 p-4">
              <h3 className="mb-3 text-sm font-semibold">Run Header</h3>
              <div className="space-y-2">
                <ValueRow label="run_id" value={run.run_id} />
                <ValueRow label="status" value={<StatusBadge status={run.status} />} />
                <ValueRow label="lane" value={<LaneBadge lane={run.lane} />} />
                <ValueRow label="rule_id" value={run.rule_id} />
                <ValueRow label="playbook_id" value={run.playbook_id} />
                <ValueRow label="node_id" value={run.node_id} />
                <ValueRow label="source_type" value={run.source_type} />
                <ValueRow label="event_type" value={run.event_type} />
                <ValueRow label="src_ip" value={run.src_ip} />
                <ValueRow label="user" value={run.user_name} />
                <ValueRow label="target_agent_id" value={run.target_agent_id} />
                <ValueRow label="updated" value={unixMsToLocal(run.last_updated_at_unix_ms)} />
              </div>
            </div>

            <div className="rounded-lg border border-ink-700 p-4">
              <h3 className="mb-3 text-sm font-semibold">Approval Widget</h3>
              {canApprove ? (
                <div className="space-y-3">
                  <p className="text-sm text-ink-200">FAST run is waiting approval. Submit deterministic decision.</p>
                  <input
                    className="w-full rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm"
                    value={actor}
                    onChange={(e) => setActor(e.target.value)}
                    placeholder="actor"
                  />
                  <div className="flex gap-2">
                    <button disabled={approvalBusy} className="rounded bg-green-700 px-3 py-2 text-sm hover:bg-green-600 disabled:opacity-50" onClick={() => doDecision("approve")}>
                      Approve
                    </button>
                    <button disabled={approvalBusy} className="rounded bg-rose-700 px-3 py-2 text-sm hover:bg-rose-600 disabled:opacity-50" onClick={() => doDecision("reject")}>
                      Reject
                    </button>
                  </div>
                  {approvalMsg ? <p className="text-xs text-ink-300">{approvalMsg}</p> : null}
                </div>
              ) : (
                <p className="text-sm text-ink-300">Run is not in FAST+RUNNING approval state.</p>
              )}
            </div>
          </div>

          <div className="rounded-lg border border-ink-700 p-4">
            <h3 className="mb-3 text-sm font-semibold">Steps</h3>
            {steps.length === 0 ? <EmptyState title="No steps found" /> : null}
            {steps.length > 0 ? (
              <div className="space-y-3">
                {steps.map((s) => (
                  <div key={`${s.step_id}-${s.finished_at_unix_ms}`} className="rounded border border-ink-800 p-3 text-sm">
                    <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                      <div className="font-medium">step {s.step_index}: {s.step_id}</div>
                      <StatusBadge status={s.status} />
                    </div>
                    <div className="grid grid-cols-1 gap-1 md:grid-cols-2">
                      <ValueRow label="action" value={s.action_type} />
                      <ValueRow label="lane" value={s.lane} />
                      <ValueRow label="target_agent_id" value={s.target_agent_id} />
                      <ValueRow label="target" value={s.target} />
                      <ValueRow label="attempt" value={String(s.attempt ?? 0)} />
                      <ValueRow label="finished" value={unixMsToLocal(s.finished_at_unix_ms)} />
                    </div>
                    {s.receipt ? (
                      <pre className="mt-2 overflow-auto rounded bg-ink-950 p-2 text-xs text-ink-200">{JSON.stringify(s.receipt, null, 2)}</pre>
                    ) : null}
                  </div>
                ))}
              </div>
            ) : null}
          </div>

          <div className="rounded-lg border border-ink-700 p-4">
            <h3 className="mb-3 text-sm font-semibold">Timeline Evidence</h3>
            {events.length === 0 ? <EmptyState title="No DB events in selected window" /> : null}
            {events.length > 0 ? (
              <div className="max-h-[380px] overflow-auto">
                <table className="min-w-full text-sm">
                  <thead className="text-left text-ink-300">
                    <tr>
                      <th className="p-2">Time</th>
                      <th className="p-2">Node</th>
                      <th className="p-2">Source/Event</th>
                      <th className="p-2">User</th>
                      <th className="p-2">src_ip</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((ev) => (
                      <tr key={`${ev.event_idem_key}-${ev.recv_ts_unix_ms}`} className="border-t border-ink-800/80">
                        <td className="p-2">{unixMsToLocal(ev.recv_ts_unix_ms)}</td>
                        <td className="p-2">{ev.node_id}</td>
                        <td className="p-2">{ev.source_type} / {ev.event_type}</td>
                        <td className="p-2">{ev.user_name || "-"}</td>
                        <td className="p-2">{ev.src_ip || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
          </div>

          <div className="rounded-lg border border-ink-700 p-4">
            <h3 className="mb-3 text-sm font-semibold">Artifacts / Evidence</h3>
            {artifacts.length === 0 ? <EmptyState title="No FR-04 evidence artifacts detected" /> : null}
            {artifacts.length > 0 ? (
              <ul className="space-y-2 text-sm">
                {artifacts.slice(0, 40).map((a) => (
                  <li key={a.path} className="flex items-center justify-between gap-2 rounded border border-ink-800 p-2">
                    <span className="truncate">{a.path}</span>
                    {!a.is_dir ? (
                      <a
                        href={`${process.env.NEXT_PUBLIC_UI_API_BASE || "http://127.0.0.1:8090"}/api/artifact?path=${encodeURIComponent(a.path)}`}
                        className="rounded bg-ink-700 px-2 py-1 text-xs hover:bg-ink-600"
                        target="_blank"
                      >
                        Download
                      </a>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        </>
      ) : null}
    </section>
  );
}
