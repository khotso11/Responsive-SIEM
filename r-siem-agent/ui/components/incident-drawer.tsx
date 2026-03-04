"use client";

import { useEffect, useMemo, useState } from "react";
import { getApiBase, getArtifacts, getIncident, getIncidentEvents, approveIncident } from "@/lib/api";
import { EventRow, Incident, StepResult } from "@/lib/types";
import { EmptyState, LaneBadge, LoadingState, StatusBadge, ValueRow, unixMsToLocal } from "@/components/ui";

type DrawerTab = "overview" | "steps" | "timeline" | "evidence" | "actions";

export function IncidentDrawer({
  runID,
  open,
  onClose,
  fromMs,
  toMs
}: {
  runID: string;
  open: boolean;
  onClose: () => void;
  fromMs?: number;
  toMs?: number;
}) {
  const [tab, setTab] = useState<DrawerTab>("overview");
  const [run, setRun] = useState<Incident | null>(null);
  const [steps, setSteps] = useState<StepResult[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [actor, setActor] = useState("soc.analyst");
  const [decisionMsg, setDecisionMsg] = useState("");
  const [pivotUser, setPivotUser] = useState("");
  const [pivotSrcIP, setPivotSrcIP] = useState("");
  const [pivotNode, setPivotNode] = useState("");
  const [artifactMap, setArtifactMap] = useState<Array<{ path: string; is_dir: boolean; size: number; modified: string }>>([]);

  const load = async () => {
    if (!runID || !open) return;
    setLoading(true);
    setDecisionMsg("");
    try {
      const detail = await getIncident(runID);
      setRun(detail.run);
      setSteps(detail.steps || []);
      const ev = await getIncidentEvents(runID, {
        windowSeconds: 900,
        from: fromMs,
        to: toMs,
        userName: pivotUser || undefined,
        srcIP: pivotSrcIP || undefined,
        nodeID: pivotNode || undefined
      });
      setEvents(ev.items || []);
      const art = await getArtifacts("demo_artifacts");
      setArtifactMap((art.items || []).filter((a) => a.path.includes("/fr04/") || a.path.endsWith("capture.pcap") || a.path.endsWith("chain_of_custody.json")));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runID, open, fromMs, toMs, pivotUser, pivotSrcIP, pivotNode]);

  const canApprove = useMemo(() => {
    if (!run) return false;
    return run.status?.toUpperCase() === "WAITING_APPROVAL";
  }, [run]);

  const timeline = useMemo(() => {
    const cp = [...events];
    cp.sort((a, b) => {
      if ((a.recv_ts_unix_ms || 0) === (b.recv_ts_unix_ms || 0)) {
        return (a.event_idem_key || "").localeCompare(b.event_idem_key || "");
      }
      return (a.recv_ts_unix_ms || 0) - (b.recv_ts_unix_ms || 0);
    });
    return cp;
  }, [events]);

  const bundle = useMemo(
    () => ({
      run,
      steps,
      events,
      exported_at: new Date().toISOString()
    }),
    [run, steps, events]
  );

  const exportBundle = () => {
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident_bundle_${runID}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyBundle = async () => {
    await navigator.clipboard.writeText(JSON.stringify(bundle, null, 2));
  };

  const sendDecision = async (decision: "approve" | "reject") => {
    if (!run) return;
    try {
      await approveIncident(run.run_id, decision, actor);
      setDecisionMsg(`Decision sent: ${decision}`);
      await load();
    } catch (err) {
      setDecisionMsg(`Decision failed: ${(err as Error).message}`);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-40 bg-black/50">
      <div className="absolute right-0 top-0 h-full w-full max-w-4xl overflow-auto border-l border-ink-700 bg-ink-950 p-4 shadow-2xl">
        <div className="mb-3 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold">Investigation Workspace</h3>
            <p className="text-xs text-ink-300">run_id: {runID}</p>
          </div>
          <button className="rounded bg-ink-800 px-3 py-2 text-sm hover:bg-ink-700" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="mb-3 flex flex-wrap gap-2">
          {(["overview", "steps", "timeline", "evidence", "actions"] as DrawerTab[]).map((t) => (
            <button
              key={t}
              className={`rounded px-3 py-1.5 text-xs ${tab === t ? "bg-ink-700 text-white" : "bg-ink-800 text-ink-200 hover:bg-ink-700"}`}
              onClick={() => setTab(t)}
            >
              {t.toUpperCase()}
            </button>
          ))}
        </div>

        {loading ? <LoadingState /> : null}

        {!loading && run && tab === "overview" ? (
          <div className="space-y-2 rounded border border-ink-800 p-3 text-sm">
            <ValueRow label="run_id" value={run.run_id} />
            <ValueRow label="status" value={<StatusBadge status={run.status} />} />
            <ValueRow label="lane" value={<LaneBadge lane={run.lane} />} />
            <ValueRow label="severity" value={run.severity} />
            <ValueRow label="rule_id" value={run.rule_id} />
            <ValueRow label="playbook_id" value={run.playbook_id} />
            <ValueRow label="target_agent_id" value={run.target_agent_id} />
            <ValueRow label="node_id" value={run.node_id} />
            <ValueRow label="source_type" value={run.source_type} />
            <ValueRow label="event_type" value={run.event_type} />
            <ValueRow label="src_ip" value={run.src_ip} />
            <ValueRow label="user_name" value={run.user_name} />
            <ValueRow label="failed_safe_reason" value={run.failed_safe_reason} />
            <ValueRow label="operator_action" value={run.operator_action} />
            <ValueRow label="updated" value={unixMsToLocal(run.last_updated_at_unix_ms)} />
          </div>
        ) : null}

        {!loading && tab === "steps" ? (
          <div className="space-y-2">
            {steps.length === 0 ? <EmptyState title="No steps for this run" /> : null}
            {steps.map((step) => (
              <div key={`${step.step_id}-${step.finished_at_unix_ms}`} className="rounded border border-ink-800 p-3 text-sm">
                <div className="mb-1 flex items-center justify-between">
                  <div className="font-medium">
                    step[{step.step_index}] {step.step_id}
                  </div>
                  <StatusBadge status={step.status} />
                </div>
                <div className="grid grid-cols-1 gap-1 md:grid-cols-2">
                  <ValueRow label="action_type" value={step.action_type} />
                  <ValueRow label="lane" value={step.lane} />
                  <ValueRow label="attempt" value={String(step.attempt || 0)} />
                  <ValueRow label="retries" value={String(Math.max((step.attempt || 1) - 1, 0))} />
                  <ValueRow label="target_agent_id" value={step.target_agent_id} />
                  <ValueRow label="last_error" value={step.last_error} />
                  <ValueRow label="command_id" value={String(step.receipt?.command_id || step.receipt?.command || "-")} />
                  <ValueRow label="routing_subject" value={String(step.receipt?.subject || step.receipt?.routing_subject || "-")} />
                  <ValueRow label="receipt_message" value={String(step.receipt?.message || "-")} />
                  <ValueRow label="finished" value={unixMsToLocal(step.finished_at_unix_ms)} />
                </div>
                {step.receipt ? <pre className="mt-2 overflow-auto rounded bg-ink-900 p-2 text-xs">{JSON.stringify(step.receipt, null, 2)}</pre> : null}
              </div>
            ))}
          </div>
        ) : null}

        {!loading && tab === "timeline" ? (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2 text-xs">
              {run?.user_name ? (
                <button className="rounded bg-ink-800 px-2 py-1 hover:bg-ink-700" onClick={() => setPivotUser(run.user_name || "")}>
                  user: {run.user_name}
                </button>
              ) : null}
              {run?.src_ip ? (
                <button className="rounded bg-ink-800 px-2 py-1 hover:bg-ink-700" onClick={() => setPivotSrcIP(run.src_ip || "")}>
                  src_ip: {run.src_ip}
                </button>
              ) : null}
              {run?.node_id ? (
                <button className="rounded bg-ink-800 px-2 py-1 hover:bg-ink-700" onClick={() => setPivotNode(run.node_id || "")}>
                  node_id: {run.node_id}
                </button>
              ) : null}
              <button
                className="rounded bg-ink-700 px-2 py-1 hover:bg-ink-600"
                onClick={() => {
                  setPivotUser("");
                  setPivotSrcIP("");
                  setPivotNode("");
                }}
              >
                clear pivots
              </button>
            </div>
            <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
              <input className="rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm" placeholder="pivot user_name" value={pivotUser} onChange={(e) => setPivotUser(e.target.value)} />
              <input className="rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm" placeholder="pivot src_ip" value={pivotSrcIP} onChange={(e) => setPivotSrcIP(e.target.value)} />
              <input className="rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm" placeholder="pivot node_id" value={pivotNode} onChange={(e) => setPivotNode(e.target.value)} />
            </div>
            {timeline.length === 0 ? <EmptyState title="No timeline events for selected pivots/window" /> : null}
            {timeline.length > 0 ? (
              <div className="max-h-[420px] overflow-auto rounded border border-ink-800">
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
                    {timeline.map((ev) => (
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
        ) : null}

        {!loading && tab === "evidence" ? (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <button className="rounded bg-ink-700 px-3 py-2 text-sm hover:bg-ink-600" onClick={exportBundle}>
                Export JSON
              </button>
              <button className="rounded bg-ink-700 px-3 py-2 text-sm hover:bg-ink-600" onClick={copyBundle}>
                Copy run bundle JSON
              </button>
            </div>
            {artifactMap.length === 0 ? <EmptyState title="No FR-04 artifacts detected" /> : null}
            {artifactMap.length > 0 ? (
              <div className="space-y-2">
                {artifactMap.slice(0, 30).map((a) => (
                  <div key={a.path} className="flex items-center justify-between rounded border border-ink-800 p-2 text-xs">
                    <span className="truncate pr-4">{a.path}</span>
                    {!a.is_dir ? (
                      <a
                        href={`${getApiBase()}/api/artifact?path=${encodeURIComponent(a.path)}`}
                        target="_blank"
                        className="rounded bg-ink-700 px-2 py-1 hover:bg-ink-600"
                      >
                        Download
                      </a>
                    ) : null}
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}

        {!loading && tab === "actions" ? (
          <div className="space-y-3 rounded border border-ink-800 p-3">
            {canApprove ? (
              <>
                <p className="text-sm text-ink-200">Incident is waiting approval.</p>
                <input value={actor} onChange={(e) => setActor(e.target.value)} className="w-full rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm" placeholder="actor" />
                <div className="flex gap-2">
                  <button className="rounded bg-green-700 px-3 py-2 text-sm hover:bg-green-600" onClick={() => sendDecision("approve")}>
                    Approve
                  </button>
                  <button className="rounded bg-rose-700 px-3 py-2 text-sm hover:bg-rose-600" onClick={() => sendDecision("reject")}>
                    Reject
                  </button>
                </div>
              </>
            ) : (
              <p className="text-sm text-ink-300">No approval action available for current status.</p>
            )}
            {decisionMsg ? <div className="rounded bg-ink-900 px-2 py-2 text-xs">{decisionMsg}</div> : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}
