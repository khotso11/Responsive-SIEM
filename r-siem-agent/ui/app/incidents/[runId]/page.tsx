"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { approveIncident, getArtifacts, getIncident, getIncidentEvents, isUnauthorizedError, reissueIncident, restoreIncidentAccess, verifyIncidentUser } from "@/lib/api";
import { EventRow, Incident, IncidentUIState, StepResult } from "@/lib/types";
import { EmptyState, ErrorState, LaneBadge, LoadingState, StatusBadge, ValueRow, unixMsToLocal } from "@/components/ui";

export default function IncidentDetailPage({ params }: { params: { runId: string } }) {
  const runID = decodeURIComponent(params.runId);
  const [run, setRun] = useState<Incident | null>(null);
  const [steps, setSteps] = useState<StepResult[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [artifacts, setArtifacts] = useState<Array<{ path: string; is_dir: boolean; size: number; modified: string }>>([]);
  const [uiState, setUIState] = useState<IncidentUIState>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actor, setActor] = useState("khotso");
  const [approvalBusy, setApprovalBusy] = useState(false);
  const [approvalMsg, setApprovalMsg] = useState("");
  const [newRunID, setNewRunID] = useState("");
  const [reissueReason, setReissueReason] = useState("");
  const [verificationMethod, setVerificationMethod] = useState("phone");
  const [verificationReference, setVerificationReference] = useState("");
  const [verificationNotes, setVerificationNotes] = useState("");
  const [restoreScope, setRestoreScope] = useState<"src_ip" | "user" | "both">("both");
  const [restoreReason, setRestoreReason] = useState("");
  const [restoreReference, setRestoreReference] = useState("");

  const load = async () => {
    setLoading(true);
    setError(null);
    setNewRunID("");
    try {
      const detail = await getIncident(runID);
      setRun(detail.run);
      setSteps(detail.steps || []);
      setUIState(detail.ui_state || {});
      const ev = await getIncidentEvents(runID, { windowSeconds: 900 });
      setEvents(ev.items || []);
      const collected: Array<{ path: string; is_dir: boolean; size: number; modified: string }> = [];
      try {
        for (let p = 1; p <= 3; p++) {
          const art = await getArtifacts("demo_artifacts", { q: "/fr04/", page: p, limit: 200 });
          collected.push(...(art.items || []));
          if (!art.has_more) break;
        }
      } catch {
        // Artifact proofs are optional; do not fail the page if the folder is missing.
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

  const requiresManualReview = useMemo(() => {
    if (!run) return false;
    return (run.status || "").toUpperCase() === "MANUAL_REVIEW_REQUIRED";
  }, [run]);

  const isIdentityIncident = useMemo(() => {
    if (!run) return false;
    const rule = (run.rule_id || "").toUpperCase();
    const playbook = (run.playbook_id || "").toUpperCase();
    return rule.startsWith("R-AUTH-") || playbook.startsWith("PB-AUTH-") || rule === "R-COLLECT-INVALID-USER";
  }, [run]);

  const canRunIdentityWorkflow = useMemo(() => Boolean(run?.identity_workflow_eligible), [run]);
  const identityWorkflowReason = useMemo(
    () => run?.identity_workflow_reason || "Identity workflow is available only after a successful auth containment run.",
    [run]
  );

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

  const doReissue = async () => {
    if (!run) return;
    setApprovalBusy(true);
    setApprovalMsg("");
    try {
      const res = await reissueIncident(run.run_id, actor, reissueReason);
      setNewRunID(res.new_run_id || "");
      setApprovalMsg(
        res.new_run_id
          ? `Fresh response trigger published on ${res.lane}. New run ${res.new_run_id} is ready.`
          : `Fresh response trigger published on ${res.lane}. A new run will appear in the queue shortly.`
      );
      await load();
    } catch (e) {
      setApprovalMsg(`Re-issue failed: ${(e as Error).message || String(e)}`);
    } finally {
      setApprovalBusy(false);
    }
  };

  const doVerifyUser = async () => {
    if (!run || !verificationMethod.trim() || !verificationReference.trim()) return;
    if (!canRunIdentityWorkflow) {
      setApprovalMsg(identityWorkflowReason);
      return;
    }
    setApprovalBusy(true);
    setApprovalMsg("");
    try {
      await verifyIncidentUser(run.run_id, actor, verificationMethod.trim(), verificationReference.trim(), verificationNotes.trim());
      setApprovalMsg(`User verification recorded via ${verificationMethod.trim()}`);
      await load();
    } catch (e) {
      setApprovalMsg(isUnauthorizedError(e) ? "Verification failed: session expired. Please log in again." : `Verification failed: ${(e as Error).message || String(e)}`);
    } finally {
      setApprovalBusy(false);
    }
  };

  const doRestoreAccess = async () => {
    if (!run || !restoreReason.trim()) return;
    if (!canRunIdentityWorkflow) {
      setApprovalMsg(identityWorkflowReason);
      return;
    }
    if (!uiState.verification?.verified) {
      setApprovalMsg("Restore blocked: verify the user first.");
      return;
    }
    setApprovalBusy(true);
    setApprovalMsg("");
    try {
      await restoreIncidentAccess(run.run_id, actor, restoreScope, restoreReason.trim(), restoreReference.trim());
      setApprovalMsg(`Access restore submitted for scope ${restoreScope}`);
      await load();
    } catch (e) {
      setApprovalMsg(isUnauthorizedError(e) ? "Restore failed: session expired. Please log in again." : `Restore failed: ${(e as Error).message || String(e)}`);
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
        <div className="flex flex-wrap gap-2">
          <Link
            className="rounded border border-cyan-700/60 bg-cyan-950/40 px-3 py-2 text-sm text-cyan-100 hover:bg-cyan-900/40"
            href={`/incidents?open_run_id=${encodeURIComponent(runID)}&open_tab=evidence`}
          >
            Open Investigation Workspace
          </Link>
          <Link
            className="rounded border border-ink-700 bg-ink-900 px-3 py-2 text-sm text-ink-100 hover:bg-ink-800"
            href="/incidents"
          >
            Back to Queue
          </Link>
        </div>
      </div>

      <div className="rounded-lg border border-ink-700 bg-ink-900/30 px-4 py-3 text-sm text-ink-200">
        VirusTotal and other provider intelligence are rendered in the investigation workspace evidence view.
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
                <ValueRow label="operator_action" value={run.operator_action} />
                <ValueRow label="lane" value={<LaneBadge lane={run.lane} />} />
                <ValueRow label="rule_id" value={run.rule_id} />
                <ValueRow label="playbook_id" value={run.playbook_id} />
                <ValueRow label="approval_policy_rule_id" value={run.approval_policy_rule_id} />
                <ValueRow label="allowlist_rule_id" value={run.allowlist_rule_id} />
                <ValueRow label="retention_rule_id" value={run.retention_rule_id} />
                <ValueRow label="node_id" value={run.node_id} />
                <ValueRow label="asset_environment" value={run.asset_environment} />
                <ValueRow label="asset_criticality" value={run.asset_criticality} />
                <ValueRow label="asset_owner" value={run.asset_owner} />
                <ValueRow label="asset_team" value={run.asset_team} />
                <ValueRow label="asset_role" value={run.asset_role} />
                <ValueRow label="source_type" value={run.source_type} />
                <ValueRow label="event_type" value={run.event_type} />
                <ValueRow label="src_ip" value={run.src_ip} />
                <ValueRow label="dst_ip" value={run.dst_ip} />
                <ValueRow label="user" value={run.user_name} />
                <ValueRow label="identity_display_name" value={run.identity_display_name} />
                <ValueRow label="identity_department" value={run.identity_department} />
                <ValueRow label="identity_manager" value={run.identity_manager} />
                <ValueRow label="identity_privileged" value={run.identity_privileged ? "yes" : "no"} />
                <ValueRow label="identity_service_account" value={run.identity_service_account ? "yes" : "no"} />
                <ValueRow label="target_agent_id" value={run.target_agent_id} />
                <ValueRow label="identity_workflow_eligible" value={run.identity_workflow_eligible ? "yes" : "no"} />
                <ValueRow label="identity_workflow_reason" value={run.identity_workflow_reason || "-"} />
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
                  {approvalMsg ? (
                    <div className="space-y-2 text-xs text-ink-300">
                      <p>{approvalMsg}</p>
                      {newRunID ? (
                        <p>
                          <Link className="underline text-cyan-300" href={`/incidents/${encodeURIComponent(newRunID)}`}>
                            Open new run
                          </Link>
                        </p>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              ) : requiresManualReview ? (
                <div className="space-y-3">
                  <div className="rounded border border-amber-700/60 bg-amber-950/30 px-3 py-2 text-sm text-amber-100">
                    Approval timed out. This run now requires manual review and cannot be resumed by a late approve/reject action.
                  </div>
                  <ValueRow label="approval_decision" value={run.approval_decision || "timeout"} />
                  <ValueRow label="operator_action" value={run.operator_action || "manual_review_required"} />
                  <input
                    className="w-full rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm"
                    value={actor}
                    onChange={(e) => setActor(e.target.value)}
                    placeholder="actor"
                  />
                  <input
                    className="w-full rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm"
                    value={reissueReason}
                    onChange={(e) => setReissueReason(e.target.value)}
                    placeholder="optional re-issue reason"
                  />
                  <button disabled={approvalBusy} className="rounded bg-cyan-400 px-3 py-2 text-sm text-slate-950 hover:bg-cyan-300 disabled:opacity-50" onClick={doReissue}>
                    Re-issue Response
                  </button>
                  {approvalMsg ? <p className="text-xs text-ink-300">{approvalMsg}</p> : null}
                </div>
              ) : isIdentityIncident ? (
                <div className="space-y-4">
                  <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-2 text-xs text-ink-300">
                    Use this panel to record identity verification and issue a controlled access restore after validation.
                  </div>
                  <div className="space-y-2 rounded border border-ink-800 p-3">
                    <h4 className="text-sm font-semibold">Verify User</h4>
                    {!canRunIdentityWorkflow ? (
                      <div className="rounded border border-amber-700/40 bg-amber-950/20 px-3 py-2 text-xs text-amber-100">
                        {identityWorkflowReason}
                      </div>
                    ) : uiState.verification?.verified ? (
                      <div className="rounded border border-emerald-700/40 bg-emerald-950/20 px-3 py-2 text-xs text-emerald-100">
                        Verified by {uiState.verification.actor || "-"} via {uiState.verification.method || "-"} at {uiState.verification.ts || "-"}
                      </div>
                    ) : (
                      <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-2 text-xs text-ink-300">
                        Record user verification before restore. Restore remains locked until verification exists.
                      </div>
                    )}
                    <input
                      className="w-full rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm"
                      value={verificationMethod}
                      onChange={(e) => setVerificationMethod(e.target.value)}
                      placeholder="verification method"
                    />
                    <input
                      className="w-full rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm"
                      value={verificationReference}
                      onChange={(e) => setVerificationReference(e.target.value)}
                      placeholder="verification reference / ticket"
                    />
                    <input
                      className="w-full rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm"
                      value={verificationNotes}
                      onChange={(e) => setVerificationNotes(e.target.value)}
                      placeholder="verification notes"
                    />
                    <button disabled={approvalBusy || !canRunIdentityWorkflow} className="rounded border border-ink-700 px-3 py-2 text-sm hover:bg-ink-800 disabled:opacity-50" onClick={doVerifyUser}>
                      Verify User
                    </button>
                  </div>
                  <div className="space-y-2 rounded border border-ink-800 p-3">
                    <h4 className="text-sm font-semibold">Restore Access</h4>
                    {!canRunIdentityWorkflow ? (
                      <div className="rounded border border-amber-700/40 bg-amber-950/20 px-3 py-2 text-xs text-amber-100">
                        {identityWorkflowReason}
                      </div>
                    ) : !uiState.verification?.verified ? (
                      <div className="rounded border border-amber-700/40 bg-amber-950/20 px-3 py-2 text-xs text-amber-100">
                        Verify User first. Access restore is blocked until a verification record exists for this incident.
                      </div>
                    ) : null}
                    <select
                      className="w-full rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm"
                      value={restoreScope}
                      onChange={(e) => setRestoreScope(e.target.value as "src_ip" | "user" | "both")}
                    >
                      <option value="both">Restore both</option>
                      <option value="src_ip">Restore src_ip only</option>
                      <option value="user">Restore user only</option>
                    </select>
                    <input
                      className="w-full rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm"
                      value={restoreReference}
                      onChange={(e) => setRestoreReference(e.target.value)}
                      placeholder="change reference"
                    />
                    <input
                      className="w-full rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm"
                      value={restoreReason}
                      onChange={(e) => setRestoreReason(e.target.value)}
                      placeholder="restore reason"
                    />
                    <button disabled={approvalBusy || !canRunIdentityWorkflow || !uiState.verification?.verified} className="rounded bg-cyan-400 px-3 py-2 text-sm text-slate-950 hover:bg-cyan-300 disabled:opacity-50" onClick={doRestoreAccess}>
                      Restore Access
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
                      <ValueRow label="allowlist_rule_id" value={s.allowlist_rule_id || "-"} />
                      <ValueRow label="guardrail_rule_ids" value={s.guardrail_rule_ids?.join(", ") || "-"} />
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
                      <th className="p-2">dst_ip</th>
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
                        <td className="p-2">{ev.dst_ip || "-"}</td>
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
