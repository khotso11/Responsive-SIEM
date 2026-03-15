"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  addIncidentNote,
  approveIncident,
  assignIncident,
  downloadIncidentReport,
  getApiBase,
  getArtifacts,
  getInvestigation,
  getIncident,
  getIncidentEvents,
  isUnauthorizedError,
  me,
  markIncidentReviewed,
  refreshInvestigation,
  reissueIncident,
  restoreIncidentAccess,
  rejectIncident
  ,
  verifyIncidentUser
} from "@/lib/api";
import { emitIncidentMutated, emitIncidentsUpdated, INCIDENT_MUTATED_EVENT, INCIDENTS_UPDATED_EVENT } from "@/lib/events";
import { AuditEntry, AuthUser, EventRow, Incident, IncidentUIState, StepResult, InvestigationResponse } from "@/lib/types";
import { EmptyState, LaneBadge, LoadingState, StatusBadge, ValueRow, unixMsToLocal } from "@/components/ui";

type DrawerTab = "overview" | "steps" | "timeline" | "entities" | "evidence" | "actions";

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

function policyHighlights(run: Incident | null): string[] {
  if (!run) return [];
  const reason = (run.approval_policy_reason || "").toLowerCase();
  const highlights: string[] = [];
  if (reason.includes("privileged_identity")) highlights.push("Privileged identity escalation");
  if (reason.includes("local_source")) highlights.push("Local source escalation");
  if (reason.includes("missing_identity_context")) highlights.push("Identity context missing");
  if (reason.includes("confidence_below_threshold")) highlights.push("Confidence below auto threshold");
  if (reason.includes("irreversible")) highlights.push("Irreversible action path");
  return highlights;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function annotationSummary(entry: AuditEntry): string {
  if (entry.msg !== "response_run_corroborated") {
    return entry.msg.replaceAll("_", " ");
  }
  const details = asRecord(entry.details) || {};
  const sourceType = String(details.source_type || entry.source || "system");
  const protocolFamily = String(details.protocol_family || "");
  const dstIP = String(details.dst_ip || "");
  const dstPort = Number(details.dst_port || 0);
  const execPath = String(details.exec_path || details.comm || "");
  const parts = [`Later ${sourceType} telemetry corroborated this incident`];
  const destination = [protocolFamily || "", dstPort > 0 ? String(dstPort) : "", dstIP || ""].filter(Boolean).join(" ");
  if (destination) parts.push(`for ${destination}`);
  if (execPath) parts.push(`from ${execPath}`);
  return parts.join(" ") + ".";
}

function intFromUnknown(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  return 0;
}

function stringFromUnknown(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function requestMetrics(data?: Record<string, unknown>): { attempts: number; latencyMs: number; httpStatus: number; errorClass: string } {
  const req = asRecord(data?._request);
  if (!req) {
    return { attempts: 0, latencyMs: 0, httpStatus: 0, errorClass: "" };
  }
  return {
    attempts: intFromUnknown(req.attempts),
    latencyMs: intFromUnknown(req.latency_ms),
    httpStatus: intFromUnknown(req.http_status),
    errorClass: stringFromUnknown(req.error_class)
  };
}

function intelligenceStatusLabel(status?: string): string {
  switch ((status || "").toLowerCase()) {
    case "ok":
      return "ok";
    case "timeout":
      return "timeout";
    case "timed_out":
      return "timed out";
    case "network_error":
      return "network";
    case "upstream_error":
      return "upstream";
    case "auth_failed":
      return "auth failed";
    case "rate_limited":
      return "rate limited";
    case "running":
      return "running";
    case "requested":
      return "requested";
    case "completed":
      return "completed";
    default:
      return status || "unknown";
  }
}

function intelligenceStatusClass(status?: string): string {
  switch ((status || "").toLowerCase()) {
    case "ok":
    case "completed":
      return "border-emerald-700/60 bg-emerald-950/70 text-emerald-200";
    case "timeout":
    case "timed_out":
      return "border-amber-700/60 bg-amber-950/70 text-amber-200";
    case "network_error":
      return "border-sky-700/60 bg-sky-950/70 text-sky-200";
    case "upstream_error":
    case "rate_limited":
      return "border-fuchsia-700/60 bg-fuchsia-950/70 text-fuchsia-200";
    case "auth_failed":
      return "border-rose-700/60 bg-rose-950/70 text-rose-200";
    case "running":
    case "requested":
      return "border-cyan-700/60 bg-cyan-950/70 text-cyan-200";
    default:
      return "border-ink-700/60 bg-ink-900/70 text-ink-200";
  }
}

function providerMeta(provider?: string): { label: string; mark: string; cardClass: string; markClass: string } {
  switch ((provider || "").toLowerCase()) {
    case "virustotal":
      return {
        label: "VirusTotal",
        mark: "VT",
        cardClass: "border-sky-800/70 bg-sky-950/20",
        markClass: "border-sky-700/70 bg-sky-950/70 text-sky-100"
      };
    case "abuseipdb":
      return {
        label: "AbuseIPDB",
        mark: "AB",
        cardClass: "border-emerald-800/70 bg-emerald-950/20",
        markClass: "border-emerald-700/70 bg-emerald-950/70 text-emerald-100"
      };
    case "greynoise":
      return {
        label: "GreyNoise",
        mark: "GN",
        cardClass: "border-fuchsia-800/70 bg-fuchsia-950/20",
        markClass: "border-fuchsia-700/70 bg-fuchsia-950/70 text-fuchsia-100"
      };
    case "urlscan":
      return {
        label: "urlscan",
        mark: "US",
        cardClass: "border-amber-800/70 bg-amber-950/20",
        markClass: "border-amber-700/70 bg-amber-950/70 text-amber-100"
      };
    default:
      return {
        label: provider || "provider",
        mark: (provider || "?").slice(0, 2).toUpperCase(),
        cardClass: "border-ink-800 bg-ink-950/70",
        markClass: "border-ink-700 bg-ink-900 text-ink-100"
      };
  }
}

function combinedReputationSummary(
  summaries: Array<{ provider: string; status: string; verdict: string; score?: number; summary: string }>
): { tone: string; title: string; detail: string } | null {
  if (summaries.length === 0) return null;
  const ok = summaries.filter((item) => item.status === "ok");
  if (ok.length === 0) {
    return {
      tone: "border-amber-800/60 bg-amber-950/20 text-amber-100",
      title: "Reputation: no completed provider verdicts yet",
      detail: "Enabled providers have not returned a completed reputation verdict for this incident."
    };
  }

  const suspicious = ok.filter((item) => {
    const verdict = (item.verdict || "").toLowerCase();
    return verdict === "malicious" || verdict === "suspicious";
  });
  if (suspicious.length > 0) {
    return {
      tone: "border-rose-800/60 bg-rose-950/20 text-rose-100",
      title: "Reputation: suspicious across enabled providers",
      detail: suspicious.map((item) => `${providerMeta(item.provider).label}: ${item.summary}`).join(" | ")
    };
  }

  const cleanish = ok.filter((item) => {
    const verdict = (item.verdict || "").toLowerCase();
    return verdict === "benign" || verdict === "harmless" || verdict === "unknown" || verdict === "";
  });
  if (cleanish.length === ok.length) {
    return {
      tone: "border-emerald-800/60 bg-emerald-950/20 text-emerald-100",
      title: "Reputation: clean across enabled providers",
      detail: `${ok.length} provider${ok.length === 1 ? "" : "s"} reported no negative reputation signal. A score of 0 here means clean/no signal, not a failed lookup.`
    };
  }

  return {
    tone: "border-cyan-800/60 bg-cyan-950/20 text-cyan-100",
    title: "Reputation: mixed provider context",
    detail: ok.map((item) => `${providerMeta(item.provider).label}: ${item.summary}`).join(" | ")
  };
}

function providerSummaryHeadline(summary: { provider: string; status: string; verdict: string; score?: number; summary: string }): string {
  const provider = (summary.provider || "").toLowerCase();
  const verdict = (summary.verdict || "").toLowerCase();
  const score = typeof summary.score === "number" ? summary.score : undefined;
  if (summary.status === "ok" && score === 0) {
    if (provider === "abuseipdb" && (verdict === "benign" || verdict === "unknown" || verdict === "")) {
      return "No abuse reports found in AbuseIPDB";
    }
    if (provider === "virustotal" && (verdict === "benign" || verdict === "harmless" || verdict === "unknown" || verdict === "")) {
      return "No malicious or suspicious detections in VirusTotal";
    }
    return "No negative reputation signal returned";
  }
  return summary.summary;
}

function providerScoreHint(summary: { provider: string; status: string; verdict: string; score?: number }): string {
  if (summary.status !== "ok" || summary.score !== 0) return "";
  const provider = (summary.provider || "").toLowerCase();
  if (provider === "abuseipdb") {
    return "Score 0 means AbuseIPDB reported no abuse confidence for this observable.";
  }
  if (provider === "virustotal") {
    return "Score 0 means VirusTotal returned no malicious or suspicious signal for this observable.";
  }
  return "Score 0 means the provider returned no negative reputation signal.";
}

export function IncidentDrawer({
  runID,
  open,
  onClose,
  fromMs,
  toMs,
  initialTab
}: {
  runID: string;
  open: boolean;
  onClose: () => void;
  fromMs?: number;
  toMs?: number;
  initialTab?: DrawerTab;
}) {
  const [tab, setTab] = useState<DrawerTab>("overview");
  const [run, setRun] = useState<Incident | null>(null);
  const [steps, setSteps] = useState<StepResult[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [hasLoadedOnce, setHasLoadedOnce] = useState(false);
  const [investigation, setInvestigation] = useState<InvestigationResponse | null>(null);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const [investigationError, setInvestigationError] = useState("");
  const [actionBusy, setActionBusy] = useState(false);
  const [actor, setActor] = useState("");
  const [actorDirty, setActorDirty] = useState(false);
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [decisionMsg, setDecisionMsg] = useState("");
  const [newRunID, setNewRunID] = useState("");
  const [pivotUser, setPivotUser] = useState("");
  const [pivotSrcIP, setPivotSrcIP] = useState("");
  const [pivotNode, setPivotNode] = useState("");
  const [artifactMap, setArtifactMap] = useState<Array<{ path: string; is_dir: boolean; size: number; modified: string }>>([]);
  const [uiState, setUIState] = useState<IncidentUIState>({ notes: [], assignment: "", reviewed: false });
  const [annotations, setAnnotations] = useState<AuditEntry[]>([]);
  const [assignee, setAssignee] = useState("");
  const [assigneeDirty, setAssigneeDirty] = useState(false);
  const [noteText, setNoteText] = useState("");
  const [reissueReason, setReissueReason] = useState("");
  const [verificationMethod, setVerificationMethod] = useState("phone");
  const [verificationReference, setVerificationReference] = useState("");
  const [verificationNotes, setVerificationNotes] = useState("");
  const [restoreScope, setRestoreScope] = useState<"src_ip" | "user" | "both">("both");
  const [restoreReason, setRestoreReason] = useState("");
  const [restoreReference, setRestoreReference] = useState("");

  const load = useCallback(async () => {
    if (!runID || !open) return;
    if (hasLoadedOnce) setRefreshing(true);
    else setLoading(true);
    try {
      const [detail, auth] = await Promise.all([getIncident(runID), me().catch(() => null)]);
      const user = auth?.user || null;
      setRun(detail.run);
      setSteps(detail.steps || []);
      setAuthUser(user);
      setUIState(detail.ui_state || { notes: [], assignment: "", reviewed: false });
      setAnnotations(detail.annotations || []);
      if (!actorDirty) {
        setActor(user?.username || "soc.analyst");
      }
      if (!assigneeDirty) {
        setAssignee(
          detail.ui_state?.assignment ||
            (user?.role === "analyst" ? user.username : detail.run.target_agent_id || detail.run.node_id || "")
        );
      }
      const ev = await getIncidentEvents(runID, {
        windowSeconds: 900,
        from: fromMs,
        to: toMs,
        userName: pivotUser || undefined,
        srcIP: pivotSrcIP || undefined,
        nodeID: pivotNode || undefined
      });
      setEvents(ev.items || []);
      const collected: Array<{ path: string; is_dir: boolean; size: number; modified: string }> = [];
      for (let p = 1; p <= 3; p++) {
        const art = await getArtifacts("demo_artifacts", { q: "/fr04/", page: p, limit: 200 });
        collected.push(...(art.items || []));
        if (!art.has_more) break;
      }
      setArtifactMap(
        collected.filter((a) => a.path.includes("/fr04/") || a.path.endsWith("capture.pcap") || a.path.endsWith("chain_of_custody.json"))
      );
      setHasLoadedOnce(true);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [actorDirty, assigneeDirty, fromMs, hasLoadedOnce, open, pivotNode, pivotSrcIP, pivotUser, runID, toMs]);

  const loadInvestigationData = useCallback(async () => {
    if (!runID || !open) return;
    setInvestigationError("");
    setInvestigationLoading(true);
    try {
      const res = await getInvestigation(runID);
      setInvestigation(res);
    } catch (err: any) {
      setInvestigationError(err?.message || "investigation load failed");
    } finally {
      setInvestigationLoading(false);
    }
  }, [open, runID]);

  useEffect(() => {
    if (!open) return;
    setTab(initialTab || "overview");
    setDecisionMsg("");
    setNewRunID("");
    setActor("");
    setActorDirty(false);
    setAssignee("");
    setAssigneeDirty(false);
    setNoteText("");
    setReissueReason("");
    setVerificationMethod("phone");
    setVerificationReference("");
    setVerificationNotes("");
    setRestoreScope("both");
    setRestoreReason("");
    setRestoreReference("");
    setInvestigation(null);
    setInvestigationError("");
    setInvestigationLoading(false);
    setHasLoadedOnce(false);
    setLoading(false);
    setRefreshing(false);
  }, [initialTab, runID, open]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!open || tab !== "evidence") return;
    void loadInvestigationData();
  }, [loadInvestigationData, open, tab, runID]);

  useEffect(() => {
    if (!open || !runID) return;
    const onIncidentMutated = (event: Event) => {
      const detail = (event as CustomEvent<{ runID?: string }>).detail;
      if (!detail?.runID || detail.runID === runID) {
        void load();
      }
    };
    const onIncidentsUpdated = () => {
      void load();
    };
    window.addEventListener(INCIDENT_MUTATED_EVENT, onIncidentMutated as EventListener);
    window.addEventListener(INCIDENTS_UPDATED_EVENT, onIncidentsUpdated);
    return () => {
      window.removeEventListener(INCIDENT_MUTATED_EVENT, onIncidentMutated as EventListener);
      window.removeEventListener(INCIDENTS_UPDATED_EVENT, onIncidentsUpdated);
    };
  }, [load, open, runID]);

  const canApprove = useMemo(() => {
    if (!run) return false;
    return run.status?.toUpperCase() === "WAITING_APPROVAL";
  }, [run]);

  const requiresManualReview = useMemo(() => {
    if (!run) return false;
    return run.status?.toUpperCase() === "MANUAL_REVIEW_REQUIRED";
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
  const policySummary = useMemo(() => policyHighlights(run), [run]);

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

  const refreshInvestigationNow = useCallback(async () => {
    if (!runID) return;
    setInvestigationError("");
    setInvestigationLoading(true);
    try {
      await refreshInvestigation(runID);
      await loadInvestigationData();
    } catch (err: any) {
      setInvestigationError(err?.message || "refresh failed");
    } finally {
      setInvestigationLoading(false);
    }
  }, [loadInvestigationData, runID]);

  const bundle = useMemo(
    () => ({
      run,
      steps,
      events,
      ui_state: uiState,
      exported_at: new Date().toISOString()
    }),
    [run, steps, events, uiState]
  );

  const investigationJobs = Array.isArray(investigation?.jobs) ? investigation.jobs : [];
  const investigationObservables = Array.isArray(investigation?.observables) ? investigation.observables : [];
  const investigationEnrichments = Array.isArray(investigation?.enrichments) ? investigation.enrichments : [];
  const investigationSummaries = Array.isArray(investigation?.summaries) ? investigation.summaries : [];
  const visibleInvestigationSummaries = investigationSummaries.filter((summary) => summary.status !== "skipped_no_api_key");
  const visibleInvestigationEnrichments = investigationEnrichments.filter((enrichment) => enrichment.status !== "skipped_no_api_key");
  const reputationSummary = combinedReputationSummary(visibleInvestigationSummaries);
  const scanTopDestinations = Array.isArray(run?.top_destinations) ? run.top_destinations.filter(Boolean) : [];
  const scanContextVisible = Boolean(run?.protocol_family || run?.dst_port || run?.scan_fanout || scanTopDestinations.length > 0);
  const observableFieldHints = [
    { label: "dst_ip", value: run?.dst_ip },
    { label: "src_ip", value: run?.src_ip },
    { label: "url", value: typeof run?.target === "string" && /^https?:\/\//i.test(run.target) ? run.target : "" },
    { label: "domain", value: run?.dns_name },
    { label: "file hash", value: run?.file_sha256 || run?.exec_sha256 }
  ];
  const presentObservableHints = observableFieldHints.filter((item) => item.value);
  const missingObservableHints = observableFieldHints.filter((item) => !item.value);

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
      setActionBusy(true);
      if (decision === "approve") {
        await approveIncident(run.run_id, decision, actor);
      } else {
        await rejectIncident(run.run_id, actor);
      }
      setDecisionMsg(`Decision sent: ${decision}`);
      await load();
      emitIncidentMutated(run.run_id);
      emitIncidentsUpdated({ runID: run.run_id });
    } catch (err) {
      setDecisionMsg(`Decision failed: ${(err as Error).message}`);
    } finally {
      setActionBusy(false);
    }
  };

  const doReissue = async () => {
    if (!run) return;
    try {
      setActionBusy(true);
      const res = await reissueIncident(run.run_id, actor || authUser?.username || "soc.analyst", reissueReason.trim());
      setNewRunID(res.new_run_id || "");
      setDecisionMsg(
        res.new_run_id
          ? `Fresh response trigger published on ${res.lane}. New run ${res.new_run_id} is ready.`
          : `Fresh response trigger published on ${res.lane}. A new run will appear in the queue shortly.`
      );
      await load();
      emitIncidentMutated(run.run_id);
      emitIncidentsUpdated({ runID: run.run_id });
    } catch (err) {
      setDecisionMsg(`Re-issue failed: ${(err as Error).message}`);
    } finally {
      setActionBusy(false);
    }
  };

  const doAssign = async () => {
    if (!run || !assignee.trim()) return;
    try {
      setActionBusy(true);
      const targetAssignee = authUser?.role === "analyst" ? authUser.username : assignee.trim();
      await assignIncident(run.run_id, targetAssignee);
      setDecisionMsg(`Assigned to ${targetAssignee}`);
      await load();
      emitIncidentMutated(run.run_id);
    } catch (err) {
      setDecisionMsg(`Assign failed: ${(err as Error).message}`);
    } finally {
      setActionBusy(false);
    }
  };

  const doAddNote = async () => {
    if (!run || !noteText.trim()) return;
    try {
      setActionBusy(true);
      await addIncidentNote(run.run_id, noteText.trim());
      setNoteText("");
      setDecisionMsg("Note saved");
      await load();
      emitIncidentMutated(run.run_id);
    } catch (err) {
      setDecisionMsg(`Note failed: ${(err as Error).message}`);
    } finally {
      setActionBusy(false);
    }
  };

  const doMarkReviewed = async () => {
    if (!run) return;
    try {
      setActionBusy(true);
      await markIncidentReviewed(run.run_id);
      setDecisionMsg("Run marked reviewed");
      await load();
      emitIncidentMutated(run.run_id);
    } catch (err) {
      setDecisionMsg(`Mark reviewed failed: ${(err as Error).message}`);
    } finally {
      setActionBusy(false);
    }
  };

  const doVerifyUser = async () => {
    if (!run || !verificationMethod.trim() || !verificationReference.trim()) return;
    if (!canRunIdentityWorkflow) {
      setDecisionMsg(identityWorkflowReason);
      return;
    }
    try {
      setActionBusy(true);
      await verifyIncidentUser(
        run.run_id,
        actor || authUser?.username || "soc.analyst",
        verificationMethod.trim(),
        verificationReference.trim(),
        verificationNotes.trim()
      );
      setDecisionMsg(`User verification recorded via ${verificationMethod.trim()}`);
      await load();
      emitIncidentMutated(run.run_id);
    } catch (err) {
      setDecisionMsg(isUnauthorizedError(err) ? "Verification failed: session expired. Please log in again." : `Verification failed: ${(err as Error).message}`);
    } finally {
      setActionBusy(false);
    }
  };

  const doRestoreAccess = async () => {
    if (!run || !restoreReason.trim()) return;
    if (!canRunIdentityWorkflow) {
      setDecisionMsg(identityWorkflowReason);
      return;
    }
    if (!uiState.verification?.verified) {
      setDecisionMsg("Restore blocked: verify the user first.");
      return;
    }
    try {
      setActionBusy(true);
      await restoreIncidentAccess(
        run.run_id,
        actor || authUser?.username || "soc.analyst",
        restoreScope,
        restoreReason.trim(),
        restoreReference.trim()
      );
      setDecisionMsg(`Access restore submitted for scope ${restoreScope}`);
      await load();
      emitIncidentMutated(run.run_id);
    } catch (err) {
      setDecisionMsg(isUnauthorizedError(err) ? "Restore failed: session expired. Please log in again." : `Restore failed: ${(err as Error).message}`);
    } finally {
      setActionBusy(false);
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
          <button className="btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="mb-3 flex flex-wrap gap-2">
          {(["overview", "steps", "timeline", "entities", "evidence", "actions"] as DrawerTab[]).map((t) => (
            <button
              key={t}
              className={`rounded px-3 py-1.5 text-xs ${tab === t ? "bg-ink-700 text-white" : "bg-ink-800 text-ink-200 hover:bg-ink-700"}`}
              onClick={() => setTab(t)}
            >
              {t.toUpperCase()}
            </button>
          ))}
        </div>

        {loading && !hasLoadedOnce ? <LoadingState /> : null}
        {refreshing && hasLoadedOnce ? (
          <div className="mb-3 rounded border border-ink-800 bg-ink-900/60 px-3 py-2 text-xs text-ink-300">
            Refreshing investigation workspace...
          </div>
        ) : null}

        {hasLoadedOnce && run && (policyBadge(run.approval_policy_reason) || policySummary.length > 0) ? (
          <div className="mb-3 rounded border border-cyan-900/70 bg-cyan-950/20 px-3 py-3">
            <div className="mb-1 text-[11px] uppercase tracking-[0.18em] text-cyan-300">Policy Summary</div>
            <div className="flex flex-wrap gap-2">
              {policyBadge(run.approval_policy_reason) ? (
                <span className="rounded border border-cyan-800/80 bg-cyan-950/40 px-2 py-1 text-xs text-cyan-100">
                  {policyBadge(run.approval_policy_reason)}
                </span>
              ) : null}
              {policySummary.map((item) => (
                <span key={item} className="rounded border border-ink-700/80 bg-ink-900/70 px-2 py-1 text-xs text-ink-200">
                  {item}
                </span>
              ))}
            </div>
            <div className="mt-2 text-xs text-ink-300">
              Rule: <span className="text-ink-100">{run.approval_policy_rule_id || "-"}</span>
              {" · "}
              Allowlist Rule: <span className="text-ink-100">{run.allowlist_rule_id || "-"}</span>
              {" · "}
              Retention Rule: <span className="text-ink-100">{run.retention_rule_id || "-"}</span>
              {" · "}
              Mode: <span className="text-ink-100">{run.approval_policy_mode || "-"}</span>
              {" · "}
              Confidence: <span className="text-ink-100">{run.confidence_score ?? "-"}</span>
              {" · "}
              Reversibility: <span className="text-ink-100">{run.playbook_reversibility || "-"}</span>
            </div>
          </div>
        ) : null}

        {hasLoadedOnce && run && tab === "overview" ? (
          <div className="space-y-2 rounded border border-ink-800 p-3 text-sm">
            <ValueRow label="run_id" value={run.run_id} />
            <ValueRow label="status" value={<StatusBadge status={run.status} />} />
            <ValueRow label="lane" value={<LaneBadge lane={run.lane} />} />
            <ValueRow label="severity" value={run.severity} />
            <ValueRow label="rule_id" value={run.rule_id} />
            <ValueRow label="playbook_id" value={run.playbook_id} />
            <ValueRow label="target_agent_id" value={run.target_agent_id} />
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
            <ValueRow label="dst_port" value={run.dst_port ? String(run.dst_port) : "-"} />
            <ValueRow label="protocol_family" value={run.protocol_family} />
            <ValueRow label="scan_fanout" value={run.scan_fanout ? String(run.scan_fanout) : "-"} />
            <ValueRow label="top_destinations" value={scanTopDestinations.length > 0 ? scanTopDestinations.join(", ") : "-"} />
            <ValueRow label="user_name" value={run.user_name} />
            <ValueRow label="identity_display_name" value={run.identity_display_name} />
            <ValueRow label="identity_department" value={run.identity_department} />
            <ValueRow label="identity_manager" value={run.identity_manager} />
            <ValueRow label="identity_privileged" value={run.identity_privileged ? "yes" : "no"} />
            <ValueRow label="identity_service_account" value={run.identity_service_account ? "yes" : "no"} />
            <ValueRow label="failed_safe_reason" value={run.failed_safe_reason} />
            <ValueRow label="operator_action" value={run.operator_action} />
            <ValueRow label="approval_policy_mode" value={run.approval_policy_mode} />
            <ValueRow label="approval_policy_rule_id" value={run.approval_policy_rule_id} />
            <ValueRow label="allowlist_rule_id" value={run.allowlist_rule_id} />
            <ValueRow label="approval_policy_reason" value={run.approval_policy_reason} />
            <ValueRow label="playbook_reversibility" value={run.playbook_reversibility} />
            <ValueRow label="confidence_score" value={String(run.confidence_score ?? "-")} />
            <ValueRow label="lifecycle_state" value={run.lifecycle_state} />
            <ValueRow label="environment_class" value={run.environment_class} />
            <ValueRow label="retention_class" value={run.retention_class} />
            <ValueRow label="retention_rule_id" value={run.retention_rule_id} />
            <ValueRow label="archived" value={run.archived ? "yes" : "no"} />
            <ValueRow label="age_days" value={String(run.age_days ?? "-")} />
            <ValueRow label="archive_after_days" value={String(run.archive_after_days ?? "-")} />
            <ValueRow label="purge_after_days" value={String(run.purge_after_days ?? "-")} />
            <ValueRow label="purge_eligible" value={run.purge_eligible ? "yes" : "no"} />
            <ValueRow label="identity_workflow_eligible" value={run.identity_workflow_eligible ? "yes" : "no"} />
            <ValueRow label="identity_workflow_reason" value={run.identity_workflow_reason || "-"} />
            <ValueRow label="assigned_to" value={uiState.assignment || "-"} />
            <ValueRow label="reviewed" value={uiState.reviewed ? "yes" : "no"} />
            <ValueRow label="updated" value={unixMsToLocal(run.last_updated_at_unix_ms)} />
          </div>
        ) : null}

        {hasLoadedOnce && tab === "steps" ? (
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
                  <ValueRow label="allowlist_rule_id" value={step.allowlist_rule_id || "-"} />
                  <ValueRow label="guardrail_rule_ids" value={step.guardrail_rule_ids?.join(", ") || "-"} />
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

        {hasLoadedOnce && tab === "timeline" ? (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2 text-xs">
              {run?.user_name ? (
                <button className="btn-secondary px-2 py-1 text-xs" onClick={() => setPivotUser(run.user_name || "")}>user: {run.user_name}</button>
              ) : null}
              {run?.src_ip ? (
                <button className="btn-secondary px-2 py-1 text-xs" onClick={() => setPivotSrcIP(run.src_ip || "")}>src_ip: {run.src_ip}</button>
              ) : null}
              {run?.node_id ? (
                <button className="btn-secondary px-2 py-1 text-xs" onClick={() => setPivotNode(run.node_id || "")}>node_id: {run.node_id}</button>
              ) : null}
              <button
                className="btn-secondary px-2 py-1 text-xs"
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
              <input className="input-field" placeholder="pivot user_name" value={pivotUser} onChange={(e) => setPivotUser(e.target.value)} />
              <input className="input-field" placeholder="pivot src_ip" value={pivotSrcIP} onChange={(e) => setPivotSrcIP(e.target.value)} />
              <input className="input-field" placeholder="pivot node_id" value={pivotNode} onChange={(e) => setPivotNode(e.target.value)} />
            </div>
            {timeline.length === 0 ? <EmptyState title="No timeline events for selected pivots/window" /> : null}
            {timeline.length > 0 ? (
              <div className="max-h-[420px] overflow-auto rounded border border-ink-800">
                <table className="min-w-full text-sm">
                  <thead className="text-left">
                    <tr>
                      <th className="table-head p-2">Time</th>
                      <th className="table-head p-2">Node</th>
                      <th className="table-head p-2">Source/Event</th>
                      <th className="table-head p-2">User</th>
                      <th className="table-head p-2">src_ip</th>
                      <th className="table-head p-2">dst_ip</th>
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
                        <td className="p-2">{ev.dst_ip || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
          </div>
        ) : null}

        {hasLoadedOnce && tab === "entities" ? (
          <div className="space-y-3 text-sm">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div className="rounded border border-ink-800 p-3">
                <h4 className="mb-2 text-sm font-semibold">Primary Entities</h4>
                <ValueRow label="node_id" value={run?.node_id} />
                <ValueRow label="src_ip" value={run?.src_ip} />
                <ValueRow label="dst_ip" value={run?.dst_ip} />
                <ValueRow label="user_name" value={run?.user_name} />
                <ValueRow label="rule_id" value={run?.rule_id} />
                <ValueRow label="playbook_id" value={run?.playbook_id} />
              </div>
              <div className="rounded border border-ink-800 p-3">
                <h4 className="mb-2 text-sm font-semibold">Entity Pivot</h4>
                <div className="flex flex-wrap gap-2 text-xs">
                  {run?.src_ip ? <button className="btn-secondary px-2 py-1 text-xs" onClick={() => { setTab("timeline"); setPivotSrcIP(run.src_ip || ""); }}>pivot src_ip</button> : null}
                  {run?.user_name ? <button className="btn-secondary px-2 py-1 text-xs" onClick={() => { setTab("timeline"); setPivotUser(run.user_name || ""); }}>pivot user</button> : null}
                  {run?.node_id ? <button className="btn-secondary px-2 py-1 text-xs" onClick={() => { setTab("timeline"); setPivotNode(run.node_id || ""); }}>pivot node</button> : null}
                </div>
              </div>
            </div>
          </div>
        ) : null}

        {hasLoadedOnce && tab === "evidence" ? (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <button className="btn-secondary" onClick={exportBundle}>
                Export JSON
              </button>
              <button className="btn-secondary" onClick={copyBundle}>
                Copy run bundle JSON
              </button>
              <button className="btn-secondary" onClick={() => void downloadIncidentReport(runID, "html")}>
                Download HTML Report
              </button>
              <button className="btn-secondary" onClick={() => void downloadIncidentReport(runID, "pdf")}>
                Download PDF Report
              </button>
              <button className="btn-secondary" onClick={() => void loadInvestigationData()} disabled={investigationLoading}>
                {investigationLoading ? "Loading intel..." : "Reload Intelligence"}
              </button>
              <button className="btn-primary" onClick={() => void refreshInvestigationNow()} disabled={investigationLoading}>
                Run Enrichment
              </button>
            </div>
            {scanContextVisible ? (
              <div className="rounded border border-cyan-900/70 bg-cyan-950/20 p-3">
                <div className="mb-2 text-sm font-semibold text-cyan-100">Scan Context</div>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                  <div>
                    <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300/80">Protocol</div>
                    <div className="mt-1 text-sm text-ink-100">{run?.protocol_family || "-"}</div>
                  </div>
                  <div>
                    <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300/80">Destination Port</div>
                    <div className="mt-1 text-sm text-ink-100">{run?.dst_port || "-"}</div>
                  </div>
                  <div>
                    <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300/80">Fan-out</div>
                    <div className="mt-1 text-sm text-ink-100">{run?.scan_fanout || "-"}</div>
                  </div>
                </div>
                {scanTopDestinations.length > 0 ? (
                  <div className="mt-3">
                    <div className="mb-2 text-[11px] uppercase tracking-[0.18em] text-cyan-300/80">Top Destinations</div>
                    <div className="flex flex-wrap gap-2 text-xs">
                      {scanTopDestinations.map((destination) => (
                        <span key={destination} className="rounded border border-cyan-800/70 bg-cyan-950/40 px-2 py-1 text-cyan-50">
                          {destination}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            ) : null}
            <div className="rounded border border-ink-800 bg-ink-900/40 p-3 space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-semibold">External Intelligence</h4>
                {investigationJobs[0] ? (
                  <div className="flex items-center gap-2 text-xs text-ink-400">
                    <span>last job:</span>
                    <span className={`rounded border px-2 py-0.5 ${intelligenceStatusClass(investigationJobs[0].status)}`}>
                      {intelligenceStatusLabel(investigationJobs[0].status)}
                    </span>
                    <span>{unixMsToLocal(investigationJobs[0].requested_at_unix_ms)}</span>
                  </div>
                ) : null}
              </div>
              {investigationJobs.length > 0 ? (
                <div className="flex flex-wrap gap-2 text-[11px]">
                  {investigationJobs.slice(0, 4).map((job) => (
                    <span key={job.job_id} className="rounded border border-ink-800 bg-ink-950/70 px-2 py-1 text-ink-300">
                      <span className={`mr-2 rounded border px-1.5 py-0.5 ${intelligenceStatusClass(job.status)}`}>
                        {intelligenceStatusLabel(job.status)}
                      </span>
                      {job.job_id}
                    </span>
                  ))}
                </div>
              ) : null}
              {reputationSummary ? (
                <div className={`rounded border px-3 py-2 text-sm ${reputationSummary.tone}`}>
                  <div className="font-semibold">{reputationSummary.title}</div>
                  <div className="mt-1 text-xs opacity-90">{reputationSummary.detail}</div>
                </div>
              ) : null}
              {visibleInvestigationSummaries.length > 0 ? (
                <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
                  {visibleInvestigationSummaries.map((summary) => {
                    const meta = providerMeta(summary.provider);
                    return (
                    <div key={summary.provider} className={`rounded border p-3 text-xs shadow-[0_0_0_1px_rgba(15,23,42,0.25)] ${meta.cardClass}`}>
                      <div className="mb-3 flex items-start justify-between gap-3">
                        <div className="flex items-center gap-3">
                          <span className={`inline-flex h-9 w-9 items-center justify-center rounded border text-[11px] font-semibold tracking-[0.18em] ${meta.markClass}`}>
                            {meta.mark}
                          </span>
                          <div>
                            <div className="font-semibold text-ink-100">{meta.label}</div>
                            <div className="text-[11px] text-ink-400">{summary.provider}</div>
                          </div>
                        </div>
                        <span className={`rounded border px-2 py-0.5 ${intelligenceStatusClass(summary.status)}`}>
                          {intelligenceStatusLabel(summary.status)}
                        </span>
                      </div>
                        <div className="space-y-2 text-ink-300">
                        <div className="text-sm text-ink-100">{providerSummaryHeadline(summary)}</div>
                        {providerScoreHint(summary) ? (
                          <div className="text-[11px] text-ink-400">{providerScoreHint(summary)}</div>
                        ) : null}
                        <div className="flex flex-wrap gap-1 text-[11px]">
                          {summary.verdict ? <span className="rounded border border-ink-700 bg-ink-900 px-1.5 py-0.5">{summary.verdict}</span> : null}
                          {summary.latency_ms > 0 ? <span className="rounded border border-ink-700 bg-ink-900 px-1.5 py-0.5">{summary.latency_ms} ms</span> : null}
                          {summary.attempts > 0 ? <span className="rounded border border-ink-700 bg-ink-900 px-1.5 py-0.5">{summary.attempts}x</span> : null}
                          {summary.http_status > 0 ? <span className="rounded border border-ink-700 bg-ink-900 px-1.5 py-0.5">HTTP {summary.http_status}</span> : null}
                          {summary.error_class ? <span className="rounded border border-ink-700 bg-ink-900 px-1.5 py-0.5">{summary.error_class}</span> : null}
                        </div>
                      </div>
                    </div>
                  );
                  })}
                </div>
              ) : null}
              {investigationError ? <div className="text-xs text-red-400">{investigationError}</div> : null}
              {investigationLoading && !investigation ? <LoadingState /> : null}
              {investigation && investigationObservables.length === 0 ? (
                <div className="rounded border border-amber-800/60 bg-amber-950/20 p-4">
                  <div className="mb-2 text-sm font-semibold text-amber-100">No enrichable observables found for this incident</div>
                  <div className="mb-3 text-xs text-amber-50/90">
                    External intelligence only runs when the incident contains an observable such as `dst_ip`, `src_ip`, a URL,
                    a domain, or a file hash.
                  </div>
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                    <div className="rounded border border-ink-800 bg-ink-950/60 p-3">
                      <div className="mb-2 text-[11px] uppercase tracking-[0.18em] text-ink-400">Detected On This Run</div>
                      {presentObservableHints.length > 0 ? (
                        <div className="flex flex-wrap gap-2 text-xs">
                          {presentObservableHints.map((item) => (
                            <span key={item.label} className="rounded border border-ink-700 bg-ink-900 px-2 py-1 text-ink-200">
                              {item.label}: {item.value}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <div className="text-xs text-ink-400">No supported IOC fields are attached to this run yet.</div>
                      )}
                    </div>
                    <div className="rounded border border-ink-800 bg-ink-950/60 p-3">
                      <div className="mb-2 text-[11px] uppercase tracking-[0.18em] text-ink-400">Supported For Enrichment</div>
                      <div className="flex flex-wrap gap-2 text-xs">
                        {missingObservableHints.map((item) => (
                          <span key={item.label} className="rounded border border-ink-700 bg-ink-900 px-2 py-1 text-ink-300">
                            {item.label}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ) : null}
              {investigationObservables.length > 0 ? (
                <div className="space-y-3">
                  <div className="flex flex-wrap gap-2 text-xs">
                    {investigationObservables.map((o) => (
                      <span key={`${o.kind}-${o.value}-${o.role}`} className="rounded border border-ink-700 bg-ink-900 px-2 py-1">
                        {o.kind}:{o.value} <span className="text-ink-400">({o.role})</span>
                      </span>
                    ))}
                  </div>
                  <div className="overflow-auto rounded border border-ink-800">
                    <table className="min-w-full text-xs">
                      <thead>
                        <tr className="text-left">
                          <th className="p-2">Observable</th>
                          <th className="p-2">Provider</th>
                          <th className="p-2">Status</th>
                          <th className="p-2">Verdict</th>
                          <th className="p-2">Score</th>
                          <th className="p-2">Summary</th>
                          <th className="p-2">Metrics</th>
                          <th className="p-2">Fetched</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visibleInvestigationEnrichments.map((e) => {
                          const meta = requestMetrics(e.data);
                          const provider = providerMeta(e.provider);
                          return (
                            <tr key={`${e.observable_value}-${e.provider}`} className="border-t border-ink-800/70">
                              <td className="p-2">{e.observable_kind}:{e.observable_value}</td>
                              <td className="p-2">
                                <div className="flex items-center gap-2">
                                  <span className={`inline-flex h-6 w-6 items-center justify-center rounded border text-[10px] font-semibold tracking-[0.14em] ${provider.markClass}`}>
                                    {provider.mark}
                                  </span>
                                  <span className="text-ink-200">{provider.label}</span>
                                </div>
                              </td>
                              <td className="p-2">
                                <span className={`rounded border px-2 py-0.5 ${intelligenceStatusClass(e.status)}`}>
                                  {intelligenceStatusLabel(e.status)}
                                </span>
                              </td>
                              <td className="p-2 text-ink-100">{e.verdict}</td>
                              <td className="p-2">{e.score ?? 0}</td>
                              <td className="p-2">
                                {e.evidence_url ? (
                                  <a href={e.evidence_url} target="_blank" className="text-sky-300 hover:underline">
                                    {e.summary || "view"}
                                  </a>
                                ) : (
                                  e.summary || ""
                                )}
                              </td>
                              <td className="p-2">
                                <div className="flex flex-wrap gap-1 text-[11px]">
                                  {meta.latencyMs > 0 ? <span className="rounded border border-ink-700 bg-ink-950/80 px-1.5 py-0.5">{meta.latencyMs} ms</span> : null}
                                  {meta.attempts > 0 ? <span className="rounded border border-ink-700 bg-ink-950/80 px-1.5 py-0.5">{meta.attempts}x</span> : null}
                                  {meta.httpStatus > 0 ? <span className="rounded border border-ink-700 bg-ink-950/80 px-1.5 py-0.5">HTTP {meta.httpStatus}</span> : null}
                                  {meta.errorClass ? <span className="rounded border border-ink-700 bg-ink-950/80 px-1.5 py-0.5">{meta.errorClass}</span> : null}
                                </div>
                              </td>
                              <td className="p-2 text-ink-400">{e.fetched_at_unix_ms ? unixMsToLocal(e.fetched_at_unix_ms) : ""}</td>
                            </tr>
                          );
                        })}
                        {visibleInvestigationEnrichments.length === 0 ? (
                          <tr>
                            <td className="p-2 text-ink-400" colSpan={8}>
                              No active provider results yet. Run enrichment after an observable is attached to this incident.
                            </td>
                          </tr>
                        ) : null}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : null}
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
                        className="btn-secondary px-2 py-1 text-xs"
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

        {hasLoadedOnce && tab === "actions" ? (
          <div className="space-y-3 rounded border border-ink-800 p-3">
            {canApprove ? (
              <>
                <p className="text-sm text-ink-200">Incident is waiting approval.</p>
                <input value={actor} onChange={(e) => { setActor(e.target.value); setActorDirty(true); }} className="input-field w-full" placeholder="actor" />
                <div className="flex gap-2">
                  <button disabled={actionBusy} className="btn-primary disabled:opacity-60" onClick={() => sendDecision("approve")}>
                    Approve
                  </button>
                  <button disabled={actionBusy} className="btn-danger disabled:opacity-60" onClick={() => sendDecision("reject")}>
                    Reject
                  </button>
                </div>
              </>
            ) : requiresManualReview ? (
              <div className="space-y-3">
                <div className="rounded border border-amber-700/60 bg-amber-950/30 px-3 py-2 text-sm text-amber-100">
                  Approval timed out. This run now requires manual review and cannot be resumed by a late approve/reject action.
                </div>
                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                  <ValueRow label="approval_decision" value={run?.approval_decision || "timeout"} />
                  <ValueRow label="operator_action" value={run?.operator_action || "manual_review_required"} />
                </div>
                <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-2 text-xs text-ink-300">
                  Recommended next step: review the incident context, then re-issue containment as a new controlled response if action is still required.
                </div>
                <input value={actor} onChange={(e) => { setActor(e.target.value); setActorDirty(true); }} className="input-field w-full" placeholder="actor" />
                <input
                  value={reissueReason}
                  onChange={(e) => setReissueReason(e.target.value)}
                  className="input-field w-full"
                  placeholder="optional re-issue reason"
                />
                <button disabled={actionBusy} className="btn-primary w-fit disabled:opacity-60" onClick={doReissue}>
                  Re-issue Response
                </button>
              </div>
            ) : (
              <p className="text-sm text-ink-300">No approval action available for current status.</p>
            )}

            <div className="rounded border border-ink-800 p-3">
              <h4 className="mb-2 text-sm font-semibold">Assignment</h4>
              {authUser?.role === "analyst" ? (
                <p className="mb-2 text-xs text-ink-400">Analysts can only assign incidents to themselves.</p>
              ) : null}
              <div className="flex gap-2">
                <input
                  value={assignee}
                  onChange={(e) => { setAssignee(e.target.value); setAssigneeDirty(true); }}
                  readOnly={authUser?.role === "analyst"}
                  className="input-field w-full"
                  placeholder="assignee username"
                />
                <button disabled={actionBusy} className="btn-secondary disabled:opacity-60" onClick={doAssign}>
                  {authUser?.role === "analyst" ? "Assign to me" : "Assign"}
                </button>
              </div>
            </div>

            <div className="rounded border border-ink-800 p-3">
              <h4 className="mb-2 text-sm font-semibold">System Annotations</h4>
              {annotations.length > 0 ? (
                <div className="max-h-36 space-y-1 overflow-auto text-xs">
                  {annotations.map((entry, i) => (
                    <div key={`${entry.ts}-${entry.msg}-${i}`} className="rounded bg-ink-900 px-2 py-1">
                      <div className="text-ink-400">{entry.ts} • {entry.source}</div>
                      <div>{annotationSummary(entry)}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-ink-400">No system annotations recorded for this run.</p>
              )}
            </div>

            <div className="rounded border border-ink-800 p-3">
              <h4 className="mb-2 text-sm font-semibold">Notes</h4>
              <div className="flex gap-2">
                <input value={noteText} onChange={(e) => setNoteText(e.target.value)} className="input-field w-full" placeholder="add note" />
                <button disabled={actionBusy} className="btn-secondary disabled:opacity-60" onClick={doAddNote}>Save</button>
              </div>
              {(uiState.notes || []).length > 0 ? (
                <div className="mt-2 max-h-36 space-y-1 overflow-auto text-xs">
                  {(uiState.notes || []).slice().reverse().map((n, i) => (
                    <div key={`${n.ts}-${i}`} className="rounded bg-ink-900 px-2 py-1">
                      <div className="text-ink-400">{n.ts} • {n.actor}</div>
                      <div>{n.note}</div>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>

            {isIdentityIncident ? (
              <div className="rounded border border-ink-800 p-3">
                <h4 className="mb-2 text-sm font-semibold">Identity Verification</h4>
                {!canRunIdentityWorkflow ? (
                  <div className="mb-3 rounded border border-amber-700/40 bg-amber-950/20 px-3 py-2 text-xs text-amber-100">
                    {identityWorkflowReason}
                  </div>
                ) : uiState.verification?.verified ? (
                  <div className="mb-3 rounded border border-emerald-700/40 bg-emerald-950/20 px-3 py-2 text-xs text-emerald-100">
                    Verified by {uiState.verification.actor || "-"} via {uiState.verification.method || "-"} at {uiState.verification.ts || "-"}
                  </div>
                ) : (
                  <div className="mb-3 rounded border border-ink-800 bg-ink-900/40 px-3 py-2 text-xs text-ink-300">
                    Record user verification before attempting access restore. Restore is expected to safe-deny until verification exists.
                  </div>
                )}
                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                  <input value={verificationMethod} onChange={(e) => setVerificationMethod(e.target.value)} className="input-field w-full" placeholder="verification method" />
                  <input value={verificationReference} onChange={(e) => setVerificationReference(e.target.value)} className="input-field w-full" placeholder="verification reference / ticket" />
                </div>
                <input value={verificationNotes} onChange={(e) => setVerificationNotes(e.target.value)} className="input-field mt-2 w-full" placeholder="verification notes" />
                <button disabled={actionBusy || !canRunIdentityWorkflow} className="btn-secondary mt-2 disabled:opacity-60" onClick={doVerifyUser}>
                  Verify User
                </button>
              </div>
            ) : null}

            {isIdentityIncident ? (
              <div className="rounded border border-ink-800 p-3">
                <h4 className="mb-2 text-sm font-semibold">Restore Access</h4>
                {uiState.restore?.restored ? (
                  <div className="mb-3 rounded border border-cyan-700/40 bg-cyan-950/20 px-3 py-2 text-xs text-cyan-100">
                    Restore recorded by {uiState.restore.actor || "-"} for scope {uiState.restore.scope || "-"} at {uiState.restore.ts || "-"}
                  </div>
                ) : null}
                {!canRunIdentityWorkflow ? (
                  <div className="mb-3 rounded border border-amber-700/40 bg-amber-950/20 px-3 py-2 text-xs text-amber-100">
                    {identityWorkflowReason}
                  </div>
                ) : !uiState.verification?.verified ? (
                  <div className="mb-3 rounded border border-amber-700/40 bg-amber-950/20 px-3 py-2 text-xs text-amber-100">
                    Verify User first. Access restore is blocked until a verification record exists for this incident.
                  </div>
                ) : null}
                <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
                  <select value={restoreScope} onChange={(e) => setRestoreScope(e.target.value as "src_ip" | "user" | "both")} className="input-field w-full">
                    <option value="both">Restore both</option>
                    <option value="src_ip">Restore src_ip only</option>
                    <option value="user">Restore user only</option>
                  </select>
                  <input value={restoreReference} onChange={(e) => setRestoreReference(e.target.value)} className="input-field w-full md:col-span-2" placeholder="change reference" />
                </div>
                <input value={restoreReason} onChange={(e) => setRestoreReason(e.target.value)} className="input-field mt-2 w-full" placeholder="restore reason" />
                <button disabled={actionBusy || !canRunIdentityWorkflow || !uiState.verification?.verified} className="btn-primary mt-2 disabled:opacity-60" onClick={doRestoreAccess}>
                  Restore Access
                </button>
              </div>
            ) : null}

            <button disabled={actionBusy} className="btn-primary disabled:opacity-60" onClick={doMarkReviewed}>Mark as reviewed</button>
            {decisionMsg ? (
              <div className="rounded bg-ink-900 px-2 py-2 text-xs">
                <div>{decisionMsg}</div>
                {newRunID ? (
                  <div className="mt-2">
                    <Link className="text-cyan-300 underline" href={`/incidents/${encodeURIComponent(newRunID)}`}>
                      Open new run
                    </Link>
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}
