"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  addIncidentNote,
  approveIncident,
  assignIncident,
  downloadIncidentReport,
  getApiBase,
  getArtifacts,
  getEntityIP,
  getEntityUser,
  getIncidentActions,
  getInvestigation,
  getInvestigationProviders,
  getIncident,
  getIncidentLogic,
  getIncidentResponseHistory,
  getSearchEvents,
  isUnauthorizedError,
  me,
  markIncidentReviewed,
  postIncidentAction,
  refreshInvestigation,
  reissueIncident,
  restoreIncidentAccess,
  rejectIncident,
  clearIncidentAction,
  verifyIncidentUser
} from "@/lib/api";
import { emitIncidentMutated, emitIncidentsUpdated, INCIDENT_MUTATED_EVENT, INCIDENTS_UPDATED_EVENT } from "@/lib/events";
import {
  AuditEntry,
  AuthUser,
  EntityProfileResponse,
  EventRow,
  Incident,
  IncidentLogicResponse,
  IncidentUIState,
  InvestigationProvidersResponse,
  InvestigationResponse,
  ResponseActionListResponse,
  ResponseActionView,
  ResponseHistoryResponse,
  StepResult
} from "@/lib/types";
import { EmptyState, LaneBadge, LoadingState, StatusBadge, ValueRow, unixMsToLocal } from "@/components/ui";
import { ResponseTargetBuilder } from "@/components/response-target-builder";

type DrawerTab = "overview" | "steps" | "timeline" | "entities" | "evidence" | "actions" | "logic";

const TAB_META: Array<{ id: DrawerTab; label: string; detail: string }> = [
  { id: "overview", label: "Summary", detail: "High-level triage context, scope, and immediate pivots for this incident." },
  { id: "steps", label: "Response History", detail: "Execution history, receipts, retries, and response outcomes for each step." },
  { id: "timeline", label: "Advanced Search", detail: "Pivot across related events by user, source IP, and node to inspect raw activity." },
  { id: "entities", label: "Entity Pages", detail: "Host, user, and network entities involved in the incident with investigation pivots." },
  { id: "evidence", label: "Evidence", detail: "Reports, enrichment, observables, artifacts, and supporting evidence for the run." },
  { id: "actions", label: "Response Actions", detail: "Approval workflow, operator notes, identity actions, and run state changes." },
  { id: "logic", label: "Detection Logic", detail: "Rule, playbook, policy, and confidence context that explain why this run exists." }
];

const ACTION_DURATION_PRESETS: Array<{ label: string; value: number }> = [
  { label: "2 hours", value: 2 * 60 * 60 * 1000 },
  { label: "1 day", value: 24 * 60 * 60 * 1000 },
  { label: "30 days", value: 30 * 24 * 60 * 60 * 1000 },
  { label: "1 year", value: 365 * 24 * 60 * 60 * 1000 }
];

function responseActionTone(bucket?: string): string {
  switch ((bucket || "").toLowerCase()) {
    case "pending":
      return "border-amber-700/60 bg-amber-950/20 text-amber-100";
    case "active":
      return "border-cyan-700/60 bg-cyan-950/20 text-cyan-100";
    case "cleared":
      return "border-emerald-700/60 bg-emerald-950/20 text-emerald-100";
    case "expired":
      return "border-fuchsia-700/60 bg-fuchsia-950/20 text-fuchsia-100";
    case "failed":
      return "border-rose-700/60 bg-rose-950/20 text-rose-100";
    default:
      return "border-ink-700/60 bg-ink-900/70 text-ink-200";
  }
}

function responseActionEligibilityTone(available: boolean): string {
  return available
    ? "border-emerald-700/60 bg-emerald-950/20 text-emerald-100"
    : "border-amber-700/60 bg-amber-950/20 text-amber-100";
}

function groupResponseActions(items: ResponseActionView[] | undefined) {
  const out: Record<string, ResponseActionView[]> = {
    pending: [],
    active: [],
    cleared: [],
    expired: [],
    failed: []
  };
  for (const item of items || []) {
    const bucket = (item.bucket || "active").toLowerCase();
    if (!out[bucket]) out[bucket] = [];
    out[bucket].push(item);
  }
  return out;
}

function humanDuration(value?: number): string {
  const ms = Number(value || 0);
  if (!Number.isFinite(ms) || ms <= 0) return "-";
  const hours = Math.round(ms / (60 * 60 * 1000));
  if (hours < 24) return `${hours}h`;
  const days = Math.round(hours / 24);
  if (days < 365) return `${days}d`;
  const years = Math.round(days / 365);
  return `${years}y`;
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
  const [hasLoadedOnce, setHasLoadedOnce] = useState(false);
  const hasLoadedOnceRef = useRef(false);
  const [investigation, setInvestigation] = useState<InvestigationResponse | null>(null);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const [investigationError, setInvestigationError] = useState("");
  const [logic, setLogic] = useState<IncidentLogicResponse | null>(null);
  const [logicLoading, setLogicLoading] = useState(false);
  const [logicError, setLogicError] = useState("");
  const [responseHistory, setResponseHistory] = useState<ResponseHistoryResponse | null>(null);
  const [responseHistoryLoading, setResponseHistoryLoading] = useState(false);
  const [responseHistoryError, setResponseHistoryError] = useState("");
  const [responseActions, setResponseActions] = useState<ResponseActionListResponse | null>(null);
  const [responseActionsLoading, setResponseActionsLoading] = useState(false);
  const [responseActionsError, setResponseActionsError] = useState("");
  const [entityUserProfile, setEntityUserProfile] = useState<EntityProfileResponse | null>(null);
  const [entitySrcProfile, setEntitySrcProfile] = useState<EntityProfileResponse | null>(null);
  const [entityDstProfile, setEntityDstProfile] = useState<EntityProfileResponse | null>(null);
  const [entityLoading, setEntityLoading] = useState(false);
  const [entityError, setEntityError] = useState("");
  const [providerCatalog, setProviderCatalog] = useState<InvestigationProvidersResponse | null>(null);
  const [providerCatalogLoading, setProviderCatalogLoading] = useState(false);
  const [providerCatalogError, setProviderCatalogError] = useState("");
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
  const [manualActionName, setManualActionName] = useState("block_matching_connections");
  const [manualActionDurationMs, setManualActionDurationMs] = useState<number>(ACTION_DURATION_PRESETS[0].value);
  const [manualActionReason, setManualActionReason] = useState("");
  const [manualActionReference, setManualActionReference] = useState("");
  const [manualActionTargets, setManualActionTargets] = useState<Array<{ kind: "ip" | "dns" | "hostname" | "cidr"; value: string; port?: number; protocol?: "tcp" | "udp" | "any" | "" }>>([
    { kind: "ip", value: "", port: undefined, protocol: "" }
  ]);
  const advancedSearchHref = useMemo(() => {
    const params = new URLSearchParams();
    if (fromMs) params.set("from", String(fromMs));
    if (toMs) params.set("to", String(toMs));
    if (pivotUser || run?.user_name) params.set("user_name", pivotUser || run?.user_name || "");
    if (pivotSrcIP || run?.src_ip) params.set("src_ip", pivotSrcIP || run?.src_ip || "");
    if (pivotNode || run?.node_id) params.set("node_id", pivotNode || run?.node_id || "");
    if (run?.source_type) params.set("source_type", run.source_type);
    if (run?.event_type) params.set("event_type", run.event_type);
    if (run?.rule_id) params.set("rule_id", run.rule_id);
    params.set("limit", "100");
    return `/search?${params.toString()}`;
  }, [fromMs, pivotNode, pivotSrcIP, pivotUser, run?.event_type, run?.node_id, run?.rule_id, run?.source_type, run?.src_ip, run?.user_name, toMs]);

  const load = useCallback(async () => {
    if (!runID || !open) return;
    if (!hasLoadedOnceRef.current) setLoading(true);
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
      const ev = await getSearchEvents({
        from: fromMs,
        to: toMs,
        user_name: pivotUser || detail.run.user_name || undefined,
        src_ip: pivotSrcIP || detail.run.src_ip || undefined,
        node_id: pivotNode || detail.run.node_id || undefined,
        source_type: detail.run.source_type || undefined,
        event_type: detail.run.event_type || undefined,
        rule_id: detail.run.rule_id || undefined,
        limit: 100,
        page: 1,
        sort: "recv_desc"
      });
      setEvents(ev.items || []);
      const collected: Array<{ path: string; is_dir: boolean; size: number; modified: string }> = [];
      try {
        for (let p = 1; p <= 3; p++) {
          const art = await getArtifacts("demo_artifacts", { q: "/fr04/", page: p, limit: 200 });
          collected.push(...(art.items || []));
          if (!art.has_more) break;
        }
      } catch {
        // Artifact proofs are optional; keep the investigation workspace available.
      }
      setArtifactMap(
        collected.filter((a) => a.path.includes("/fr04/") || a.path.endsWith("capture.pcap") || a.path.endsWith("chain_of_custody.json"))
      );
      hasLoadedOnceRef.current = true;
      setHasLoadedOnce(true);
    } finally {
      setLoading(false);
    }
  }, [actorDirty, assigneeDirty, fromMs, open, pivotNode, pivotSrcIP, pivotUser, runID, toMs]);

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

  const loadLogicData = useCallback(async () => {
    if (!runID || !open) return;
    setLogicError("");
    setLogicLoading(true);
    try {
      const res = await getIncidentLogic(runID);
      setLogic(res);
    } catch (err: any) {
      setLogicError(err?.message || "logic load failed");
    } finally {
      setLogicLoading(false);
    }
  }, [open, runID]);

  const loadResponseHistoryData = useCallback(async () => {
    if (!runID || !open) return;
    setResponseHistoryError("");
    setResponseHistoryLoading(true);
    try {
      const res = await getIncidentResponseHistory(runID);
      setResponseHistory(res);
    } catch (err: any) {
      setResponseHistoryError(err?.message || "response history load failed");
    } finally {
      setResponseHistoryLoading(false);
    }
  }, [open, runID]);

  const loadResponseActionsData = useCallback(async () => {
    if (!runID || !open) return;
    setResponseActionsError("");
    setResponseActionsLoading(true);
    try {
      const res = await getIncidentActions(runID);
      setResponseActions(res);
      if (!manualActionReason && res.available_actions?.length > 0 && !res.available_actions.find((item) => item.id === manualActionName)) {
        const first = res.available_actions.find((item) => item.available) || res.available_actions[0];
        setManualActionName(first?.id || "");
        setManualActionDurationMs(first?.default_duration_ms || ACTION_DURATION_PRESETS[0].value);
      }
    } catch (err: any) {
      setResponseActionsError(err?.message || "response actions load failed");
    } finally {
      setResponseActionsLoading(false);
    }
  }, [manualActionName, manualActionReason, open, runID]);

  const loadEntityProfiles = useCallback(async (currentRun: Incident | null) => {
    if (!open || !currentRun) return;
    const tasks: Array<Promise<void>> = [];
    setEntityError("");
    setEntityLoading(true);
    setEntityUserProfile(null);
    setEntitySrcProfile(null);
    setEntityDstProfile(null);
    if (currentRun.user_name) {
      tasks.push(getEntityUser(currentRun.user_name).then(setEntityUserProfile));
    }
    if (currentRun.src_ip) {
      tasks.push(getEntityIP(currentRun.src_ip).then(setEntitySrcProfile));
    }
    if (currentRun.dst_ip) {
      tasks.push(getEntityIP(currentRun.dst_ip).then(setEntityDstProfile));
    }
    try {
      await Promise.all(tasks);
    } catch (err: any) {
      setEntityError(err?.message || "entity profile load failed");
    } finally {
      setEntityLoading(false);
    }
  }, [open]);

  const loadProviderCatalog = useCallback(async () => {
    if (!open) return;
    setProviderCatalogError("");
    setProviderCatalogLoading(true);
    try {
      const res = await getInvestigationProviders();
      setProviderCatalog(res);
    } catch (err: any) {
      setProviderCatalogError(err?.message || "provider catalog load failed");
    } finally {
      setProviderCatalogLoading(false);
    }
  }, [open]);

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
    setManualActionName("block_matching_connections");
    setManualActionDurationMs(ACTION_DURATION_PRESETS[0].value);
    setManualActionReason("");
    setManualActionReference("");
    setManualActionTargets([{ kind: "ip", value: "", port: undefined, protocol: "" }]);
    setInvestigation(null);
    setInvestigationError("");
    setInvestigationLoading(false);
    setLogic(null);
    setLogicError("");
    setLogicLoading(false);
    setResponseHistory(null);
    setResponseHistoryError("");
    setResponseHistoryLoading(false);
    setResponseActions(null);
    setResponseActionsError("");
    setResponseActionsLoading(false);
    setEntityUserProfile(null);
    setEntitySrcProfile(null);
    setEntityDstProfile(null);
    setEntityError("");
    setEntityLoading(false);
    setProviderCatalog(null);
    setProviderCatalogError("");
    setProviderCatalogLoading(false);
    hasLoadedOnceRef.current = false;
    setHasLoadedOnce(false);
    setLoading(false);
  }, [initialTab, runID, open]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!open || tab !== "evidence") return;
    void loadInvestigationData();
  }, [loadInvestigationData, open, tab, runID]);

  useEffect(() => {
    if (!open || tab !== "logic") return;
    if (logic || logicLoading) return;
    void loadLogicData();
  }, [loadLogicData, logic, logicLoading, open, tab]);

  useEffect(() => {
    if (!open || tab !== "steps") return;
    if (responseHistory || responseHistoryLoading) return;
    void loadResponseHistoryData();
  }, [loadResponseHistoryData, open, responseHistory, responseHistoryLoading, tab]);

  useEffect(() => {
    if (!open || tab !== "actions") return;
    if (responseActions || responseActionsLoading) return;
    void loadResponseActionsData();
  }, [loadResponseActionsData, open, responseActions, responseActionsLoading, tab]);

  useEffect(() => {
    if (!open || tab !== "entities" || !run) return;
    if ((entityUserProfile || entitySrcProfile || entityDstProfile) || entityLoading) return;
    void loadEntityProfiles(run);
  }, [entityDstProfile, entityLoading, entitySrcProfile, entityUserProfile, loadEntityProfiles, open, run, tab]);

  useEffect(() => {
    if (!open || tab !== "evidence") return;
    if (providerCatalog || providerCatalogLoading) return;
    void loadProviderCatalog();
  }, [loadProviderCatalog, open, providerCatalog, providerCatalogLoading, tab]);

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
  const actionGroups = useMemo(() => groupResponseActions(responseActions?.items), [responseActions?.items]);
  const selectedManualAction = useMemo(
    () =>
      responseActions?.available_actions?.find((item) => item.id === manualActionName) ||
      responseActions?.available_actions?.find((item) => item.available) ||
      responseActions?.available_actions?.[0] ||
      null,
    [manualActionName, responseActions?.available_actions]
  );

  useEffect(() => {
    if (!open) return;
    setManualActionTargets([{ kind: "ip", value: "", port: undefined, protocol: "" }]);
  }, [open, selectedManualAction?.id]);

  useEffect(() => {
    if (!open) return;
    if (!selectedManualAction?.requires_targets) return;
    setManualActionTargets((current) => (current.length > 0 ? current : [{ kind: "ip", value: "", port: undefined, protocol: "" }]));
  }, [open, selectedManualAction?.id, selectedManualAction?.requires_targets]);

  const policySummary = useMemo(() => policyHighlights(run), [run]);
  const selectedTabMeta = useMemo(() => TAB_META.find((item) => item.id === tab) || TAB_META[0], [tab]);

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

  const doLaunchManualAction = async () => {
    if (!run || !selectedManualAction) return;
    if (!selectedManualAction.available) {
      setDecisionMsg(selectedManualAction.unavailable_reason || "Selected response action is not available for this incident.");
      return;
    }
    const targetPayload = manualActionTargets
      .map((item) => ({
        kind: item.kind,
        value: item.value.trim(),
        port: item.port,
        protocol: item.protocol
      }))
      .filter((item) => item.value.length > 0);
    if (selectedManualAction.requires_targets && targetPayload.length === 0) {
      setDecisionMsg("This response action requires at least one explicit target.");
      return;
    }
    try {
      setActionBusy(true);
      await postIncidentAction(run.run_id, {
        actor: actor || authUser?.username || "soc.analyst",
        action_name: selectedManualAction.id,
        duration_ms: manualActionDurationMs,
        reason: manualActionReason.trim(),
        reference: manualActionReference.trim(),
        target: targetPayload.map((item) => item.value).join(", "),
        target_agent_id: run.target_agent_id || run.node_id || "",
        targets: targetPayload
      });
      setDecisionMsg(`Response action launched: ${selectedManualAction.label}`);
      setManualActionReason("");
      setManualActionReference("");
      setManualActionTargets([{ kind: "ip", value: "", port: undefined, protocol: "" }]);
      await Promise.all([load(), loadResponseActionsData(), loadResponseHistoryData()]);
      emitIncidentMutated(run.run_id);
      emitIncidentsUpdated({ runID: run.run_id });
    } catch (err) {
      setDecisionMsg(`Action launch failed: ${(err as Error).message}`);
    } finally {
      setActionBusy(false);
    }
  };

  const doClearManualAction = async (actionID: string) => {
    if (!run) return;
    try {
      setActionBusy(true);
      await clearIncidentAction(run.run_id, actionID, {
        actor: actor || authUser?.username || "soc.analyst",
        reason: manualActionReason.trim() || "manual clear from incident workspace",
        reference: manualActionReference.trim()
      });
      setDecisionMsg(`Response action cleared: ${actionID}`);
      await Promise.all([loadResponseActionsData(), loadResponseHistoryData()]);
      emitIncidentMutated(run.run_id);
    } catch (err) {
      setDecisionMsg(`Action clear failed: ${(err as Error).message}`);
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
            <h3 className="text-lg font-semibold">Incident Investigation</h3>
            <p className="text-xs text-ink-300">run_id: {runID}</p>
          </div>
          <button className="btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="mb-3 flex flex-wrap gap-2">
          {TAB_META.map((item) => (
            <button
              key={item.id}
              className={`rounded px-3 py-1.5 text-xs ${tab === item.id ? "bg-ink-700 text-white" : "bg-ink-800 text-ink-200 hover:bg-ink-700"}`}
              onClick={() => setTab(item.id)}
            >
              {item.label}
            </button>
          ))}
        </div>

        <div className="mb-3 rounded border border-ink-800 bg-ink-900/50 px-3 py-2 text-xs text-ink-300">
          <span className="font-medium text-ink-100">{selectedTabMeta.label}:</span> {selectedTabMeta.detail}
        </div>

        {loading && !hasLoadedOnce ? <LoadingState /> : null}
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
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <div className="rounded border border-ink-800 bg-ink-900/50 p-3 text-sm">
                <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Status</div>
                <div className="mt-2"><StatusBadge status={run.status} /></div>
              </div>
              <div className="rounded border border-ink-800 bg-ink-900/50 p-3 text-sm">
                <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Rule</div>
                <div className="mt-2 font-medium text-ink-100">{run.rule_id || "-"}</div>
              </div>
              <div className="rounded border border-ink-800 bg-ink-900/50 p-3 text-sm">
                <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Playbook</div>
                <div className="mt-2 font-medium text-ink-100">{run.playbook_id || "-"}</div>
              </div>
              <div className="rounded border border-ink-800 bg-ink-900/50 p-3 text-sm">
                <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Confidence</div>
                <div className="mt-2 font-medium text-ink-100">{run.confidence_score ?? "-"}</div>
              </div>
            </div>

            <div className="rounded border border-ink-800 p-3">
              <div className="mb-2 text-sm font-semibold">Investigation pivots</div>
              <div className="flex flex-wrap gap-2 text-xs">
                <button className="btn-secondary px-2 py-1 text-xs" onClick={() => setTab("timeline")}>
                  Open advanced search
                </button>
                <button className="btn-secondary px-2 py-1 text-xs" onClick={() => setTab("entities")}>
                  Review entity pages
                </button>
                <button className="btn-secondary px-2 py-1 text-xs" onClick={() => setTab("steps")}>
                  Review response history
                </button>
                <button className="btn-secondary px-2 py-1 text-xs" onClick={() => setTab("logic")}>
                  View detection logic
                </button>
              </div>
            </div>

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
          </div>
        ) : null}

        {hasLoadedOnce && tab === "steps" ? (
          <div className="space-y-2">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <div className="rounded border border-ink-800 bg-ink-900/50 p-3 text-sm">
                <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Step total</div>
                <div className="mt-2 text-lg font-semibold text-ink-100">{run?.step_total ?? steps.length}</div>
              </div>
              <div className="rounded border border-ink-800 bg-ink-900/50 p-3 text-sm">
                <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Succeeded</div>
                <div className="mt-2 text-lg font-semibold text-emerald-200">{run?.step_succeeded_count ?? 0}</div>
              </div>
              <div className="rounded border border-ink-800 bg-ink-900/50 p-3 text-sm">
                <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Failed safe</div>
                <div className="mt-2 text-lg font-semibold text-rose-200">{run?.step_failed_safe_count ?? 0}</div>
              </div>
              <div className="rounded border border-ink-800 bg-ink-900/50 p-3 text-sm">
                <div className="text-[11px] uppercase tracking-[0.12em] text-ink-400">Transient</div>
                <div className="mt-2 text-lg font-semibold text-amber-200">{run?.step_failed_transient_count ?? 0}</div>
              </div>
            </div>
            {responseHistoryError ? (
              <div className="rounded border border-rose-700/60 bg-rose-950/30 px-3 py-2 text-sm text-rose-100">
                {responseHistoryError}
              </div>
            ) : null}
            {!responseHistory && responseHistoryLoading ? <LoadingState /> : null}
            {responseHistory && responseHistory.items.length > 0 ? (
              <div className="max-h-[520px] overflow-auto rounded border border-ink-800">
                <table className="min-w-full text-sm">
                  <thead className="text-left">
                    <tr>
                      <th className="table-head p-2">Time</th>
                      <th className="table-head p-2">Stage</th>
                      <th className="table-head p-2">Label</th>
                      <th className="table-head p-2">Status</th>
                      <th className="table-head p-2">Actor</th>
                      <th className="table-head p-2">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {responseHistory.items.map((item) => (
                      <tr key={`${item.source}-${item.label}-${item.ts_unix_ms}-${item.step_id || ""}`} className="border-t border-ink-800/80 align-top">
                        <td className="p-2 whitespace-nowrap">{unixMsToLocal(item.ts_unix_ms)}</td>
                        <td className="p-2">{item.stage}</td>
                        <td className="p-2">
                          <div className="font-medium text-ink-100">{item.label}</div>
                          {item.step_id ? <div className="mt-1 text-xs text-ink-400">step[{item.step_index}] {item.step_id}</div> : null}
                        </td>
                        <td className="p-2">{item.status ? <StatusBadge status={item.status} /> : "-"}</td>
                        <td className="p-2">{item.actor || item.decision || "-"}</td>
                        <td className="p-2">
                          {item.details && Object.keys(item.details).length > 0 ? (
                            <pre className="max-w-[28rem] overflow-auto rounded bg-ink-900 p-2 text-xs">{JSON.stringify(item.details, null, 2)}</pre>
                          ) : (
                            <span className="text-ink-500">-</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
            {!responseHistoryLoading && (!responseHistory || responseHistory.items.length === 0) ? <EmptyState title="No response history for this run" /> : null}
          </div>
        ) : null}

        {hasLoadedOnce && tab === "timeline" ? (
          <div className="space-y-3">
            <div className="rounded border border-ink-800 bg-ink-900/50 px-3 py-2 text-xs text-ink-300">
              Use these pivots to move from the summarized incident into related raw activity. This is the analyst-facing advanced search surface for this run.
            </div>
            <div className="flex justify-end">
              <Link className="btn-secondary px-2 py-1 text-xs" href={advancedSearchHref}>
                Open full Advanced Search
              </Link>
            </div>
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
            <div className="text-xs text-ink-400">Related events in view: {timeline.length}</div>
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
                      <th className="table-head p-2">Protocol</th>
                      <th className="table-head p-2">Process</th>
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
                        <td className="p-2">{[ev.protocol_family || "-", ev.dst_port ? String(ev.dst_port) : ""].filter(Boolean).join(" ")}</td>
                        <td className="p-2">{ev.comm || ev.exec_path || "-"}</td>
                        <td className="p-2">{ev.src_ip || "-"}</td>
                        <td className="p-2">{[ev.dst_ip || "-", ev.dns_name ? `(${ev.dns_name})` : ""].filter(Boolean).join(" ")}</td>
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
                <h4 className="mb-2 text-sm font-semibold">Entity Pivots</h4>
                <div className="flex flex-wrap gap-2 text-xs">
                  {run?.src_ip ? <button className="btn-secondary px-2 py-1 text-xs" onClick={() => { setTab("timeline"); setPivotSrcIP(run.src_ip || ""); }}>pivot src_ip</button> : null}
                  {run?.user_name ? <button className="btn-secondary px-2 py-1 text-xs" onClick={() => { setTab("timeline"); setPivotUser(run.user_name || ""); }}>pivot user</button> : null}
                  {run?.node_id ? <button className="btn-secondary px-2 py-1 text-xs" onClick={() => { setTab("timeline"); setPivotNode(run.node_id || ""); }}>pivot node</button> : null}
                </div>
                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  <Link className="btn-secondary px-2 py-1 text-xs" href="/endpoints">
                    Open endpoint pages
                  </Link>
                  <Link className="btn-secondary px-2 py-1 text-xs" href={advancedSearchHref}>
                    Open advanced search
                  </Link>
                </div>
              </div>
            </div>
            {entityError ? (
              <div className="rounded border border-rose-700/60 bg-rose-950/30 px-3 py-2 text-sm text-rose-100">
                {entityError}
              </div>
            ) : null}
            {entityLoading ? <LoadingState /> : null}
            {!entityLoading ? (
              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                {[entityUserProfile, entitySrcProfile, entityDstProfile].filter(Boolean).map((profile) => {
                  const current = profile as EntityProfileResponse;
                  return (
                    <div key={`${current.kind}:${current.value}`} className="rounded border border-ink-800 p-3">
                      <div className="mb-2 flex items-center justify-between">
                        <h4 className="text-sm font-semibold capitalize">{current.kind} profile</h4>
                        <span className="rounded border border-ink-700/70 bg-ink-900/70 px-2 py-0.5 text-xs text-ink-200">{current.source}</span>
                      </div>
                      <div className="mb-3 text-sm text-ink-100">{current.value}</div>
                      <div className="space-y-2 text-xs">
                        <ValueRow label="total_events" value={String(current.summary.total_events || 0)} />
                        <ValueRow label="detections" value={String(current.summary.detections || 0)} />
                        <ValueRow label="first_seen" value={unixMsToLocal(current.summary.first_seen_unix_ms)} />
                        <ValueRow label="last_seen" value={unixMsToLocal(current.summary.last_seen_unix_ms)} />
                        <ValueRow label="nodes" value={current.summary.nodes?.join(", ") || "-"} />
                        <ValueRow label="source_types" value={current.summary.source_types?.join(", ") || "-"} />
                        <ValueRow label="rules" value={current.summary.rules?.join(", ") || "-"} />
                      </div>
                      <div className="mt-3 text-xs text-ink-400">
                        {current.count_events} recent events, {current.count_incidents} recent incidents
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : null}
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
              {providerCatalogError ? (
                <div className="rounded border border-rose-700/60 bg-rose-950/30 px-3 py-2 text-sm text-rose-100">
                  {providerCatalogError}
                </div>
              ) : null}
              {providerCatalog && providerCatalog.items.length > 0 ? (
                <div className="rounded border border-ink-800 bg-ink-950/50 p-3">
                  <div className="mb-2 text-sm font-semibold">Provider Capability Surface</div>
                  <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                    {providerCatalog.items.map((provider) => (
                      <div key={provider.provider} className="rounded border border-ink-800 bg-ink-900/50 p-3 text-xs">
                        <div className="flex items-center justify-between">
                          <div className="font-medium text-ink-100">{provider.label}</div>
                          <span className={`rounded border px-2 py-0.5 ${provider.enabled ? "border-emerald-700/60 bg-emerald-950/70 text-emerald-200" : "border-ink-700/60 bg-ink-900/70 text-ink-300"}`}>
                            {provider.enabled ? "enabled" : "disabled"}
                          </span>
                        </div>
                        <div className="mt-2 space-y-1 text-ink-300">
                          <div>API key: {provider.api_key_configured ? "configured" : "missing"} ({provider.env_var})</div>
                          <div>Supports: {provider.supported_kinds.join(", ") || "-"}</div>
                          <div>Last status: {provider.last_status || "-"}</div>
                          <div>Last verdict: {provider.last_verdict || "-"}</div>
                          <div>Last fetched: {unixMsToLocal(provider.last_fetched_at_unix_ms)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
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

        {hasLoadedOnce && run && tab === "logic" ? (
          <div className="space-y-3">
            <div className="rounded border border-cyan-900/70 bg-cyan-950/20 px-3 py-2 text-sm text-cyan-50">
              This is the operator-readable detection and response logic for the current incident. Live editing of models is handled in configuration management, not inside the incident drawer.
            </div>
            <div className="flex flex-wrap gap-2">
              <button className="btn-secondary" onClick={() => void loadLogicData()} disabled={logicLoading}>
                {logicLoading ? "Loading logic..." : "Reload logic"}
              </button>
            </div>
            {logicError ? (
              <div className="rounded border border-rose-700/60 bg-rose-950/30 px-3 py-2 text-sm text-rose-100">
                {logicError}
              </div>
            ) : null}
            {!logic && logicLoading ? <LoadingState /> : null}
            {logic ? (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div className="rounded border border-ink-800 p-3">
                <h4 className="mb-2 text-sm font-semibold">Detection Model</h4>
                <div className="space-y-2 text-sm">
                  <ValueRow label="rule_id" value={logic.rule.id || "-"} />
                  <ValueRow label="enabled" value={logic.rule.enabled ? "yes" : "no"} />
                  <ValueRow label="kind" value={logic.rule.kind || "-"} />
                  <ValueRow label="severity" value={logic.rule.severity || "-"} />
                  <ValueRow label="group_by" value={logic.rule.group_by || "-"} />
                  <ValueRow label="window_ms" value={logic.rule.window_ms ? String(logic.rule.window_ms) : "-"} />
                  <ValueRow label="threshold" value={logic.rule.threshold ? String(logic.rule.threshold) : "-"} />
                  <ValueRow label="when_type" value={logic.rule.when_type || "-"} />
                </div>
                {logic.rule.conditions && logic.rule.conditions.length > 0 ? (
                  <div className="mt-3">
                    <div className="mb-2 text-[11px] uppercase tracking-[0.18em] text-ink-400">Conditions</div>
                    <div className="flex flex-wrap gap-2 text-xs">
                      {logic.rule.conditions.map((condition) => (
                        <span key={condition} className="rounded border border-ink-700/70 bg-ink-900/70 px-2 py-1 text-ink-200">
                          {condition}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}
                {logic.rule.sequence && logic.rule.sequence.length > 0 ? (
                  <div className="mt-3">
                    <div className="mb-2 text-[11px] uppercase tracking-[0.18em] text-ink-400">Sequence</div>
                    <div className="flex flex-wrap gap-2 text-xs">
                      {logic.rule.sequence.map((value) => (
                        <span key={value} className="rounded border border-cyan-800/70 bg-cyan-950/30 px-2 py-1 text-cyan-100">
                          {value}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}
                {logic.rule.predicates && logic.rule.predicates.length > 0 ? (
                  <div className="mt-3">
                    <div className="mb-2 text-[11px] uppercase tracking-[0.18em] text-ink-400">Predicates</div>
                    <div className="space-y-1 text-xs text-ink-300">
                      {logic.rule.predicates.map((predicate) => (
                        <div key={predicate} className="rounded border border-ink-800 bg-ink-900/40 px-2 py-1">
                          {predicate}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
              <div className="rounded border border-ink-800 p-3">
                <h4 className="mb-2 text-sm font-semibold">Response Model</h4>
                <div className="space-y-2 text-sm">
                  <ValueRow label="playbook_id" value={logic.playbook.id || "-"} />
                  <ValueRow label="enabled" value={logic.playbook.enabled ? "yes" : "no"} />
                  <ValueRow label="version" value={logic.playbook.version ? String(logic.playbook.version) : "-"} />
                  <ValueRow label="lane" value={<LaneBadge lane={run.lane} />} />
                  <ValueRow label="status" value={<StatusBadge status={run.status} />} />
                  <ValueRow label="approval_mode" value={logic.playbook.approval_mode || "-"} />
                  <ValueRow label="max_blast_radius" value={logic.playbook.max_blast_radius ? String(logic.playbook.max_blast_radius) : "-"} />
                  <ValueRow label="auto_min_confidence" value={logic.playbook.auto_min_confidence ? String(logic.playbook.auto_min_confidence) : "-"} />
                  <ValueRow label="auto_max_severity" value={logic.playbook.auto_max_severity || "-"} />
                </div>
                {logic.playbook.selector_rule_ids && logic.playbook.selector_rule_ids.length > 0 ? (
                  <div className="mt-3">
                    <div className="mb-2 text-[11px] uppercase tracking-[0.18em] text-ink-400">Selector rule ids</div>
                    <div className="flex flex-wrap gap-2 text-xs">
                      {logic.playbook.selector_rule_ids.map((value) => (
                        <span key={value} className="rounded border border-ink-700/70 bg-ink-900/70 px-2 py-1 text-ink-200">
                          {value}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
              <div className="rounded border border-ink-800 p-3">
                <h4 className="mb-2 text-sm font-semibold">Scope and Entities</h4>
                <div className="space-y-2 text-sm">
                  <ValueRow label="node_id" value={logic.scope.node_id || "-"} />
                  <ValueRow label="target_agent_id" value={logic.scope.target_agent_id || "-"} />
                  <ValueRow label="source_type" value={logic.scope.source_type || "-"} />
                  <ValueRow label="event_type" value={logic.scope.event_type || "-"} />
                  <ValueRow label="user_name" value={logic.scope.user_name || "-"} />
                  <ValueRow label="src_ip" value={logic.scope.src_ip || "-"} />
                  <ValueRow label="dst_ip" value={logic.scope.dst_ip || "-"} />
                  <ValueRow label="dst_port" value={logic.scope.dst_port ? String(logic.scope.dst_port) : "-"} />
                  <ValueRow label="protocol_family" value={logic.scope.protocol_family || "-"} />
                  <ValueRow label="top_destinations" value={logic.scope.top_destinations && logic.scope.top_destinations.length > 0 ? logic.scope.top_destinations.join(", ") : "-"} />
                </div>
              </div>
              <div className="rounded border border-ink-800 p-3">
                <h4 className="mb-2 text-sm font-semibold">Observed Context</h4>
                <div className="space-y-2 text-sm">
                  <ValueRow label="comm" value={logic.scope.comm || "-"} />
                  <ValueRow label="exec_path" value={logic.scope.exec_path || "-"} />
                  <ValueRow label="cmdline" value={logic.scope.cmdline || "-"} />
                  <ValueRow label="dns_name" value={logic.scope.dns_name || "-"} />
                  <ValueRow label="target" value={logic.scope.target || "-"} />
                  <ValueRow label="file_sha256" value={logic.scope.file_sha256 || "-"} />
                  <ValueRow label="exec_sha256" value={logic.scope.exec_sha256 || "-"} />
                </div>
              </div>
              <div className="rounded border border-ink-800 p-3 md:col-span-2">
                <h4 className="mb-2 text-sm font-semibold">Governance and Retention</h4>
                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                  <ValueRow label="approval_mode" value={logic.policy.approval_mode || "-"} />
                  <ValueRow label="approval_rule_id" value={logic.policy.approval_rule_id || "-"} />
                  <ValueRow label="approval_reason" value={logic.policy.approval_reason || "-"} />
                  <ValueRow label="playbook_reversibility" value={logic.policy.playbook_reversibility || "-"} />
                  <ValueRow label="allowlist_rule_id" value={logic.policy.allowlist_rule_id || "-"} />
                  <ValueRow label="approval_timeout_ms" value={logic.policy.approval_timeout_ms ? String(logic.policy.approval_timeout_ms) : "-"} />
                  <ValueRow label="default_auto_min_confidence" value={logic.policy.default_auto_min_confidence ? String(logic.policy.default_auto_min_confidence) : "-"} />
                  <ValueRow label="identity_workflow_eligible" value={run.identity_workflow_eligible ? "yes" : "no"} />
                </div>
                {logic.policy.approval_rule ? (
                  <div className="mt-3 rounded border border-ink-800 bg-ink-900/40 px-3 py-3">
                    <div className="mb-2 text-sm font-semibold">Matched approval rule</div>
                    <div className="space-y-2 text-sm">
                      <ValueRow label="id" value={logic.policy.approval_rule.id} />
                      <ValueRow label="required" value={logic.policy.approval_rule.required ? "yes" : "no"} />
                      <ValueRow label="reason" value={logic.policy.approval_rule.reason || "-"} />
                    </div>
                    {logic.policy.approval_rule.conditions && logic.policy.approval_rule.conditions.length > 0 ? (
                      <div className="mt-3 flex flex-wrap gap-2 text-xs">
                        {logic.policy.approval_rule.conditions.map((condition) => (
                          <span key={condition} className="rounded border border-ink-700/70 bg-ink-900/70 px-2 py-1 text-ink-200">
                            {condition}
                          </span>
                        ))}
                      </div>
                    ) : null}
                  </div>
                ) : null}
                {logic.playbook.steps && logic.playbook.steps.length > 0 ? (
                  <div className="mt-3 rounded border border-ink-800 bg-ink-900/40 px-3 py-3">
                    <div className="mb-2 text-sm font-semibold">Playbook steps</div>
                    <div className="space-y-2">
                      {logic.playbook.steps.map((step) => (
                        <div key={step.name} className="rounded border border-ink-800 bg-ink-950/60 px-3 py-2">
                          <div className="flex flex-wrap items-center gap-2 text-sm">
                            <span className="font-medium text-ink-100">{step.name}</span>
                            <span className="rounded border border-ink-700/70 bg-ink-900/70 px-2 py-0.5 text-xs text-ink-200">{step.action_type}</span>
                            {step.reversibility ? (
                              <span className="rounded border border-cyan-800/70 bg-cyan-950/30 px-2 py-0.5 text-xs text-cyan-100">{step.reversibility}</span>
                            ) : null}
                          </div>
                          <div className="mt-2 grid grid-cols-1 gap-2 text-xs text-ink-300 md:grid-cols-4">
                            <div>target_from: {step.target_from || "-"}</div>
                            <div>timeout_ms: {step.timeout_ms ?? "-"}</div>
                            <div>retries: {step.retries ?? "-"}</div>
                            <div>backoff_ms: {step.backoff_ms ?? "-"}</div>
                          </div>
                          {step.param_keys && step.param_keys.length > 0 ? (
                            <div className="mt-2 flex flex-wrap gap-2 text-xs">
                              {step.param_keys.map((key) => (
                                <span key={key} className="rounded border border-fuchsia-800/70 bg-fuchsia-950/30 px-2 py-1 text-fuchsia-100">
                                  {key}
                                </span>
                              ))}
                            </div>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
            ) : (
              !logicLoading ? <EmptyState title="No logic metadata found for this run" detail="The incident exists, but no resolved rule/playbook logic was returned by the backend." /> : null
            )}
          </div>
        ) : null}

        {hasLoadedOnce && tab === "actions" ? (
          <div className="space-y-3 rounded border border-ink-800 p-3">
            <div className="rounded border border-ink-800 bg-ink-900/40 px-3 py-2 text-xs text-ink-300">
              This panel controls analyst workflow state and manual response actions: approvals, launched controls, notes, identity workflow, and reviewed status.
            </div>
            <div className="grid grid-cols-2 gap-2 md:grid-cols-5">
              {[
                ["Pending", responseActions?.buckets?.pending || 0],
                ["Active", responseActions?.buckets?.active || 0],
                ["Cleared", responseActions?.buckets?.cleared || 0],
                ["Expired", responseActions?.buckets?.expired || 0],
                ["Failed", responseActions?.buckets?.failed || 0]
              ].map(([label, value]) => (
                <div key={String(label)} className="rounded border border-ink-800 bg-ink-900/40 px-3 py-2">
                  <div className="text-[11px] uppercase tracking-[0.24em] text-ink-400">{label}</div>
                  <div className="mt-1 text-lg font-semibold">{value}</div>
                </div>
              ))}
            </div>

            <div className="rounded border border-ink-800 p-3">
              <div className="mb-2 flex items-center justify-between gap-2">
                <h4 className="text-sm font-semibold">Launch Response Action</h4>
              </div>
              {responseActionsError ? (
                <div className="mb-2 rounded border border-rose-700/50 bg-rose-950/20 px-3 py-2 text-xs text-rose-100">
                  {responseActionsError}
                </div>
              ) : null}
              <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                <select
                  value={selectedManualAction?.id || manualActionName}
                  onChange={(e) => {
                    const nextID = e.target.value;
                    setManualActionName(nextID);
                    const next = responseActions?.available_actions?.find((item) => item.id === nextID);
                    if (next?.default_duration_ms) setManualActionDurationMs(next.default_duration_ms);
                  }}
                  className="input-field w-full"
                >
                  {(responseActions?.available_actions || []).map((item) => (
                    <option key={item.id} value={item.id} disabled={!item.available}>
                      {item.label}{item.available ? "" : " (unavailable)"}
                    </option>
                  ))}
                </select>
                <select
                  value={String(manualActionDurationMs)}
                  onChange={(e) => setManualActionDurationMs(Number(e.target.value))}
                  className="input-field w-full"
                >
                  {ACTION_DURATION_PRESETS.map((preset) => (
                    <option key={preset.label} value={preset.value}>
                      {preset.label}
                    </option>
                  ))}
                </select>
              </div>
              {selectedManualAction ? (
                <div className="mt-2 rounded border border-ink-800 bg-ink-900/40 px-3 py-2 text-xs text-ink-300">
                  <div className="font-medium text-ink-100">{selectedManualAction.label}</div>
                  <div>{selectedManualAction.description}</div>
                  <div className="mt-1 flex flex-wrap gap-2">
                    <span className="badge-info">mode:{selectedManualAction.execution_mode}</span>
                    <span className="badge-info">clear:{selectedManualAction.clear_supported ? "supported" : "expiry only"}</span>
                    {selectedManualAction.requires_targets ? <span className="badge-info">targets:required</span> : null}
                    <span className="badge-info">default:{humanDuration(selectedManualAction.default_duration_ms)}</span>
                  </div>
                  {!selectedManualAction.available ? (
                    <div className="mt-2 rounded border border-amber-700/50 bg-amber-950/20 px-2 py-1 text-amber-100">
                      {selectedManualAction.unavailable_reason || "This action is not available for this incident."}
                    </div>
                  ) : null}
                </div>
              ) : null}
              {selectedManualAction?.requires_targets ? (
                <ResponseTargetBuilder
                  title="Explicit block targets"
                  description="Add one or more IPs, CIDRs, DNS names, or hostnames. The endpoint will block only the targets you enter."
                  targets={manualActionTargets}
                  onChange={setManualActionTargets}
                  disabled={actionBusy}
                />
              ) : null}
              {(responseActions?.available_actions || []).length > 0 ? (
                <div className="mt-2 grid gap-2 lg:grid-cols-2">
                  {(responseActions?.available_actions || []).map((item) => (
                    <div
                      key={item.id}
                      className={`rounded border px-3 py-2 text-xs ${item.id === selectedManualAction?.id ? "border-cyan-600 bg-cyan-950/20" : "border-ink-800 bg-ink-900/40"}`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="font-medium text-ink-100">{item.label}</div>
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.22em] ${responseActionEligibilityTone(item.available)}`}>
                          {item.available ? "Eligible" : "Not Eligible"}
                        </span>
                      </div>
                      <div className="mt-1 text-ink-300">{item.description}</div>
                      {!item.available && item.unavailable_reason ? (
                        <div className="mt-2 text-amber-100">{item.unavailable_reason}</div>
                      ) : null}
                    </div>
                  ))}
                </div>
              ) : null}
              <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                <input
                  value={manualActionReference}
                  onChange={(e) => setManualActionReference(e.target.value)}
                  className="input-field mt-2 w-full"
                  placeholder="change / case reference"
                />
                <input
                  value={manualActionReason}
                  onChange={(e) => setManualActionReason(e.target.value)}
                  className="input-field mt-2 w-full"
                  placeholder="operator reason"
                />
              </div>
              <button disabled={actionBusy || !selectedManualAction || !selectedManualAction.available} className="btn-primary mt-2 disabled:opacity-60" onClick={doLaunchManualAction}>
                Launch Action
              </button>
            </div>

            {(["pending", "active", "cleared", "expired", "failed"] as const).map((bucket) => (
              <div key={bucket} className="rounded border border-ink-800 p-3">
                <h4 className="mb-2 text-sm font-semibold capitalize">{bucket} Actions</h4>
                {(actionGroups[bucket] || []).length === 0 ? (
                  <p className="text-xs text-ink-400">No {bucket} actions for this incident.</p>
                ) : (
                  <div className="space-y-2">
                    {(actionGroups[bucket] || []).map((item) => (
                      <div key={item.action_id} className={`rounded border px-3 py-2 text-xs ${responseActionTone(item.bucket)}`}>
                        <div className="flex items-start justify-between gap-2">
                        <div>
                            <div className="font-medium">{item.label}</div>
                            <div className="text-ink-300">
                              {item.target || run?.node_id || "-"} • {item.action_type}
                              {item.execution_mode ? ` • ${item.execution_mode}` : ""}
                            </div>
                            {Array.isArray(item.targets) && item.targets.length > 0 ? (
                              <div className="mt-1 text-ink-400">
                                targets: {item.targets
                                  .map((target) => [target.kind, target.value, target.port ? `:${target.port}` : "", target.protocol ? `/${target.protocol}` : ""].join(""))
                                  .join(", ")}
                              </div>
                            ) : null}
                          </div>
                          <span className="rounded border border-current/40 px-2 py-0.5 uppercase tracking-[0.24em]">{item.status}</span>
                        </div>
                        <div className="mt-2 grid grid-cols-1 gap-1 md:grid-cols-2">
                          <div>actor: {item.actor || "-"}</div>
                          <div>duration: {humanDuration(item.duration_ms)}</div>
                          <div>started: {item.started_at_unix_ms ? unixMsToLocal(item.started_at_unix_ms) : "-"}</div>
                          <div>expires: {item.expires_at_unix_ms ? unixMsToLocal(item.expires_at_unix_ms) : "-"}</div>
                          {item.reason ? <div className="md:col-span-2">reason: {item.reason}</div> : null}
                          {item.status_detail ? <div className="md:col-span-2">detail: {item.status_detail}</div> : null}
                        </div>
                        {item.clear_supported && item.bucket === "active" ? (
                          <button disabled={actionBusy} className="btn-secondary mt-2 disabled:opacity-60" onClick={() => doClearManualAction(item.action_id)}>
                            Clear Action
                          </button>
                        ) : null}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
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
