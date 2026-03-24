"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  applyModelProposal,
  approveModelProposal,
  getModelDetail,
  getModelProposals,
  getModels,
  me,
  proposeModelChange,
  rejectModelProposal,
  validateModelChange
} from "@/lib/api";
import {
  AuthUser,
  ModelCatalogItem,
  ModelDetailResponse,
  ModelEditorCurrent,
  ModelEditorPatch,
  ModelProposal,
  ModelRestartTarget,
  ModelValidationResponse
} from "@/lib/types";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui";

type DiffRow = { field: string; label: string; current: string; next: string };

const FIELD_LABELS: Record<string, string> = {
  enabled: "Enabled",
  severity: "Severity",
  group_by: "Group By",
  window_ms: "Window (ms)",
  threshold: "Threshold",
  approval_mode: "Approval Mode",
  max_blast_radius: "Max Blast Radius",
  auto_min_confidence: "Auto Min Confidence",
  auto_max_blast_radius: "Auto Max Blast Radius",
  auto_max_severity: "Auto Max Severity",
  require_approval_for_privileged: "Approval For Privileged",
  require_approval_for_local_src: "Approval For Local Source",
  require_identity_context: "Require Identity Context",
  default_containment_duration_ms: "Default Containment (ms)",
  max_containment_duration_ms: "Max Containment (ms)",
  required: "Required",
  reason: "Reason"
};

function modelKey(item: { kind: string; id: string }): string {
  return `${item.kind}:${item.id}`;
}

function boolValue(value?: boolean | null): string {
  if (value === undefined || value === null) return "inherit";
  return value ? "true" : "false";
}

function parseBoolInput(value: string): boolean | undefined {
  if (value === "true") return true;
  if (value === "false") return false;
  return undefined;
}

function parseNumberInput(value: string): number | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const parsed = Number(trimmed);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function patchFromCurrent(detail: ModelDetailResponse): ModelEditorPatch {
  const current = detail.current || {};
  return {
    enabled: current.enabled,
    severity: current.severity || undefined,
    group_by: current.group_by || undefined,
    window_ms: current.window_ms,
    threshold: current.threshold,
    approval_mode: current.approval_mode || undefined,
    max_blast_radius: current.max_blast_radius,
    auto_min_confidence: current.auto_min_confidence,
    auto_max_blast_radius: current.auto_max_blast_radius,
    auto_max_severity: current.auto_max_severity || undefined,
    require_approval_for_privileged: current.require_approval_for_privileged,
    require_approval_for_local_src: current.require_approval_for_local_src,
    require_identity_context: current.require_identity_context,
    default_containment_duration_ms: current.default_containment_duration_ms,
    max_containment_duration_ms: current.max_containment_duration_ms,
    required: current.required,
    reason: current.reason || undefined
  };
}

function proposalLabel(item: ModelProposal): string {
  return `${item.kind}:${item.model_id}`;
}

function proposalStatusTone(status: string): string {
  const value = (status || "").toLowerCase();
  if (value === "applied") return "badge-good";
  if (value === "approved") return "badge-info";
  if (value === "pending_approval") return "badge-warn";
  if (value === "rejected") return "badge-bad";
  return "badge";
}

function formatModelValue(value: unknown): string {
  if (value === undefined || value === null || value === "") return "-";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "-";
  return String(value);
}

function diffRowsFromCurrent(current: ModelEditorCurrent, draft: ModelEditorPatch, editableFields: string[]): DiffRow[] {
  const rows: DiffRow[] = [];
  for (const field of editableFields) {
    const currentValue = (current as Record<string, unknown>)[field];
    const nextValue = (draft as Record<string, unknown>)[field];
    if (formatModelValue(currentValue) === formatModelValue(nextValue)) continue;
    rows.push({
      field,
      label: FIELD_LABELS[field] || field,
      current: formatModelValue(currentValue),
      next: formatModelValue(nextValue)
    });
  }
  return rows;
}

function diffRowsFromPatch(patch: ModelEditorPatch): DiffRow[] {
  return Object.entries(patch)
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .map(([field, value]) => ({
      field,
      label: FIELD_LABELS[field] || field,
      current: "current",
      next: formatModelValue(value)
    }));
}

function mergeRestartTargets(...sets: Array<ModelRestartTarget[] | undefined>): ModelRestartTarget[] {
  const byID = new Map<string, ModelRestartTarget>();
  for (const items of sets) {
    for (const item of items || []) {
      if (!item?.id) continue;
      byID.set(item.id, item);
    }
  }
  return Array.from(byID.values()).sort((a, b) => a.label.localeCompare(b.label));
}

function FieldDiffTable({ rows, emptyMessage }: { rows: DiffRow[]; emptyMessage: string }) {
  if (rows.length === 0) {
    return <p className="text-sm text-ink-300">{emptyMessage}</p>;
  }
  return (
    <div className="overflow-auto rounded-lg border border-ink-800 bg-ink-950/70">
      <table className="min-w-full text-sm">
        <thead className="border-b border-ink-800 bg-ink-950/90 text-xs uppercase tracking-[0.22em] text-ink-400">
          <tr>
            <th className="px-3 py-2 text-left">Field</th>
            <th className="px-3 py-2 text-left">Current</th>
            <th className="px-3 py-2 text-left">Next</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.field} className="border-b border-ink-900/70 last:border-b-0">
              <td className="px-3 py-2 text-ink-100">{row.label}</td>
              <td className="px-3 py-2 text-ink-300">{row.current}</td>
              <td className="px-3 py-2 font-medium text-cyan-200">{row.next}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RestartTargetPicker({
  targets,
  selected,
  onToggle
}: {
  targets: ModelRestartTarget[];
  selected: string[];
  onToggle: (id: string) => void;
}) {
  if (targets.length === 0) {
    return <p className="text-sm text-ink-300">No UI-managed restart targets are available.</p>;
  }
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {targets.map((target) => {
        const checked = selected.includes(target.id);
        return (
          <label key={target.id} className="flex items-start gap-3 rounded-xl border border-ink-800 bg-ink-950/40 px-3 py-3 text-sm text-ink-200">
            <input type="checkbox" className="mt-1" checked={checked} onChange={() => onToggle(target.id)} />
            <span>
              <span className="block font-medium text-white">{target.label}</span>
              {target.description ? <span className="mt-1 block text-xs text-ink-400">{target.description}</span> : null}
            </span>
          </label>
        );
      })}
    </div>
  );
}

function RestartTargetStatusPanel({ targets }: { targets: ModelRestartTarget[] }) {
  if (targets.length === 0) {
    return <p className="text-sm text-ink-300">No UI-managed restart targets are available.</p>;
  }
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {targets.map((target) => {
        const status = (target.status || "unknown").toLowerCase();
        const tone =
          status === "running"
            ? "badge-good"
            : status === "missing_pid"
              ? "badge"
              : "badge-bad";
        return (
          <div key={target.id} className="rounded-xl border border-ink-800 bg-ink-950/40 px-3 py-3 text-sm">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="font-medium text-white">{target.label}</p>
                {target.description ? <p className="mt-1 text-xs text-ink-400">{target.description}</p> : null}
              </div>
              <span className={tone}>{status}</span>
            </div>
            <div className="mt-3 space-y-1 text-xs text-ink-300">
              <p>running: {target.running ? "yes" : "no"}</p>
              <p>pid: {target.pid || "-"}</p>
              <p>pid file: {target.pid_file || "-"}</p>
              <p>log file: {target.log_file || "-"}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function ModelTextField({
  label,
  value,
  onChange,
  placeholder
}: {
  label: string;
  value?: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="flex flex-col gap-2 text-xs uppercase tracking-[0.22em] text-ink-300">
      <span>{label}</span>
      <input
        className="rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 text-sm normal-case tracking-normal text-ink-100 outline-none transition focus:border-cyan-400"
        value={value || ""}
        placeholder={placeholder || label}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}

function ModelNumberField({
  label,
  value,
  onChange,
  placeholder
}: {
  label: string;
  value?: number;
  onChange: (value: number | undefined) => void;
  placeholder?: string;
}) {
  return (
    <label className="flex flex-col gap-2 text-xs uppercase tracking-[0.22em] text-ink-300">
      <span>{label}</span>
      <input
        className="rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 text-sm normal-case tracking-normal text-ink-100 outline-none transition focus:border-cyan-400"
        value={value ?? ""}
        placeholder={placeholder || label}
        onChange={(e) => onChange(parseNumberInput(e.target.value))}
      />
    </label>
  );
}

function ModelBoolField({
  label,
  value,
  onChange
}: {
  label: string;
  value?: boolean;
  onChange: (value: boolean | undefined) => void;
}) {
  return (
    <label className="flex flex-col gap-2 text-xs uppercase tracking-[0.22em] text-ink-300">
      <span>{label}</span>
      <select
        className="rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 text-sm normal-case tracking-normal text-ink-100 outline-none transition focus:border-cyan-400"
        value={boolValue(value)}
        onChange={(e) => onChange(parseBoolInput(e.target.value))}
      >
        <option value="inherit">inherit current</option>
        <option value="true">true</option>
        <option value="false">false</option>
      </select>
    </label>
  );
}

export default function ModelsPage() {
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [catalog, setCatalog] = useState<ModelCatalogItem[]>([]);
  const [proposals, setProposals] = useState<ModelProposal[]>([]);
  const [selectedKey, setSelectedKey] = useState("");
  const [detail, setDetail] = useState<ModelDetailResponse | null>(null);
  const [draft, setDraft] = useState<ModelEditorPatch>({});
  const [summary, setSummary] = useState("");
  const [validation, setValidation] = useState<ModelValidationResponse | null>(null);
  const [restartTargets, setRestartTargets] = useState<ModelRestartTarget[]>([]);
  const [selectedRestartTargets, setSelectedRestartTargets] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [lastStatusRefreshTs, setLastStatusRefreshTs] = useState<number>(Date.now());

  const selectedCatalogItem = useMemo(
    () => catalog.find((item) => modelKey(item) === selectedKey) || null,
    [catalog, selectedKey]
  );

  const loadCatalog = useCallback(async () => {
    const [meRes, catalogRes, proposalsRes] = await Promise.all([me(), getModels(), getModelProposals()]);
    setAuthUser(meRes.user);
    setCatalog(catalogRes.items || []);
    setProposals(proposalsRes.items || []);
    setRestartTargets(mergeRestartTargets(catalogRes.restart_targets, proposalsRes.restart_targets));
    setLastStatusRefreshTs(Date.now());
    setSelectedKey((prev) => {
      if (prev && (catalogRes.items || []).some((item) => modelKey(item) === prev)) return prev;
      return catalogRes.items?.length ? modelKey(catalogRes.items[0]) : "";
    });
  }, []);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    setError(null);
    loadCatalog()
      .catch((e) => {
        if (!mounted) return;
        setError((e as Error).message || String(e));
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [loadCatalog]);

  useEffect(() => {
    if (!selectedKey) {
      setDetail(null);
      setDraft({});
      setValidation(null);
      return;
    }
    const nextSelected = catalog.find((item) => modelKey(item) === selectedKey) || null;
    if (!nextSelected) {
      setDetail(null);
      setDraft({});
      setValidation(null);
      return;
    }
    let mounted = true;
    setDetailLoading(true);
    setValidation(null);
    getModelDetail(nextSelected.kind, nextSelected.id)
      .then((res) => {
        if (!mounted) return;
        setDetail(res);
        setDraft(patchFromCurrent(res));
        setRestartTargets((prev) => mergeRestartTargets(prev, res.restart_targets));
      })
      .catch((e) => {
        if (!mounted) return;
        setError((e as Error).message || String(e));
      })
      .finally(() => {
        if (mounted) setDetailLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [selectedKey]);

  useEffect(() => {
    if (!selectedKey) return;
    if (catalog.some((item) => modelKey(item) === selectedKey)) return;
    setDetail(null);
    setDraft({});
    setValidation(null);
  }, [catalog, selectedKey]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (document.hidden || loading || actionLoading) return;
      void loadCatalog().catch(() => {});
    }, 15000);
    return () => window.clearInterval(timer);
  }, [actionLoading, loadCatalog, loading]);

  const updateDraft = useCallback((partial: Partial<ModelEditorPatch>) => {
    setDraft((prev) => ({ ...prev, ...partial }));
  }, []);

  const toggleRestartTarget = useCallback((id: string) => {
    setSelectedRestartTargets((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
  }, []);

  const refreshSelectedDetail = useCallback(async () => {
    if (!selectedCatalogItem) return;
    const refreshed = await getModelDetail(selectedCatalogItem.kind, selectedCatalogItem.id);
    setDetail(refreshed);
    setDraft(patchFromCurrent(refreshed));
    setRestartTargets((prev) => mergeRestartTargets(prev, refreshed.restart_targets));
  }, [selectedCatalogItem]);

  const validateDraft = useCallback(async () => {
    if (!detail) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await validateModelChange(detail.kind, detail.id, draft, summary);
      setValidation(res);
      setToast(res.ok ? "Validation passed" : "Validation failed");
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setActionLoading(false);
    }
  }, [detail, draft, summary]);

  const proposeDraft = useCallback(async () => {
    if (!detail) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await proposeModelChange(detail.kind, detail.id, draft, summary);
      setToast(`Proposal created: ${res.proposal_id}`);
      setSummary("");
      setValidation(null);
      await loadCatalog();
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setActionLoading(false);
    }
  }, [detail, draft, summary, loadCatalog]);

  const approveProposal = useCallback(async (proposalId: string) => {
    setActionLoading(true);
    setError(null);
    try {
      const res = await approveModelProposal(proposalId);
      setToast(`Proposal ${res.status}: ${res.proposal_id}`);
      await loadCatalog();
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setActionLoading(false);
    }
  }, [loadCatalog]);

  const rejectProposal = useCallback(async (proposalId: string) => {
    setActionLoading(true);
    setError(null);
    try {
      const res = await rejectModelProposal(proposalId);
      setToast(`Proposal ${res.status}: ${res.proposal_id}`);
      await loadCatalog();
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setActionLoading(false);
    }
  }, [loadCatalog]);

  const applyProposal = useCallback(async (proposalId: string) => {
    setActionLoading(true);
    setError(null);
    try {
      const res = await applyModelProposal(proposalId, selectedRestartTargets);
      const restartSummary = (res.restart_results || []).length
        ? `; restarted ${res.restart_results?.filter((item) => item.ok).length}/${res.restart_results?.length}`
        : "";
      setToast(`Proposal applied: ${res.proposal_id}${restartSummary}`);
      await loadCatalog();
      await refreshSelectedDetail();
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setActionLoading(false);
    }
  }, [loadCatalog, refreshSelectedDetail, selectedRestartTargets]);

  const openProposalCount = proposals.filter((item) => item.status === "pending_approval" || item.status === "approved").length;
  const diffRows = useMemo(
    () => (detail ? diffRowsFromCurrent(detail.current, draft, detail.editable_fields || []) : []),
    [detail, draft]
  );

  const refreshStatusPanel = useCallback(async () => {
    setActionLoading(true);
    setError(null);
    try {
      await loadCatalog();
      setToast("Restart target status refreshed");
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setActionLoading(false);
    }
  }, [loadCatalog]);

  if (loading) {
    return (
      <section className="flex h-full min-h-0 flex-col gap-4">
        <LoadingState />
      </section>
    );
  }

  if (error && !detail && catalog.length === 0) {
    return (
      <section className="flex h-full min-h-0 flex-col gap-4">
        <ErrorState message={error} />
      </section>
    );
  }

  if (authUser?.role !== "admin") {
    return (
      <section className="flex h-full min-h-0 flex-col gap-4">
        <EmptyState title="Admin Access Required" detail="Model editing is restricted to admin users because it changes detection and response behavior." />
      </section>
    );
  }

  return (
    <section className="flex h-full min-h-0 flex-col gap-4">
      {toast ? (
        <div className="fixed right-6 top-6 z-50 rounded-lg border border-cyan-700/60 bg-cyan-950/85 px-4 py-3 text-sm text-cyan-100 shadow-lg">
          {toast}
        </div>
      ) : null}

      <div className="rounded-2xl border border-ink-800 bg-panel px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-[0.28em] text-cyan-300">Admin Workspace</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">Model Editor</h1>
            <p className="mt-2 max-w-3xl text-sm text-ink-300">
              Controlled configuration management for rules, playbooks, and approval policies. Proposals require separate approval, changes are audit logged,
              and only bounded repo-side restarts are exposed from the UI.
            </p>
          </div>
          <div className="flex flex-col gap-2 text-right text-xs text-ink-300">
            <span>{catalog.length} editable models</span>
            <span>{openProposalCount} open proposals</span>
            <span className="rounded-full border border-amber-600/40 bg-amber-950/40 px-3 py-1 text-amber-200">
              Runtime daemons do not hot reload. Apply writes config; restart is explicit and bounded.
            </span>
          </div>
        </div>
      </div>

      {error ? <ErrorState message={error} /> : null}

      <div className="grid min-h-0 gap-4 xl:grid-cols-[320px_minmax(0,1fr)_380px]">
        <aside className="flex min-h-[52rem] flex-col rounded-2xl border border-ink-800 bg-panel">
          <div className="border-b border-ink-800 px-4 py-3">
            <h2 className="text-sm font-semibold text-white">Editable Models</h2>
            <p className="mt-1 text-xs text-ink-300">Rules, playbooks, and approval rules sourced from `configs/master.yaml`.</p>
          </div>
          <div className="flex-1 overflow-auto p-3">
            {catalog.length === 0 ? (
              <EmptyState title="No models found" detail="The UI API did not load any editable rule, playbook, or approval definitions." />
            ) : (
              <div className="flex flex-col gap-2">
                {catalog.map((item) => {
                  const active = modelKey(item) === selectedKey;
                  return (
                    <button
                      key={modelKey(item)}
                      className={`rounded-xl border px-3 py-3 text-left transition ${
                        active ? "border-cyan-500 bg-cyan-950/30" : "border-ink-800 bg-ink-950/40 hover:border-ink-600"
                      }`}
                      onClick={() => setSelectedKey(modelKey(item))}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="text-sm font-semibold text-white">{item.title}</p>
                          <p className="mt-1 text-xs uppercase tracking-[0.22em] text-ink-400">{item.kind}</p>
                        </div>
                        <span className={item.enabled ? "badge-good" : "badge-bad"}>{item.enabled ? "enabled" : "disabled"}</span>
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2 text-xs text-ink-300">
                        {item.severity ? <span className="rounded-full border border-ink-700 px-2 py-1">severity {item.severity}</span> : null}
                        {item.approval_mode ? <span className="rounded-full border border-ink-700 px-2 py-1">approval {item.approval_mode}</span> : null}
                        {item.pending_proposals ? <span className="rounded-full border border-amber-600/30 px-2 py-1 text-amber-200">{item.pending_proposals} open</span> : null}
                      </div>
                      {item.summary ? <p className="mt-3 text-xs text-ink-400">{item.summary}</p> : null}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </aside>

        <main className="flex min-h-[52rem] flex-col rounded-2xl border border-ink-800 bg-panel">
          <div className="border-b border-ink-800 px-4 py-3">
            <h2 className="text-sm font-semibold text-white">Change Workspace</h2>
            <p className="mt-1 text-xs text-ink-300">Stage bounded edits, validate them, then submit a proposal into the approval queue.</p>
          </div>
          <div className="flex-1 overflow-auto p-4">
            {detailLoading ? (
              <LoadingState />
            ) : !detail ? (
              <EmptyState title="Select a model" detail="Choose a rule, playbook, or approval rule from the catalog to inspect and edit." />
            ) : (
              <div className="flex flex-col gap-5">
                <div className="rounded-xl border border-ink-800 bg-ink-950/40 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <p className="text-lg font-semibold text-white">{detail.title}</p>
                      <p className="mt-1 text-xs uppercase tracking-[0.24em] text-ink-400">{detail.kind} • {detail.id}</p>
                    </div>
                    <div className="flex flex-col gap-2 text-right text-xs text-ink-300">
                      <span>Live reload supported: {detail.live_reload_supported ? "yes" : "no"}</span>
                      <span>Effective after restart: {detail.effective_after_restart ? "yes" : "no"}</span>
                    </div>
                  </div>
                  {detail.editable_fields?.length ? (
                    <div className="mt-4 flex flex-wrap gap-2 text-xs text-ink-300">
                      {detail.editable_fields.map((field) => (
                        <span key={field} className="rounded-full border border-ink-700 px-2 py-1">{FIELD_LABELS[field] || field}</span>
                      ))}
                    </div>
                  ) : null}
                </div>

                <div className="grid gap-4 lg:grid-cols-2">
                  <div className="rounded-xl border border-ink-800 bg-ink-950/30 p-4">
                    <h3 className="text-sm font-semibold text-white">Current Values</h3>
                    <div className="mt-3 grid gap-2 text-sm">
                      {(detail.editable_fields || []).map((field) => (
                        <div key={field} className="grid grid-cols-[220px_1fr] gap-2 rounded-lg border border-ink-800 bg-ink-950/60 px-3 py-2">
                          <span className="text-ink-300">{FIELD_LABELS[field] || field}</span>
                          <span className="break-all text-ink-100">{formatModelValue((detail.current as Record<string, unknown>)[field])}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="rounded-xl border border-ink-800 bg-ink-950/30 p-4">
                    <h3 className="text-sm font-semibold text-white">Field-Level Diff</h3>
                    <div className="mt-3">
                      <FieldDiffTable rows={diffRows} emptyMessage="No staged changes relative to current values." />
                    </div>
                  </div>
                </div>

                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {detail.kind === "rule" ? (
                    <>
                      <ModelBoolField label="Enabled" value={draft.enabled} onChange={(value) => updateDraft({ enabled: value })} />
                      <ModelTextField label="Severity" value={draft.severity} onChange={(value) => updateDraft({ severity: value || undefined })} placeholder="critical|high|medium|low|info" />
                      <ModelTextField label="Group By" value={draft.group_by} onChange={(value) => updateDraft({ group_by: value || undefined })} />
                      <ModelNumberField label="Window Ms" value={draft.window_ms} onChange={(value) => updateDraft({ window_ms: value })} />
                      <ModelNumberField label="Threshold" value={draft.threshold} onChange={(value) => updateDraft({ threshold: value })} />
                    </>
                  ) : null}

                  {detail.kind === "playbook" ? (
                    <>
                      <ModelBoolField label="Enabled" value={draft.enabled} onChange={(value) => updateDraft({ enabled: value })} />
                      <ModelTextField label="Approval Mode" value={draft.approval_mode} onChange={(value) => updateDraft({ approval_mode: value || undefined })} placeholder="auto|required|required_for_high|required_for_critical" />
                      <ModelNumberField label="Max Blast Radius" value={draft.max_blast_radius} onChange={(value) => updateDraft({ max_blast_radius: value })} />
                      <ModelNumberField label="Auto Min Confidence" value={draft.auto_min_confidence} onChange={(value) => updateDraft({ auto_min_confidence: value })} />
                      <ModelNumberField label="Auto Max Blast Radius" value={draft.auto_max_blast_radius} onChange={(value) => updateDraft({ auto_max_blast_radius: value })} />
                      <ModelTextField label="Auto Max Severity" value={draft.auto_max_severity} onChange={(value) => updateDraft({ auto_max_severity: value || undefined })} placeholder="critical|high|medium|low|info" />
                      <ModelBoolField label="Approval For Privileged" value={draft.require_approval_for_privileged} onChange={(value) => updateDraft({ require_approval_for_privileged: value })} />
                      <ModelBoolField label="Approval For Local Src" value={draft.require_approval_for_local_src} onChange={(value) => updateDraft({ require_approval_for_local_src: value })} />
                      <ModelBoolField label="Require Identity Context" value={draft.require_identity_context} onChange={(value) => updateDraft({ require_identity_context: value })} />
                      <ModelNumberField label="Default Containment Ms" value={draft.default_containment_duration_ms} onChange={(value) => updateDraft({ default_containment_duration_ms: value })} />
                      <ModelNumberField label="Max Containment Ms" value={draft.max_containment_duration_ms} onChange={(value) => updateDraft({ max_containment_duration_ms: value })} />
                    </>
                  ) : null}

                  {detail.kind === "approval_rule" ? (
                    <>
                      <ModelBoolField label="Required" value={draft.required} onChange={(value) => updateDraft({ required: value })} />
                      <ModelTextField label="Reason" value={draft.reason} onChange={(value) => updateDraft({ reason: value || undefined })} placeholder="human-readable policy reason" />
                    </>
                  ) : null}
                </div>

                <div className="rounded-xl border border-ink-800 bg-ink-950/30 p-4">
                  <label className="flex flex-col gap-2 text-xs uppercase tracking-[0.22em] text-ink-300">
                    <span>Change Summary</span>
                    <textarea
                      className="min-h-[7rem] rounded-lg border border-ink-700 bg-ink-950 px-3 py-3 text-sm normal-case tracking-normal text-ink-100 outline-none transition focus:border-cyan-400"
                      value={summary}
                      placeholder="Explain why this change is needed, what risk it reduces, and what should be observed after restart."
                      onChange={(e) => setSummary(e.target.value)}
                    />
                  </label>
                  <div className="mt-4 flex flex-wrap gap-3">
                    <button className="btn-secondary px-4 py-2 text-sm" disabled={actionLoading} onClick={() => setDraft(patchFromCurrent(detail))}>
                      Reset To Current
                    </button>
                    <button className="btn-secondary px-4 py-2 text-sm" disabled={actionLoading} onClick={() => void validateDraft()}>
                      Validate Change
                    </button>
                    <button className="btn-primary px-4 py-2 text-sm" disabled={actionLoading} onClick={() => void proposeDraft()}>
                      Create Proposal
                    </button>
                  </div>
                </div>

                <div className="rounded-xl border border-ink-800 bg-ink-950/30 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h3 className="text-sm font-semibold text-white">Restart Target Status</h3>
                      <p className="mt-1 text-xs text-ink-300">Live backend view of repo-side daemons that the UI is allowed to restart.</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-ink-400">Last refresh: {new Date(lastStatusRefreshTs).toLocaleTimeString()}</span>
                      <button className="btn-secondary px-3 py-2 text-sm" disabled={actionLoading} onClick={() => void refreshStatusPanel()}>
                        Refresh Status
                      </button>
                    </div>
                  </div>
                  <div className="mt-4">
                    <RestartTargetStatusPanel targets={restartTargets} />
                  </div>
                </div>

                <div className="rounded-xl border border-ink-800 bg-ink-950/30 p-4">
                  <h3 className="text-sm font-semibold text-white">Optional Repo-Side Restarts</h3>
                  <p className="mt-1 text-xs text-ink-300">These are the only daemons the UI may restart: repo-side `master-roe`, `master-roe-worker`, `detector-v0`, and `investigation-enricher`.</p>
                  <div className="mt-4">
                    <RestartTargetPicker targets={restartTargets} selected={selectedRestartTargets} onToggle={toggleRestartTarget} />
                  </div>
                </div>

                {validation ? (
                  <div className="rounded-xl border border-ink-800 bg-ink-950/30 p-4">
                    <div className="flex items-center justify-between gap-4">
                      <h3 className="text-sm font-semibold text-white">Validation Result</h3>
                      <span className={validation.ok ? "badge-good" : "badge-bad"}>{validation.ok ? "valid" : "invalid"}</span>
                    </div>
                    {validation.warnings?.length ? (
                      <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-amber-200">
                        {validation.warnings.map((warning) => (
                          <li key={warning}>{warning}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="mt-3 text-sm text-ink-300">No validation warnings.</p>
                    )}
                  </div>
                ) : null}
              </div>
            )}
          </div>
        </main>

        <aside className="flex min-h-[52rem] flex-col rounded-2xl border border-ink-800 bg-panel">
          <div className="border-b border-ink-800 px-4 py-3">
            <h2 className="text-sm font-semibold text-white">Proposal Queue</h2>
            <p className="mt-1 text-xs text-ink-300">Dual-control path: propose, separate approval, then apply with optional repo-side restart targets.</p>
          </div>
          <div className="flex-1 overflow-auto p-3">
            {proposals.length === 0 ? (
              <EmptyState title="No proposals yet" detail="Validated changes will appear here before and after application." />
            ) : (
              <div className="flex flex-col gap-3">
                {proposals.map((proposal) => {
                  const patchRows = diffRowsFromPatch(proposal.changes);
                  const selfProposed = authUser?.username === proposal.actor;
                  return (
                    <div key={proposal.proposal_id} className="rounded-xl border border-ink-800 bg-ink-950/40 p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="text-sm font-semibold text-white">{proposalLabel(proposal)}</p>
                          <p className="mt-1 text-xs text-ink-400">{proposal.proposal_id}</p>
                        </div>
                        <span className={proposalStatusTone(proposal.status)}>{proposal.status}</span>
                      </div>
                      <div className="mt-3 space-y-1 text-xs text-ink-300">
                        <p>proposed by: {proposal.actor}</p>
                        <p>created: {new Date(proposal.created_at).toLocaleString()}</p>
                        {proposal.approved_at ? <p>approved: {new Date(proposal.approved_at).toLocaleString()} by {proposal.approved_by || "-"}</p> : null}
                        {proposal.rejected_at ? <p>rejected: {new Date(proposal.rejected_at).toLocaleString()} by {proposal.rejected_by || "-"}</p> : null}
                        {proposal.applied_at ? <p>applied: {new Date(proposal.applied_at).toLocaleString()} by {proposal.applied_by || "-"}</p> : null}
                        <p>effective after restart: {proposal.effective_after_restart ? "yes" : "no"}</p>
                      </div>
                      {proposal.summary ? <p className="mt-3 text-sm text-ink-200">{proposal.summary}</p> : null}
                      {proposal.warnings?.length ? (
                        <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-amber-200">
                          {proposal.warnings.map((warning) => (
                            <li key={warning}>{warning}</li>
                          ))}
                        </ul>
                      ) : null}
                      <div className="mt-3">
                        <FieldDiffTable rows={patchRows} emptyMessage="No field-level changes captured." />
                      </div>
                      {proposal.restart_results?.length ? (
                        <div className="mt-3 rounded-lg border border-ink-800 bg-ink-950/60 p-3 text-xs text-ink-300">
                          <p className="font-medium text-white">Restart Results</p>
                          <div className="mt-2 space-y-1">
                            {proposal.restart_results.map((result) => (
                              <p key={result.target}>
                                {result.target}: {result.ok ? `restarted pid=${result.pid || "-"}` : `failed (${result.error || "unknown error"})`}
                              </p>
                            ))}
                          </div>
                        </div>
                      ) : null}
                      <div className="mt-3 flex flex-wrap items-center gap-2">
                        {proposal.status === "pending_approval" && !selfProposed ? (
                          <>
                            <button className="btn-primary px-3 py-2 text-sm" disabled={actionLoading} onClick={() => void approveProposal(proposal.proposal_id)}>
                              Approve
                            </button>
                            <button className="btn-secondary px-3 py-2 text-sm" disabled={actionLoading} onClick={() => void rejectProposal(proposal.proposal_id)}>
                              Reject
                            </button>
                          </>
                        ) : null}
                        {proposal.status === "pending_approval" && selfProposed ? (
                          <span className="text-xs text-amber-200">Dual control required. Another admin must approve this proposal.</span>
                        ) : null}
                        {proposal.status === "approved" ? (
                          <>
                            <button className="btn-primary px-3 py-2 text-sm" disabled={actionLoading} onClick={() => void applyProposal(proposal.proposal_id)}>
                              Apply Approved Proposal
                            </button>
                            <button className="btn-secondary px-3 py-2 text-sm" disabled={actionLoading} onClick={() => void rejectProposal(proposal.proposal_id)}>
                              Reject Instead
                            </button>
                          </>
                        ) : null}
                        {proposal.backup_path ? <span className="text-xs text-ink-400">backup: {proposal.backup_path}</span> : null}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </aside>
      </div>
    </section>
  );
}
