"use client";

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { getAudit } from "@/lib/api";
import { AuditEntry } from "@/lib/types";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui";

function parseQueryTime(v: string | null): number | undefined {
  if (!v) return undefined;
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return n;
  const p = Date.parse(v);
  if (!Number.isNaN(p) && p > 0) return p;
  return undefined;
}

export default function AuditPage() {
  const searchParams = useSearchParams();
  const [items, setItems] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState(searchParams.get("gq") || "");
  const fromMs = useMemo(() => parseQueryTime(searchParams.get("gfrom")), [searchParams]);
  const toMs = useMemo(() => parseQueryTime(searchParams.get("gto")), [searchParams]);

  useEffect(() => {
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (fromMs) params.set("from", String(fromMs));
    if (toMs) params.set("to", String(toMs));

    setLoading(true);
    getAudit(params.toString())
      .then((res) => setItems(res.items || []))
      .catch((e) => setError(e.message || String(e)))
      .finally(() => setLoading(false));
  }, [q, fromMs, toMs]);

  useEffect(() => {
    setQ(searchParams.get("gq") || "");
  }, [searchParams]);

  const approvalItems = useMemo(
    () =>
      items.filter((e) => {
        const msg = (e.msg || "").toLowerCase();
        return msg.includes("approval") || msg === "ui_approval_published";
      }),
    [items]
  );
  const enrichedApprovalItems = useMemo(() => {
    const latestReceivedByRun = new Map<string, { actor?: string; decision?: string }>();
    for (const entry of approvalItems) {
      const msg = (entry.msg || "").toLowerCase();
      if (msg !== "approval_received") continue;
      const runID = (entry.run_id || "").trim();
      if (!runID || latestReceivedByRun.has(runID)) continue;
      latestReceivedByRun.set(runID, {
        actor: entry.actor || "",
        decision: entry.decision || ""
      });
    }

    return approvalItems.map((entry) => {
      const msg = (entry.msg || "").toLowerCase();
      if (msg !== "approval_approved") return entry;
      const runID = (entry.run_id || "").trim();
      if (!runID) return entry;
      const latest = latestReceivedByRun.get(runID);
      if (!latest) return entry;
      return {
        ...entry,
        actor: entry.actor || latest.actor || "",
        decision: entry.decision || latest.decision || ""
      };
    });
  }, [approvalItems]);
  const otherItems = useMemo(() => items.filter((e) => !approvalItems.includes(e)), [items, approvalItems]);

  return (
    <section className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Audit Trail</h2>
        <p className="text-sm text-ink-300">Approvals, failed-safe outcomes, and key operator-relevant actions.</p>
      </div>

      <div className="grid grid-cols-1 gap-2 md:grid-cols-[1fr_auto]">
        <input
          className="rounded border border-ink-700 bg-ink-900 px-2 py-2 text-sm"
          placeholder="Search actor/action/run_id/status..."
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <div className="rounded border border-ink-700 bg-ink-900 px-3 py-2 text-xs text-ink-300">
          range: {fromMs ? new Date(fromMs).toLocaleString() : "-"} to {toMs ? new Date(toMs).toLocaleString() : "-"}
        </div>
      </div>

      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {!loading && !error && items.length === 0 ? <EmptyState title="No audit entries" /> : null}

      {!loading && !error && items.length > 0 ? (
        <div className="space-y-4">
          <div className="rounded border border-rose-800/60 bg-rose-950/20 p-3">
            <h3 className="mb-2 text-sm font-semibold text-rose-200">Approval Events ({approvalItems.length})</h3>
            <div className="space-y-2">
              {approvalItems.length === 0 ? <EmptyState title="No approval events in range" /> : null}
              {enrichedApprovalItems.map((e, idx) => (
                <div key={`approval-${e.ts}-${e.run_id || idx}`} className="rounded border border-rose-900/40 bg-ink-950 p-3 text-sm">
                  <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
                    <div className="font-medium">{e.msg}</div>
                    <div className="text-xs text-ink-300">{e.ts}</div>
                  </div>
                  <div className="grid grid-cols-1 gap-1 text-xs md:grid-cols-2">
                    <div>actor: <span className="text-ink-200">{e.actor || "-"}</span></div>
                    <div>run_id: <span className="text-ink-200">{e.run_id || "-"}</span></div>
                    <div>decision: <span className="text-ink-200">{e.decision || "-"}</span></div>
                    <div>status: <span className="text-ink-200">{e.status || "-"}</span></div>
                    <div>source: <span className="text-ink-200">{e.source}</span></div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded border border-ink-800 p-3">
            <h3 className="mb-2 text-sm font-semibold">Other Audit Events ({otherItems.length})</h3>
            <div className="space-y-2">
              {otherItems.length === 0 ? <EmptyState title="No additional audit events in range" /> : null}
              {otherItems.map((e, idx) => (
                <div key={`${e.ts}-${e.run_id || idx}`} className="rounded border border-ink-800 p-3 text-sm">
                  <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
                    <div className="font-medium">{e.msg}</div>
                    <div className="text-xs text-ink-300">{e.ts}</div>
                  </div>
                  <div className="grid grid-cols-1 gap-1 text-xs md:grid-cols-2">
                    <div>actor: <span className="text-ink-200">{e.actor || "-"}</span></div>
                    <div>run_id: <span className="text-ink-200">{e.run_id || "-"}</span></div>
                    <div>decision: <span className="text-ink-200">{e.decision || "-"}</span></div>
                    <div>status: <span className="text-ink-200">{e.status || "-"}</span></div>
                    <div>source: <span className="text-ink-200">{e.source}</span></div>
                  </div>
                  {e.details ? <pre className="mt-2 overflow-auto rounded bg-ink-950 p-2 text-[11px] text-ink-300">{JSON.stringify(e.details, null, 2)}</pre> : null}
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
