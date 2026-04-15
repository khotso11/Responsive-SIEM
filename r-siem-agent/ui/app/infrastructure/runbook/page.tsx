"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { getInfrastructureTopology } from "@/lib/api";
import { EmptyState, ErrorState, LoadingState, unixMsToLocal } from "@/components/ui";
import type { InfrastructureTopologyResponse } from "@/lib/types";

export default function InfrastructureRunbookPage() {
  const [data, setData] = useState<InfrastructureTopologyResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await getInfrastructureTopology());
    } catch (err) {
      setError((err as Error).message || String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading) return <LoadingState />;
  if (error) return <ErrorState message={error} />;
  if (!data) return <EmptyState title="No runbook data" detail="The topology API returned no runbook context." />;

  return (
    <section className="flex h-full min-h-0 flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-[11px] uppercase tracking-[0.24em] text-cyan-300">Operations Runbook</div>
          <h2 className="mt-1 text-[24px] font-semibold tracking-tight">EVE-NG Bring-up and Demonstration Sequence</h2>
          <p className="mt-1 max-w-4xl text-[13px] text-ink-300">
            This page is the operator checklist for the live EVE-NG session. It shows which lab is expected, how to bring devices up, and which verifier commands to run while the topology and incident views are open.
          </p>
        </div>
        <div className="flex flex-wrap gap-2 text-xs">
          <Link className="btn-secondary px-3 py-2 text-xs" href="/infrastructure/topology">Open Topology</Link>
          <Link className="btn-secondary px-3 py-2 text-xs" href="/search?category=infrastructure">Search Infrastructure</Link>
          <button className="btn-secondary px-3 py-2 text-xs" onClick={() => void load()}>Refresh</button>
        </div>
      </div>

      <div className="panel-elevated p-4">
        <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">Provider</div>
        <div className="mt-3 grid gap-3 lg:grid-cols-4">
          <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
            <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Lab</div>
            <div className="mt-1 text-sm font-semibold text-ink-100">{data.provider.name || data.lab.id}</div>
          </div>
          <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
            <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">EVE UI</div>
            <div className="mt-1 break-all text-sm text-ink-100">{data.provider.ui_url || "-"}</div>
          </div>
          <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
            <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Runtime status</div>
            <div className="mt-1 text-sm text-ink-100">{data.provider.runtime_status || "-"}</div>
          </div>
          <div className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
            <div className="text-[10px] uppercase tracking-[0.18em] text-ink-500">Last sync</div>
            <div className="mt-1 text-sm text-ink-100">{unixMsToLocal(data.provider.runtime_last_sync_unix_ms)}</div>
          </div>
        </div>
        <div className="mt-3 rounded-2xl border border-ink-800 bg-ink-950/20 p-3 text-sm text-ink-300">
          Set on the host running `ui-api`: <span className="font-mono text-ink-100">RSIEM_EVE_NG_USERNAME</span> and <span className="font-mono text-ink-100">RSIEM_EVE_NG_PASSWORD</span>.
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <div className="panel-elevated p-4">
          <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">Bring-up order</div>
          <div className="mt-4 grid gap-3">
            {data.startup.map((step) => (
              <div key={`${step.order}-${step.device_id}`} className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold text-ink-100">{step.order}. {step.device_id}</div>
                    <div className="mt-1 text-[11px] uppercase tracking-[0.18em] text-ink-400">{step.device_type || "device"}{step.eve_node_name ? ` • eve ${step.eve_node_name}` : ""}</div>
                  </div>
                  {step.image ? <span className="rounded border border-ink-700/70 bg-ink-900/60 px-2 py-1 text-[11px] text-ink-200">{step.image}</span> : null}
                </div>
                {step.boot_command ? <div className="mt-2 text-sm text-ink-200">{step.boot_command}</div> : null}
                {step.validation_hint ? <div className="mt-2 text-xs text-cyan-100">{step.validation_hint}</div> : null}
              </div>
            ))}
          </div>
        </div>

        <div className="panel-elevated p-4">
          <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">Verifier order</div>
          <div className="mt-4 grid gap-3">
            {data.tests.map((test) => (
              <div key={test.id} className="rounded-2xl border border-ink-800 bg-ink-950/20 p-3">
                <div className="text-sm font-semibold text-ink-100">{test.id}</div>
                <div className="mt-1 text-xs text-ink-300">{test.objective}</div>
                <div className="mt-3 rounded border border-ink-800/80 bg-ink-950/40 px-3 py-3 text-[11px] font-mono text-cyan-100">{test.command_hint || "-"}</div>
                <div className="mt-2 text-[11px] text-ink-400">Expected rule: <span className="text-ink-100">{test.expected_rule_id || "-"}</span></div>
                <div className="mt-2 flex flex-wrap gap-2 text-xs">
                  <Link className="btn-secondary px-3 py-2 text-xs" href={`/search?category=infrastructure&rule_id=${encodeURIComponent(test.expected_rule_id || "")}`}>Search pivot</Link>
                  <Link className="btn-secondary px-3 py-2 text-xs" href={`/incidents?category=infrastructure&rule_id=${encodeURIComponent(test.expected_rule_id || "")}`}>Incident queue</Link>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
