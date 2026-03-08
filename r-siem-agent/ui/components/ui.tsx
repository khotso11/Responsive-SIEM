"use client";

import { ReactNode } from "react";

export function StatusBadge({ status }: { status?: string }) {
  const s = (status || "unknown").toUpperCase();
  if (s === "SUCCEEDED") return <span className="badge-good">SUCCEEDED</span>;
  if (s === "FAILED_SAFE") return <span className="badge-bad">FAILED_SAFE</span>;
  if (s === "WAITING_APPROVAL") return <span className="badge-warn">WAITING_APPROVAL</span>;
  if (s === "FAILED_TRANSIENT") return <span className="badge-warn">FAILED_TRANSIENT</span>;
  if (s === "RUNNING") return <span className="badge-info">RUNNING</span>;
  return <span className="badge" style={{ background: "rgba(30,42,68,0.65)", color: "#E7ECFF" }}>{s}</span>;
}

export function LaneBadge({ lane }: { lane?: string }) {
  const l = (lane || "").toUpperCase();
  if (l === "FAST") return <span className="badge-lane-fast">FAST</span>;
  if (l === "STANDARD") return <span className="badge-lane-standard">STANDARD</span>;
  return <span className="badge" style={{ background: "rgba(30,42,68,0.65)", color: "#E7ECFF" }}>N/A</span>;
}

export function EmptyState({ title, detail }: { title: string; detail?: string }) {
  return (
    <div className="rounded-lg border border-dashed border-ink-600 p-6 text-center">
      <p className="text-sm font-medium text-ink-100">{title}</p>
      {detail ? <p className="mt-1 text-xs text-ink-300">{detail}</p> : null}
    </div>
  );
}

export function LoadingState() {
  return <p className="text-sm text-ink-300">Loading...</p>;
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-rose-700/40 bg-rose-950/30 p-3 text-sm text-rose-200">
      {message}
    </div>
  );
}

export function ValueRow({ label, value }: { label: string; value?: ReactNode }) {
  return (
    <div className="grid grid-cols-[160px_1fr] gap-2 text-sm">
      <span className="text-ink-300">{label}</span>
      <span className="text-ink-100 break-all">{value ?? "-"}</span>
    </div>
  );
}

export function unixMsToLocal(v?: number): string {
  if (!v || v <= 0) return "-";
  return new Date(v).toLocaleString();
}
