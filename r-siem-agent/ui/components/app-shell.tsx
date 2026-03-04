"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Activity, Clock3, ListChecks, Search, ShieldCheck, Zap } from "lucide-react";
import { ReactNode, useEffect, useMemo, useState } from "react";
import { getStreamURL } from "@/lib/api";

const NAV = [
  { href: "/incidents", label: "Incidents", icon: ListChecks },
  { href: "/endpoints", label: "Endpoints", icon: Activity },
  { href: "/audit", label: "Audit", icon: ShieldCheck }
];

const RANGE_PRESETS = [
  { value: "15m", label: "Last 15m" },
  { value: "1h", label: "Last 1h" },
  { value: "24h", label: "Last 24h" },
  { value: "7d", label: "Last 7d" },
  { value: "custom", label: "Custom" }
];

function rangeToMs(range: string): number {
  switch (range) {
    case "15m":
      return 15 * 60 * 1000;
    case "1h":
      return 60 * 60 * 1000;
    case "24h":
      return 24 * 60 * 60 * 1000;
    case "7d":
      return 7 * 24 * 60 * 60 * 1000;
    default:
      return 24 * 60 * 60 * 1000;
  }
}

function toLocalInput(v: number): string {
  const d = new Date(v);
  const offset = d.getTimezoneOffset();
  const local = new Date(d.getTime() - offset * 60_000);
  return local.toISOString().slice(0, 16);
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const router = useRouter();

  const [globalQuery, setGlobalQuery] = useState(searchParams.get("gq") || "");
  const [range, setRange] = useState(searchParams.get("grange") || "1h");
  const [customFrom, setCustomFrom] = useState(searchParams.get("gfrom") || "");
  const [customTo, setCustomTo] = useState(searchParams.get("gto") || "");
  const [live, setLive] = useState(searchParams.get("live") !== "0");
  const [mounted, setMounted] = useState(false);
  const [nowMs, setNowMs] = useState(0);
  const [lastRefresh, setLastRefresh] = useState<number>(0);
  const [waitingApprovals, setWaitingApprovals] = useState<number>(0);
  const [streamStatus, setStreamStatus] = useState<"live" | "polling">("polling");

  useEffect(() => {
    const now = Date.now();
    setMounted(true);
    setNowMs(now);
    setLastRefresh(now);
  }, []);

  useEffect(() => {
    setGlobalQuery(searchParams.get("gq") || "");
    setRange(searchParams.get("grange") || "1h");
    setCustomFrom(searchParams.get("gfrom") || "");
    setCustomTo(searchParams.get("gto") || "");
    setLive(searchParams.get("live") !== "0");
  }, [searchParams]);

  useEffect(() => {
    if (!live) {
      setStreamStatus("polling");
      return;
    }
    const ev = new EventSource(getStreamURL());
    let closed = false;
    ev.addEventListener("hint", (raw) => {
      if (closed) return;
      try {
        const parsed = JSON.parse((raw as MessageEvent).data) as { waiting_approvals?: number };
        setWaitingApprovals(parsed.waiting_approvals || 0);
      } catch {
        // ignore parse errors; keep UI functional
      }
      const now = Date.now();
      setNowMs(now);
      setLastRefresh(now);
      setStreamStatus("live");
    });
    ev.onerror = () => {
      setStreamStatus("polling");
    };
    return () => {
      closed = true;
      ev.close();
    };
  }, [live]);

  useEffect(() => {
    if (live && streamStatus === "live") {
      return;
    }
    const t = setInterval(() => {
      const now = Date.now();
      setNowMs(now);
      setLastRefresh(now);
    }, 15_000);
    return () => clearInterval(t);
  }, [live, streamStatus]);

  const applyGlobalControls = () => {
    const params = new URLSearchParams(searchParams.toString());
    if (globalQuery.trim()) {
      params.set("gq", globalQuery.trim());
    } else {
      params.delete("gq");
    }
    params.set("grange", range);
    params.set("live", live ? "1" : "0");
    if (range === "custom") {
      if (customFrom) params.set("gfrom", customFrom);
      else params.delete("gfrom");
      if (customTo) params.set("gto", customTo);
      else params.delete("gto");
    } else {
      const now = Date.now();
      const from = now - rangeToMs(range);
      params.set("gfrom", String(from));
      params.set("gto", String(now));
    }
    router.push(`${pathname}?${params.toString()}`);
  };

  const quickNow = useMemo(() => {
    if (!mounted || lastRefresh <= 0) return "--:--:--";
    return new Date(lastRefresh).toLocaleTimeString();
  }, [mounted, lastRefresh]);

  return (
    <div className="min-h-screen px-4 py-4 md:px-8">
      <header className="panel mb-4 p-4">
        <div className="mb-4 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">R-SIEM SOC Console</h1>
            <p className="text-sm text-ink-300">Queue triage, investigation workspace, approvals, endpoint posture, and audit.</p>
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-900/70 px-3 py-2 text-xs text-ink-200">
            <Clock3 className="h-4 w-4" />
            <span>Last refresh: {quickNow}</span>
            <span className={`rounded px-2 py-0.5 ${streamStatus === "live" ? "bg-sky-900 text-sky-300" : "bg-amber-900 text-amber-300"}`}>
              {streamStatus === "live" ? "LIVE" : "POLL"}
            </span>
            <span className="rounded bg-ink-800 px-2 py-0.5">FAST waiting: {waitingApprovals}</span>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-2 md:grid-cols-[1.6fr_0.8fr_1fr_auto]">
          <div className="flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-900 px-2">
            <Search className="h-4 w-4 text-ink-300" />
            <input
              value={globalQuery}
              onChange={(e) => setGlobalQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") applyGlobalControls();
              }}
              placeholder="Global search: run_id user src_ip node_id rule_id playbook_id"
              className="w-full border-0 bg-transparent px-1 py-2 text-sm outline-none"
            />
          </div>

          <select value={range} onChange={(e) => setRange(e.target.value)} className="rounded-lg border border-ink-700 bg-ink-900 px-2 py-2 text-sm">
            {RANGE_PRESETS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>

          {range === "custom" ? (
            <div className="grid grid-cols-2 gap-2">
              <input type="datetime-local" value={customFrom} onChange={(e) => setCustomFrom(e.target.value)} className="rounded-lg border border-ink-700 bg-ink-900 px-2 py-2 text-sm" />
              <input type="datetime-local" value={customTo} onChange={(e) => setCustomTo(e.target.value)} className="rounded-lg border border-ink-700 bg-ink-900 px-2 py-2 text-sm" />
            </div>
          ) : (
            <div className="flex items-center rounded-lg border border-ink-700 bg-ink-900 px-2 text-xs text-ink-300">
              {mounted && nowMs > 0 ? (
                <span>
                  Window auto-applied: {toLocalInput(nowMs - rangeToMs(range)).replace("T", " ")} to {toLocalInput(nowMs).replace("T", " ")}
                </span>
              ) : (
                <span>Window auto-applied after load</span>
              )}
            </div>
          )}

          <div className="flex items-center justify-end gap-2">
            <button
              className={`rounded px-2 py-2 text-xs ${live ? "bg-sky-700 text-white" : "bg-ink-700 text-ink-200"}`}
              onClick={() => setLive((v) => !v)}
              title="Toggle live mode"
            >
              <Zap className="mr-1 inline h-3.5 w-3.5" />
              {live ? "Live ON" : "Live OFF"}
            </button>
            <button className="rounded bg-ink-700 px-3 py-2 text-sm hover:bg-ink-600" onClick={applyGlobalControls}>
              Apply
            </button>
          </div>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-[260px_1fr]">
        <aside className="panel p-3">
          <nav className="space-y-1.5">
            {NAV.map((item) => {
              const active = pathname.startsWith(item.href);
              const Icon = item.icon;
              return (
                <Link
                  key={item.href}
                  href={`${item.href}?${searchParams.toString()}`}
                  className={`flex items-center justify-between rounded-lg px-3 py-2.5 text-sm transition ${
                    active ? "bg-ink-700 text-white" : "text-ink-200 hover:bg-ink-800"
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Icon className="h-4 w-4" />
                    {item.label}
                  </span>
                  {item.href === "/incidents" && waitingApprovals > 0 ? (
                    <span className="rounded bg-rose-900 px-2 py-0.5 text-[11px] text-rose-300">{waitingApprovals}</span>
                  ) : null}
                </Link>
              );
            })}
          </nav>
        </aside>

        <main className="panel p-4 md:p-5">{children}</main>
      </div>
    </div>
  );
}
