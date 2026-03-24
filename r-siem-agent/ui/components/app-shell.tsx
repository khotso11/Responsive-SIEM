"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Activity, BarChart3, Clock3, ListChecks, Search, Settings2, ShieldCheck, UserCircle2, Zap } from "lucide-react";
import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { getStreamURL, login, logout, me, setAuthToken } from "@/lib/api";
import { AUTH_REQUIRED_EVENT, emitIncidentsUpdated } from "@/lib/events";
import { AuthUser } from "@/lib/types";

const NAV = [
  { href: "/", label: "Dashboard", icon: BarChart3 },
  { href: "/incidents", label: "Incidents", icon: ListChecks },
  { href: "/endpoints", label: "Endpoints", icon: Activity },
  { href: "/actions", label: "Actions", icon: Zap },
  { href: "/search", label: "Search", icon: Search },
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
  const mainRef = useRef<HTMLElement | null>(null);

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

  const [authLoading, setAuthLoading] = useState(true);
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [loginUser, setLoginUser] = useState("analyst");
  const [loginPass, setLoginPass] = useState("");
  const [loginErr, setLoginErr] = useState("");
  const scrollStorageKey = useMemo(() => `rsiem:scroll:${pathname}`, [pathname]);

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
    const el = mainRef.current;
    if (!el || typeof window === "undefined") return;
    const saved = window.sessionStorage.getItem(scrollStorageKey);
    if (!saved) return;
    const nextTop = Number(saved);
    if (!Number.isFinite(nextTop) || nextTop < 0) return;
    const frame = window.requestAnimationFrame(() => {
      el.scrollTop = nextTop;
    });
    return () => window.cancelAnimationFrame(frame);
  }, [pathname, searchParams, scrollStorageKey]);

  useEffect(() => {
    const el = mainRef.current;
    if (!el || typeof window === "undefined") return;
    const persistScroll = () => {
      window.sessionStorage.setItem(scrollStorageKey, String(el.scrollTop));
    };
    persistScroll();
    el.addEventListener("scroll", persistScroll, { passive: true });
    return () => {
      persistScroll();
      el.removeEventListener("scroll", persistScroll);
    };
  }, [scrollStorageKey]);

  useEffect(() => {
    let cancelled = false;
    const probeToken = (searchParams.get("ui_probe_token") || "").trim();
    if (probeToken) {
      setAuthToken(probeToken);
    }
    setAuthLoading(true);
    me()
      .then((res) => {
        if (!cancelled) {
          setAuthUser(res.user);
          setLoginErr("");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setAuthUser(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setAuthLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [searchParams]);

  useEffect(() => {
    const onAuthRequired = () => {
      setAuthUser(null);
      setAuthLoading(false);
      setLoginErr("Session expired. Please log in again.");
      setLoginPass("");
    };
    window.addEventListener(AUTH_REQUIRED_EVENT, onAuthRequired);
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, onAuthRequired);
  }, []);

  useEffect(() => {
    if (!live || !authUser) {
      setStreamStatus("polling");
      return;
    }
    const ev = new EventSource(getStreamURL());
    let closed = false;
    const onRefresh = (raw: MessageEvent) => {
      if (closed) return;
      let parsed: { waiting_approvals?: number } | undefined;
      try {
        parsed = JSON.parse(raw.data) as { waiting_approvals?: number };
        setWaitingApprovals(parsed.waiting_approvals || 0);
      } catch {
        // ignore parse errors
      }
      emitIncidentsUpdated(parsed);
      const now = Date.now();
      setNowMs(now);
      setLastRefresh(now);
      setStreamStatus("live");
    };
    ev.addEventListener("hint", onRefresh as EventListener);
    ev.addEventListener("incidents_updated", onRefresh as EventListener);
    ev.onerror = () => {
      setStreamStatus("polling");
    };
    return () => {
      closed = true;
      ev.close();
    };
  }, [live, authUser]);

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
    if (typeof window !== "undefined" && mainRef.current) {
      window.sessionStorage.setItem(scrollStorageKey, String(mainRef.current.scrollTop));
    }
    router.push(`${pathname}?${params.toString()}`, { scroll: false });
  };

  const quickNow = useMemo(() => {
    if (!mounted || lastRefresh <= 0) return "--:--:--";
    return new Date(lastRefresh).toLocaleTimeString();
  }, [mounted, lastRefresh]);

  const navItems = useMemo(() => {
    const items = [...NAV];
    if (authUser?.role === "admin") {
      items.splice(items.length - 1, 0, { href: "/models", label: "Models", icon: Settings2 });
    }
    return items;
  }, [authUser]);

  const doLogin = async () => {
    try {
      setLoginErr("");
      const res = await login(loginUser, loginPass);
      setAuthUser(res.user);
      setLoginPass("");
    } catch (e) {
      setLoginErr((e as Error).message);
    }
  };

  const doLogout = async () => {
    await logout();
    setAuthUser(null);
  };

  if (authLoading) {
    return <div className="p-8 text-sm text-ink-200">Loading authentication...</div>;
  }

  if (!authUser) {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <div className="panel w-full max-w-md p-5">
          <h1 className="mb-2 text-xl font-semibold">R-SIEM SOC Console Login</h1>
          <p className="mb-4 text-sm text-ink-300">Sign in with a local UI API user (admin/analyst).</p>
          <div className="space-y-3">
            <input
              value={loginUser}
              onChange={(e) => setLoginUser(e.target.value)}
              className="input-field w-full"
              placeholder="username"
            />
            <input
              type="password"
              value={loginPass}
              onChange={(e) => setLoginPass(e.target.value)}
              className="input-field w-full"
              placeholder="password"
              onKeyDown={(e) => {
                if (e.key === "Enter") doLogin();
              }}
            />
            <button className="btn-primary w-full" onClick={doLogin}>
              Login
            </button>
            {loginErr ? <div className="rounded bg-rose-950/50 px-3 py-2 text-xs text-rose-300">{loginErr}</div> : null}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen overflow-hidden px-2 py-2 md:px-4 md:py-4">
      <div className="flex h-full w-full min-w-0 flex-col">
      <header className="panel mb-4 shrink-0 p-4">
        <div className="mb-4 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-[24px] font-semibold tracking-tight">R-SIEM SOC Console</h1>
            <p className="text-sm text-ink-300">Posture dashboard, triage, investigations, approvals, endpoints, and audit.</p>
          </div>
          <div className="flex flex-wrap items-center gap-2 rounded-lg border border-ink-700 bg-ink-900/70 px-3 py-2 text-xs text-ink-200">
            <Clock3 className="h-4 w-4" />
            <span>Last refresh: {quickNow}</span>
            <span className={`rounded px-2 py-0.5 ${streamStatus === "live" ? "bg-sky-900 text-sky-300" : "bg-amber-900 text-amber-300"}`}>
              {streamStatus === "live" ? "LIVE" : "POLL"}
            </span>
            <span className="rounded bg-ink-800 px-2 py-0.5">FAST waiting: {waitingApprovals}</span>
            <span className="ml-1 inline-flex items-center gap-1 rounded bg-ink-800 px-2 py-0.5">
              <UserCircle2 className="h-3.5 w-3.5" /> {authUser.username} ({authUser.role})
            </span>
            <button className="btn-secondary px-2 py-0.5 text-xs" onClick={doLogout}>
              Logout
            </button>
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

          <select value={range} onChange={(e) => setRange(e.target.value)} className="select-field">
            {RANGE_PRESETS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>

          {range === "custom" ? (
            <div className="grid grid-cols-2 gap-2">
              <input type="datetime-local" value={customFrom} onChange={(e) => setCustomFrom(e.target.value)} className="input-field" />
              <input type="datetime-local" value={customTo} onChange={(e) => setCustomTo(e.target.value)} className="input-field" />
            </div>
          ) : (
            <div className="flex items-center rounded-lg border border-ink-700 bg-ink-900 px-2 text-xs text-ink-300">
              {mounted && nowMs > 0 ? (
                <span>
                  Window: {toLocalInput(nowMs - rangeToMs(range)).replace("T", " ")} to {toLocalInput(nowMs).replace("T", " ")}
                </span>
              ) : (
                <span>Window auto-applied after load</span>
              )}
            </div>
          )}

          <div className="flex items-center justify-end gap-2">
            <button
              className={`rounded px-2 py-2 text-xs ${live ? "bg-accent-cyan text-[#071019]" : "bg-ink-700 text-ink-200"}`}
              onClick={() => setLive((v) => !v)}
              title="Toggle live mode"
            >
              <Zap className="mr-1 inline h-3.5 w-3.5" />
              {live ? "Live ON" : "Live OFF"}
            </button>
            <button className="btn-secondary" onClick={applyGlobalControls}>
              Apply
            </button>
          </div>
        </div>
      </header>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 md:grid-cols-[280px_minmax(0,1fr)]">
        <aside className="panel overflow-auto p-3">
          <nav className="space-y-1.5">
            {navItems.map((item) => {
              const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
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

        <main ref={mainRef} className="panel min-h-0 overflow-auto p-3 md:p-5">{children}</main>
      </div>
      </div>
    </div>
  );
}
