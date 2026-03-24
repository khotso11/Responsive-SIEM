"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { getSearchEvents } from "@/lib/api";
import { INCIDENT_MUTATED_EVENT, INCIDENTS_UPDATED_EVENT } from "@/lib/events";
import { EventRow, EventSearchQuery, EventSearchResponse } from "@/lib/types";
import { EmptyState, ErrorState, LoadingState, unixMsToLocal } from "@/components/ui";

function parseQueryTime(v: string | null): number | undefined {
  if (!v) return undefined;
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return n;
  const p = Date.parse(v);
  if (!Number.isNaN(p) && p > 0) return p;
  return undefined;
}

function eventTypeTone(sourceType?: string): string {
  const value = (sourceType || "").toLowerCase();
  if (value.includes("audit")) return "badge-info";
  if (value.includes("proc")) return "badge-lane-standard";
  if (value.includes("dns")) return "badge-good";
  if (value.includes("deception")) return "badge-bad";
  return "badge";
}

function initialQuery(searchParams: URLSearchParams): EventSearchQuery {
  return {
    q: searchParams.get("q") || "",
    from: parseQueryTime(searchParams.get("from")) || parseQueryTime(searchParams.get("gfrom")),
    to: parseQueryTime(searchParams.get("to")) || parseQueryTime(searchParams.get("gto")),
    node_id: searchParams.get("node_id") || "",
    user_name: searchParams.get("user_name") || "",
    src_ip: searchParams.get("src_ip") || "",
    dst_ip: searchParams.get("dst_ip") || "",
    dst_port: Number(searchParams.get("dst_port") || 0) || undefined,
    protocol_family: searchParams.get("protocol_family") || "",
    source_type: searchParams.get("source_type") || "",
    event_type: searchParams.get("event_type") || "",
    rule_id: searchParams.get("rule_id") || "",
    severity: searchParams.get("severity") || "",
    comm: searchParams.get("comm") || "",
    exec_path: searchParams.get("exec_path") || "",
    cmdline: searchParams.get("cmdline") || "",
    dns_name: searchParams.get("dns_name") || "",
    file_sha256: searchParams.get("file_sha256") || "",
    exec_sha256: searchParams.get("exec_sha256") || "",
    event_idem_key: searchParams.get("event_idem_key") || "",
    raw_line_sha256: searchParams.get("raw_line_sha256") || "",
    page: Number(searchParams.get("page") || 1) || 1,
    limit: Number(searchParams.get("limit") || 100) || 100,
    sort: (searchParams.get("sort") as EventSearchQuery["sort"]) || "recv_desc"
  };
}

function eventProcessLabel(event: EventRow): string {
  const parts = [event.comm || "", event.exec_path || "", event.cmdline || ""].filter(Boolean);
  return parts.length > 0 ? parts.join(" | ") : "-";
}

function eventNetworkLabel(event: EventRow): string {
  const parts = [
    event.src_ip || "-",
    "->",
    event.dst_ip || "-",
    event.dst_port ? String(event.dst_port) : "",
    event.protocol_family ? `(${event.protocol_family})` : "",
    event.dns_name ? `[${event.dns_name}]` : ""
  ].filter(Boolean);
  return parts.join(" ");
}

type FilterChip = {
  key: string;
  label: string;
  value: string;
};

type AnalysisMode = "source_type" | "event_type" | "rule_id" | "severity" | "protocol_family" | "node_id" | "user_name";

type TimelineBucket = {
  label: string;
  count: number;
  ts: number;
};

type AnalysisRow = {
  rank: number;
  value: string;
  count: number;
  percent: number;
};

type QueryToken = {
  key?: string;
  value: string;
};

const SOURCE_TYPE_OPTIONS = ["", "auditd_connect", "auditd_exec", "proc_net", "dns_packet", "inotify", "tail"];
const EVENT_TYPE_OPTIONS = ["", "network_connection", "process_exec", "dns_query", "file_change", "auth_failed"];
const PROTOCOL_OPTIONS = ["", "rdp", "winrm", "ssh", "smb", "rpc", "ldap", "dns", "ftp"];
const SEVERITY_OPTIONS = ["", "critical", "high", "medium", "low", "info"];
const WINDOW_PRESETS: Array<{ label: string; ms: number }> = [
  { label: "<30s", ms: 30 * 1000 },
  { label: "<1m", ms: 60 * 1000 },
  { label: "<10m", ms: 10 * 60 * 1000 },
  { label: "<1h", ms: 60 * 60 * 1000 },
  { label: "<1d", ms: 24 * 60 * 60 * 1000 }
];

function toDatetimeLocalValue(unixMs?: number): string {
  if (!unixMs) return "";
  const d = new Date(unixMs);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function fromDatetimeLocalValue(value: string): number | undefined {
  if (!value.trim()) return undefined;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed) || parsed <= 0) return undefined;
  return parsed;
}

function activeFilterChips(filters: EventSearchQuery): FilterChip[] {
  const chips: FilterChip[] = [];
  const push = (key: string, label: string, value?: string | number) => {
    if (value === undefined || value === null) return;
    const trimmed = String(value).trim();
    if (!trimmed) return;
    chips.push({ key, label, value: trimmed });
  };
  push("q", "Text", filters.q);
  push("node_id", "Node", filters.node_id);
  push("user_name", "User", filters.user_name);
  push("source_type", "Source", filters.source_type);
  push("event_type", "Event", filters.event_type);
  push("rule_id", "Rule", filters.rule_id);
  push("severity", "Severity", filters.severity);
  push("src_ip", "Src IP", filters.src_ip);
  push("dst_ip", "Dst IP", filters.dst_ip);
  push("dst_port", "Dst Port", filters.dst_port);
  push("protocol_family", "Protocol", filters.protocol_family);
  push("exec_path", "Exec Path", filters.exec_path);
  push("comm", "Comm", filters.comm);
  push("cmdline", "Cmdline", filters.cmdline);
  push("dns_name", "Domain", filters.dns_name);
  push("file_sha256", "File SHA256", filters.file_sha256);
  push("exec_sha256", "Exec SHA256", filters.exec_sha256);
  push("event_idem_key", "Event ID", filters.event_idem_key);
  push("raw_line_sha256", "Raw Hash", filters.raw_line_sha256);
  if (filters.from) chips.push({ key: "from", label: "From", value: unixMsToLocal(filters.from) });
  if (filters.to) chips.push({ key: "to", label: "To", value: unixMsToLocal(filters.to) });
  return chips;
}

function buildSearchStatement(filters: EventSearchQuery): string {
  const parts: string[] = [];
  const push = (label: string, value?: string | number) => {
    if (value === undefined || value === null) return;
    const trimmed = String(value).trim();
    if (!trimmed) return;
    parts.push(`@${label}:${trimmed.includes(" ") ? `"${trimmed}"` : trimmed}`);
  };
  push("q", filters.q);
  push("fields.node_id", filters.node_id);
  push("fields.user_name", filters.user_name);
  push("fields.src_ip", filters.src_ip);
  push("fields.dst_ip", filters.dst_ip);
  push("fields.dst_port", filters.dst_port);
  push("fields.protocol_family", filters.protocol_family);
  push("fields.source_type", filters.source_type);
  push("fields.event_type", filters.event_type);
  push("fields.rule_id", filters.rule_id);
  push("fields.severity", filters.severity);
  push("fields.exec_path", filters.exec_path);
  push("fields.comm", filters.comm);
  push("fields.cmdline", filters.cmdline);
  push("fields.dns_name", filters.dns_name);
  push("fields.file_sha256", filters.file_sha256);
  push("fields.exec_sha256", filters.exec_sha256);
  push("fields.event_idem_key", filters.event_idem_key);
  push("fields.raw_line_sha256", filters.raw_line_sha256);
  return parts.join(" AND ") || "No active field expression. Querying visible timeframe broadly.";
}

function hasStructuredFilters(filters: EventSearchQuery): boolean {
  return Boolean(
    filters.node_id ||
    filters.user_name ||
    filters.src_ip ||
    filters.dst_ip ||
    filters.dst_port ||
    filters.protocol_family ||
    filters.source_type ||
    filters.event_type ||
    filters.rule_id ||
    filters.severity ||
    filters.comm ||
    filters.exec_path ||
    filters.cmdline ||
    filters.dns_name ||
    filters.file_sha256 ||
    filters.exec_sha256 ||
    filters.event_idem_key ||
    filters.raw_line_sha256
  );
}

function tokenizeQuery(input: string): QueryToken[] {
  const tokens: QueryToken[] = [];
  let i = 0;
  const s = input.trim();
  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (i >= s.length) break;
    let token = "";
    let quote = "";
    while (i < s.length) {
      const ch = s[i];
      if (quote) {
        if (ch === quote) {
          quote = "";
          i++;
          continue;
        }
        token += ch;
        i++;
        continue;
      }
      if (ch === "'" || ch === "\"") {
        quote = ch;
        i++;
        continue;
      }
      if (/\s/.test(ch)) break;
      token += ch;
      i++;
    }
    if (!token) continue;
    if (/^AND$/i.test(token)) continue;
    const idx = token.indexOf(":");
    if (idx > 0) {
      tokens.push({
        key: token.slice(0, idx),
        value: token.slice(idx + 1)
      });
    } else {
      tokens.push({ value: token });
    }
  }
  return tokens;
}

function normalizedQueryKey(raw?: string): string {
  const value = (raw || "").trim().toLowerCase().replace(/^@/, "");
  const map: Record<string, string> = {
    "fields.node_id": "node_id",
    "fields.user_name": "user_name",
    "fields.src_ip": "src_ip",
    "fields.dst_ip": "dst_ip",
    "fields.dst_port": "dst_port",
    "fields.protocol_family": "protocol_family",
    "fields.source_type": "source_type",
    "fields.event_type": "event_type",
    "fields.rule_id": "rule_id",
    "fields.severity": "severity",
    "fields.exec_path": "exec_path",
    "fields.comm": "comm",
    "fields.cmdline": "cmdline",
    "fields.dns_name": "dns_name",
    "fields.file_sha256": "file_sha256",
    "fields.exec_sha256": "exec_sha256",
    "fields.event_idem_key": "event_idem_key",
    "fields.raw_line_sha256": "raw_line_sha256",
    q: "q",
    text: "q"
  };
  return map[value] || value;
}

function filtersFromQuery(input: string, base: EventSearchQuery): EventSearchQuery {
  const next: EventSearchQuery = {
    ...base,
    q: "",
    node_id: "",
    user_name: "",
    src_ip: "",
    dst_ip: "",
    dst_port: undefined,
    protocol_family: "",
    source_type: "",
    event_type: "",
    rule_id: "",
    severity: "",
    comm: "",
    exec_path: "",
    cmdline: "",
    dns_name: "",
    file_sha256: "",
    exec_sha256: "",
    event_idem_key: "",
    raw_line_sha256: "",
    page: 1
  };
  const freeText: string[] = [];
  for (const token of tokenizeQuery(input)) {
    if (!token.key) {
      freeText.push(token.value);
      continue;
    }
    const key = normalizedQueryKey(token.key);
    const value = token.value.trim();
    switch (key) {
      case "q":
        if (value) freeText.push(value);
        break;
      case "dst_port":
        next.dst_port = Number(value) || undefined;
        break;
      case "node_id":
      case "user_name":
      case "src_ip":
      case "dst_ip":
      case "protocol_family":
      case "source_type":
      case "event_type":
      case "rule_id":
      case "severity":
      case "comm":
      case "exec_path":
      case "cmdline":
      case "dns_name":
      case "file_sha256":
      case "exec_sha256":
      case "event_idem_key":
      case "raw_line_sha256":
        (next as Record<string, string | number | undefined>)[key] = value;
        break;
      default:
        freeText.push(`${token.key}:${value}`);
        break;
    }
  }
  next.q = freeText.join(" ").trim();
  return next;
}

function floorBucket(ts: number, bucketMs: number): number {
  return Math.floor(ts / bucketMs) * bucketMs;
}

function chooseBucketMs(from?: number, to?: number): number {
  const span = Math.max((to || Date.now()) - (from || Date.now() - 60 * 60 * 1000), 1);
  if (span <= 30 * 60 * 1000) return 60 * 1000;
  if (span <= 3 * 60 * 60 * 1000) return 5 * 60 * 1000;
  if (span <= 12 * 60 * 60 * 1000) return 15 * 60 * 1000;
  if (span <= 2 * 24 * 60 * 60 * 1000) return 60 * 60 * 1000;
  return 6 * 60 * 60 * 1000;
}

function formatBucketLabel(ts: number, bucketMs: number): string {
  const d = new Date(ts);
  if (bucketMs >= 60 * 60 * 1000) {
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function buildTimeline(items: EventRow[], from?: number, to?: number): TimelineBucket[] {
  if (items.length === 0) return [];
  const bucketMs = chooseBucketMs(from, to);
  const counts = new Map<number, number>();
  for (const item of items) {
    const ts = item.recv_ts_unix_ms || item.event_ts_unix_ms;
    const bucket = floorBucket(ts, bucketMs);
    counts.set(bucket, (counts.get(bucket) || 0) + 1);
  }
  return Array.from(counts.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([ts, count]) => ({ ts, count, label: formatBucketLabel(ts, bucketMs) }));
}

function analysisValue(event: EventRow, mode: AnalysisMode): string {
  switch (mode) {
    case "source_type":
      return event.source_type || "-";
    case "event_type":
      return event.event_type || "-";
    case "rule_id":
      return event.rule_id || "-";
    case "severity":
      return event.severity || "-";
    case "protocol_family":
      return event.protocol_family || "-";
    case "node_id":
      return event.node_id || "-";
    case "user_name":
      return event.user_name || "-";
    default:
      return "-";
  }
}

function buildAnalysisRows(items: EventRow[], mode: AnalysisMode): AnalysisRow[] {
  if (items.length === 0) return [];
  const counts = new Map<string, number>();
  for (const item of items) {
    const key = analysisValue(item, mode);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const total = items.length;
  return Array.from(counts.entries())
    .sort((a, b) => {
      if (a[1] === b[1]) return a[0].localeCompare(b[0]);
      return b[1] - a[1];
    })
    .slice(0, 8)
    .map(([value, count], index) => ({
      rank: index + 1,
      value,
      count,
      percent: Math.round((count / total) * 1000) / 10
    }));
}

function analysisLabel(mode: AnalysisMode): string {
  switch (mode) {
    case "source_type":
      return "source type";
    case "event_type":
      return "event type";
    case "rule_id":
      return "rule";
    case "severity":
      return "severity";
    case "protocol_family":
      return "protocol";
    case "node_id":
      return "node";
    case "user_name":
      return "user";
    default:
      return "field";
  }
}

export default function SearchPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const [filters, setFilters] = useState<EventSearchQuery>(() => initialQuery(searchParams));
  const [draftFilters, setDraftFilters] = useState<EventSearchQuery>(() => initialQuery(searchParams));
  const [result, setResult] = useState<EventSearchResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasLoadedOnce, setHasLoadedOnce] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [analysisMode, setAnalysisMode] = useState<AnalysisMode>("source_type");
  const [queryText, setQueryText] = useState(() => buildSearchStatement(initialQuery(searchParams)));

  useEffect(() => {
    const next = initialQuery(searchParams);
    setFilters(next);
    setDraftFilters(next);
    setQueryText(buildSearchStatement(next));
    setShowFilters(hasStructuredFilters(next));
  }, [searchParams]);

  const load = useCallback(async () => {
    if (hasLoadedOnce) setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const res = await getSearchEvents(filters);
      setResult(res);
      setHasLoadedOnce(true);
    } catch (err) {
      setError((err as Error).message || String(err));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [filters, hasLoadedOnce]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const onRefresh = () => {
      void load();
    };
    window.addEventListener(INCIDENTS_UPDATED_EVENT, onRefresh);
    window.addEventListener(INCIDENT_MUTATED_EVENT, onRefresh);
    return () => {
      window.removeEventListener(INCIDENTS_UPDATED_EVENT, onRefresh);
      window.removeEventListener(INCIDENT_MUTATED_EVENT, onRefresh);
    };
  }, [load]);

  const pushFilters = useCallback((next: EventSearchQuery) => {
    const params = new URLSearchParams(searchParams.toString());
    const values: Array<[string, string | number | undefined]> = [
      ["q", next.q],
      ["from", next.from],
      ["to", next.to],
      ["node_id", next.node_id],
      ["user_name", next.user_name],
      ["src_ip", next.src_ip],
      ["dst_ip", next.dst_ip],
      ["dst_port", next.dst_port],
      ["protocol_family", next.protocol_family],
      ["source_type", next.source_type],
      ["event_type", next.event_type],
      ["rule_id", next.rule_id],
      ["severity", next.severity],
      ["comm", next.comm],
      ["exec_path", next.exec_path],
      ["cmdline", next.cmdline],
      ["dns_name", next.dns_name],
      ["file_sha256", next.file_sha256],
      ["exec_sha256", next.exec_sha256],
      ["event_idem_key", next.event_idem_key],
      ["raw_line_sha256", next.raw_line_sha256],
      ["page", next.page || 1],
      ["limit", next.limit || 100],
      ["sort", next.sort || "recv_desc"]
    ];
    for (const [key, value] of values) {
      if (value === undefined || value === null || String(value).trim() === "") {
        params.delete(key);
      } else {
        params.set(key, String(value));
      }
    }
    router.push(`${pathname}?${params.toString()}`);
  }, [pathname, router, searchParams]);

  const updateDraftFilters = useCallback((updater: EventSearchQuery | ((prev: EventSearchQuery) => EventSearchQuery)) => {
    setDraftFilters((prev) => {
      const next = typeof updater === "function" ? (updater as (prev: EventSearchQuery) => EventSearchQuery)(prev) : updater;
      setQueryText(buildSearchStatement(next));
      return next;
    });
  }, []);

  const applyFilters = () => {
    setFilters(draftFilters);
    pushFilters(draftFilters);
  };

  const applyQueryBar = () => {
    const parsed = filtersFromQuery(queryText, draftFilters);
    setDraftFilters(parsed);
    setFilters(parsed);
    pushFilters(parsed);
  };

  const goToPage = (page: number) => {
    const next = Math.max(1, page);
    const updated = { ...filters, page: next };
    setFilters(updated);
    setDraftFilters(updated);
    pushFilters(updated);
  };

  const clearFilters = () => {
    const reset = initialQuery(new URLSearchParams());
    reset.from = parseQueryTime(searchParams.get("gfrom"));
    reset.to = parseQueryTime(searchParams.get("gto"));
    setFilters(reset);
    setDraftFilters(reset);
    setQueryText(buildSearchStatement(reset));
    pushFilters(reset);
  };

  const applyWindowPreset = (windowMs: number) => {
    const now = Date.now();
    updateDraftFilters((prev) => ({
      ...prev,
      from: now - windowMs,
      to: now,
      page: 1
    }));
  };

  const items = result?.items || [];
  const total = result?.total || 0;
  const currentPage = result?.page || filters.page || 1;
  const pageSize = result?.limit || filters.limit || 100;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const chips = activeFilterChips(draftFilters);
  const structuredChips = chips.filter((chip) => chip.key !== "q" && chip.key !== "from" && chip.key !== "to");
  const timeline = useMemo(() => buildTimeline(items, filters.from, filters.to), [filters.from, filters.to, items]);
  const analysisRows = useMemo(() => buildAnalysisRows(items, analysisMode), [analysisMode, items]);
  const maxTimelineCount = useMemo(() => Math.max(...timeline.map((bucket) => bucket.count), 1), [timeline]);

  return (
    <section className="flex h-full min-h-0 flex-col gap-4 overflow-hidden">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-[11px] uppercase tracking-[0.22em] text-cyan-300">Analyst Workspace</div>
          <h2 className="mt-1 text-[22px] font-semibold tracking-tight">Advanced Search</h2>
          <p className="mt-1 text-[13px] text-ink-300">
            Search normalized endpoint activity, pivot into timeline analysis, and inspect grouped evidence without leaving the investigation surface.
          </p>
        </div>
        {refreshing ? (
          <div className="rounded-full border border-cyan-700/70 bg-cyan-950/40 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-cyan-200">
            Refreshing
          </div>
        ) : null}
      </div>

      <div className="panel-elevated flex flex-col gap-4 p-4">
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-[9rem_minmax(0,1fr)_11rem]">
          <label className="space-y-1">
            <span className="text-[11px] uppercase tracking-[0.2em] text-ink-500">Window</span>
            <select
              className="select-field"
              value={draftFilters.to && draftFilters.from ? String(Math.max(draftFilters.to - draftFilters.from, 0)) : "custom"}
              onChange={(e) => {
                if (e.target.value === "custom") return;
                applyWindowPreset(Number(e.target.value));
              }}
            >
              <option value="custom">Custom</option>
              <option value={30 * 1000}>30 seconds</option>
              <option value={60 * 1000}>1 minute</option>
              <option value={10 * 60 * 1000}>10 minutes</option>
              <option value={60 * 60 * 1000}>1 hour</option>
              <option value={24 * 60 * 60 * 1000}>1 day</option>
            </select>
          </label>
          <div className="space-y-1">
            <span className="text-[11px] uppercase tracking-[0.2em] text-ink-500">Search Statement</span>
            <div className="flex min-h-[3.15rem] items-center rounded-2xl border border-ink-700/80 bg-ink-950/90 px-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
              <div className="mr-3 rounded-full border border-cyan-700/60 bg-cyan-950/40 px-2.5 py-1 text-[10px] uppercase tracking-[0.18em] text-cyan-200">
                Query
              </div>
              <input
                className="w-full border-0 bg-transparent px-0 py-0 text-sm text-ink-100 outline-none placeholder:text-ink-500"
                value={queryText}
                onChange={(e) => {
                  const nextText = e.target.value;
                  setQueryText(nextText);
                  setDraftFilters((prev) => filtersFromQuery(nextText, prev));
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    applyQueryBar();
                  }
                }}
                placeholder='Example: @fields.rule_id:R-PROC-FIRST-SEEN-SUSPICIOUS AND @fields.user_name:khotso'
              />
            </div>
            <div className="text-[11px] text-ink-500">
              Supports field queries like `@fields.rule_id:value`, `src_ip:1.2.3.4`, `event_idem_key:...`, plus free text.
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <button className="btn-secondary px-3 py-2 text-xs" onClick={() => setShowFilters((v) => !v)}>
              {showFilters ? "Hide Filters" : "Show Filters"}
            </button>
            <button className="btn-primary px-3 py-2 text-xs" onClick={applyQueryBar}>
              Search
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 xl:grid-cols-[1fr_12rem_12rem_10rem]">
          <div className="rounded-2xl border border-ink-800 bg-ink-950/55 px-4 py-3">
            <div className="text-[11px] uppercase tracking-[0.2em] text-ink-500">Current timeframe</div>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-ink-300">
              <span>{draftFilters.from ? unixMsToLocal(draftFilters.from) : "now - 24h"}</span>
              <span className="text-ink-600">to</span>
              <span>{draftFilters.to ? unixMsToLocal(draftFilters.to) : "now"}</span>
              <span className="rounded-full border border-ink-700/80 bg-ink-900/80 px-2 py-0.5 text-[11px]">
                grouped by auto
              </span>
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {WINDOW_PRESETS.map((preset) => (
                <button key={preset.label} className="rounded-full border border-ink-700/80 bg-ink-900/60 px-2.5 py-1 text-[11px] text-ink-300 transition hover:border-cyan-700/70 hover:text-cyan-100" onClick={() => applyWindowPreset(preset.ms)}>
                  {preset.label}
                </button>
              ))}
            </div>
          </div>
          <label className="space-y-1">
            <span className="text-[11px] uppercase tracking-[0.2em] text-ink-500">From</span>
            <input className="input-field" type="datetime-local" value={toDatetimeLocalValue(draftFilters.from)} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, from: fromDatetimeLocalValue(e.target.value), page: 1 }))} />
          </label>
          <label className="space-y-1">
            <span className="text-[11px] uppercase tracking-[0.2em] text-ink-500">To</span>
            <input className="input-field" type="datetime-local" value={toDatetimeLocalValue(draftFilters.to)} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, to: fromDatetimeLocalValue(e.target.value), page: 1 }))} />
          </label>
          <div className="space-y-1">
            <span className="text-[11px] uppercase tracking-[0.2em] text-ink-500">Rows / Sort</span>
            <div className="grid grid-cols-1 gap-2">
              <select className="select-field" value={draftFilters.sort || "recv_desc"} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, sort: e.target.value as EventSearchQuery["sort"] }))}>
                <option value="recv_desc">Newest received</option>
                <option value="recv_asc">Oldest received</option>
                <option value="event_desc">Newest event time</option>
                <option value="event_asc">Oldest event time</option>
              </select>
              <select className="select-field" value={String(draftFilters.limit || 100)} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, limit: Number(e.target.value), page: 1 }))}>
                <option value="50">50 rows</option>
                <option value="100">100 rows</option>
                <option value="250">250 rows</option>
                <option value="500">500 rows</option>
              </select>
            </div>
          </div>
        </div>

        {showFilters ? (
          <div className="rounded-2xl border border-ink-800 bg-[linear-gradient(180deg,rgba(18,28,53,0.82),rgba(7,12,26,0.92))] p-4">
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
              <div className="rounded-xl border border-ink-800/80 bg-ink-950/45 p-3">
                <div className="mb-3 text-[11px] uppercase tracking-[0.2em] text-cyan-300">Detection Context</div>
                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                  <input className="input-field" placeholder="free_text" value={draftFilters.q || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, q: e.target.value, page: 1 }))} />
                  <input className="input-field" placeholder="node_id" value={draftFilters.node_id || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, node_id: e.target.value, page: 1 }))} />
                  <input className="input-field" placeholder="user_name" value={draftFilters.user_name || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, user_name: e.target.value, page: 1 }))} />
                  <input className="input-field" placeholder="rule_id" value={draftFilters.rule_id || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, rule_id: e.target.value, page: 1 }))} />
                  <select className="select-field" value={draftFilters.source_type || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, source_type: e.target.value, page: 1 }))}>
                    {SOURCE_TYPE_OPTIONS.map((option) => (
                      <option key={option || "all"} value={option}>{option || "all source types"}</option>
                    ))}
                  </select>
                  <select className="select-field" value={draftFilters.event_type || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, event_type: e.target.value, page: 1 }))}>
                    {EVENT_TYPE_OPTIONS.map((option) => (
                      <option key={option || "all"} value={option}>{option || "all event types"}</option>
                    ))}
                  </select>
                  <select className="select-field md:col-span-2" value={draftFilters.severity || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, severity: e.target.value, page: 1 }))}>
                    {SEVERITY_OPTIONS.map((option) => (
                      <option key={option || "all"} value={option}>{option || "all severities"}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="rounded-xl border border-ink-800/80 bg-ink-950/45 p-3">
                <div className="mb-3 text-[11px] uppercase tracking-[0.2em] text-cyan-300">Network</div>
                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                  <input className="input-field" placeholder="src_ip" value={draftFilters.src_ip || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, src_ip: e.target.value, page: 1 }))} />
                  <input className="input-field" placeholder="dst_ip" value={draftFilters.dst_ip || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, dst_ip: e.target.value, page: 1 }))} />
                  <input className="input-field" placeholder="dst_port" value={draftFilters.dst_port || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, dst_port: Number(e.target.value) || undefined, page: 1 }))} />
                  <select className="select-field" value={draftFilters.protocol_family || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, protocol_family: e.target.value, page: 1 }))}>
                    {PROTOCOL_OPTIONS.map((option) => (
                      <option key={option || "all"} value={option}>{option || "all protocols"}</option>
                    ))}
                  </select>
                  <input className="input-field md:col-span-2" placeholder="dns_name" value={draftFilters.dns_name || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, dns_name: e.target.value, page: 1 }))} />
                </div>
              </div>

              <div className="rounded-xl border border-ink-800/80 bg-ink-950/45 p-3">
                <div className="mb-3 text-[11px] uppercase tracking-[0.2em] text-cyan-300">Process And Evidence</div>
                <div className="grid grid-cols-1 gap-2">
                  <input className="input-field" placeholder="exec_path" value={draftFilters.exec_path || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, exec_path: e.target.value, page: 1 }))} />
                  <input className="input-field" placeholder="comm" value={draftFilters.comm || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, comm: e.target.value, page: 1 }))} />
                  <input className="input-field" placeholder="cmdline" value={draftFilters.cmdline || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, cmdline: e.target.value, page: 1 }))} />
                  <input className="input-field" placeholder="file_sha256" value={draftFilters.file_sha256 || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, file_sha256: e.target.value, page: 1 }))} />
                  <input className="input-field" placeholder="exec_sha256" value={draftFilters.exec_sha256 || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, exec_sha256: e.target.value, page: 1 }))} />
                  <input className="input-field" placeholder="event_idem_key" value={draftFilters.event_idem_key || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, event_idem_key: e.target.value, page: 1 }))} />
                  <input className="input-field" placeholder="raw_line_sha256" value={draftFilters.raw_line_sha256 || ""} onChange={(e) => updateDraftFilters((prev) => ({ ...prev, raw_line_sha256: e.target.value, page: 1 }))} />
                </div>
              </div>
            </div>
            <div className="mt-4 flex flex-wrap items-center justify-between gap-2">
              {chips.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {chips.map((chip) => (
                    <span key={`${chip.key}:${chip.value}`} className="rounded-full border border-cyan-800/70 bg-cyan-950/30 px-2.5 py-1 text-[11px] text-cyan-100">
                      {chip.label}: {chip.value}
                    </span>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-ink-500">No exact-match filters active. The current query will search broadly across normalized events.</div>
              )}
              <div className="flex gap-2">
                <button className="btn-secondary px-3 py-2 text-xs" onClick={clearFilters}>Clear Filters</button>
                <button className="btn-primary px-3 py-2 text-xs" onClick={applyFilters}>Apply Search</button>
              </div>
            </div>
          </div>
        ) : (
          <div className="rounded-2xl border border-ink-800 bg-ink-950/35 px-4 py-3">
            <div className="flex items-center justify-between gap-3 text-sm">
              <div className="text-ink-300">
                {structuredChips.length > 0
                  ? "Parsed field filters are active from the search bar."
                  : "Field filters are collapsed. Use the search statement above for a cleaner analyst view."}
              </div>
              <button className="btn-secondary px-3 py-2 text-xs" onClick={() => setShowFilters(true)}>
                {structuredChips.length > 0 ? "Review Parsed Filters" : "Expand Filters"}
              </button>
            </div>
            {structuredChips.length > 0 ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {structuredChips.map((chip) => (
                  <span key={`${chip.key}:${chip.value}`} className="rounded-full border border-cyan-800/70 bg-cyan-950/30 px-2.5 py-1 text-[11px] text-cyan-100">
                    {chip.label}: {chip.value}
                  </span>
                ))}
              </div>
            ) : null}
          </div>
        )}
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.65fr)_minmax(21rem,0.95fr)]">
        <div className="panel-elevated flex min-h-0 flex-col overflow-hidden p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">Time Analysis</div>
              <div className="mt-1 text-sm text-ink-300">
                Visualized from the currently returned {items.length} result rows. Source: {result?.source || "db"}.
              </div>
            </div>
            <div className="rounded-full border border-ink-700/80 bg-ink-900/70 px-3 py-1 text-xs text-ink-300">
              Page {currentPage} / {totalPages}
            </div>
          </div>

          <div className="mt-4 flex min-h-[18rem] flex-1 items-end gap-2 overflow-hidden rounded-2xl border border-ink-800 bg-[linear-gradient(180deg,rgba(7,12,26,0.55),rgba(3,7,18,0.96))] px-4 pb-6 pt-4">
            {timeline.length > 0 ? timeline.map((bucket) => (
              <div key={bucket.ts} className="flex min-w-0 flex-1 flex-col items-center justify-end gap-2">
                <div
                  className="w-full rounded-t-sm bg-[linear-gradient(180deg,#a5f08a,#4a8f56)] shadow-[0_0_18px_rgba(118,214,120,0.18)]"
                  style={{ height: `${Math.max((bucket.count / maxTimelineCount) * 100, 4)}%` }}
                  title={`${bucket.label}: ${bucket.count} events`}
                />
                <div className="text-[10px] text-ink-500">{bucket.label}</div>
              </div>
            )) : (
              <div className="flex h-full w-full items-center justify-center text-sm text-ink-500">
                No timeline buckets available for the current result set.
              </div>
            )}
          </div>

          <div className="mt-4 flex min-h-0 flex-1 flex-col overflow-hidden">
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">Result Log</div>
                <div className="mt-1 text-xs text-ink-400">
                  Scroll vertically to review rows and horizontally to inspect wide network or process context.
                </div>
              </div>
              <div className="text-xs text-ink-400">
                Returned {items.length} of {total} events
              </div>
            </div>

            {loading ? <LoadingState /> : null}
            {!loading && error ? <ErrorState message={error} /> : null}
            {!loading && !error && items.length === 0 ? <EmptyState title="No events match the current search" detail="Broaden the timeframe or remove one or two exact-match filters." /> : null}
            {!loading && !error && items.length > 0 ? (
              <div className="mt-3 min-h-[22rem] flex-1 overflow-auto rounded-2xl border border-ink-800 bg-ink-950/20">
                <table className="min-w-[116rem] text-sm">
                  <thead className="text-left">
                    <tr>
                      <th className="table-head sticky top-0 z-10 min-w-[11rem] bg-ink-950/95 p-2">Received</th>
                      <th className="table-head sticky top-0 z-10 min-w-[13rem] bg-ink-950/95 p-2">Node / User</th>
                      <th className="table-head sticky top-0 z-10 min-w-[13rem] bg-ink-950/95 p-2">Source / Event</th>
                      <th className="table-head sticky top-0 z-10 min-w-[14rem] bg-ink-950/95 p-2">Rule / Severity</th>
                      <th className="table-head sticky top-0 z-10 min-w-[22rem] bg-ink-950/95 p-2">Network</th>
                      <th className="table-head sticky top-0 z-10 min-w-[31rem] bg-ink-950/95 p-2">Process</th>
                      <th className="table-head sticky top-0 z-10 min-w-[20rem] bg-ink-950/95 p-2">Observables</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((event) => (
                      <tr key={`${event.event_idem_key}-${event.recv_ts_unix_ms}`} className="border-t border-ink-800/80 align-top transition hover:bg-ink-900/30">
                        <td className="p-2 text-xs text-ink-300 whitespace-nowrap">
                          <div>{unixMsToLocal(event.recv_ts_unix_ms)}</div>
                          <div className="text-[11px] text-ink-500">event {unixMsToLocal(event.event_ts_unix_ms)}</div>
                        </td>
                        <td className="p-2">
                          <div className="font-medium text-ink-100 break-all">{event.node_id}</div>
                          <div className="mt-1 text-[11px] text-ink-500">{event.user_name || "-"}</div>
                        </td>
                        <td className="p-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={eventTypeTone(event.source_type)}>{event.source_type}</span>
                            <span className="text-ink-200">{event.event_type}</span>
                          </div>
                        </td>
                        <td className="p-2">
                          <div className="break-all text-ink-100">{event.rule_id || "-"}</div>
                          <div className="mt-1 text-[11px] text-ink-500">{event.severity || "-"}</div>
                        </td>
                        <td className="p-2 text-xs break-all text-ink-200">{eventNetworkLabel(event)}</td>
                        <td className="p-2 text-xs break-all text-ink-200">{eventProcessLabel(event)}</td>
                        <td className="p-2 text-xs text-ink-300">
                          <div className="break-all">{event.dns_name || "-"}</div>
                          <div className="mt-1 break-all">{event.file_sha256 || event.exec_sha256 || event.raw_line_sha256 || "-"}</div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}

            <div className="mt-3 flex items-center justify-end gap-2">
              <button
                className="btn-secondary px-3 py-2 text-xs"
                disabled={currentPage <= 1}
                onClick={() => goToPage(currentPage - 1)}
              >
                Previous
              </button>
              <button
                className="btn-secondary px-3 py-2 text-xs"
                disabled={currentPage >= totalPages}
                onClick={() => goToPage(Math.min(totalPages, currentPage + 1))}
              >
                Next
              </button>
            </div>
          </div>
        </div>

        <aside className="panel-elevated flex min-h-0 flex-col overflow-hidden p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <div className="text-[11px] uppercase tracking-[0.2em] text-cyan-300">Quick Analysis</div>
              <div className="mt-1 text-sm text-ink-300">
                Based on all {items.length} events in the current visible result set.
              </div>
            </div>
            <select className="select-field max-w-[10rem]" value={analysisMode} onChange={(e) => setAnalysisMode(e.target.value as AnalysisMode)}>
              <option value="source_type">Source type</option>
              <option value="event_type">Event type</option>
              <option value="rule_id">Rule</option>
              <option value="severity">Severity</option>
              <option value="protocol_family">Protocol</option>
              <option value="node_id">Node</option>
              <option value="user_name">User</option>
            </select>
          </div>

          <div className="mt-4 rounded-2xl border border-ink-800 bg-ink-950/35 px-4 py-3">
            <div className="text-sm font-medium text-ink-100">Quick analysis of {analysisLabel(analysisMode)}</div>
            <div className="mt-1 text-xs text-ink-500">
              This analysis is based on the current visible page of search results and is intended for triage pivots, not long-range aggregation.
            </div>
          </div>

          <div className="mt-4 min-h-[18rem] flex-1 overflow-auto rounded-2xl border border-ink-800 bg-ink-950/20">
            <table className="min-w-full text-sm">
              <thead className="text-left">
                <tr>
                  <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Rank</th>
                  <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">{analysisLabel(analysisMode)}</th>
                  <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Count</th>
                  <th className="table-head sticky top-0 z-10 bg-ink-950/95 p-2">Percent</th>
                </tr>
              </thead>
              <tbody>
                {analysisRows.map((row) => (
                  <tr key={`${analysisMode}-${row.value}`} className="border-t border-ink-800/80">
                    <td className="p-2 text-ink-300">{row.rank}</td>
                    <td className="p-2 break-all text-ink-100">{row.value}</td>
                    <td className="p-2 text-ink-200">{row.count}</td>
                    <td className="p-2 text-ink-300">{row.percent}%</td>
                  </tr>
                ))}
                {analysisRows.length === 0 ? (
                  <tr>
                    <td className="p-4 text-center text-sm text-ink-500" colSpan={4}>
                      No grouped analysis available for the current result set.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </aside>
      </div>
    </section>
  );
}
