"use client";

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { disableUser, getAdminUsers, getAudit, me, upsertAdminUser } from "@/lib/api";
import { AuditEntry, AuthUser } from "@/lib/types";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui";

function parseQueryTime(v: string | null): number | undefined {
  if (!v) return undefined;
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return n;
  const p = Date.parse(v);
  if (!Number.isNaN(p) && p > 0) return p;
  return undefined;
}

function typeChipClass(msg: string): string {
  const m = (msg || "").toLowerCase();
  if (m.includes("approval")) return "badge-warn";
  if (m.includes("failed") || m.includes("partial")) return "badge-bad";
  if (m.includes("succeeded")) return "badge-good";
  return "badge-info";
}

export default function AuditPage() {
  const searchParams = useSearchParams();
  const [items, setItems] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState(searchParams.get("gq") || "");
  const [actorFilter, setActorFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");

  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [users, setUsers] = useState<Array<{ username: string; role: string; disabled: boolean }>>([]);
  const [newUser, setNewUser] = useState("new.analyst");
  const [newRole, setNewRole] = useState("analyst");
  const [newPass, setNewPass] = useState("");
  const [userMsg, setUserMsg] = useState("");

  const fromMs = useMemo(() => parseQueryTime(searchParams.get("gfrom")), [searchParams]);
  const toMs = useMemo(() => parseQueryTime(searchParams.get("gto")), [searchParams]);

  const load = async () => {
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (fromMs) params.set("from", String(fromMs));
    if (toMs) params.set("to", String(toMs));

    setLoading(true);
    setError(null);
    try {
      const [auditRes, meRes] = await Promise.all([getAudit(params.toString()), me()]);
      setItems(auditRes.items || []);
      setAuthUser(meRes.user);
      if (meRes.user?.role === "admin") {
        const userRes = await getAdminUsers();
        setUsers(userRes.items || []);
      }
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, fromMs, toMs]);

  useEffect(() => {
    setQ(searchParams.get("gq") || "");
  }, [searchParams]);

  const filtered = useMemo(() => {
    return items.filter((entry) => {
      if (actorFilter && (entry.actor || "").toLowerCase() !== actorFilter.toLowerCase()) {
        return false;
      }
      if (typeFilter && !(entry.msg || "").toLowerCase().includes(typeFilter.toLowerCase())) {
        return false;
      }
      return true;
    });
  }, [items, actorFilter, typeFilter]);

  const createUser = async () => {
    try {
      await upsertAdminUser({ username: newUser.trim(), role: newRole, password: newPass.trim(), disabled: false });
      setUserMsg(`User upserted: ${newUser.trim()}`);
      setNewPass("");
      const userRes = await getAdminUsers();
      setUsers(userRes.items || []);
    } catch (e) {
      setUserMsg(`User upsert failed: ${(e as Error).message}`);
    }
  };

  const disableSelectedUser = async (username: string) => {
    try {
      await disableUser(username);
      setUserMsg(`User disabled: ${username}`);
      const userRes = await getAdminUsers();
      setUsers(userRes.items || []);
    } catch (e) {
      setUserMsg(`Disable failed: ${(e as Error).message}`);
    }
  };

  return (
    <section className="space-y-4">
      <div>
        <h2 className="text-[18px] font-semibold">Audit Trail</h2>
        <p className="text-[13px] text-ink-300">Approval flow, failed-safe outcomes, and operator actions with timeline filters.</p>
      </div>

      <div className="panel-elevated grid grid-cols-1 gap-2 p-3 md:grid-cols-[1.2fr_0.8fr_0.8fr_auto]">
        <input
          className="input-field"
          placeholder="Search actor/action/run_id/status..."
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <input className="input-field" placeholder="Filter actor" value={actorFilter} onChange={(e) => setActorFilter(e.target.value)} />
        <input className="input-field" placeholder="Filter type (approval/failed)" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} />
        <div className="rounded border border-ink-700 bg-ink-900 px-3 py-2 text-xs text-ink-300">
          range: {fromMs ? new Date(fromMs).toLocaleString() : "-"} to {toMs ? new Date(toMs).toLocaleString() : "-"}
        </div>
      </div>

      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {!loading && !error && filtered.length === 0 ? <EmptyState title="No audit entries" /> : null}

      {!loading && !error && filtered.length > 0 ? (
        <div className="space-y-2">
          {filtered.map((entry, idx) => (
            <div key={`${entry.ts}-${entry.run_id || idx}`} className="panel-elevated p-3 text-sm">
              <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className={typeChipClass(entry.msg)}>{entry.msg}</span>
                  {entry.status ? <span className="badge-info">{entry.status}</span> : null}
                </div>
                <div className="text-xs text-ink-300">{entry.ts}</div>
              </div>
              <div className="grid grid-cols-1 gap-1 text-xs md:grid-cols-2">
                <div>actor: <span className="text-ink-100">{entry.actor || "-"}</span></div>
                <div>run_id: <span className="text-ink-100">{entry.run_id || "-"}</span></div>
                <div>decision: <span className="text-ink-100">{entry.decision || "-"}</span></div>
                <div>source: <span className="text-ink-100">{entry.source}</span></div>
              </div>
              {entry.details ? <pre className="mt-2 overflow-auto rounded bg-ink-900 p-2 text-[11px] text-ink-300">{JSON.stringify(entry.details, null, 2)}</pre> : null}
            </div>
          ))}
        </div>
      ) : null}

      {authUser?.role === "admin" ? (
        <div className="panel-elevated space-y-3 p-4">
          <h3 className="text-[16px] font-semibold">User Management (Admin)</h3>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-4">
            <input className="input-field" value={newUser} onChange={(e) => setNewUser(e.target.value)} placeholder="username" />
            <select className="select-field" value={newRole} onChange={(e) => setNewRole(e.target.value)}>
              <option value="analyst">analyst</option>
              <option value="admin">admin</option>
            </select>
            <input className="input-field" type="password" value={newPass} onChange={(e) => setNewPass(e.target.value)} placeholder="password" />
            <button className="btn-primary" onClick={createUser}>Create/Update</button>
          </div>
          {userMsg ? <div className="rounded bg-ink-900 px-2 py-2 text-xs text-ink-300">{userMsg}</div> : null}

          <div className="overflow-auto">
            <table className="min-w-full text-sm">
              <thead className="text-left">
                <tr>
                  <th className="table-head p-2">Username</th>
                  <th className="table-head p-2">Role</th>
                  <th className="table-head p-2">Disabled</th>
                  <th className="table-head p-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.username} className="border-t border-ink-800/80">
                    <td className="p-2">{u.username}</td>
                    <td className="p-2">{u.role}</td>
                    <td className="p-2">{u.disabled ? "yes" : "no"}</td>
                    <td className="p-2">
                      <button className="btn-danger px-2 py-1 text-xs disabled:opacity-50" disabled={u.disabled} onClick={() => disableSelectedUser(u.username)}>
                        Disable
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </section>
  );
}
