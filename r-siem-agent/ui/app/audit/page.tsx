"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { deleteUser, disableUser, getAdminUsers, getAudit, me, upsertAdminUser } from "@/lib/api";
import { INCIDENT_MUTATED_EVENT, INCIDENTS_UPDATED_EVENT } from "@/lib/events";
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

function auditMessageLabel(msg: string): string {
  switch ((msg || "").toLowerCase()) {
    case "ui_user_upserted":
      return "User Created/Updated";
    case "ui_user_disabled":
      return "User Disabled";
    case "ui_user_deleted":
      return "User Deleted";
    case "ui_response_reissued":
      return "Response Re-issued";
    case "identity_verification_completed":
      return "Identity Verification Completed";
    case "identity_verification_failed_safe":
      return "Identity Verification Failed Safe";
    case "identity_verification_failed":
      return "Identity Verification Failed";
    case "auth_access_restored":
      return "Access Restored";
    case "auth_restore_failed_safe":
      return "Access Restore Failed Safe";
    case "auth_access_restore_failed":
      return "Access Restore Failed";
    case "ui_model_change_proposed":
      return "Model Change Proposed";
    case "ui_model_change_approved":
      return "Model Change Approved";
    case "ui_model_change_rejected":
      return "Model Change Rejected";
    case "ui_model_change_applied":
      return "Model Change Applied";
    default:
      return msg;
  }
}

export default function AuditPage() {
  const [toasts, setToasts] = useState<Array<{ id: number; tone: "success" | "error"; message: string }>>([]);
  const searchParams = useSearchParams();
  const [items, setItems] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [hasLoadedOnce, setHasLoadedOnce] = useState(false);
  const hasLoadedOnceRef = useRef(false);
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
  const [pendingDeleteUser, setPendingDeleteUser] = useState<string | null>(null);

  const pushToast = useCallback((tone: "success" | "error", message: string) => {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    setToasts((prev) => [...prev, { id, tone, message }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((toast) => toast.id !== id));
    }, 3500);
  }, []);

  const fromMs = useMemo(() => parseQueryTime(searchParams.get("gfrom")), [searchParams]);
  const toMs = useMemo(() => parseQueryTime(searchParams.get("gto")), [searchParams]);

  const load = useCallback(async () => {
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (fromMs) params.set("from", String(fromMs));
    if (toMs) params.set("to", String(toMs));

    if (!hasLoadedOnceRef.current) {
      setLoading(true);
    }
    setError(null);
    try {
      const [auditRes, meRes] = await Promise.all([getAudit(params.toString()), me()]);
      setItems(auditRes.items || []);
      setAuthUser(meRes.user);
      if (meRes.user?.role === "admin") {
        const userRes = await getAdminUsers();
        setUsers(userRes.items || []);
      }
      hasLoadedOnceRef.current = true;
      setHasLoadedOnce(true);
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setLoading(false);
    }
  }, [fromMs, q, toMs]);

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
      pushToast("success", `User saved: ${newUser.trim()}`);
      setNewPass("");
      const userRes = await getAdminUsers();
      setUsers(userRes.items || []);
    } catch (e) {
      const message = `User upsert failed: ${(e as Error).message}`;
      setUserMsg(message);
      pushToast("error", message);
    }
  };

  const disableSelectedUser = async (username: string) => {
    try {
      await disableUser(username);
      setUserMsg(`User disabled: ${username}`);
      pushToast("success", `User disabled: ${username}`);
      const userRes = await getAdminUsers();
      setUsers(userRes.items || []);
    } catch (e) {
      const message = `Disable failed: ${(e as Error).message}`;
      setUserMsg(message);
      pushToast("error", message);
    }
  };

  const deleteSelectedUser = async (username: string) => {
    try {
      await deleteUser(username);
      setUsers((prev) => prev.filter((user) => user.username !== username));
      setUserMsg(`User deleted: ${username}`);
      pushToast("success", `User deleted: ${username}`);
      const userRes = await getAdminUsers();
      setUsers(userRes.items || []);
      setPendingDeleteUser(null);
    } catch (e) {
      const message = `Delete failed: ${(e as Error).message}`;
      setUserMsg(message);
      pushToast("error", message);
    }
  };

  return (
    <section className="flex h-full min-h-0 flex-col gap-4">
      {toasts.length > 0 ? (
        <div className="fixed right-6 top-6 z-50 flex max-w-sm flex-col gap-2">
          {toasts.map((toast) => (
            <div
              key={toast.id}
              className={`rounded-lg border px-3 py-2 text-sm shadow-lg ${
                toast.tone === "success"
                  ? "border-emerald-700/60 bg-emerald-950/80 text-emerald-100"
                  : "border-rose-700/60 bg-rose-950/80 text-rose-100"
              }`}
            >
              {toast.message}
            </div>
          ))}
        </div>
      ) : null}

      {pendingDeleteUser ? (
        <div className="fixed inset-0 z-40 bg-black/50">
          <div className="absolute inset-y-0 right-0 flex w-full max-w-md flex-col border-l border-ink-800 bg-ink-950 shadow-2xl">
            <div className="flex items-center justify-between border-b border-ink-800 px-4 py-3">
              <div>
                <h3 className="text-[16px] font-semibold">Delete User</h3>
                <p className="text-xs text-ink-300">This permanently removes the account from the local UI user store.</p>
              </div>
              <button className="btn-secondary px-3 py-2 text-xs" onClick={() => setPendingDeleteUser(null)}>
                Close
              </button>
            </div>
            <div className="flex flex-1 flex-col gap-4 px-4 py-4 text-sm text-ink-200">
              <p>
                Delete user <span className="font-semibold text-ink-100">{pendingDeleteUser}</span>?
              </p>
              <p className="text-xs text-ink-300">
                This action is permanent. The user must already be disabled and the account will be removed from both the UI list and
                <code className="ml-1 rounded bg-ink-900 px-1 py-0.5">configs/ui_users.json</code>.
              </p>
              <div className="mt-auto flex justify-end gap-2">
                <button className="btn-secondary px-3 py-2 text-xs" onClick={() => setPendingDeleteUser(null)}>
                  Cancel
                </button>
                <button className="btn-danger px-3 py-2 text-xs" onClick={() => deleteSelectedUser(pendingDeleteUser)}>
                  Delete Permanently
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-[18px] font-semibold">Audit Trail</h2>
          <p className="text-[13px] text-ink-300">Approval flow, failed-safe outcomes, and operator actions with timeline filters.</p>
        </div>
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

      {loading && !hasLoadedOnce ? <LoadingState /> : null}
      {error && !items.length ? <ErrorState message={error} /> : null}
      {error && items.length > 0 ? (
        <div className="rounded border border-rose-900/80 bg-rose-950/30 px-3 py-2 text-sm text-rose-200">
          {error}
        </div>
      ) : null}
      {!loading && !error && filtered.length === 0 ? <EmptyState title="No audit entries" /> : null}

      {!loading && !error && filtered.length > 0 ? (
        <div className="space-y-2">
          {filtered.map((entry, idx) => (
            <div key={`${entry.ts}-${entry.run_id || idx}`} className="panel-elevated p-3 text-sm">
              <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className={typeChipClass(entry.msg)}>{auditMessageLabel(entry.msg)}</span>
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
                      <button
                        className="btn-secondary ml-2 px-2 py-1 text-xs text-rose-200 hover:bg-rose-950/40 disabled:opacity-50"
                        disabled={!u.disabled || authUser?.username === u.username}
                        onClick={() => setPendingDeleteUser(u.username)}
                        title={
                          authUser?.username === u.username
                            ? "Cannot delete current user"
                            : !u.disabled
                              ? "Disable user before delete"
                              : "Delete user"
                        }
                      >
                        Delete
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
