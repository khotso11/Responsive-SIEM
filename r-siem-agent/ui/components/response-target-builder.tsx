"use client";

import { ResponseActionTargetDraft } from "@/lib/types";

const KIND_OPTIONS: Array<{ value: ResponseActionTargetDraft["kind"]; label: string }> = [
  { value: "ip", label: "IP" },
  { value: "cidr", label: "CIDR" },
  { value: "dns", label: "DNS / Hostname" },
  { value: "hostname", label: "Hostname" }
];

const PROTOCOL_OPTIONS: Array<{ value: ResponseActionTargetDraft["protocol"]; label: string }> = [
  { value: "", label: "any" },
  { value: "tcp", label: "tcp" },
  { value: "udp", label: "udp" }
];

function updateTargetAtIndex(
  targets: ResponseActionTargetDraft[],
  index: number,
  patch: Partial<ResponseActionTargetDraft>
): ResponseActionTargetDraft[] {
  return targets.map((item, idx) => (idx === index ? { ...item, ...patch } : item));
}

export function ResponseTargetBuilder({
  title,
  description,
  targets,
  onChange,
  disabled
}: {
  title: string;
  description?: string;
  targets: ResponseActionTargetDraft[];
  onChange: (next: ResponseActionTargetDraft[]) => void;
  disabled?: boolean;
}) {
  const addTarget = () => {
    onChange([...targets, { kind: "ip", value: "", port: undefined, protocol: "" }]);
  };

  const removeTarget = (index: number) => {
    const next = targets.filter((_, idx) => idx !== index);
    onChange(next.length > 0 ? next : [{ kind: "ip", value: "", port: undefined, protocol: "" }]);
  };

  return (
    <div className="rounded border border-ink-800 bg-ink-900/40 p-3">
      <div className="mb-2 flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-ink-100">{title}</div>
          {description ? <p className="text-xs text-ink-300">{description}</p> : null}
        </div>
        <button type="button" className="btn-secondary" disabled={disabled} onClick={addTarget}>
          Add target
        </button>
      </div>
      <div className="space-y-2">
        {targets.map((target, index) => (
          <div key={`${target.kind}-${index}`} className="grid grid-cols-1 gap-2 rounded border border-ink-800 bg-ink-950/50 p-2 lg:grid-cols-[120px_1fr_110px_110px_110px]">
            <select
              value={target.kind}
              disabled={disabled}
              onChange={(e) => onChange(updateTargetAtIndex(targets, index, { kind: e.target.value as ResponseActionTargetDraft["kind"] }))}
              className="input-field w-full"
            >
              {KIND_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <input
              value={target.value}
              disabled={disabled}
              onChange={(e) => onChange(updateTargetAtIndex(targets, index, { value: e.target.value }))}
              className="input-field w-full"
              placeholder="IP address, CIDR, DNS, or hostname"
            />
            <input
              value={target.port ?? ""}
              disabled={disabled}
              onChange={(e) => {
                const raw = e.target.value.trim();
                onChange(updateTargetAtIndex(targets, index, { port: raw === "" ? undefined : Number(raw) }));
              }}
              className="input-field w-full"
              placeholder="port"
            />
            <select
              value={target.protocol || ""}
              disabled={disabled}
              onChange={(e) => onChange(updateTargetAtIndex(targets, index, { protocol: e.target.value as ResponseActionTargetDraft["protocol"] }))}
              className="input-field w-full"
            >
              {PROTOCOL_OPTIONS.map((opt) => (
                <option key={String(opt.value)} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <button type="button" className="btn-secondary w-full" disabled={disabled} onClick={() => removeTarget(index)}>
              Remove
            </button>
          </div>
        ))}
      </div>
      <div className="mt-2 text-xs text-ink-400">
        Port and protocol are recorded with the action for audit clarity. The endpoint firewall applies the target list against the selected endpoint.
      </div>
    </div>
  );
}
