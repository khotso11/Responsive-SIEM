"use client";

import { EventRow, Incident, ResponseActionView } from "@/lib/types";

export const HONEYPOT_RULE_ID = "R-FR03-DECEPTION-TRIPWIRE";
export const HONEYPOT_PLAYBOOK_ID = "PB-DECEPTION-HONEYPOT-TRIAGE";

export function isHoneypotIncident(item?: Incident | null): boolean {
  if (!item) return false;
  const sourceType = String(item.source_type || "").toLowerCase();
  const eventType = String(item.event_type || "").toLowerCase();
  return (
    item.rule_id === HONEYPOT_RULE_ID ||
    item.playbook_id === HONEYPOT_PLAYBOOK_ID ||
    sourceType.includes("deception") ||
    eventType.includes("honeypot")
  );
}

export function isHoneypotEvent(item?: EventRow | null): boolean {
  if (!item) return false;
  const sourceType = String(item.source_type || "").toLowerCase();
  const eventType = String(item.event_type || "").toLowerCase();
  return item.rule_id === HONEYPOT_RULE_ID || sourceType.includes("deception") || eventType.includes("honeypot");
}

export function honeypotServiceLabel(event: EventRow): string {
  const port = Number(event.dst_port || 0);
  if (port === 18081) return "Admin login decoy";
  if (port === 2222) return "SSH decoy";
  if (port === 2323) return "Telnet decoy";
  if (event.protocol_family) return event.protocol_family;
  return event.source_type || "deception";
}

export function honeypotSummary(event: EventRow): string {
  const parts = [
    event.src_ip ? `src ${event.src_ip}` : "",
    event.dst_ip ? `dst ${event.dst_ip}` : "",
    event.user_name ? `user ${event.user_name}` : "",
    event.cmdline ? event.cmdline : ""
  ].filter(Boolean);
  return parts.join(" • ") || event.event_idem_key;
}

export function honeypotSeverityTone(value?: string): string {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "critical") return "badge-bad";
  if (normalized === "high") return "badge-warn";
  if (normalized === "medium") return "badge-info";
  return "badge-good";
}

function normalized(value?: string | number | null): string {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

function eventObservedUnixMs(event: EventRow): number {
  return Number(event.recv_ts_unix_ms || event.event_ts_unix_ms || 0);
}

function incidentObservedUnixMs(incident: Incident): number {
  return Number(incident.last_updated_at_unix_ms || 0);
}

export function correlateHoneypotEventIncident(event: EventRow, incidents: Incident[]): Incident | null {
  const exact = incidents.find((item) => normalized(item.event_idem_key) !== "" && normalized(item.event_idem_key) === normalized(event.event_idem_key));
  if (exact) return exact;

  const candidates = incidents.filter((item) => {
    if (!isHoneypotIncident(item)) return false;
    if (normalized(item.src_ip) && normalized(item.src_ip) !== normalized(event.src_ip)) return false;
    if (normalized(item.user_name) && normalized(item.user_name) !== normalized(event.user_name)) return false;
    if (normalized(item.node_id) && normalized(item.node_id) !== normalized(event.node_id)) return false;
    if (normalized(item.dst_ip) && normalized(item.dst_ip) !== normalized(event.dst_ip)) return false;
    if (item.dst_port && event.dst_port && Number(item.dst_port) !== Number(event.dst_port)) return false;
    return true;
  });

  if (!candidates.length) return null;
  const eventTs = eventObservedUnixMs(event);
  const sorted = [...candidates].sort(
    (a, b) => Math.abs(incidentObservedUnixMs(a) - eventTs) - Math.abs(incidentObservedUnixMs(b) - eventTs)
  );
  const match = sorted[0];
  if (!match) return null;
  const incidentTs = incidentObservedUnixMs(match);
  if (!incidentTs || !eventTs) return match;
  return Math.abs(incidentTs - eventTs) <= 10 * 60 * 1000 ? match : null;
}

export function honeypotActionTargetLabel(action: ResponseActionView): string {
  const details = action.details || {};
  return (
    action.target ||
    (typeof details.dst_ip === "string" ? details.dst_ip : "") ||
    (typeof details.dns_name === "string" ? details.dns_name : "") ||
    (typeof details.cidr === "string" ? details.cidr : "") ||
    "-"
  );
}
