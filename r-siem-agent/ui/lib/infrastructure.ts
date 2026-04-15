import { EventRow, Incident } from "@/lib/types";

export const INFRA_SOURCE_TYPES = ["syslog", "netflow_v5", "snmp_trap"] as const;
export const INFRA_EVENT_TYPES = ["netflow_flow", "snmp_trap", "syslog"] as const;

type InfraMeta = {
  label: string;
  shortLabel: string;
  tone: string;
  description: string;
};

const INFRA_RULE_META: Record<string, InfraMeta> = {
  "R-INFRA-FIREWALL-DENY-BURST": {
    label: "Firewall deny burst",
    shortLabel: "FW deny burst",
    tone: "border-rose-700/60 bg-rose-950/70 text-rose-100",
    description: "Repeated firewall deny telemetry from the infrastructure plane."
  },
  "R-INFRA-NETWORK-ADMIN-LOGIN": {
    label: "Network admin login",
    shortLabel: "Admin login",
    tone: "border-amber-700/60 bg-amber-950/70 text-amber-100",
    description: "Administrative login observed on an infrastructure device."
  },
  "R-INFRA-LINK-FLAP-BURST": {
    label: "Link flap burst",
    shortLabel: "Link flap",
    tone: "border-fuchsia-700/60 bg-fuchsia-950/70 text-fuchsia-100",
    description: "Burst of link-up/link-down style infrastructure events."
  },
  "R-INFRA-EAST-WEST-FLOW-SCAN": {
    label: "East-west flow scan",
    shortLabel: "EW scan",
    tone: "border-cyan-700/60 bg-cyan-950/70 text-cyan-100",
    description: "One internal source fanned out to multiple internal destinations on risky ports."
  },
  "R-INFRA-FIREWALL-CONFIG-CHANGE-OOW": {
    label: "Firewall config change outside window",
    shortLabel: "Config OOW",
    tone: "border-orange-700/60 bg-orange-950/70 text-orange-100",
    description: "Firewall or policy configuration changed outside the approved window."
  },
  "R-INFRA-POST-CONTAINMENT-BLOCK-VERIFY": {
    label: "Post-containment block verified",
    shortLabel: "Block verified",
    tone: "border-emerald-700/60 bg-emerald-950/70 text-emerald-100",
    description: "Infrastructure deny telemetry confirms a containment block is holding."
  }
};

export function isInfrastructureIncident(incident?: Incident | null): boolean {
  if (!incident) return false;
  if ((incident.category || "").toLowerCase() === "infrastructure") return true;
  if ((incident.rule_id || "").toUpperCase().startsWith("R-INFRA-")) return true;
  return INFRA_SOURCE_TYPES.includes((incident.source_type || "").toLowerCase() as (typeof INFRA_SOURCE_TYPES)[number]);
}

export function isInfrastructureEvent(event?: EventRow | null): boolean {
  if (!event) return false;
  if ((event.category || "").toLowerCase() === "infrastructure") return true;
  if ((event.rule_id || "").toUpperCase().startsWith("R-INFRA-")) return true;
  if (INFRA_SOURCE_TYPES.includes((event.source_type || "").toLowerCase() as (typeof INFRA_SOURCE_TYPES)[number])) return true;
  return INFRA_EVENT_TYPES.includes((event.event_type || "").toLowerCase() as (typeof INFRA_EVENT_TYPES)[number]);
}

export function infrastructureMetaForRule(ruleID?: string): InfraMeta | null {
  if (!ruleID) return null;
  return INFRA_RULE_META[ruleID] || null;
}

export function infrastructureBadgeClass(ruleID?: string): string {
  return infrastructureMetaForRule(ruleID)?.tone || "border-cyan-700/60 bg-cyan-950/70 text-cyan-100";
}

export function infrastructureLabel(ruleID?: string): string {
  return infrastructureMetaForRule(ruleID)?.label || "Infrastructure event";
}

export function infrastructureShortLabel(ruleID?: string): string {
  return infrastructureMetaForRule(ruleID)?.shortLabel || "Infrastructure";
}

export function infrastructureDescription(ruleID?: string): string {
  return infrastructureMetaForRule(ruleID)?.description || "Infrastructure telemetry from syslog, NetFlow, or SNMP sources.";
}
