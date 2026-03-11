"use client";

export const INCIDENTS_UPDATED_EVENT = "rsiem:incidents-updated";
export const INCIDENT_MUTATED_EVENT = "rsiem:incident-mutated";
export const AUTH_REQUIRED_EVENT = "rsiem:auth-required";

export function emitIncidentsUpdated(detail?: Record<string, unknown>): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(INCIDENTS_UPDATED_EVENT, { detail }));
}

export function emitIncidentMutated(runID: string): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(INCIDENT_MUTATED_EVENT, { detail: { runID } }));
}

export function emitAuthRequired(detail?: { reason?: string }): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(AUTH_REQUIRED_EVENT, { detail }));
}
