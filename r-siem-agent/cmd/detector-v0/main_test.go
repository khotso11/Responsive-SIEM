package main

import (
	"testing"
	"time"
)

func TestEnrichNetworkEventIdentityFromRecentProcessContext(t *testing.T) {
	recentSuspiciousProcContext = newRecentProcessContextTracker(2 * time.Minute)
	recentSuspiciousProcContext.Observe("node-a", recentProcessContext{
		User:       "alice",
		ExecPath:   "/usr/bin/nmap",
		Comm:       "nmap",
		Cmdline:    "/usr/bin/nmap --version",
		ObservedAt: 10_000,
	})

	enriched := enrichNetworkEventIdentity(rawEvent{
		EventType:        "network_connection",
		NodeID:           "node-a",
		User:             "unknown",
		ObservedAtUnixMs: 10_500,
	})

	if enriched.User != "alice" {
		t.Fatalf("expected user alice, got %q", enriched.User)
	}
	if enriched.ExecPath != "/usr/bin/nmap" {
		t.Fatalf("expected exec_path to be inherited, got %q", enriched.ExecPath)
	}
	if enriched.Comm != "nmap" {
		t.Fatalf("expected comm to be inherited, got %q", enriched.Comm)
	}
	if enriched.Cmdline != "/usr/bin/nmap --version" {
		t.Fatalf("expected cmdline to be inherited, got %q", enriched.Cmdline)
	}
}

func TestEnrichNetworkEventIdentityDoesNotUseExpiredContext(t *testing.T) {
	recentSuspiciousProcContext = newRecentProcessContextTracker(2 * time.Minute)
	recentSuspiciousProcContext.Observe("node-a", recentProcessContext{
		User:       "alice",
		ExecPath:   "/usr/bin/nmap",
		Comm:       "nmap",
		Cmdline:    "/usr/bin/nmap --version",
		ObservedAt: 10_000,
	})

	enriched := enrichNetworkEventIdentity(rawEvent{
		EventType:        "network_connection",
		NodeID:           "node-a",
		User:             "unknown",
		ObservedAtUnixMs: 131_000,
	})

	if enriched.User != "unknown" {
		t.Fatalf("expected stale context to be ignored, got %q", enriched.User)
	}
	if enriched.ExecPath != "" || enriched.Comm != "" || enriched.Cmdline != "" {
		t.Fatalf("expected no process metadata from stale context, got exec=%q comm=%q cmdline=%q", enriched.ExecPath, enriched.Comm, enriched.Cmdline)
	}
}
