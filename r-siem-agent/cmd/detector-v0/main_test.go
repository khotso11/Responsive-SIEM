package main

import (
	"testing"
	"time"

	"r-siem-agent/internal/config"
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

func TestInternalSMBScanRequiresFanoutThreshold(t *testing.T) {
	configPathCfg, err := config.LoadDetector("../../configs/detector.yaml")
	if err != nil {
		t.Fatalf("load detector config: %v", err)
	}
	resetDetectorRegressionState(configPathCfg)

	base := rawEvent{
		EventType: "network_connection",
		NodeID:    "node-a",
		Host:      "node-a",
		User:      "alice",
		SrcIP:     "10.0.0.15",
		DstPort:   445,
	}
	for i, dst := range []string{"10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.1.13"} {
		evt := base
		evt.DstIP = dst
		evt.ObservedAtUnixMs = int64((i + 1) * 1000)
		match, ok := matchRule("", evt)
		if ok {
			t.Fatalf("unexpected match before threshold: %+v", match)
		}
	}

	final := base
	final.DstIP = "10.0.1.14"
	final.ObservedAtUnixMs = 5_000
	match, ok := matchRule("", final)
	if !ok {
		t.Fatal("expected internal SMB scan match at threshold")
	}
	if match.RuleID != internalSMBScanRuleID {
		t.Fatalf("rule_id=%q want %q", match.RuleID, internalSMBScanRuleID)
	}
	if match.GroupKey != "node-a" {
		t.Fatalf("group_key=%q want node-a", match.GroupKey)
	}
	if match.ConfidenceScore != 90 {
		t.Fatalf("confidence=%d want 90", match.ConfidenceScore)
	}
}

func TestAuditdConnectInternalScanIsNotMisclassifiedAsProcess(t *testing.T) {
	configPathCfg, err := config.LoadDetector("../../configs/detector.yaml")
	if err != nil {
		t.Fatalf("load detector config: %v", err)
	}
	resetDetectorRegressionState(configPathCfg)

	base := rawEvent{
		EventType: "network_connection",
		SourceType: "auditd_connect",
		NodeID:    "khotso-Latitude-5500",
		Host:      "khotso-Latitude-5500",
		User:      "khotso",
		ExecPath:  "/usr/bin/nmap",
		Comm:      "nmap",
		Cmdline:   "/usr/bin/nmap -Pn -n -sT -p 445 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14 172.30.50.15",
		DstPort:   445,
	}

	for i, dst := range []string{"172.30.50.11", "172.30.50.12", "172.30.50.13", "172.30.50.14"} {
		evt := base
		evt.DstIP = dst
		evt.ObservedAtUnixMs = int64((i + 1) * 1000)
		match, ok := matchRule("", evt)
		if ok {
			t.Fatalf("unexpected match before threshold: %+v", match)
		}
	}

	final := base
	final.DstIP = "172.30.50.15"
	final.ObservedAtUnixMs = 5_000
	match, ok := matchRule("", final)
	if !ok {
		t.Fatal("expected internal SMB scan match at threshold")
	}
	if match.RuleID != internalSMBScanRuleID {
		t.Fatalf("rule_id=%q want %q", match.RuleID, internalSMBScanRuleID)
	}
	if match.ProtocolFamily != "smb" {
		t.Fatalf("protocol_family=%q want smb", match.ProtocolFamily)
	}
	if match.ScanFanout != 5 {
		t.Fatalf("scan_fanout=%d want 5", match.ScanFanout)
	}
}

func TestInternalScanApprovedSourceUsesUserAllowlistNotToolNameOnly(t *testing.T) {
	configPathCfg, err := config.LoadDetector("../../configs/detector.yaml")
	if err != nil {
		t.Fatalf("load detector config: %v", err)
	}
	resetDetectorRegressionState(configPathCfg)

	base := rawEvent{
		EventType: "network_connection",
		SourceType: "auditd_connect",
		NodeID:    "scanner-appliance-01",
		Host:      "scanner-appliance-01",
		User:      "admin",
		ExecPath:  "/usr/bin/nmap",
		Comm:      "nmap",
		Cmdline:   "/usr/bin/nmap -Pn -n -sT -p 445 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14 172.30.50.15",
		DstPort:   445,
	}

	for i, dst := range []string{"172.30.50.11", "172.30.50.12", "172.30.50.13", "172.30.50.14"} {
		evt := base
		evt.DstIP = dst
		evt.ObservedAtUnixMs = int64((i + 1) * 1000)
		match, ok := matchRule("", evt)
		if ok {
			t.Fatalf("unexpected match before threshold: %+v", match)
		}
	}

	final := base
	final.DstIP = "172.30.50.15"
	final.ObservedAtUnixMs = 5_000
	match, ok := matchRule("", final)
	if !ok {
		t.Fatal("expected approved internal scan match at threshold")
	}
	if match.RuleID != internalApprovedScanRuleID {
		t.Fatalf("rule_id=%q want %q", match.RuleID, internalApprovedScanRuleID)
	}
}
