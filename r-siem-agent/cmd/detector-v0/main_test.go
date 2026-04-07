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

func TestEnrichNetworkEventIdentityBackfillsExecContextWhenUserKnown(t *testing.T) {
	recentSuspiciousProcContext = newRecentProcessContextTracker(2 * time.Minute)
	recentSuspiciousProcContext.Observe("node-a", recentProcessContext{
		User:       "alice",
		ExecPath:   "/usr/bin/nmap",
		Comm:       "nmap",
		Cmdline:    "/usr/bin/nmap -Pn -n -p 5985 172.30.50.11",
		ObservedAt: 10_000,
	})

	enriched := enrichNetworkEventIdentity(rawEvent{
		EventType:        "network_connection",
		NodeID:           "node-a",
		User:             "alice",
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
	if enriched.Cmdline != "/usr/bin/nmap -Pn -n -p 5985 172.30.50.11" {
		t.Fatalf("expected cmdline to be inherited, got %q", enriched.Cmdline)
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
		EventType:  "network_connection",
		SourceType: "auditd_connect",
		NodeID:     "khotso-Latitude-5500",
		Host:       "khotso-Latitude-5500",
		User:       "khotso",
		ExecPath:   "/usr/bin/nmap",
		Comm:       "nmap",
		Cmdline:    "/usr/bin/nmap -Pn -n -sT -p 445 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14 172.30.50.15",
		DstPort:    445,
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
		EventType:  "network_connection",
		SourceType: "auditd_connect",
		NodeID:     "scanner-appliance-01",
		Host:       "scanner-appliance-01",
		User:       "admin",
		ExecPath:   "/usr/bin/nmap",
		Comm:       "nmap",
		Cmdline:    "/usr/bin/nmap -Pn -n -sT -p 445 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14 172.30.50.15",
		DstPort:    445,
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

func TestInfrastructureFirewallDenyBurstMatchesAtThreshold(t *testing.T) {
	cfg, err := config.LoadDetector("../../configs/detector.yaml")
	if err != nil {
		t.Fatalf("load detector config: %v", err)
	}
	resetDetectorRegressionState(cfg)

	base := rawEvent{
		EventType:        "syslog",
		SourceType:       "syslog",
		Host:             "fw-01",
		NodeID:           "collector-syslog",
		SrcIP:            "10.10.0.22",
		ObservedAtUnixMs: 0,
	}
	msg := "<134>Apr 07 20:00:00 fw-01 firewall policy denied src=10.30.0.11 dst=10.20.30.11 dpt=443"
	for i := 0; i < 4; i++ {
		evt := base
		evt.ObservedAtUnixMs = int64((i + 1) * 1000)
		match, ok := matchRule(msg, evt)
		if ok {
			t.Fatalf("unexpected early match at i=%d: %+v", i, match)
		}
	}

	final := base
	final.ObservedAtUnixMs = 5_000
	match, ok := matchRule(msg, final)
	if !ok {
		t.Fatal("expected firewall deny burst match")
	}
	if match.RuleID != infraFirewallDenyRuleID {
		t.Fatalf("rule_id=%q want %q", match.RuleID, infraFirewallDenyRuleID)
	}
	if match.GroupKey != "fw-01" {
		t.Fatalf("group_key=%q want fw-01", match.GroupKey)
	}
}

func TestInfrastructureNetworkAdminLoginMatchesAdminUser(t *testing.T) {
	cfg, err := config.LoadDetector("../../configs/detector.yaml")
	if err != nil {
		t.Fatalf("load detector config: %v", err)
	}
	resetDetectorRegressionState(cfg)

	evt := rawEvent{
		EventType:        "syslog",
		SourceType:       "syslog",
		Host:             "edge-rtr-01",
		NodeID:           "collector-syslog",
		SrcIP:            "10.10.0.21",
		ObservedAtUnixMs: 1_000,
	}
	msg := "<134>Apr 07 20:00:00 edge-rtr-01 sshd[123]: Accepted password for admin from 10.30.0.11 port 2222 ssh2"
	match, ok := matchRule(msg, evt)
	if !ok {
		t.Fatal("expected infrastructure admin login match")
	}
	if match.RuleID != infraNetworkAdminRuleID {
		t.Fatalf("rule_id=%q want %q", match.RuleID, infraNetworkAdminRuleID)
	}
	if match.GroupKey != "edge-rtr-01" {
		t.Fatalf("group_key=%q want edge-rtr-01", match.GroupKey)
	}
}

func TestInfrastructureLinkFlapBurstUsesRecentTrapCorroboration(t *testing.T) {
	cfg, err := config.LoadDetector("../../configs/detector.yaml")
	if err != nil {
		t.Fatalf("load detector config: %v", err)
	}
	resetDetectorRegressionState(cfg)

	trapEvt := rawEvent{
		EventType:        "snmp_trap",
		SourceType:       "snmp_trap",
		Host:             "sw-core-01",
		SrcIP:            "10.10.0.23",
		ObservedAtUnixMs: 500,
	}
	if match, ok := matchRule("snmp trap", trapEvt); ok {
		t.Fatalf("unexpected trap match: %+v", match)
	}

	base := rawEvent{
		EventType:  "syslog",
		SourceType: "syslog",
		Host:       "sw-core-01",
		NodeID:     "collector-syslog",
		SrcIP:      "10.10.0.23",
	}
	msg := "<134>Apr 07 20:00:00 sw-core-01 interface Gi0/1 changed state to down"
	for i := 0; i < 2; i++ {
		evt := base
		evt.ObservedAtUnixMs = int64((i + 1) * 1000)
		match, ok := matchRule(msg, evt)
		if ok {
			t.Fatalf("unexpected early link event match at i=%d: %+v", i, match)
		}
	}

	final := base
	final.ObservedAtUnixMs = 3_000
	match, ok := matchRule(msg, final)
	if !ok {
		t.Fatal("expected link flap burst match")
	}
	if match.RuleID != infraLinkFlapRuleID {
		t.Fatalf("rule_id=%q want %q", match.RuleID, infraLinkFlapRuleID)
	}
	if match.GroupKey != "sw-core-01" {
		t.Fatalf("group_key=%q want sw-core-01", match.GroupKey)
	}
	if match.ConfidenceScore != 84 {
		t.Fatalf("confidence=%d want 84", match.ConfidenceScore)
	}
}
