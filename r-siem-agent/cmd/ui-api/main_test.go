package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestApplyIncidentRetentionPolicyUsesServiceAccountRule(t *testing.T) {
	a := &app{
		retentionRules: []retentionRule{
			{
				ID:               "operational_service_account",
				ServiceAccount:   boolPtr(true),
				Class:            "operational_service_account",
				ArchiveAfterDays: 30,
				PurgeAfterDays:   365,
			},
			{
				ID:               "operational_standard",
				Class:            "operational_standard",
				ArchiveAfterDays: 30,
				PurgeAfterDays:   180,
			},
		},
	}
	run := incident{
		RunID:                  "svc-run",
		Status:                 "SUCCEEDED",
		User:                   "svc_telegraf",
		IdentityServiceAccount: true,
		LastUpdatedAtUnixMs:    1_000,
	}
	got := a.applyIncidentRetentionPolicy(run, 2_000)
	if got.RetentionRuleID != "operational_service_account" {
		t.Fatalf("retention_rule_id=%q, want operational_service_account", got.RetentionRuleID)
	}
	if got.RetentionClass != "operational_service_account" {
		t.Fatalf("retention_class=%q, want operational_service_account", got.RetentionClass)
	}
}

func TestApplyIncidentRetentionPolicyDoesNotTreatUnknownAsServiceAccount(t *testing.T) {
	a := &app{
		retentionRules: []retentionRule{
			{
				ID:               "operational_service_account",
				ServiceAccount:   boolPtr(true),
				Class:            "operational_service_account",
				ArchiveAfterDays: 30,
				PurgeAfterDays:   365,
			},
			{
				ID:               "operational_standard",
				Class:            "operational_standard",
				ArchiveAfterDays: 30,
				PurgeAfterDays:   180,
			},
		},
	}
	run := incident{
		RunID:                  "unknown-user-run",
		Status:                 "SUCCEEDED",
		User:                   "unknown",
		IdentityServiceAccount: true,
		LastUpdatedAtUnixMs:    1_000,
	}
	got := a.applyIncidentRetentionPolicy(run, 2_000)
	if got.RetentionRuleID != "operational_standard" {
		t.Fatalf("retention_rule_id=%q, want operational_standard", got.RetentionRuleID)
	}
	if got.RetentionClass != "operational_standard" {
		t.Fatalf("retention_class=%q, want operational_standard", got.RetentionClass)
	}
	if got.IdentityServiceAccount {
		t.Fatalf("identity_service_account=%v, want false after normalization", got.IdentityServiceAccount)
	}
	if incidentHighImpact(got) {
		t.Fatalf("incidentHighImpact(%+v)=true, want false for unknown service-account-like run", got)
	}
}

func TestApplyIncidentRetentionPolicyRecomputesStaleRetentionClass(t *testing.T) {
	a := &app{
		retentionRules: []retentionRule{
			{
				ID:               "operational_service_account",
				ServiceAccount:   boolPtr(true),
				Class:            "operational_service_account",
				ArchiveAfterDays: 30,
				PurgeAfterDays:   365,
			},
			{
				ID:               "operational_standard",
				Class:            "operational_standard",
				ArchiveAfterDays: 30,
				PurgeAfterDays:   180,
			},
		},
	}
	run := incident{
		RunID:                  "stale-retention-run",
		Status:                 "SUCCEEDED",
		User:                   "unknown",
		IdentityServiceAccount: true,
		RetentionRuleID:        "operational_service_account",
		RetentionClass:         "operational_service_account",
		ArchiveAfterDays:       30,
		PurgeAfterDays:         365,
		LastUpdatedAtUnixMs:    1_000,
	}
	got := a.applyIncidentRetentionPolicy(run, 2_000)
	if got.RetentionRuleID != "operational_standard" {
		t.Fatalf("retention_rule_id=%q, want operational_standard", got.RetentionRuleID)
	}
	if got.RetentionClass != "operational_standard" {
		t.Fatalf("retention_class=%q, want operational_standard", got.RetentionClass)
	}
	if got.PurgeAfterDays != 180 {
		t.Fatalf("purge_after_days=%d, want 180", got.PurgeAfterDays)
	}
}

func TestApplyIncidentRetentionPolicyUsesCriticalAssetRule(t *testing.T) {
	a := &app{
		retentionRules: []retentionRule{
			{
				ID:                 "operational_critical_asset",
				AssetCriticalityIn: []string{"critical"},
				Class:              "operational_critical_asset",
				ArchiveAfterDays:   30,
				PurgeAfterDays:     365,
			},
			{
				ID:               "operational_standard",
				Class:            "operational_standard",
				ArchiveAfterDays: 30,
				PurgeAfterDays:   180,
			},
		},
	}
	run := incident{
		RunID:               "critical-run",
		Status:              "FAILED_SAFE",
		AssetCriticality:    "critical",
		LastUpdatedAtUnixMs: 1_000,
	}
	got := a.applyIncidentRetentionPolicy(run, 2_000)
	if got.RetentionRuleID != "operational_critical_asset" {
		t.Fatalf("retention_rule_id=%q, want operational_critical_asset", got.RetentionRuleID)
	}
	if got.RetentionClass != "operational_critical_asset" {
		t.Fatalf("retention_class=%q, want operational_critical_asset", got.RetentionClass)
	}
}

func TestLoadDashboardHintsParsesRetentionRuleConditions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.yaml")
	content := []byte(`policies:
  retention:
    rules:
      - id: "operational_service_account"
        when:
          service_account: true
        decision:
          class: "operational_service_account"
          archive_after_days: 30
          purge_after_days: 365
      - id: "operational_critical_asset"
        when:
          asset_criticality_in: ["critical"]
        decision:
          class: "operational_critical_asset"
          archive_after_days: 30
          purge_after_days: 365
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, _, rules, _, _, _, _ := loadDashboardHints(path)
	if len(rules) != 2 {
		t.Fatalf("rules=%d, want 2", len(rules))
	}
	if rules[0].ServiceAccount == nil || !*rules[0].ServiceAccount {
		t.Fatalf("service_account rule not parsed correctly: %+v", rules[0])
	}
	if len(rules[1].AssetCriticalityIn) != 1 || rules[1].AssetCriticalityIn[0] != "critical" {
		t.Fatalf("asset_criticality_in rule not parsed correctly: %+v", rules[1])
	}
}

func TestLoadDashboardHintsParsesAssetAndIdentityInventory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.yaml")
	content := []byte(`policies:
  assets:
    default_environment: "lab"
    nodes:
      - node_id: "khotso-Latitude-5500"
        target_agent_id: "khotso-Latitude-5500"
        environment: "lab"
        criticality: "high"
        owner: "khotso"
        team: "security-engineering"
        role: "engineering-workstation"
  identity:
    users:
      - username: "khotso"
        display_name: "Khotso"
        department: "security-engineering"
        manager: "platform-security"
        privileged: true
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, _, _, defaultEnv, assetsByNode, assetsByTarget, identities := loadDashboardHints(path)
	if defaultEnv != "lab" {
		t.Fatalf("default environment=%q, want lab", defaultEnv)
	}
	asset, ok := assetsByNode["khotso-latitude-5500"]
	if !ok {
		t.Fatalf("asset inventory missing node lookup")
	}
	if asset.Criticality != "high" || asset.Owner != "khotso" {
		t.Fatalf("asset inventory parsed incorrectly: %+v", asset)
	}
	if _, ok := assetsByTarget["khotso-latitude-5500"]; !ok {
		t.Fatalf("asset inventory missing target-agent lookup")
	}
	identity, ok := identities["khotso"]
	if !ok {
		t.Fatalf("identity inventory missing user lookup")
	}
	if identity.DisplayName != "Khotso" || identity.Department != "security-engineering" || !identity.Privileged {
		t.Fatalf("identity inventory parsed incorrectly: %+v", identity)
	}
}

func TestParseAuditLogKeepsCorroborationEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.log")
	content := []byte("{\"time\":\"2026-03-15T09:31:15Z\",\"msg\":\"response_run_corroborated\",\"run_id\":\"run-1\",\"source_type\":\"auditd_connect\",\"dst_ip\":\"172.30.50.13\",\"dst_port\":5985}\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	entries := parseAuditLog(path, "master")
	if len(entries) != 1 {
		t.Fatalf("entries=%d, want 1", len(entries))
	}
	if entries[0].Msg != "response_run_corroborated" {
		t.Fatalf("msg=%q, want response_run_corroborated", entries[0].Msg)
	}
}

func TestLoadIncidentAnnotationsReturnsCorroborationForRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.log")
	content := []byte("" +
		"{\"time\":\"2026-03-15T09:31:15Z\",\"msg\":\"response_run_corroborated\",\"run_id\":\"run-1\",\"source_type\":\"auditd_connect\",\"dst_ip\":\"172.30.50.13\",\"dst_port\":5985}\n" +
		"{\"time\":\"2026-03-15T09:31:16Z\",\"msg\":\"response_run_corroborated\",\"run_id\":\"run-2\",\"source_type\":\"auditd_connect\",\"dst_ip\":\"172.30.50.14\",\"dst_port\":3389}\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	a := &app{cfg: serverConfig{MasterLogPath: path}}
	annotations := a.loadIncidentAnnotations("run-1")
	if len(annotations) != 1 {
		t.Fatalf("annotations=%d, want 1", len(annotations))
	}
	if annotations[0].RunID != "run-1" {
		t.Fatalf("run_id=%q, want run-1", annotations[0].RunID)
	}
	if annotations[0].Msg != "response_run_corroborated" {
		t.Fatalf("msg=%q, want response_run_corroborated", annotations[0].Msg)
	}
}

func TestEnrichIncidentFromInventoryUsesNodeAndUserFallback(t *testing.T) {
	a := &app{
		defaultAssetEnv: "lab",
		assetByNodeID: map[string]assetInventoryEntry{
			"khotso-latitude-5500": {
				Environment: "lab",
				Criticality: "high",
				Owner:       "khotso",
				Team:        "security-engineering",
				Role:        "engineering-workstation",
			},
		},
		assetByTargetAgent: map[string]assetInventoryEntry{},
		identityByUser: map[string]identityInventoryEntry{
			"khotso": {
				DisplayName: "Khotso",
				Department:  "security-engineering",
				Manager:     "platform-security",
				Privileged:  true,
			},
		},
	}
	run := incident{
		RunID:  "run-1",
		NodeID: "khotso-Latitude-5500",
		User:   "khotso",
	}
	got := a.enrichIncidentFromInventory(run)
	if got.AssetEnvironment != "lab" || got.AssetCriticality != "high" || got.AssetOwner != "khotso" {
		t.Fatalf("asset enrichment failed: %+v", got)
	}
	if got.AssetTeam != "security-engineering" || got.AssetRole != "engineering-workstation" {
		t.Fatalf("asset enrichment incomplete: %+v", got)
	}
	if got.IdentityDisplayName != "Khotso" || got.IdentityDepartment != "security-engineering" || got.IdentityManager != "platform-security" {
		t.Fatalf("identity enrichment failed: %+v", got)
	}
	if !got.IdentityPrivileged {
		t.Fatalf("identity privileged flag not preserved: %+v", got)
	}
}

func TestDeriveIncidentConfidenceUsesEvidenceFactors(t *testing.T) {
	bare := deriveIncidentConfidence(incident{
		Severity:   "high",
		SourceType: "proc_net",
		EventType:  "network_connection",
		User:       "unknown",
		DstIP:      "93.184.216.13",
		Lane:       "STANDARD",
	})
	rich := deriveIncidentConfidence(incident{
		Severity:   "high",
		SourceType: "auditd_exec",
		EventType:  "process_exec",
		User:       "alice",
		ExecPath:   "/usr/bin/nmap",
		Comm:       "nmap",
		Cmdline:    "/usr/bin/nmap --version",
		Lane:       "FAST",
	})
	if rich <= bare {
		t.Fatalf("rich confidence=%d, want greater than bare=%d", rich, bare)
	}
	if bare >= 80 {
		t.Fatalf("bare confidence=%d, want less than old hardcoded-high default", bare)
	}
}

func TestBuildRunObservablesIncludesHashesDomainsAndURLs(t *testing.T) {
	run := incident{
		SrcIP:      "10.0.0.8",
		DstIP:      "104.18.32.47",
		ExecSHA256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		FileSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		DNSName:    "api.example.com",
		Target:     "https://portal.example.com/login",
		Cmdline:    `curl https://download.example.net/tool.sh`,
	}

	obs := buildRunObservables(run)
	var got []string
	for _, item := range obs {
		got = append(got, string(item.Kind)+":"+item.Value)
	}

	want := []string{
		"ip:104.18.32.47",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"domain:api.example.com",
		"url:https://portal.example.com/login",
		"domain:portal.example.com",
		"url:https://download.example.net/tool.sh",
		"domain:download.example.net",
	}
	for _, candidate := range want {
		if !slices.Contains(got, candidate) {
			t.Fatalf("missing observable %q in %v", candidate, got)
		}
	}
	for _, item := range got {
		if item == "ip:10.0.0.8" {
			t.Fatalf("unexpected private IP observable in %v", got)
		}
	}
}

func TestBuildRunObservablesRejectsInvalidHashesAndDomains(t *testing.T) {
	run := incident{
		ExecSHA256: "not-a-hash",
		FileSHA256: "short",
		DNSName:    "172.30.50.14",
		Target:     "not a url",
		Cmdline:    "echo example",
	}

	obs := buildRunObservables(run)
	if len(obs) != 0 {
		t.Fatalf("observables=%v, want empty for invalid inputs", obs)
	}
}
