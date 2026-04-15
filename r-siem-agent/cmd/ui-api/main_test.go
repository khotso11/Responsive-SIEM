package main

import (
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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
	_, _, rules, _, _, _, _, _, _, _, _, _ := loadDashboardHints(path)
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
	_, _, _, defaultEnv, assetsByNode, assetsByTarget, identities, _, _, _, _, _ := loadDashboardHints(path)
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

func TestBuildResponseActionRequestSupportsDNSDestination(t *testing.T) {
	template, ok := responseActionTemplateByID("block_matching_connections")
	if !ok {
		t.Fatalf("missing block_matching_connections template")
	}
	req, err := buildResponseActionRequest(
		template,
		"uiact_dns_1",
		"analyst",
		"run-1",
		"node-1",
		"node-1",
		incident{RunID: "run-1", NodeID: "node-1", DNSName: "proof-rsiem-demo.zip", DstIP: "104.18.32.47"},
		"",
		60000,
		"manual dns block",
		"case-1",
	)
	if err != nil {
		t.Fatalf("buildResponseActionRequest error: %v", err)
	}
	if req.command.ActionType != "network_block" {
		t.Fatalf("action_type=%q, want network_block", req.command.ActionType)
	}
	if req.command.Target != "proof-rsiem-demo.zip" {
		t.Fatalf("target=%q, want dns target", req.command.Target)
	}
	if got := strings.TrimSpace(strVal(req.command.Params["resolved_targets"])); got != "104.18.32.47" {
		t.Fatalf("resolved_targets=%q, want 104.18.32.47", got)
	}
}

func TestLoadDashboardHintsParsesLogicCatalog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.yaml")
	content := []byte(`policies:
  approvals:
    timeout_ms: 123000
    default_auto_min_confidence: 77
    rules:
      - id: "auto_within_bounds"
        when:
          mode_in: ["auto"]
          confidence_at_least_floor: true
        decision:
          required: false
          reason: "policy:auto_within_bounds"
playbooks:
  - id: "PB-NET-OUTBOUND-OBSERVE"
    version: 1
    enabled: true
    selectors:
      rule_ids: ["R-NET-OUTBOUND-CONNECTION"]
    policy_requirements:
      approval: "auto"
      max_blast_radius: 1
      auto_min_confidence: 65
    steps:
      - name: "notify_outbound_connection"
        action_type: "notify"
        reversibility: "reversible"
        timeout_ms: 2000
        retries: 0
        backoff_ms: 0
        target_from: "group_key"
        params:
          summary: "true"
rce:
  rules:
    - id: "R-NET-OUTBOUND-CONNECTION"
      enabled: true
      kind: trigger
      severity: medium
      group_by: src_ip
      when:
        type: network_connection
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, _, _, _, _, _, _, logicRules, logicPlaybooks, approvalRules, approvalTimeoutMs, defaultAutoMinConf := loadDashboardHints(path)
	if approvalTimeoutMs != 123000 {
		t.Fatalf("approvalTimeoutMs=%d, want 123000", approvalTimeoutMs)
	}
	if defaultAutoMinConf != 77 {
		t.Fatalf("defaultAutoMinConf=%d, want 77", defaultAutoMinConf)
	}
	rule, ok := logicRules["R-NET-OUTBOUND-CONNECTION"]
	if !ok {
		t.Fatalf("logic rule missing")
	}
	if rule.Kind != "trigger" || rule.WhenType != "network_connection" || rule.GroupBy != "src_ip" {
		t.Fatalf("logic rule parsed incorrectly: %+v", rule)
	}
	playbook, ok := logicPlaybooks["PB-NET-OUTBOUND-OBSERVE"]
	if !ok {
		t.Fatalf("logic playbook missing")
	}
	if playbook.ApprovalMode != "auto" || len(playbook.Steps) != 1 || len(playbook.Steps[0].ParamKeys) != 1 || playbook.Steps[0].ParamKeys[0] != "summary" {
		t.Fatalf("logic playbook parsed incorrectly: %+v", playbook)
	}
	approvalRule, ok := approvalRules["auto_within_bounds"]
	if !ok {
		t.Fatalf("approval rule missing")
	}
	if approvalRule.Reason != "policy:auto_within_bounds" || approvalRule.Required {
		t.Fatalf("approval rule parsed incorrectly: %+v", approvalRule)
	}
}

func TestBuildIncidentLogicUsesResolvedMetadata(t *testing.T) {
	a := &app{
		logicRulesByID: map[string]logicRuleDefinition{
			"R-NET-OUTBOUND-CONNECTION": {
				ID:         "R-NET-OUTBOUND-CONNECTION",
				Enabled:    true,
				Kind:       "trigger",
				Severity:   "medium",
				GroupBy:    "src_ip",
				WhenType:   "network_connection",
				Conditions: []string{"message_contains=connect"},
			},
		},
		logicPlaybooksByID: map[string]logicPlaybookDefinition{
			"PB-NET-OUTBOUND-OBSERVE": {
				ID:                "PB-NET-OUTBOUND-OBSERVE",
				Version:           1,
				Enabled:           true,
				SelectorRuleIDs:   []string{"R-NET-OUTBOUND-CONNECTION"},
				ApprovalMode:      "auto",
				AutoMinConfidence: 65,
				MaxBlastRadius:    1,
				Steps: []logicPlaybookStepDefinition{{
					Name:          "notify_outbound_connection",
					ActionType:    "notify",
					Reversibility: "reversible",
					ParamKeys:     []string{"summary"},
				}},
			},
		},
		approvalRulesByID: map[string]logicApprovalRuleDefinition{
			"auto_default": {
				ID:         "auto_default",
				Conditions: []string{"mode_in in [auto]"},
				Required:   false,
				Reason:     "policy:auto",
			},
		},
		approvalTimeoutMs:  300000,
		defaultAutoMinConf: 70,
	}
	resp := a.buildIncidentLogic(incident{
		RunID:                 "run-1",
		RuleID:                "R-NET-OUTBOUND-CONNECTION",
		PlaybookID:            "PB-NET-OUTBOUND-OBSERVE",
		ApprovalPolicyMode:    "auto",
		ApprovalPolicyRuleID:  "auto_default",
		ApprovalPolicyReason:  "policy:auto",
		PlaybookReversibility: "reversible",
		NodeID:                "node-1",
		SrcIP:                 "192.0.2.50",
		DstIP:                 "104.18.32.47",
	})
	if resp.Rule.ID != "R-NET-OUTBOUND-CONNECTION" || resp.Rule.Kind != "trigger" {
		t.Fatalf("rule logic wrong: %+v", resp.Rule)
	}
	if resp.Playbook.ID != "PB-NET-OUTBOUND-OBSERVE" || len(resp.Playbook.Steps) != 1 {
		t.Fatalf("playbook logic wrong: %+v", resp.Playbook)
	}
	if resp.Policy.ApprovalRule == nil || resp.Policy.ApprovalRule.ID != "auto_default" {
		t.Fatalf("policy logic wrong: %+v", resp.Policy)
	}
	if resp.Scope.SrcIP != "192.0.2.50" || resp.Scope.DstIP != "104.18.32.47" {
		t.Fatalf("scope wrong: %+v", resp.Scope)
	}
}

func TestParseEventSearchRequestDefaultsAndFilters(t *testing.T) {
	now := time.Date(2026, 3, 21, 15, 0, 0, 0, time.UTC)
	req := parseEventSearchRequest(url.Values{
		"node_id":     {"node-1"},
		"source_type": {"auditd_connect"},
		"limit":       {"999"},
		"page":        {"0"},
		"sort":        {"EVENT_ASC"},
	}, now)
	if req.Page != 1 {
		t.Fatalf("page=%d, want 1", req.Page)
	}
	if req.Limit != 500 {
		t.Fatalf("limit=%d, want 500", req.Limit)
	}
	if req.Sort != "event_asc" {
		t.Fatalf("sort=%q, want event_asc", req.Sort)
	}
	if req.FromMs != now.Add(-24*time.Hour).UnixMilli() || req.ToMs != now.UnixMilli() {
		t.Fatalf("default window wrong: from=%d to=%d", req.FromMs, req.ToMs)
	}
	if req.Filters == nil || req.Filters["node_id"] != "node-1" || req.Filters["source_type"] != "auditd_connect" {
		t.Fatalf("filters not populated correctly: %+v", req.Filters)
	}
}

func TestBuildEventSearchPredicatesIncludesExactAndFreeTextFilters(t *testing.T) {
	req := eventSearchRequest{
		Q:             "cloudflare",
		FromMs:        1000,
		ToMs:          2000,
		NodeID:        "node-1",
		UserName:      "khotso",
		SourceType:    "auditd_connect",
		RawLineSHA256: "abc123",
	}
	clauses, args := buildEventSearchPredicates(req)
	if len(args) != 7 {
		t.Fatalf("args=%d, want 7 (%v)", len(args), args)
	}
	joined := strings.Join(clauses, " AND ")
	for _, want := range []string{
		"recv_ts_unix_ms BETWEEN $1 AND $2",
		"node_id = $3",
		"COALESCE(user_name,'') = $4",
		"source_type = $5",
		"COALESCE(raw_line_sha256,'') = $6",
		"LOWER(COALESCE(node_id,'')) LIKE $7",
		"LOWER(COALESCE(raw_line_sha256,'')) LIKE $7",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("predicate missing %q in %s", want, joined)
		}
	}
	if args[6] != "%cloudflare%" {
		t.Fatalf("free text arg=%v, want %%cloudflare%%", args[6])
	}
}

func TestBuildEventSearchPredicatesIncludesInfrastructureCategory(t *testing.T) {
	req := eventSearchRequest{
		FromMs:   1000,
		ToMs:     2000,
		Category: "infrastructure",
	}
	clauses, args := buildEventSearchPredicates(req)
	if len(args) != 2 {
		t.Fatalf("args=%d, want 2 (%v)", len(args), args)
	}
	joined := strings.Join(clauses, " AND ")
	if !strings.Contains(joined, "COALESCE(rule_id,'') LIKE 'R-INFRA-%'") {
		t.Fatalf("infrastructure category predicate missing in %s", joined)
	}
	if !strings.Contains(joined, "source_type IN ('syslog','netflow_v5','snmp_trap')") {
		t.Fatalf("infrastructure source predicate missing in %s", joined)
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

func TestSameIPHostIgnoresCIDRDecorations(t *testing.T) {
	if !sameIPHost("172.30.50.11/32", "172.30.50.11") {
		t.Fatalf("sameIPHost should match host and /32 decorated form")
	}
	if sameIPHost("172.30.50.11/32", "172.30.50.12") {
		t.Fatalf("sameIPHost should not match different hosts")
	}
}

func TestParseEnabledProvidersLocalDedupesAndSorts(t *testing.T) {
	got := parseEnabledProvidersLocal(" virustotal , abuseipdb,virustotal , urlscan ")
	want := []string{"abuseipdb", "urlscan", "virustotal"}
	if !slices.Equal(got, want) {
		t.Fatalf("providers=%v, want %v", got, want)
	}
}

func TestLoadResponseHistoryCombinesMasterLogsStepsAndUIState(t *testing.T) {
	dir := t.TempDir()
	masterLog := filepath.Join(dir, "master.log")
	assignments := filepath.Join(dir, "assignments.jsonl")
	identity := filepath.Join(dir, "identity_actions.jsonl")
	if err := os.WriteFile(masterLog, []byte(""+
		"{\"time\":\"2026-03-21T10:00:00Z\",\"msg\":\"response_run_created\",\"run_id\":\"run-1\",\"status\":\"CREATED\"}\n"+
		"{\"time\":\"2026-03-21T10:00:05Z\",\"msg\":\"approval_approved\",\"run_id\":\"run-1\",\"actor\":\"analyst\",\"decision\":\"approve\"}\n"), 0o600); err != nil {
		t.Fatalf("write master log: %v", err)
	}
	if err := os.WriteFile(assignments, []byte("{\"ts\":\"2026-03-21T10:00:07Z\",\"action\":\"assign\",\"run_id\":\"run-1\",\"actor\":\"analyst\",\"assignee\":\"khotso\",\"status\":\"assigned\"}\n"), 0o600); err != nil {
		t.Fatalf("write assignments: %v", err)
	}
	if err := os.WriteFile(identity, []byte("{\"ts\":\"2026-03-21T10:00:09Z\",\"action\":\"verify_user\",\"run_id\":\"run-1\",\"actor\":\"analyst\",\"method\":\"phone\",\"reference\":\"ticket-1\",\"status\":\"verified\",\"result\":\"ok\"}\n"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	a := &app{cfg: serverConfig{MasterLogPath: masterLog, UIStateDir: dir}}
	items := a.loadResponseHistory(incident{RunID: "run-1", Status: "SUCCEEDED", LastUpdatedAtUnixMs: time.Date(2026, 3, 21, 10, 0, 10, 0, time.UTC).UnixMilli()}, []stepResult{{
		RunID:        "run-1",
		StepID:       "step-1",
		StepIndex:    0,
		Status:       "SUCCEEDED",
		ActionType:   "agent_command",
		FinishedAtMs: time.Date(2026, 3, 21, 10, 0, 8, 0, time.UTC).UnixMilli(),
	}})
	if len(items) < 5 {
		t.Fatalf("history items=%d, want at least 5", len(items))
	}
	labels := make([]string, 0, len(items))
	for _, item := range items {
		labels = append(labels, item.Label)
	}
	for _, want := range []string{"response run created", "approval approved", "Step 0 succeeded", "assign", "verify user"} {
		if !slices.Contains(labels, want) {
			t.Fatalf("history labels=%v, missing %q", labels, want)
		}
	}
	if items[0].TSUnixMs > items[len(items)-1].TSUnixMs {
		t.Fatalf("history is not sorted ascending by timestamp: first=%d last=%d", items[0].TSUnixMs, items[len(items)-1].TSUnixMs)
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
