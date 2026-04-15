package main

import "testing"

func TestParseROEConfigApprovalsTimeout(t *testing.T) {
	data := []byte("policies:\n  approvals:\n    timeout_ms: 300000\n  assets:\n    default_environment: lab\n  identity:\n    users:\n      - user_name: admin\n        privileged: true\n")
	cfg, err := parseROEConfig(data)
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	if cfg.Policies.Approvals.TimeoutMs != 300000 {
		t.Fatalf("expected approvals timeout 300000, got %d", cfg.Policies.Approvals.TimeoutMs)
	}
	if cfg.Policies.Approvals.DefaultAutoMinConfidence != 70 {
		t.Fatalf("expected default auto confidence 70, got %d", cfg.Policies.Approvals.DefaultAutoMinConfidence)
	}
	if len(cfg.Policies.Approvals.Rules) == 0 {
		t.Fatalf("expected default approval rules to be populated")
	}
	if len(cfg.Policies.Guardrails.Rules) == 0 {
		t.Fatalf("expected default guardrail rules to be populated")
	}
	if len(cfg.Policies.SafeMode.Rules) == 0 {
		t.Fatalf("expected default safe mode rules to be populated")
	}
	if cfg.Policies.Assets.DefaultEnvironment != "lab" {
		t.Fatalf("expected assets default environment lab, got %q", cfg.Policies.Assets.DefaultEnvironment)
	}
	if len(cfg.Policies.Identity.Users) != 1 || cfg.Policies.Identity.Users[0].UserName != "admin" || !cfg.Policies.Identity.Users[0].Privileged {
		t.Fatalf("expected identity inventory user admin to be parsed")
	}
}

func TestEvaluateApprovalUsesConfiguredRules(t *testing.T) {
	data := []byte(`
policies:
  approvals:
    timeout_ms: 300000
    rules:
      - id: "force_auto_for_test"
        when:
          mode_in: ["required_for_high"]
        decision:
          required: false
          reason: "test:forced_auto"
  safe_mode:
    require_approval_when_degraded: true
`)
	cfg, err := parseROEConfig(data)
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	rt := &roeRuntime{cfg: cfg}
	playbook := roePlaybook{
		ID: "PB-TEST",
		PolicyRequirements: roePolicyRequirements{
			Approval: "required_for_high",
		},
		Steps: []roeStep{{Reversibility: "reversible"}},
	}
	trigger := responseTrigger{UserName: "alice", SrcIP: "10.0.0.8"}
	decision := rt.evaluateApproval(playbook, trigger, "high", 80)
	if decision.Required {
		t.Fatalf("decision.Required=%v, want false", decision.Required)
	}
	if decision.Reason != "test:forced_auto" {
		t.Fatalf("decision.Reason=%q, want test:forced_auto", decision.Reason)
	}
	if decision.RuleID != "force_auto_for_test" {
		t.Fatalf("decision.RuleID=%q, want force_auto_for_test", decision.RuleID)
	}
}

func TestEvaluateApprovalDefaultRulesPreserveLocalSourceEscalation(t *testing.T) {
	cfg, err := parseROEConfig([]byte("policies:\n  approvals:\n    timeout_ms: 300000\n"))
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	rt := &roeRuntime{cfg: cfg}
	playbook := roePlaybook{
		ID: "PB-TEST",
		PolicyRequirements: roePolicyRequirements{
			Approval:                   "auto",
			RequireApprovalForLocalSrc: true,
		},
		Steps: []roeStep{{Reversibility: "reversible"}},
	}
	trigger := responseTrigger{SrcIP: "127.0.0.1"}
	decision := rt.evaluateApproval(playbook, trigger, "low", 90)
	if !decision.Required {
		t.Fatalf("decision.Required=%v, want true", decision.Required)
	}
	if decision.Reason != "policy:local_source" {
		t.Fatalf("decision.Reason=%q, want policy:local_source", decision.Reason)
	}
}

func TestEvaluateApprovalUsesIdentityInventoryForPrivilege(t *testing.T) {
	cfg, err := parseROEConfig([]byte(`
policies:
  approvals:
    timeout_ms: 300000
  identity:
    users:
      - user_name: svc-breakglass
        privileged: true
`))
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	rt := &roeRuntime{cfg: cfg}
	playbook := roePlaybook{
		ID: "PB-TEST",
		PolicyRequirements: roePolicyRequirements{
			Approval:                     "auto",
			RequireApprovalForPrivileged: true,
		},
		Steps: []roeStep{{Reversibility: "reversible"}},
	}
	trigger := responseTrigger{UserName: "svc-breakglass", SrcIP: "10.0.0.8"}
	decision := rt.evaluateApproval(playbook, trigger, "medium", 90)
	if !decision.Required {
		t.Fatalf("decision.Required=%v, want true", decision.Required)
	}
	if decision.RuleID != "privileged_identity_review" {
		t.Fatalf("decision.RuleID=%q, want privileged_identity_review", decision.RuleID)
	}
}

func TestBuildROEDBRecordPreservesSearchableEventContext(t *testing.T) {
	rec := buildROEDBRecord(responseTrigger{
		NodeID:         "node-1",
		SourceType:     "auditd_connect",
		EventType:      "network_connection",
		SrcIP:          "172.30.50.1",
		DstIP:          "172.30.50.14",
		DstPort:        5985,
		ProtocolFamily: "winrm",
		UserName:       "khotso",
		Severity:       "high",
		RuleID:         "R-NET-INTERNAL-WINRM-SCAN",
		ExecPath:       "/usr/bin/nmap",
		Comm:           "nmap",
		Cmdline:        "/usr/bin/nmap -Pn -n -p 5985 172.30.50.14",
		DNSName:        "dc.lab.internal",
		FileSHA256:     "file-sha",
		ExecSHA256:     "exec-sha",
		EventIdemKey:   "evt-1",
	}, []byte(`{"msg":"proof"}`))
	if rec.DstPort != 5985 || rec.ProtocolFamily != "winrm" {
		t.Fatalf("network context not preserved: %+v", rec)
	}
	if rec.ExecPath != "/usr/bin/nmap" || rec.Comm != "nmap" || rec.Cmdline == "" {
		t.Fatalf("process context not preserved: %+v", rec)
	}
	if rec.DNSName != "dc.lab.internal" || rec.FileSHA256 != "file-sha" || rec.ExecSHA256 != "exec-sha" {
		t.Fatalf("observable context not preserved: %+v", rec)
	}
	if rec.RawLineSHA256 == "" {
		t.Fatalf("raw_line_sha256 missing: %+v", rec)
	}
}

func TestNormalizedEventInsertArgsPreserveSearchableContext(t *testing.T) {
	args := normalizedEventInsertArgs(roeDBRecord{
		EventTsUnixMs:  1,
		RecvTsUnixMs:   2,
		NodeID:         "node-1",
		SourceType:     "proc_net",
		EventType:      "network_connection",
		SrcIP:          "172.30.50.1",
		DstIP:          "172.30.50.14",
		DstPort:        5985,
		ProtocolFamily: "winrm",
		UserName:       "khotso",
		Severity:       "high",
		RuleID:         "R-NET-INTERNAL-WINRM-SCAN",
		ExecPath:       "/usr/bin/nmap",
		Comm:           "nmap",
		Cmdline:        "/usr/bin/nmap -Pn -n -p 5985 172.30.50.14",
		DNSName:        "dc.lab.internal",
		FileSHA256:     "file-sha",
		ExecSHA256:     "exec-sha",
		EventIdemKey:   "evt-1",
		RawLineSHA256:  "raw-1",
	})
	if got := args[7]; got != 5985 {
		t.Fatalf("dst_port arg=%v, want 5985", got)
	}
	if got := args[8]; got != "winrm" {
		t.Fatalf("protocol_family arg=%v, want winrm", got)
	}
	if got := args[12]; got != "/usr/bin/nmap" {
		t.Fatalf("exec_path arg=%v, want /usr/bin/nmap", got)
	}
	if got := args[13]; got != "nmap" {
		t.Fatalf("comm arg=%v, want nmap", got)
	}
	if got := args[14]; got != "/usr/bin/nmap -Pn -n -p 5985 172.30.50.14" {
		t.Fatalf("cmdline arg=%v", got)
	}
	if got := args[15]; got != "dc.lab.internal" {
		t.Fatalf("dns_name arg=%v, want dc.lab.internal", got)
	}
}

func TestEvaluateApprovalUsesCriticalAssetRule(t *testing.T) {
	cfg, err := parseROEConfig([]byte(`
policies:
  approvals:
    timeout_ms: 300000
  assets:
    nodes:
      - node_id: crown-jewel-01
        criticality: critical
`))
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	rt := &roeRuntime{cfg: cfg}
	playbook := roePlaybook{
		ID: "PB-TEST",
		PolicyRequirements: roePolicyRequirements{
			Approval: "auto",
		},
		Steps: []roeStep{{Reversibility: "reversible"}},
	}
	trigger := responseTrigger{NodeID: "crown-jewel-01", SrcIP: "10.0.0.8", UserName: "alice"}
	decision := rt.evaluateApproval(playbook, trigger, "low", 95)
	if !decision.Required {
		t.Fatalf("decision.Required=%v, want true", decision.Required)
	}
	if decision.RuleID != "critical_asset_review" {
		t.Fatalf("decision.RuleID=%q, want critical_asset_review", decision.RuleID)
	}
}

func TestEvaluateApprovalUsesServiceAccountRule(t *testing.T) {
	cfg, err := parseROEConfig([]byte(`
policies:
  approvals:
    timeout_ms: 300000
  identity:
    users:
      - user_name: svc-backup
        service_account: true
`))
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	rt := &roeRuntime{cfg: cfg}
	playbook := roePlaybook{
		ID: "PB-TEST",
		PolicyRequirements: roePolicyRequirements{
			Approval: "auto",
		},
		Steps: []roeStep{{Reversibility: "reversible"}},
	}
	trigger := responseTrigger{UserName: "svc-backup", SrcIP: "10.0.0.8"}
	decision := rt.evaluateApproval(playbook, trigger, "low", 95)
	if !decision.Required {
		t.Fatalf("decision.Required=%v, want true", decision.Required)
	}
	if decision.RuleID != "service_account_review" {
		t.Fatalf("decision.RuleID=%q, want service_account_review", decision.RuleID)
	}
}

func TestEnrichRunContextAddsAssetAndIdentityMetadata(t *testing.T) {
	cfg, err := parseROEConfig([]byte(`
policies:
  assets:
    default_environment: operational
    nodes:
      - node_id: work-01
        environment: prod
        criticality: critical
        owner: alice
        team: secops
        role: payment-host
  identity:
    users:
      - user_name: alice
        display_name: Alice Example
        department: finance
        manager: bob
        privileged: true
        service_account: false
`))
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	rt := &roeRuntime{cfg: cfg}
	run := runRecord{NodeID: "work-01", UserName: "alice"}
	rt.enrichRunContext(&run)
	if run.AssetEnvironment != "prod" || run.AssetCriticality != "critical" || run.AssetOwner != "alice" || run.AssetTeam != "secops" || run.AssetRole != "payment-host" {
		t.Fatalf("unexpected asset context: %+v", run)
	}
	if run.IdentityDisplayName != "Alice Example" || run.IdentityDepartment != "finance" || run.IdentityManager != "bob" || !run.IdentityPrivileged || run.IdentityServiceAccount {
		t.Fatalf("unexpected identity context: %+v", run)
	}
}

func TestShouldRecordCorroborationOnlyForAuditdConnect(t *testing.T) {
	if shouldRecordCorroboration("", responseTrigger{SourceType: "auditd_connect"}) {
		t.Fatalf("empty run_id should not record corroboration")
	}
	if shouldRecordCorroboration("run-1", responseTrigger{SourceType: "proc_net"}) {
		t.Fatalf("proc_net should not record corroboration")
	}
	if !shouldRecordCorroboration("run-1", responseTrigger{SourceType: "auditd_connect"}) {
		t.Fatalf("auditd_connect should record corroboration")
	}
}

func TestBuildCorroborationDedupeKeyFallsBackWithoutEventId(t *testing.T) {
	key := buildCorroborationDedupeKey("run-1", responseTrigger{
		SourceType:     "auditd_connect",
		DstIP:          "172.30.50.14",
		DstPort:        5985,
		ProtocolFamily: "winrm",
		ExecPath:       "/usr/bin/nmap",
		Cmdline:        "/usr/bin/nmap -Pn -n",
	})
	if key == "" {
		t.Fatalf("expected non-empty corroboration dedupe key")
	}
}

func TestFailedSafeRunIncludesReasonAndOperatorAction(t *testing.T) {
	run := runRecord{
		RunID:     "run-1",
		StepTotal: 2,
		Status:    "RUNNING",
		StepStatuses: map[string]string{
			"step-1": "SUCCEEDED",
		},
	}
	result := stepResult{
		RunID:      "run-1",
		StepID:     "step-2",
		StepIndex:  1,
		ActionType: "agent_command",
		Lane:       "FAST",
		Status:     "FAILED_SAFE",
		Attempt:    1,
	}

	updateRunWithResult(&run, result)

	if run.Status != "FAILED_SAFE" {
		t.Fatalf("run status=%q, want FAILED_SAFE", run.Status)
	}
	if run.FailedSafeReason != "rollback_step_failed" {
		t.Fatalf("failed_safe_reason=%q, want rollback_step_failed", run.FailedSafeReason)
	}
	if got := operatorActionForRun(run); got != "manual_restore_check_recommended" {
		t.Fatalf("operator_action=%q, want manual_restore_check_recommended", got)
	}
}

func TestUpdateRunWithResultAuditEnrichment(t *testing.T) {
	run := runRecord{
		RunID:        "run-2",
		StepTotal:    1,
		Status:       "RUNNING",
		StepStatuses: map[string]string{},
	}
	result := stepResult{
		RunID:            "run-2",
		StepID:           "step-1",
		StepIndex:        0,
		ActionType:       "agent_command",
		Lane:             "FAST",
		Status:           "SUCCEEDED",
		Attempt:          1,
		FinishedAtUnixMs: 123456789,
		Actor:            "khotso",
		Target:           "agent:dev-instance",
	}

	updateRunWithResult(&run, result)

	if run.ApprovalActor != "khotso" {
		t.Fatalf("approval_actor=%q, want khotso", run.ApprovalActor)
	}
	if run.Target != "agent:dev-instance" {
		t.Fatalf("target=%q, want agent:dev-instance", run.Target)
	}
	if run.LastUpdatedAtUnixMs <= 0 {
		t.Fatalf("last_updated_at_unix_ms=%d, want >0", run.LastUpdatedAtUnixMs)
	}
	if run.StepSucceededCount != 1 || run.Status != "SUCCEEDED" {
		t.Fatalf("unexpected run aggregate: status=%q succeeded=%d", run.Status, run.StepSucceededCount)
	}
}

func TestCompileStepsGuardrailRequiresIdentityContext(t *testing.T) {
	cfg, err := parseROEConfig([]byte("policies:\n  approvals:\n    timeout_ms: 300000\n"))
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	playbook := roePlaybook{
		ID: "PB-AUTH-CONTAIN",
		PolicyRequirements: roePolicyRequirements{
			RequireIdentityContext: true,
		},
		Steps: []roeStep{
			{
				ActionType: "agent_command",
				TargetFrom: "global",
				Params: map[string]any{
					"command":     "auth_contain_user_access",
					"duration_ms": 99999999,
				},
			},
		},
	}
	trigger := responseTrigger{
		Lane:     "FAST",
		NodeID:   "node-1",
		UserName: "alice",
	}

	_, err = compileSteps("run-identity", trigger, playbook, cfg, nil)
	if err == nil {
		t.Fatal("expected missing identity context error")
	}
	if got := err.Error(); got != "missing_identity_context:src_ip" {
		t.Fatalf("compileSteps error=%q, want missing_identity_context:src_ip", got)
	}
}

func TestCompileStepsAppliesGuardrailDurationNormalization(t *testing.T) {
	cfg, err := parseROEConfig([]byte(`
policies:
  approvals:
    timeout_ms: 300000
  identity:
    default_containment_duration_ms: 900000
    max_containment_duration_ms: 1800000
  guardrails:
    rules:
      - id: "test_normalize_auth_containment"
        when:
          action_type_in: ["agent_command"]
          command_prefix: "auth_contain_"
        apply:
          normalize_containment_duration: true
          default_duration_ms: 600000
          max_duration_ms: 1200000
`))
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	playbook := roePlaybook{
		ID: "PB-AUTH-CONTAIN",
		PolicyRequirements: roePolicyRequirements{
			RequireIdentityContext: true,
		},
		Steps: []roeStep{
			{
				ActionType: "agent_command",
				TargetFrom: "global",
				Params: map[string]any{
					"command":     "auth_contain_src_ip",
					"duration_ms": 99999999,
				},
			},
		},
	}
	trigger := responseTrigger{
		Lane:     "FAST",
		NodeID:   "node-1",
		SrcIP:    "10.0.0.7",
		UserName: "alice",
	}

	steps, err := compileSteps("run-duration", trigger, playbook, cfg, nil)
	if err != nil {
		t.Fatalf("compileSteps error: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("len(steps)=%d, want 1", len(steps))
	}
	if got := normalizeDurationValue(steps[0].Params["duration_ms"]); got != 1200000 {
		t.Fatalf("duration_ms=%d, want 1200000", got)
	}
	if len(steps[0].GuardrailRuleIDs) != 1 || steps[0].GuardrailRuleIDs[0] != "test_normalize_auth_containment" {
		t.Fatalf("guardrail_rule_ids=%v, want [test_normalize_auth_containment]", steps[0].GuardrailRuleIDs)
	}
}

func TestCompileStepsDoesNotApplyIdentityGuardrailToNotify(t *testing.T) {
	cfg, err := parseROEConfig([]byte(`
policies:
  approvals:
    timeout_ms: 300000
`))
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	playbook := roePlaybook{
		ID: "PB-NOTIFY-ONLY",
		PolicyRequirements: roePolicyRequirements{
			RequireIdentityContext: true,
		},
		Steps: []roeStep{
			{ActionType: "notify", TargetFrom: "global"},
		},
	}
	trigger := responseTrigger{Lane: "FAST"}
	steps, err := compileSteps("run-notify", trigger, playbook, cfg, nil)
	if err != nil {
		t.Fatalf("compileSteps error: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("len(steps)=%d, want 1", len(steps))
	}
	if len(steps[0].GuardrailRuleIDs) != 0 {
		t.Fatalf("guardrail_rule_ids=%v, want empty", steps[0].GuardrailRuleIDs)
	}
}

func TestApplyAllowlistUsesDeclarativeRules(t *testing.T) {
	cfg, err := parseROEConfig([]byte(`
policies:
  approvals:
    timeout_ms: 300000
  action_allowlist:
    rules:
      - id: "allow_notify"
        when:
          action_type_in: ["notify"]
        decision:
          allowed: true
`))
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	rt := &roeRuntime{cfg: cfg}
	playbook := roePlaybook{
		ID: "PB-TEST",
		Steps: []roeStep{
			{ActionType: "notify"},
			{ActionType: "agent_command"},
		},
	}
	err = rt.applyAllowlist(playbook)
	if err == nil {
		t.Fatal("expected allowlist rejection for agent_command")
	}
	if got := err.Error(); got != "action_not_allowed:agent_command:no_matching_rule" {
		t.Fatalf("allowlist error=%q, want action_not_allowed:agent_command:no_matching_rule", got)
	}
}

func TestCompileStepsIncludesAllowlistRuleID(t *testing.T) {
	cfg, err := parseROEConfig([]byte(`
policies:
  approvals:
    timeout_ms: 300000
  action_allowlist:
    rules:
      - id: "allow_auth_abuse_containment_commands"
        when:
          playbook_ids: ["PB-AUTH-ABUSE-CONTAIN"]
          action_type_in: ["agent_command"]
          command_prefix: "auth_contain_"
        decision:
          allowed: true
      - id: "deny_auth_abuse_other_agent_commands"
        when:
          playbook_ids: ["PB-AUTH-ABUSE-CONTAIN"]
          action_type_in: ["agent_command"]
        decision:
          allowed: false
`))
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	playbook := roePlaybook{
		ID: "PB-AUTH-ABUSE-CONTAIN",
		Steps: []roeStep{
			{
				ActionType: "agent_command",
				TargetFrom: "global",
				Params:     map[string]any{"command": "auth_contain_src_ip"},
			},
		},
	}
	rt := &roeRuntime{cfg: cfg}
	decisions, err := rt.evaluatePlaybookAllowlist(playbook)
	if err != nil {
		t.Fatalf("evaluatePlaybookAllowlist error: %v", err)
	}
	steps, err := compileSteps("run-allowlist", responseTrigger{Lane: "FAST"}, playbook, cfg, decisions)
	if err != nil {
		t.Fatalf("compileSteps error: %v", err)
	}
	if got := steps[0].AllowlistRuleID; got != "allow_auth_abuse_containment_commands" {
		t.Fatalf("allowlist_rule_id=%q, want allow_auth_abuse_containment_commands", got)
	}
}

func TestCompileStepsCarriesTargetAgentID(t *testing.T) {
	cfg, err := parseROEConfig([]byte("policies:\n  approvals:\n    timeout_ms: 300000\n"))
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	playbook := roePlaybook{
		ID: "PB-INFRA-EAST-WEST-FLOW-SCAN-NOTIFY",
		Steps: []roeStep{
			{
				ActionType:    "network_block",
				TargetFrom:    "group_key",
				TargetAgentID: "{target_agent_id}",
				Params:        map[string]any{"direction": "both"},
			},
		},
	}
	trigger := responseTrigger{
		Lane:          "FAST",
		GroupKey:      "10.44.1.25",
		TargetAgentID: "gateway-lnx-01",
	}
	steps, err := compileSteps("run-target", trigger, playbook, cfg, nil)
	if err != nil {
		t.Fatalf("compileSteps error: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("len(steps)=%d, want 1", len(steps))
	}
	if got := steps[0].TargetAgentID; got != "gateway-lnx-01" {
		t.Fatalf("target_agent_id=%q, want gateway-lnx-01", got)
	}
	if got := steps[0].Target; got != "10.44.1.25" {
		t.Fatalf("target=%q, want 10.44.1.25", got)
	}
}

func TestApplyAllowlistRejectsWrongCommandFamilyForPlaybook(t *testing.T) {
	cfg, err := parseROEConfig([]byte(`
policies:
  approvals:
    timeout_ms: 300000
  action_allowlist:
    rules:
      - id: "allow_proc_first_seen_containment_commands"
        when:
          playbook_ids: ["PB-PROC-FIRST-SEEN-CONTAIN"]
          action_type_in: ["agent_command"]
          command_prefix: "contain_process_"
        decision:
          allowed: true
      - id: "deny_proc_first_seen_other_agent_commands"
        when:
          playbook_ids: ["PB-PROC-FIRST-SEEN-CONTAIN"]
          action_type_in: ["agent_command"]
        decision:
          allowed: false
`))
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	rt := &roeRuntime{cfg: cfg}
	playbook := roePlaybook{
		ID: "PB-PROC-FIRST-SEEN-CONTAIN",
		Steps: []roeStep{
			{
				ActionType: "agent_command",
				TargetFrom: "global",
				Params:     map[string]any{"command": "auth_contain_src_ip"},
			},
		},
	}
	err = rt.applyAllowlist(playbook)
	if err == nil {
		t.Fatal("expected allowlist rejection for wrong command family")
	}
	if got := err.Error(); got != "action_not_allowed:agent_command:deny_proc_first_seen_other_agent_commands" {
		t.Fatalf("allowlist error=%q, want action_not_allowed:agent_command:deny_proc_first_seen_other_agent_commands", got)
	}
}

func TestApplyAllowlistRestrictsHighImpactPlaybookCommandFamilies(t *testing.T) {
	cfg, err := loadROEConfig("../../configs/master.yaml")
	if err != nil {
		t.Fatalf("loadROEConfig error: %v", err)
	}
	rt := &roeRuntime{cfg: cfg}
	tests := []struct {
		name      string
		playbook  string
		command   string
		wantError string
	}{
		{
			name:     "privesc lockdown allowed family",
			playbook: "PB-PRIVESC-LOCKDOWN",
			command:  "lockdown_privesc",
		},
		{
			name:      "privesc lockdown wrong family denied",
			playbook:  "PB-PRIVESC-LOCKDOWN",
			command:   "halt_lateral_movement",
			wantError: "action_not_allowed:agent_command:deny_privesc_lockdown_other_agent_commands",
		},
		{
			name:     "lateral movement halt allowed family",
			playbook: "PB-LATERAL-MOVEMENT-HALT",
			command:  "halt_lateral_movement",
		},
		{
			name:      "lateral movement wrong family denied",
			playbook:  "PB-LATERAL-MOVEMENT-HALT",
			command:   "block_c2_beacon",
			wantError: "action_not_allowed:agent_command:deny_lateral_movement_halt_other_agent_commands",
		},
		{
			name:     "c2 beacon block allowed family",
			playbook: "PB-C2-BEACON-BLOCK",
			command:  "block_c2_beacon",
		},
		{
			name:      "c2 beacon wrong family denied",
			playbook:  "PB-C2-BEACON-BLOCK",
			command:   "kill_chain_stop",
			wantError: "action_not_allowed:agent_command:deny_c2_beacon_block_other_agent_commands",
		},
		{
			name:     "ransomware kill chain allowed family",
			playbook: "PB-RANSOMWARE-KILL-CHAIN-STOP",
			command:  "kill_chain_stop",
		},
		{
			name:      "ransomware kill chain wrong family denied",
			playbook:  "PB-RANSOMWARE-KILL-CHAIN-STOP",
			command:   "lockdown_privesc",
			wantError: "action_not_allowed:agent_command:deny_ransomware_kill_chain_other_agent_commands",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			playbook := roePlaybook{
				ID: tc.playbook,
				Steps: []roeStep{
					{
						ActionType: "agent_command",
						TargetFrom: "global",
						Params:     map[string]any{"command": tc.command},
					},
				},
			}
			err := rt.applyAllowlist(playbook)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("applyAllowlist error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected allowlist error %q", tc.wantError)
			}
			if got := err.Error(); got != tc.wantError {
				t.Fatalf("allowlist error=%q, want %q", got, tc.wantError)
			}
		})
	}
}
