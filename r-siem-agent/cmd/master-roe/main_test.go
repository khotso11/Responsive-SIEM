package main

import "testing"

func TestParseROEConfigApprovalsTimeout(t *testing.T) {
	data := []byte("policies:\n  approvals:\n    timeout_ms: 300000\n")
	cfg, err := parseROEConfig(data)
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	if cfg.Policies.Approvals.TimeoutMs != 300000 {
		t.Fatalf("expected approvals timeout 300000, got %d", cfg.Policies.Approvals.TimeoutMs)
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
