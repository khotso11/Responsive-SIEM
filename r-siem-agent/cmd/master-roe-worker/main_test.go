package main

import (
	"fmt"
	"testing"

	"r-siem-agent/internal/roe/connectors"
)

func TestResolveAttempt(t *testing.T) {
	step := stepMessage{Attempt: 0}
	state := &stepState{Attempt: 1}
	if got := resolveAttempt(step, state); got != 2 {
		t.Fatalf("resolveAttempt with state=%d got %d, want 2", state.Attempt, got)
	}
	step.Attempt = 3
	if got := resolveAttempt(step, state); got != 4 {
		t.Fatalf("resolveAttempt with step=%d got %d, want 4", step.Attempt, got)
	}
	if got := resolveAttempt(stepMessage{Attempt: 0}, nil); got != 1 {
		t.Fatalf("resolveAttempt nil state got %d, want 1", got)
	}
}

func TestResolveAttemptStopsAfterRetries(t *testing.T) {
	retries := 2
	step := stepMessage{Retries: &retries}
	maxAttempts := resolveMaxAttempts(step, defaultMaxAttempts)
	if maxAttempts != 3 {
		t.Fatalf("resolveMaxAttempts got %d, want 3", maxAttempts)
	}
	state := &stepState{}
	for expected := 1; expected <= maxAttempts; expected++ {
		got := resolveAttempt(step, state)
		if got != expected {
			t.Fatalf("attempt %d got %d", expected, got)
		}
		state.Attempt = got
	}
}

func TestRetryDelayMs(t *testing.T) {
	state := &stepState{NextRetryAtUnixMs: 1500}
	if got := retryDelayMs(1000, state); got != 500 {
		t.Fatalf("retryDelayMs got %d, want 500", got)
	}
	if got := retryDelayMs(1500, state); got != 0 {
		t.Fatalf("retryDelayMs at boundary got %d, want 0", got)
	}
	if got := retryDelayMs(1600, state); got != 0 {
		t.Fatalf("retryDelayMs past got %d, want 0", got)
	}
	if got := retryDelayMs(1000, &stepState{}); got != 0 {
		t.Fatalf("retryDelayMs empty state got %d, want 0", got)
	}
}

func TestRetryableErrorBackoff(t *testing.T) {
	err := connectors.Retryable(fmt.Errorf("agent_command_no_responders"))
	if !connectors.IsRetryable(err) {
		t.Fatalf("expected retryable error")
	}
	backoff := computeBackoff(1, 500, 2000)
	if backoff != 500 {
		t.Fatalf("expected backoff 500, got %d", backoff)
	}
}

func TestValidateStepParamsAllowlist(t *testing.T) {
	agentCmd := findBuiltin(t, "agent_command")
	block := findBuiltin(t, "network_block")
	rateLimit := findBuiltin(t, "network_rate_limit")

	if reason := validateStepParams(agentCmd.RequiredParams(), agentCmd.OptionalParams(), map[string]any{
		"command": "ping",
		"target":  "127.0.0.1",
	}); reason != "" {
		t.Fatalf("agent_command allowlist rejected command: %s", reason)
	}

	if reason := validateStepParams(agentCmd.RequiredParams(), agentCmd.OptionalParams(), map[string]any{
		"name": "ping",
		"args": []string{"-c", "1", "127.0.0.1"},
	}); reason != "" {
		t.Fatalf("agent_command allowlist rejected name: %s", reason)
	}

	if reason := validateStepParams(block.RequiredParams(), block.OptionalParams(), map[string]any{
		"direction": "ingress",
	}); reason != "" {
		t.Fatalf("network_block allowlist rejected direction: %s", reason)
	}

	if reason := validateStepParams(rateLimit.RequiredParams(), rateLimit.OptionalParams(), map[string]any{
		"rate_kbps":   512,
		"burst_kb":    128,
		"duration_ms": 60000,
	}); reason != "" {
		t.Fatalf("network_rate_limit allowlist rejected params: %s", reason)
	}

	if reason := validateStepParams(rateLimit.RequiredParams(), rateLimit.OptionalParams(), map[string]any{
		"unknown_param": "nope",
	}); reason == "" {
		t.Fatalf("expected unknown_param to be rejected")
	}
}

func TestValidationFailureState(t *testing.T) {
	step := stepMessage{
		RunID:      "run-1",
		StepID:     "step-1",
		StepIndex:  1,
		ActionType: "agent_command",
		Lane:       "FAST",
		Attempt:    2,
		Retries:    intPtr(2),
	}
	reason := "unknown_param:frobnicate"
	if !isValidationError(reason) {
		t.Fatalf("expected validation error for %q", reason)
	}
	final := validationFailureState(step, reason)
	if final.Status != "FAILED_SAFE" {
		t.Fatalf("expected FAILED_SAFE, got %s", final.Status)
	}
	if final.Attempt != step.Attempt {
		t.Fatalf("expected attempt %d, got %d", step.Attempt, final.Attempt)
	}
	if final.NextRetryAtUnixMs != 0 {
		t.Fatalf("expected no retry scheduled, got %d", final.NextRetryAtUnixMs)
	}
	if final.LastError != reason {
		t.Fatalf("expected last_error %q, got %q", reason, final.LastError)
	}
	if final.FinishedAtUnixMs <= 0 {
		t.Fatalf("expected finished_at_unix_ms to be set")
	}
}

func intPtr(value int) *int {
	return &value
}

func findBuiltin(t *testing.T, action string) connectors.Connector {
	t.Helper()
	for _, connector := range connectors.Builtins(connectors.BuiltinOptions{}) {
		if connector.ActionType() == action {
			return connector
		}
	}
	t.Fatalf("missing builtin connector %q", action)
	return nil
}
