package main

import "testing"

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
