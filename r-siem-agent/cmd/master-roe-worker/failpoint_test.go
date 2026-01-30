package main

import (
	"io"
	"sync/atomic"
	"testing"

	"log/slog"
)

func TestWorkerFailpointOnce(t *testing.T) {
	var exits atomic.Int64
	runtime := &workerRuntime{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		exitFunc: func(code int) {
			exits.Add(1)
		},
		failpoint: workerFailpoint{
			enabled: true,
			stage:   "after_persist_terminal",
			runID:   "run-1",
			stepID:  "step-1",
			once:    true,
		},
	}
	step := stepMessage{RunID: "run-1", StepID: "step-1"}
	final := stepState{Status: "SUCCEEDED"}

	if err := runtime.maybeFailpoint(step, final, "after_persist_terminal"); err == nil {
		t.Fatalf("expected failpoint error")
	}
	if exits.Load() != 1 {
		t.Fatalf("exit count=%d, want 1", exits.Load())
	}
	if err := runtime.maybeFailpoint(step, final, "after_persist_terminal"); err != nil {
		t.Fatalf("expected no error after once, got %v", err)
	}
	if exits.Load() != 1 {
		t.Fatalf("exit count=%d, want 1", exits.Load())
	}
}

func TestWorkerFailpointMismatch(t *testing.T) {
	var exits atomic.Int64
	runtime := &workerRuntime{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		exitFunc: func(code int) {
			exits.Add(1)
		},
		failpoint: workerFailpoint{
			enabled: true,
			stage:   "after_persist_terminal",
			runID:   "run-2",
			stepID:  "step-2",
			once:    true,
		},
	}
	step := stepMessage{RunID: "run-1", StepID: "step-1"}
	final := stepState{Status: "SUCCEEDED"}

	if err := runtime.maybeFailpoint(step, final, "after_persist_terminal"); err != nil {
		t.Fatalf("expected no error on mismatch, got %v", err)
	}
	if exits.Load() != 0 {
		t.Fatalf("exit count=%d, want 0", exits.Load())
	}
}
