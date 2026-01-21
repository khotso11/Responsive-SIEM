package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	called bool
	result execResult
}

func (f *fakeRunner) Run(ctx context.Context, spec execSpec) execResult {
	f.called = true
	return f.result
}

func TestCommandIdentifier(t *testing.T) {
	if got := commandIdentifier(map[string]any{"command": "ping"}); got != "ping" {
		t.Fatalf("command identifier=%q, want ping", got)
	}
	if got := commandIdentifier(map[string]any{"name": "ping"}); got != "ping" {
		t.Fatalf("name identifier=%q, want ping", got)
	}
	if got := commandIdentifier(map[string]any{"command": "  "}); got != "" {
		t.Fatalf("blank command=%q, want empty", got)
	}
}

func TestPolicyDenied(t *testing.T) {
	runner := &fakeRunner{}
	exec := &commandExecutor{
		logger:    slog.Default(),
		timeout:   time.Second,
		runner:    runner,
		allowlist: map[string]execSpec{"ping": {Command: "ping"}},
	}
	reply := exec.handle(context.Background(), commandRequest{
		RunID:  "run-1",
		StepID: "step-1",
		Params: map[string]any{"command": "rm"},
	})
	if runner.called {
		t.Fatalf("expected runner not called on deny")
	}
	if reply.Status != "fail_safe" || reply.Message != "policy_denied" {
		t.Fatalf("unexpected reply: %#v", reply)
	}
}

func TestTimeoutMapping(t *testing.T) {
	runner := &fakeRunner{
		result: execResult{Err: context.DeadlineExceeded},
	}
	exec := &commandExecutor{
		logger:    slog.Default(),
		timeout:   time.Millisecond,
		runner:    runner,
		allowlist: map[string]execSpec{"ping": {Command: "ping"}},
	}
	reply := exec.handle(context.Background(), commandRequest{
		RunID:  "run-1",
		StepID: "step-1",
		Params: map[string]any{"command": "ping"},
	})
	if reply.Status != "fail_transient" || reply.Message != "timeout" {
		t.Fatalf("unexpected timeout reply: %#v", reply)
	}
}

func TestBuildOutputMessageTruncation(t *testing.T) {
	result := execResult{
		Stdout:      "hello",
		StdoutTrunc: true,
		Stderr:      "oops",
	}
	msg := buildOutputMessage(result)
	if msg == "" || !strings.Contains(msg, "truncated") {
		t.Fatalf("expected truncation marker, got %q", msg)
	}
}

func TestLimitedBufferTruncates(t *testing.T) {
	buf := newLimitedBuffer(4)
	if _, err := buf.Write([]byte("1234")); err != nil {
		t.Fatalf("write err: %v", err)
	}
	if _, err := buf.Write([]byte("5678")); err != nil {
		t.Fatalf("write err: %v", err)
	}
	if buf.String() != "1234" {
		t.Fatalf("buffer=%q, want 1234", buf.String())
	}
	if !buf.Truncated() {
		t.Fatalf("expected truncated=true")
	}
}
