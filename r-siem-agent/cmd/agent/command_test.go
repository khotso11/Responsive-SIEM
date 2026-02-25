package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
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
		allowlist: map[string]execSpec{"ping": {Command: "ping", RequiresTarget: true}},
	}
	reply := exec.handle(context.Background(), commandRequest{
		RunID:  "run-1",
		StepID: "step-1",
		Params: map[string]any{"command": "rm"},
	})
	if runner.called {
		t.Fatalf("expected runner not called on deny")
	}
	if reply.Status != "error" || reply.ErrorClass != "allowlist_denied" {
		t.Fatalf("unexpected reply: %#v", reply)
	}
}

func TestDryRunNetworkBlockPlan(t *testing.T) {
	runner := &fakeRunner{}
	exec := &commandExecutor{
		logger:  slog.Default(),
		timeout: time.Second,
		runner:  runner,
		allowlist: map[string]execSpec{
			"network_block": {DryRun: true},
		},
	}
	reply := exec.handle(context.Background(), commandRequest{
		RunID:      "run-1",
		StepID:     "step-1",
		ActionType: "network_block",
		Target:     "10.0.0.1",
		Params: map[string]any{
			"direction": "ingress",
		},
	})
	if runner.called {
		t.Fatalf("expected runner not called for dry-run")
	}
	want := "dry_run: network_block target=10.0.0.1 direction=ingress"
	if reply.Status != "ok" || reply.Stdout != want {
		t.Fatalf("unexpected reply: %#v", reply)
	}
}

func TestDryRunNetworkRateLimitPlan(t *testing.T) {
	exec := &commandExecutor{
		logger:  slog.Default(),
		timeout: time.Second,
		runner:  &fakeRunner{},
		allowlist: map[string]execSpec{
			"network_rate_limit": {DryRun: true},
		},
	}
	reply := exec.handle(context.Background(), commandRequest{
		RunID:      "run-1",
		StepID:     "step-1",
		ActionType: "network_rate_limit",
		Target:     "10.0.0.1",
		Params: map[string]any{
			"rate_kbps":   100,
			"burst_kb":    0,
			"duration_ms": 60000,
		},
	})
	want := "dry_run: network_rate_limit target=10.0.0.1 rate_kbps=100 burst_kb=0 duration_ms=60000"
	if reply.Status != "ok" || reply.Stdout != want {
		t.Fatalf("unexpected reply: %#v", reply)
	}
}

func TestValidationFailureIsSafe(t *testing.T) {
	exec := &commandExecutor{
		logger:  slog.Default(),
		timeout: time.Second,
		runner:  &fakeRunner{},
		allowlist: map[string]execSpec{
			"network_block": {DryRun: true},
		},
	}
	reply := exec.handle(context.Background(), commandRequest{
		RunID:      "run-1",
		StepID:     "step-1",
		ActionType: "network_block",
		Target:     "not-an-ip",
	})
	if reply.Status != "error" || reply.ErrorClass != "allowlist_denied" {
		t.Fatalf("unexpected validation reply: %#v", reply)
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
		allowlist: map[string]execSpec{"ping": {Command: "ping", RequiresTarget: true}},
	}
	reply := exec.handle(context.Background(), commandRequest{
		RunID:  "run-1",
		StepID: "step-1",
		Target: "127.0.0.1",
		Params: map[string]any{"command": "ping"},
	})
	if reply.Status != "error" || reply.ErrorClass != "timeout" {
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

func TestQuarantineMoveRestoreCommands(t *testing.T) {
	base := t.TempDir()
	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() {
		_ = os.Chdir(prevWD)
	}()
	if err := os.Chdir(base); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if err := os.MkdirAll("srcroot", 0o755); err != nil {
		t.Fatalf("mkdir srcroot: %v", err)
	}
	src := filepath.Join("srcroot", "src.txt")
	quarantineRoot := filepath.Join("qroot")
	quarantineDir := filepath.Join(quarantineRoot, "run-1")
	if err := os.WriteFile(src, []byte("demo"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	exec := newCommandExecutor(slog.Default(), quarantinePolicy{
		QuarantineRoot:     quarantineRoot,
		AllowedSourceRoots: []string{"srcroot"},
	})
	move := exec.handle(context.Background(), commandRequest{
		RunID:      "run-1",
		StepID:     "step-1",
		ActionType: "agent_command",
		Params: map[string]any{
			"command":        "quarantine_move",
			"src_path":       src,
			"quarantine_dir": quarantineDir,
			"dest_path":      src,
		},
	})
	if move.Status != "ok" || move.ExitCode != 0 {
		t.Fatalf("unexpected move reply: %#v", move)
	}
	qFile := filepath.Join(quarantineDir, filepath.Base(src))
	if _, err := os.Stat(qFile); err != nil {
		t.Fatalf("expected quarantined file: %v", err)
	}

	restore := exec.handle(context.Background(), commandRequest{
		RunID:      "run-1",
		StepID:     "step-2",
		ActionType: "agent_command",
		Params: map[string]any{
			"command":        "quarantine_restore",
			"src_path":       src,
			"quarantine_dir": quarantineDir,
			"dest_path":      src,
		},
	})
	if restore.Status != "ok" || restore.ExitCode != 0 {
		t.Fatalf("unexpected restore reply: %#v", restore)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("expected restored file: %v", err)
	}
}

func TestMarkerCommandIdempotent(t *testing.T) {
	base := t.TempDir()
	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() {
		_ = os.Chdir(prevWD)
	}()
	if err := os.Chdir(base); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	exec := newCommandExecutor(slog.Default(), quarantinePolicy{})

	first := exec.handle(context.Background(), commandRequest{
		RunID:      "run-1",
		StepID:     "step-1",
		ActionType: "agent_command",
		Target:     "10.0.0.1",
		Params: map[string]any{
			"command": "contain_bruteforce_ip",
		},
	})
	if first.Status != "ok" || first.ExitCode != 0 {
		t.Fatalf("unexpected first marker reply: %#v", first)
	}

	second := exec.handle(context.Background(), commandRequest{
		RunID:      "run-1",
		StepID:     "step-2",
		ActionType: "agent_command",
		Target:     "10.0.0.1",
		Params: map[string]any{
			"command": "contain_bruteforce_ip",
		},
	})
	if second.Status != "ok" || second.ExitCode != 0 {
		t.Fatalf("unexpected idempotent marker reply: %#v", second)
	}
	if first.Stdout == "" || second.Stdout == "" {
		t.Fatalf("expected marker output paths, got first=%q second=%q", first.Stdout, second.Stdout)
	}
	if first.Stdout != second.Stdout {
		t.Fatalf("expected stable marker path, got first=%q second=%q", first.Stdout, second.Stdout)
	}
	if _, err := os.Stat(first.Stdout); err != nil {
		t.Fatalf("expected marker file %q: %v", first.Stdout, err)
	}
}
