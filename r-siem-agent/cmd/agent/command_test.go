package main

import (
	"context"
	"encoding/json"
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

type recordingRunner struct {
	specs   []execSpec
	results func(execSpec) execResult
}

func (r *recordingRunner) Run(ctx context.Context, spec execSpec) execResult {
	r.specs = append(r.specs, spec)
	if r.results != nil {
		return r.results(spec)
	}
	return execResult{ExitCode: 0}
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
	t.Setenv("RSIEM_AGENT_RESPONSE_ACTION_ROOT", filepath.Join(base, "response-actions"))
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

func TestHaltLateralMovementFallsBackToMarkerWithoutTargets(t *testing.T) {
	base := t.TempDir()
	t.Setenv("RSIEM_AGENT_LATERAL_CONTROL_MODE", "firewall")
	t.Setenv("RSIEM_AGENT_RESPONSE_ACTION_ROOT", filepath.Join(base, "response-actions"))

	exec := newCommandExecutor(slog.Default(), quarantinePolicy{})
	reply := exec.handle(context.Background(), commandRequest{
		RunID:      "run-lateral-marker",
		StepID:     "step-1",
		ActionType: "agent_command",
		Params: map[string]any{
			"command": "halt_lateral_movement",
		},
	})
	if reply.Status != "ok" || reply.ExitCode != 0 {
		t.Fatalf("unexpected fallback reply: %#v", reply)
	}
	if !strings.Contains(reply.Stdout, "mode=marker reason=no_scoped_targets") {
		t.Fatalf("expected marker fallback marker in stdout, got %q", reply.Stdout)
	}
}

func TestHaltLateralMovementFirewallModeProgramsNFT(t *testing.T) {
	base := t.TempDir()
	t.Setenv("RSIEM_AGENT_LATERAL_CONTROL_MODE", "firewall")
	t.Setenv("RSIEM_AGENT_RESPONSE_ACTION_ROOT", filepath.Join(base, "response-actions"))

	prevLookPath := execLookPath
	execLookPath = func(file string) (string, error) {
		if file == "nft" {
			return "/usr/sbin/nft", nil
		}
		return "", os.ErrNotExist
	}
	defer func() { execLookPath = prevLookPath }()

	runner := &recordingRunner{
		results: func(spec execSpec) execResult {
			return execResult{ExitCode: 0, Stdout: ""}
		},
	}
	exec := &commandExecutor{
		logger:      slog.Default(),
		timeout:     time.Second,
		runner:      runner,
		allowlist:   map[string]execSpec{"halt_lateral_movement": {}},
		outputLimit: 4096,
	}
	reply := exec.handle(context.Background(), commandRequest{
		RunID:      "run-lateral-fw",
		StepID:     "step-1",
		ActionType: "agent_command",
		Params: map[string]any{
			"command":          "halt_lateral_movement",
			"dst_ip":           "172.30.50.13",
			"top_destinations": "172.30.50.13,172.30.50.12,172.30.50.11,172.30.50.14",
			"protocol_family":  "rdp",
			"duration_ms":      600000,
			"reason":           "internal_protocol_scan:R-NET-INTERNAL-RDP-SCAN",
			"node_id":          "endpoint-01",
		},
	})
	if reply.Status != "ok" || reply.ExitCode != 0 {
		t.Fatalf("unexpected firewall reply: %#v", reply)
	}
	if _, err := os.Stat(reply.Stdout); err != nil {
		t.Fatalf("expected lateral containment state file %q: %v", reply.Stdout, err)
	}
	data, err := os.ReadFile(reply.Stdout)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	if !strings.Contains(string(data), "\"backend\": \"nft\"") {
		t.Fatalf("expected nft backend in state file, got %s", string(data))
	}
	if !strings.Contains(string(data), "\"protocol_family\": \"rdp\"") {
		t.Fatalf("expected protocol_family in state file, got %s", string(data))
	}
	if !strings.Contains(string(data), "172.30.50.14") {
		t.Fatalf("expected target IPs in state file, got %s", string(data))
	}

	var sawAddTable bool
	var sawRuleV4 bool
	targetAdds := map[string]bool{
		"172.30.50.13": false,
		"172.30.50.12": false,
		"172.30.50.11": false,
		"172.30.50.14": false,
	}
	for _, spec := range runner.specs {
		if spec.Command != "/usr/sbin/nft" {
			t.Fatalf("unexpected command %q", spec.Command)
		}
		joined := strings.Join(spec.Args, " ")
		if strings.Contains(joined, "add table inet rsiem_contain") {
			sawAddTable = true
		}
		if strings.Contains(joined, "add rule inet rsiem_contain rsiem_output ip daddr @lateral_block_v4 drop") {
			sawRuleV4 = true
		}
		for target := range targetAdds {
			if strings.Contains(joined, "add element inet rsiem_contain lateral_block_v4") && strings.Contains(joined, target) {
				targetAdds[target] = true
			}
		}
	}
	if !sawAddTable {
		t.Fatalf("expected nft add table command, got %#v", runner.specs)
	}
	if !sawRuleV4 {
		t.Fatalf("expected nft add rule for v4 targets, got %#v", runner.specs)
	}
	for target, seen := range targetAdds {
		if !seen {
			t.Fatalf("expected nft add element for target %s, got %#v", target, runner.specs)
		}
	}
}

func TestAuthControlContainVerifyRestore(t *testing.T) {
	base := t.TempDir()
	authRoot := filepath.Join(base, "auth-controls")
	t.Setenv("RSIEM_AGENT_AUTH_CONTROL_ROOT", authRoot)

	exec := newCommandExecutor(slog.Default(), quarantinePolicy{})

	contain := exec.handle(context.Background(), commandRequest{
		RunID:      "run-auth-1",
		StepID:     "step-1",
		ActionType: "agent_command",
		Target:     "10.10.10.10",
		Params: map[string]any{
			"command":     "auth_contain_src_ip",
			"src_ip":      "10.10.10.10",
			"user_name":   "alice",
			"duration_ms": 600000,
			"reason":      "auth abuse burst",
			"node_id":     "endpoint-01",
		},
	})
	if contain.Status != "ok" || contain.ExitCode != 0 {
		t.Fatalf("unexpected contain reply: %#v", contain)
	}

	containUser := exec.handle(context.Background(), commandRequest{
		RunID:      "run-auth-1",
		StepID:     "step-2",
		ActionType: "agent_command",
		Params: map[string]any{
			"command":     "auth_contain_user_access",
			"user_name":   "alice",
			"src_ip":      "10.10.10.10",
			"duration_ms": 600000,
		},
	})
	if containUser.Status != "ok" || containUser.ExitCode != 0 {
		t.Fatalf("unexpected contain-user reply: %#v", containUser)
	}

	restoreBeforeVerify := exec.handle(context.Background(), commandRequest{
		RunID:      "run-restore-1",
		StepID:     "step-3",
		ActionType: "agent_command",
		Params: map[string]any{
			"command":            "auth_restore_user_access",
			"containment_run_id": "run-auth-1",
			"user_name":          "alice",
		},
	})
	if restoreBeforeVerify.Status != "error" || restoreBeforeVerify.ErrorClass != safeDeniedClass || !strings.Contains(restoreBeforeVerify.Stderr, "verification_required") {
		t.Fatalf("expected verification-required denial, got %#v", restoreBeforeVerify)
	}

	verify := exec.handle(context.Background(), commandRequest{
		RunID:      "run-verify-1",
		StepID:     "step-4",
		ActionType: "agent_command",
		Params: map[string]any{
			"command":                "auth_mark_user_verified",
			"containment_run_id":     "run-auth-1",
			"user_name":              "alice",
			"verification_method":    "phone",
			"verification_reference": "HD-42",
			"verified_by":            "admin",
			"notes":                  "confirmed by helpdesk",
		},
	})
	if verify.Status != "ok" || verify.ExitCode != 0 {
		t.Fatalf("unexpected verify reply: %#v", verify)
	}

	restore := exec.handle(context.Background(), commandRequest{
		RunID:      "run-restore-2",
		StepID:     "step-5",
		ActionType: "agent_command",
		Params: map[string]any{
			"command":            "auth_restore_user_access",
			"containment_run_id": "run-auth-1",
			"user_name":          "alice",
		},
	})
	if restore.Status != "ok" || restore.ExitCode != 0 {
		t.Fatalf("unexpected restore reply: %#v", restore)
	}

	restoreIP := exec.handle(context.Background(), commandRequest{
		RunID:      "run-restore-3",
		StepID:     "step-6",
		ActionType: "agent_command",
		Params: map[string]any{
			"command":            "auth_restore_src_ip",
			"containment_run_id": "run-auth-1",
			"src_ip":             "10.10.10.10",
		},
	})
	if restoreIP.Status != "ok" || restoreIP.ExitCode != 0 {
		t.Fatalf("unexpected restore-ip reply: %#v", restoreIP)
	}

	data, err := os.ReadFile(filepath.Join(authRoot, "run-auth-1.json"))
	if err != nil {
		t.Fatalf("read auth control record: %v", err)
	}
	if !strings.Contains(string(data), "\"status\": \"restored\"") {
		t.Fatalf("expected restored state, got %s", string(data))
	}
	if !strings.Contains(string(data), "\"verified\": true") {
		t.Fatalf("expected verified state, got %s", string(data))
	}
}

func TestCommandResultStoreSaveLoad(t *testing.T) {
	root := t.TempDir()
	t.Setenv("RSIEM_AGENT_COMMAND_RESULT_ROOT", root)

	store := newCommandResultStore()
	replyBytes, err := json.Marshal(commandReply{
		Status:     "ok",
		ExitCode:   0,
		DurationMs: 12,
		Stdout:     "persisted",
	})
	if err != nil {
		t.Fatalf("marshal reply: %v", err)
	}
	key := "run-1|step-1"
	if err := store.save(key, "run-1", "step-1", replyBytes); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := store.load(key)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var got commandReply
	if err := json.Unmarshal(loaded, &got); err != nil {
		t.Fatalf("unmarshal loaded reply: %v", err)
	}
	if got.Status != "ok" || got.ExitCode != 0 || got.DurationMs != 12 || got.Stdout != "persisted" {
		t.Fatalf("unexpected loaded reply: %#v", got)
	}
}

func TestCommandResultStoreDurableReplayAvoidsReexecution(t *testing.T) {
	root := t.TempDir()
	t.Setenv("RSIEM_AGENT_COMMAND_RESULT_ROOT", root)

	runner := &fakeRunner{
		result: execResult{
			ExitCode:       0,
			Stdout:         "pong",
			DurationMillis: 1,
		},
	}
	exec := &commandExecutor{
		logger:    slog.Default(),
		timeout:   time.Second,
		runner:    runner,
		allowlist: map[string]execSpec{"ping": {Command: "ping", RequiresTarget: true}},
	}
	req := commandRequest{
		RunID:      "run-replay-1",
		StepID:     "step-replay-1",
		ActionType: "agent_command",
		Target:     "127.0.0.1",
		Params:     map[string]any{"command": "ping"},
	}
	reply := exec.handle(context.Background(), req)
	if reply.Status != "ok" || reply.ExitCode != 0 {
		t.Fatalf("unexpected first reply: %#v", reply)
	}
	if !runner.called {
		t.Fatalf("expected runner to execute initial command")
	}

	replyBytes, err := json.Marshal(reply)
	if err != nil {
		t.Fatalf("marshal first reply: %v", err)
	}
	store := newCommandResultStore()
	key := req.RunID + "|" + req.StepID
	if err := store.save(key, req.RunID, req.StepID, replyBytes); err != nil {
		t.Fatalf("save durable reply: %v", err)
	}

	restartedRunner := &fakeRunner{
		result: execResult{
			ExitCode:       99,
			Stdout:         "should-not-run",
			DurationMillis: 1,
		},
	}
	loaded, err := store.load(key)
	if err != nil {
		t.Fatalf("load durable reply: %v", err)
	}
	if len(loaded) == 0 {
		t.Fatalf("expected persisted reply bytes")
	}
	if restartedRunner.called {
		t.Fatalf("runner should not have executed before replay")
	}
	var replayed commandReply
	if err := json.Unmarshal(loaded, &replayed); err != nil {
		t.Fatalf("unmarshal replayed reply: %v", err)
	}
	if replayed.Stdout != "pong" || replayed.ExitCode != 0 {
		t.Fatalf("unexpected replayed reply: %#v", replayed)
	}
	if restartedRunner.called {
		t.Fatalf("runner should not execute for durable replay")
	}
}

func TestCommandReplySpoolEnqueueFlush(t *testing.T) {
	root := t.TempDir()
	t.Setenv("RSIEM_AGENT_COMMAND_REPLY_SPOOL_ROOT", root)

	spool := newCommandReplySpool()
	replyBytes, err := json.Marshal(commandReply{
		Status:   "ok",
		ExitCode: 0,
		Stdout:   "spooled",
	})
	if err != nil {
		t.Fatalf("marshal reply: %v", err)
	}
	if err := spool.enqueue("run-1|step-1", "run-1", "step-1", "_INBOX.test", replyBytes); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	var publishedSubject string
	var publishedData []byte
	if err := spool.flush(func(subject string, data []byte) error {
		publishedSubject = subject
		publishedData = append([]byte(nil), data...)
		return nil
	}); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if publishedSubject != "_INBOX.test" {
		t.Fatalf("published subject=%q", publishedSubject)
	}
	var got commandReply
	if err := json.Unmarshal(publishedData, &got); err != nil {
		t.Fatalf("unmarshal published data: %v", err)
	}
	if got.Status != "ok" || got.ExitCode != 0 || got.Stdout != "spooled" {
		t.Fatalf("unexpected published data: %#v", got)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected spool empty after successful flush, found %d entries", len(entries))
	}
}

func TestCommandReplySpoolFlushRetainsOnPublishFailure(t *testing.T) {
	root := t.TempDir()
	t.Setenv("RSIEM_AGENT_COMMAND_REPLY_SPOOL_ROOT", root)

	spool := newCommandReplySpool()
	replyBytes, err := json.Marshal(commandReply{
		Status:   "ok",
		ExitCode: 0,
		Stdout:   "spooled",
	})
	if err != nil {
		t.Fatalf("marshal reply: %v", err)
	}
	if err := spool.enqueue("run-2|step-2", "run-2", "step-2", "_INBOX.test", replyBytes); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	if err := spool.flush(func(subject string, data []byte) error {
		return context.DeadlineExceeded
	}); err == nil {
		t.Fatalf("expected flush error")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected spool file retained after publish failure")
	}
}
