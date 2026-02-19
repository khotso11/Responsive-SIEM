package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	agentCommandSubject    = "rsiem.agent.command"
	defaultAgentNatsURL    = "nats://127.0.0.1:4222"
	defaultCmdTimeoutMs    = 3000
	defaultOutputLimitByte = 4096
	safeDeniedClass        = "SAFE_DENIED"
)

type commandRequest struct {
	RunID      string         `json:"run_id"`
	StepID     string         `json:"step_id"`
	Lane       string         `json:"lane"`
	ActionType string         `json:"action_type"`
	Target     string         `json:"target"`
	Params     map[string]any `json:"params"`
}

type commandReply struct {
	Status          string `json:"status"`
	ExitCode        int    `json:"exit_code"`
	DurationMs      int64  `json:"duration_ms"`
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	TruncatedStdout bool   `json:"truncated_stdout,omitempty"`
	TruncatedStderr bool   `json:"truncated_stderr,omitempty"`
	ErrorClass      string `json:"error_class,omitempty"`
}

type execSpec struct {
	Command        string
	Args           []string
	RequiresTarget bool
	DryRun         bool
}

type execResult struct {
	ExitCode       int
	Stdout         string
	Stderr         string
	StdoutTrunc    bool
	StderrTrunc    bool
	DurationMillis int64
	Err            error
}

type execRunner interface {
	Run(ctx context.Context, spec execSpec) execResult
}

type osExecRunner struct {
	outputLimit int
}

func (r osExecRunner) Run(ctx context.Context, spec execSpec) execResult {
	start := time.Now()
	outBuf := newLimitedBuffer(r.outputLimit)
	errBuf := newLimitedBuffer(r.outputLimit)

	cmd := exec.CommandContext(ctx, spec.Command, spec.Args...)
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf
	err := cmd.Run()

	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ProcessState != nil {
			exitCode = exitErr.ProcessState.ExitCode()
		}
	}

	return execResult{
		ExitCode:       exitCode,
		Stdout:         outBuf.String(),
		Stderr:         errBuf.String(),
		StdoutTrunc:    outBuf.Truncated(),
		StderrTrunc:    errBuf.Truncated(),
		DurationMillis: time.Since(start).Milliseconds(),
		Err:            err,
	}
}

type commandExecutor struct {
	logger      *slog.Logger
	timeout     time.Duration
	runner      execRunner
	allowlist   map[string]execSpec
	outputLimit int
	policy      quarantinePolicy
}

type quarantinePolicy struct {
	QuarantineRoot     string
	AllowedSourceRoots []string
}

type quarantineRecord struct {
	Version         int    `json:"version"`
	RunID           string `json:"run_id"`
	SourcePath      string `json:"source_path"`
	QuarantinePath  string `json:"quarantine_path"`
	OriginalDest    string `json:"original_dest_path"`
	CreatedAtUnixMs int64  `json:"created_at_unix_ms"`
}

type safeDeniedError struct {
	reason string
}

func (e safeDeniedError) Error() string {
	return "safe_denied:" + e.reason
}

func denySafe(reason string) error {
	return safeDeniedError{reason: strings.TrimSpace(reason)}
}

func isSafeDenied(err error) bool {
	var denied safeDeniedError
	return errors.As(err, &denied)
}

func newCommandExecutor(logger *slog.Logger, policy quarantinePolicy) *commandExecutor {
	if logger == nil {
		logger = slog.Default()
	}
	timeoutMs := envInt("RSIEM_AGENT_CMD_TIMEOUT_MS", defaultCmdTimeoutMs)
	outputLimit := envInt("RSIEM_AGENT_CMD_OUTPUT_LIMIT", defaultOutputLimitByte)
	if outputLimit <= 0 {
		outputLimit = defaultOutputLimitByte
	}
	pingArgs := []string{"-c", "1", "127.0.0.1"}
	if runtime.GOOS == "windows" {
		pingArgs = []string{"-n", "1", "127.0.0.1"}
	}
	pingBaseArgs := pingArgs[:len(pingArgs)-1]
	return &commandExecutor{
		logger:  logger,
		timeout: time.Duration(timeoutMs) * time.Millisecond,
		runner:  osExecRunner{outputLimit: outputLimit},
		allowlist: map[string]execSpec{
			"ping":               {Command: "ping", Args: pingBaseArgs, RequiresTarget: true},
			"uname":              {Command: "uname", Args: []string{"-a"}},
			"quarantine_move":    {},
			"quarantine_restore": {},
		},
		outputLimit: outputLimit,
		policy:      normalizeQuarantinePolicy(policy),
	}
}

func (e *commandExecutor) handle(ctx context.Context, req commandRequest) commandReply {
	actionType := strings.TrimSpace(req.ActionType)
	if actionType == "" {
		actionType = "agent_command"
	}
	commandID := commandIdentifier(req.Params)
	runID := strings.TrimSpace(req.RunID)
	stepID := strings.TrimSpace(req.StepID)
	actionKey := commandID
	if actionType == "network_block" {
		plan, err := buildNetworkBlockPlan(req.Target, req.Params)
		if err != nil {
			return commandReply{Status: "error", ExitCode: -1, ErrorClass: "allowlist_denied"}
		}
		e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_done",
			slog.String("run_id", runID),
			slog.String("step_id", stepID),
			slog.String("command_id", "network_block"),
			slog.Int("exit_code", 0),
			slog.Int64("duration_ms", 0),
			slog.Bool("stdout_truncated", false),
			slog.Bool("stderr_truncated", false),
		)
		return commandReply{Status: "ok", ExitCode: 0, DurationMs: 0, Stdout: plan}
	}

	if actionType == "network_rate_limit" {
		plan, err := buildNetworkRateLimitPlan(req.Target, req.Params)
		if err != nil {
			return commandReply{Status: "error", ExitCode: -1, ErrorClass: "allowlist_denied"}
		}
		e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_done",
			slog.String("run_id", runID),
			slog.String("step_id", stepID),
			slog.String("command_id", "network_rate_limit"),
			slog.Int("exit_code", 0),
			slog.Int64("duration_ms", 0),
			slog.Bool("stdout_truncated", false),
			slog.Bool("stderr_truncated", false),
		)
		return commandReply{Status: "ok", ExitCode: 0, DurationMs: 0, Stdout: plan}
	}

	if actionType != "agent_command" {
		return commandReply{Status: "error", ExitCode: -1, ErrorClass: "internal"}
	}

	if actionKey == "" {
		e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_denied",
			slog.String("run_id", runID),
			slog.String("step_id", stepID),
			slog.String("reason", "missing_command"),
		)
		return commandReply{Status: "error", ExitCode: -1, ErrorClass: "allowlist_denied"}
	}

	spec, ok := e.allowlist[actionKey]
	if !ok {
		e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_denied",
			slog.String("run_id", runID),
			slog.String("step_id", stepID),
			slog.String("command_id", actionKey),
			slog.String("reason", "not_allowlisted"),
		)
		return commandReply{Status: "error", ExitCode: -1, ErrorClass: "allowlist_denied"}
	}

	startAttrs := []slog.Attr{
		slog.String("run_id", runID),
		slog.String("step_id", stepID),
		slog.String("command_id", actionKey),
	}
	startAttrs = append(startAttrs, quarantineLogAttrs(actionKey, req.Params)...)
	e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_start", startAttrs...)

	if actionKey == "quarantine_move" || actionKey == "quarantine_restore" {
		reply := e.executeQuarantineCommand(req, actionKey)
		doneAttrs := []slog.Attr{
			slog.String("run_id", runID),
			slog.String("step_id", stepID),
			slog.String("command_id", actionKey),
			slog.Int("exit_code", reply.ExitCode),
			slog.Int64("duration_ms", reply.DurationMs),
			slog.Bool("stdout_truncated", reply.TruncatedStdout),
			slog.Bool("stderr_truncated", reply.TruncatedStderr),
		}
		doneAttrs = append(doneAttrs, quarantineLogAttrs(actionKey, req.Params)...)
		e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_done", doneAttrs...)
		return reply
	}

	if spec.RequiresTarget {
		target := strings.TrimSpace(req.Target)
		if target == "" {
			target = strings.TrimSpace(stringParam(req.Params, "target"))
		}
		if !validPingTarget(target) {
			return commandReply{Status: "error", ExitCode: -1, ErrorClass: "allowlist_denied"}
		}
		args := append([]string(nil), spec.Args...)
		spec.Args = append(args, target)
	}

	execCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	result := e.runner.Run(execCtx, spec)

	e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_done",
		slog.String("run_id", runID),
		slog.String("step_id", stepID),
		slog.String("command_id", actionKey),
		slog.Int("exit_code", result.ExitCode),
		slog.Int64("duration_ms", result.DurationMillis),
		slog.Bool("stdout_truncated", result.StdoutTrunc),
		slog.Bool("stderr_truncated", result.StderrTrunc),
	)

	if errors.Is(execCtx.Err(), context.DeadlineExceeded) || errors.Is(result.Err, context.DeadlineExceeded) {
		e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_timeout",
			slog.String("run_id", runID),
			slog.String("step_id", stepID),
			slog.String("command_id", commandID),
		)
		return commandReply{
			Status:          "error",
			ExitCode:        result.ExitCode,
			DurationMs:      result.DurationMillis,
			Stdout:          result.Stdout,
			Stderr:          result.Stderr,
			TruncatedStdout: result.StdoutTrunc,
			TruncatedStderr: result.StderrTrunc,
			ErrorClass:      "timeout",
		}
	}

	if result.Err != nil {
		return commandReply{
			Status:          "error",
			ExitCode:        result.ExitCode,
			DurationMs:      result.DurationMillis,
			Stdout:          result.Stdout,
			Stderr:          result.Stderr,
			TruncatedStdout: result.StdoutTrunc,
			TruncatedStderr: result.StderrTrunc,
			ErrorClass:      "exec_failed",
		}
	}

	if result.ExitCode != 0 {
		return commandReply{
			Status:          "error",
			ExitCode:        result.ExitCode,
			DurationMs:      result.DurationMillis,
			Stdout:          result.Stdout,
			Stderr:          result.Stderr,
			TruncatedStdout: result.StdoutTrunc,
			TruncatedStderr: result.StderrTrunc,
			ErrorClass:      "exec_failed",
		}
	}

	return commandReply{
		Status:          "ok",
		ExitCode:        result.ExitCode,
		DurationMs:      result.DurationMillis,
		Stdout:          result.Stdout,
		Stderr:          result.Stderr,
		TruncatedStdout: result.StdoutTrunc,
		TruncatedStderr: result.StderrTrunc,
	}
}

func runCommandListener(ctx context.Context, logger *slog.Logger, natsURL string, policy quarantinePolicy) error {
	nc, err := nats.Connect(natsURL, nats.Name("r-siem-agent"))
	if err != nil {
		return err
	}
	defer nc.Close()

	executor := newCommandExecutor(logger, policy)
	sub, err := nc.Subscribe(agentCommandSubject, func(msg *nats.Msg) {
		if msg.Reply == "" {
			return
		}
		var req commandRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			return
		}
		reply := executor.handle(ctx, req)
		data, err := json.Marshal(reply)
		if err != nil {
			return
		}
		_ = nc.Publish(msg.Reply, data)
	})
	if err != nil {
		return err
	}

	if err := nc.Flush(); err != nil {
		_ = sub.Unsubscribe()
		return err
	}

	logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_subscribed",
		slog.String("subject", agentCommandSubject),
	)

	<-ctx.Done()
	_ = sub.Unsubscribe()
	_ = nc.Drain()
	return nil
}

func commandIdentifier(params map[string]any) string {
	if params == nil {
		return ""
	}
	if val, ok := params["command"]; ok {
		if str, ok := val.(string); ok {
			return strings.TrimSpace(str)
		}
	}
	if val, ok := params["name"]; ok {
		if str, ok := val.(string); ok {
			return strings.TrimSpace(str)
		}
	}
	return ""
}

func (e *commandExecutor) executeQuarantineCommand(req commandRequest, commandID string) commandReply {
	start := time.Now()
	paths, delayMs, err := e.resolveQuarantinePaths(req.RunID, req.Target, req.Params, commandID)
	if err != nil {
		class := "invalid_input"
		if isSafeDenied(err) {
			class = safeDeniedClass
		}
		return commandReply{
			Status:     "error",
			ExitCode:   3,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     err.Error(),
			ErrorClass: class,
		}
	}

	switch commandID {
	case "quarantine_move":
		dest := filepath.Join(paths.QuarantineDir, filepath.Base(paths.SourcePath))
		recordPath := quarantineRecordPath(paths.QuarantineDir, filepath.Base(paths.SourcePath))
		srcExists, srcErr := pathExists(paths.SourcePath)
		destExists, destErr := pathExists(dest)
		if srcErr != nil || destErr != nil {
			return commandReply{
				Status:     "error",
				ExitCode:   1,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     "stat_failed",
				ErrorClass: "exec_failed",
			}
		}
		if paths.SourcePath == dest || (!srcExists && destExists) {
			if err := ensureQuarantineRecord(recordPath, quarantineRecord{
				Version:         1,
				RunID:           req.RunID,
				SourcePath:      paths.SourcePath,
				QuarantinePath:  dest,
				OriginalDest:    paths.DestPath,
				CreatedAtUnixMs: time.Now().UnixMilli(),
			}); err != nil {
				return commandReply{
					Status:     "error",
					ExitCode:   3,
					DurationMs: time.Since(start).Milliseconds(),
					Stderr:     err.Error(),
					ErrorClass: safeDeniedClass,
				}
			}
			return commandReply{
				Status:     "ok",
				ExitCode:   0,
				DurationMs: time.Since(start).Milliseconds(),
				Stdout:     "already_quarantined",
			}
		}
		if !srcExists {
			return commandReply{
				Status:     "error",
				ExitCode:   1,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     "source_not_found",
				ErrorClass: "not_found",
			}
		}
		srcInfo, err := os.Stat(paths.SourcePath)
		if err != nil {
			return commandReply{
				Status:     "error",
				ExitCode:   1,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     "stat_failed",
				ErrorClass: "exec_failed",
			}
		}
		if !srcInfo.Mode().IsRegular() {
			return commandReply{
				Status:     "error",
				ExitCode:   3,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     "safe_denied:source_not_regular_file",
				ErrorClass: safeDeniedClass,
			}
		}
		if err := os.MkdirAll(paths.QuarantineDir, 0o700); err != nil {
			return commandReply{
				Status:     "error",
				ExitCode:   1,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     err.Error(),
				ErrorClass: "exec_failed",
			}
		}
		if destExists {
			return commandReply{
				Status:     "error",
				ExitCode:   3,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     "safe_denied:quarantine_destination_exists",
				ErrorClass: safeDeniedClass,
			}
		}
		if err := os.Rename(paths.SourcePath, dest); err != nil {
			return commandReply{
				Status:     "error",
				ExitCode:   1,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     err.Error(),
				ErrorClass: "exec_failed",
			}
		}
		if err := ensureQuarantineRecord(recordPath, quarantineRecord{
			Version:         1,
			RunID:           req.RunID,
			SourcePath:      paths.SourcePath,
			QuarantinePath:  dest,
			OriginalDest:    paths.DestPath,
			CreatedAtUnixMs: time.Now().UnixMilli(),
		}); err != nil {
			return commandReply{
				Status:     "error",
				ExitCode:   3,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     err.Error(),
				ErrorClass: safeDeniedClass,
			}
		}
		return commandReply{
			Status:     "ok",
			ExitCode:   0,
			DurationMs: time.Since(start).Milliseconds(),
			Stdout:     "moved_to_quarantine",
		}
	case "quarantine_restore":
		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
		quarantinePath := filepath.Join(paths.QuarantineDir, filepath.Base(paths.DestPath))
		recordPath := quarantineRecordPath(paths.QuarantineDir, filepath.Base(paths.DestPath))
		rec, recErr := loadQuarantineRecord(recordPath)
		if recErr != nil {
			return commandReply{
				Status:     "error",
				ExitCode:   3,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     recErr.Error(),
				ErrorClass: safeDeniedClass,
			}
		}
		if strings.TrimSpace(rec.RunID) != strings.TrimSpace(req.RunID) {
			return commandReply{
				Status:     "error",
				ExitCode:   3,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     "safe_denied:run_id_record_mismatch",
				ErrorClass: safeDeniedClass,
			}
		}
		if rec.OriginalDest != paths.DestPath {
			return commandReply{
				Status:     "error",
				ExitCode:   3,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     "safe_denied:restore_target_mismatch",
				ErrorClass: safeDeniedClass,
			}
		}
		if rec.QuarantinePath != quarantinePath {
			return commandReply{
				Status:     "error",
				ExitCode:   3,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     "safe_denied:quarantine_record_mismatch",
				ErrorClass: safeDeniedClass,
			}
		}
		destExists, destErr := pathExists(paths.DestPath)
		quarantineExists, quarantineErr := pathExists(quarantinePath)
		if destErr != nil || quarantineErr != nil {
			return commandReply{
				Status:     "error",
				ExitCode:   1,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     "stat_failed",
				ErrorClass: "exec_failed",
			}
		}
		if quarantinePath == paths.DestPath || (destExists && !quarantineExists) {
			return commandReply{
				Status:     "ok",
				ExitCode:   0,
				DurationMs: time.Since(start).Milliseconds(),
				Stdout:     "already_restored",
			}
		}
		if !quarantineExists {
			return commandReply{
				Status:     "error",
				ExitCode:   3,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     "safe_denied:quarantine_file_not_found",
				ErrorClass: safeDeniedClass,
			}
		}
		qInfo, err := os.Stat(quarantinePath)
		if err != nil || !qInfo.Mode().IsRegular() {
			return commandReply{
				Status:     "error",
				ExitCode:   3,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     "safe_denied:quarantine_file_not_regular",
				ErrorClass: safeDeniedClass,
			}
		}
		if err := os.MkdirAll(filepath.Dir(paths.DestPath), 0o755); err != nil {
			return commandReply{
				Status:     "error",
				ExitCode:   1,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     err.Error(),
				ErrorClass: "exec_failed",
			}
		}
		if err := os.Rename(quarantinePath, paths.DestPath); err != nil {
			return commandReply{
				Status:     "error",
				ExitCode:   1,
				DurationMs: time.Since(start).Milliseconds(),
				Stderr:     err.Error(),
				ErrorClass: "exec_failed",
			}
		}
		_ = os.Remove(recordPath)
		return commandReply{
			Status:     "ok",
			ExitCode:   0,
			DurationMs: time.Since(start).Milliseconds(),
			Stdout:     "restored_from_quarantine",
		}
	default:
		return commandReply{
			Status:     "error",
			ExitCode:   2,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     "unknown_command",
			ErrorClass: "allowlist_denied",
		}
	}
}

type quarantinePaths struct {
	SourcePath    string
	QuarantineDir string
	DestPath      string
}

func quarantineLogAttrs(commandID string, params map[string]any) []slog.Attr {
	if commandID != "quarantine_move" && commandID != "quarantine_restore" {
		return nil
	}
	return []slog.Attr{
		slog.String("src_path", strings.TrimSpace(stringParam(params, "src_path"))),
		slog.String("quarantine_dir", strings.TrimSpace(stringParam(params, "quarantine_dir"))),
		slog.String("dest_path", strings.TrimSpace(stringParam(params, "dest_path"))),
	}
}

func normalizeQuarantinePolicy(policy quarantinePolicy) quarantinePolicy {
	policy.QuarantineRoot = strings.TrimSpace(policy.QuarantineRoot)
	if policy.QuarantineRoot == "" {
		policy.QuarantineRoot = "tmp/quarantine"
	}
	cleanRoots := make([]string, 0, len(policy.AllowedSourceRoots))
	for _, root := range policy.AllowedSourceRoots {
		root = strings.TrimSpace(root)
		if root != "" {
			cleanRoots = append(cleanRoots, root)
		}
	}
	if len(cleanRoots) == 0 {
		cleanRoots = []string{"tmp"}
	}
	policy.AllowedSourceRoots = cleanRoots
	return policy
}

func (e *commandExecutor) resolveQuarantinePaths(runID, target string, params map[string]any, commandID string) (quarantinePaths, int64, error) {
	wd, err := os.Getwd()
	if err != nil {
		return quarantinePaths{}, 0, err
	}
	runID = strings.TrimSpace(runID)
	if runID == "" || runID != filepath.Base(runID) || strings.Contains(runID, string(filepath.Separator)) {
		return quarantinePaths{}, 0, denySafe("invalid_run_id")
	}
	srcRaw := expandTemplateVars(stringParam(params, "src_path"), runID, target)
	quarantineRaw := expandTemplateVars(stringParam(params, "quarantine_dir"), runID, target)
	destRaw := expandTemplateVars(stringParam(params, "dest_path"), runID, target)
	if strings.TrimSpace(srcRaw) == "" {
		return quarantinePaths{}, 0, fmt.Errorf("missing src_path")
	}
	if strings.TrimSpace(quarantineRaw) == "" {
		return quarantinePaths{}, 0, fmt.Errorf("missing quarantine_dir")
	}
	if commandID == "quarantine_restore" && strings.TrimSpace(destRaw) == "" {
		destRaw = srcRaw
	}
	sourcePath, err := normalizeUserPath(srcRaw, wd, false)
	if err != nil {
		return quarantinePaths{}, 0, denySafe(err.Error())
	}
	quarantineDir, err := normalizeUserPath(quarantineRaw, wd, false)
	if err != nil {
		return quarantinePaths{}, 0, denySafe(err.Error())
	}
	destPath := sourcePath
	if strings.TrimSpace(destRaw) != "" {
		destPath, err = normalizeUserPath(destRaw, wd, false)
		if err != nil {
			return quarantinePaths{}, 0, denySafe(err.Error())
		}
	}
	if filepath.Base(sourcePath) == "." || filepath.Base(sourcePath) == string(filepath.Separator) {
		return quarantinePaths{}, 0, denySafe("invalid_src_path")
	}
	if filepath.Base(destPath) == "." || filepath.Base(destPath) == string(filepath.Separator) {
		return quarantinePaths{}, 0, denySafe("invalid_dest_path")
	}
	resolvedRoot, err := ensureResolvedDirectory(e.policy.QuarantineRoot, wd)
	if err != nil {
		return quarantinePaths{}, 0, denySafe("invalid_quarantine_root")
	}
	expectedQuarantineDir := filepath.Join(resolvedRoot, runID)
	if filepath.Clean(quarantineDir) != filepath.Clean(expectedQuarantineDir) {
		return quarantinePaths{}, 0, denySafe("quarantine_dir_must_match_root_and_run_id")
	}
	resolvedAllowedRoots, err := resolveAllowedRoots(e.policy.AllowedSourceRoots, wd)
	if err != nil {
		return quarantinePaths{}, 0, denySafe("invalid_allowed_source_roots")
	}
	resolvedSource := sourcePath
	if commandID == "quarantine_move" {
		resolvedSource, err = resolveRegularFilePath(sourcePath)
		if err != nil {
			return quarantinePaths{}, 0, denySafe(err.Error())
		}
	} else {
		if err := ensureNoSymlinkPath(sourcePath, true); err != nil {
			return quarantinePaths{}, 0, denySafe(err.Error())
		}
	}
	if !isWithinAny(resolvedAllowedRoots, resolvedSource) {
		return quarantinePaths{}, 0, denySafe("source_outside_allowed_roots")
	}
	if err := ensureNoSymlinkParents(quarantineDir); err != nil {
		return quarantinePaths{}, 0, denySafe(err.Error())
	}
	if !isSubpath(resolvedRoot, quarantineDir) {
		return quarantinePaths{}, 0, denySafe("quarantine_dir_outside_root")
	}
	if err := ensureNoSymlinkPath(destPath, true); err != nil {
		return quarantinePaths{}, 0, denySafe(err.Error())
	}
	if !isWithinAny(resolvedAllowedRoots, destPath) {
		return quarantinePaths{}, 0, denySafe("dest_outside_allowed_roots")
	}
	for _, p := range []string{resolvedSource, quarantineDir, destPath} {
		if strings.TrimSpace(p) == "" {
			return quarantinePaths{}, 0, denySafe("empty_resolved_path")
		}
	}
	delayMs, _, err := intParam(params, "delay_ms")
	if err != nil {
		return quarantinePaths{}, 0, err
	}
	if delayMs < 0 {
		return quarantinePaths{}, 0, fmt.Errorf("invalid delay_ms")
	}
	if delayMs > 10000 {
		delayMs = 10000
	}
	return quarantinePaths{
		SourcePath:    resolvedSource,
		QuarantineDir: quarantineDir,
		DestPath:      destPath,
	}, delayMs, nil
}

func normalizeUserPath(raw, wd string, allowAbs bool) (string, error) {
	// User-supplied src/dest/quarantine paths are normalized and (by default)
	// must remain repo-relative to prevent absolute-path escape.
	cleaned := filepath.Clean(strings.TrimSpace(raw))
	if cleaned == "" || cleaned == "." || cleaned == ".." {
		return "", fmt.Errorf("invalid_path_syntax")
	}
	if strings.Contains(cleaned, ".."+string(filepath.Separator)) || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path_traversal_detected")
	}
	if filepath.IsAbs(cleaned) {
		if allowAbs {
			return cleaned, nil
		}
		return "", fmt.Errorf("absolute_path_not_allowed")
	}
	if wd == "" {
		return "", fmt.Errorf("missing_workdir")
	}
	return filepath.Clean(filepath.Join(wd, cleaned)), nil
}

func isSubpath(base, path string) bool {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

func resolveRegularFilePath(path string) (string, error) {
	if err := ensureNoSymlinkPath(path, false); err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("source_not_found")
		}
		return "", fmt.Errorf("source_stat_failed")
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("source_not_regular_file")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("source_eval_symlink_failed")
	}
	return filepath.Clean(resolved), nil
}

func ensureResolvedDirectory(raw, wd string) (string, error) {
	path, err := normalizeUserPath(raw, wd, true)
	if err != nil {
		return "", err
	}
	if err := ensureNoSymlinkParents(path); err != nil {
		return "", err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func resolveAllowedRoots(rawRoots []string, wd string) ([]string, error) {
	roots := make([]string, 0, len(rawRoots))
	for _, raw := range rawRoots {
		resolved, err := ensureResolvedDirectory(raw, wd)
		if err != nil {
			return nil, err
		}
		roots = append(roots, resolved)
	}
	return roots, nil
}

func isWithinAny(roots []string, path string) bool {
	for _, root := range roots {
		if isSubpath(root, path) {
			return true
		}
	}
	return false
}

func ensureNoSymlinkParents(path string) error {
	if path == "" {
		return fmt.Errorf("empty_path")
	}
	dir := filepath.Clean(path)
	return ensureNoSymlinkPath(dir, true)
}

func ensureNoSymlinkPath(path string, allowMissingLeaf bool) error {
	clean := filepath.Clean(path)
	vol := filepath.VolumeName(clean)
	rest := strings.TrimPrefix(clean, vol)
	if rest == "" {
		rest = string(filepath.Separator)
	}
	cur := vol + string(filepath.Separator)
	if !strings.HasPrefix(rest, string(filepath.Separator)) {
		cur = "."
	}
	parts := strings.Split(strings.TrimPrefix(rest, string(filepath.Separator)), string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if allowMissingLeaf && i == len(parts)-1 {
					return nil
				}
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink_not_allowed")
		}
	}
	return nil
}

func quarantineRecordPath(quarantineDir, basename string) string {
	return filepath.Join(quarantineDir, ".quarantine_record_"+basename+".json")
}

func ensureQuarantineRecord(path string, rec quarantineRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return denySafe("record_dir_create_failed")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return denySafe("record_symlink_not_allowed")
		}
	}
	if existing, err := loadQuarantineRecord(path); err == nil {
		if existing.SourcePath == rec.SourcePath && existing.OriginalDest == rec.OriginalDest && existing.QuarantinePath == rec.QuarantinePath {
			return nil
		}
		return denySafe("record_immutable_mismatch")
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return denySafe("record_encode_failed")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return denySafe("record_already_exists")
		}
		return denySafe("record_create_failed")
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return denySafe("record_write_failed")
	}
	return nil
}

func loadQuarantineRecord(path string) (quarantineRecord, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return quarantineRecord{}, denySafe("record_symlink_not_allowed")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return quarantineRecord{}, denySafe("quarantine_record_missing")
		}
		return quarantineRecord{}, denySafe("quarantine_record_read_failed")
	}
	var rec quarantineRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return quarantineRecord{}, denySafe("quarantine_record_invalid")
	}
	return rec, nil
}

func expandTemplateVars(input, runID, target string) string {
	value := strings.TrimSpace(input)
	if value == "" {
		return ""
	}
	target = strings.TrimSpace(target)
	targetOctet := target
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}
	if ip := net.ParseIP(target); ip != nil {
		s := ip.To4()
		if s != nil {
			targetOctet = strconv.Itoa(int(s[3]))
		}
	}
	repl := map[string]string{
		"{run_id}":         runID,
		"{{run_id}}":       runID,
		"{target}":         target,
		"{{target}}":       target,
		"{target_octet}":   targetOctet,
		"{{target_octet}}": targetOctet,
	}
	for token, replacement := range repl {
		value = strings.ReplaceAll(value, token, replacement)
	}
	return value
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func buildOutputMessage(result execResult) string {
	parts := make([]string, 0, 2)
	if result.Stdout != "" {
		parts = append(parts, "stdout="+markTrunc(result.Stdout, result.StdoutTrunc))
	}
	if result.Stderr != "" {
		parts = append(parts, "stderr="+markTrunc(result.Stderr, result.StderrTrunc))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

func markTrunc(value string, truncated bool) string {
	if !truncated {
		return value
	}
	return value + "...(truncated)"
}

type limitedBuffer struct {
	max       int
	buf       strings.Builder
	truncated bool
}

func newLimitedBuffer(max int) *limitedBuffer {
	return &limitedBuffer{max: max}
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.max <= 0 {
		return len(p), nil
	}
	remaining := b.max - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}

func (b *limitedBuffer) Truncated() bool {
	return b.truncated
}

func envInt(key string, fallback int) int {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return parsed
}

func commandNatsURL() string {
	val := strings.TrimSpace(os.Getenv("RSIEM_AGENT_CMD_NATS_URL"))
	if val == "" {
		return defaultAgentNatsURL
	}
	return val
}

func buildNetworkBlockPlan(target string, params map[string]any) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" || !validIPOrCIDR(target) {
		return "", fmt.Errorf("invalid_target")
	}
	direction := strings.TrimSpace(stringParam(params, "direction"))
	if direction != "" && direction != "ingress" && direction != "egress" && direction != "both" {
		return "", fmt.Errorf("invalid_direction")
	}
	parts := []string{"dry_run: network_block", "target=" + target}
	if direction != "" {
		parts = append(parts, "direction="+direction)
	}
	return strings.Join(parts, " "), nil
}

func buildNetworkRateLimitPlan(target string, params map[string]any) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" || !validIPOrCIDR(target) {
		return "", fmt.Errorf("invalid_target")
	}
	rateVal, rateSet, err := intParam(params, "rate_kbps")
	if err != nil {
		return "", err
	}
	if rateSet && rateVal <= 0 {
		return "", fmt.Errorf("invalid_rate_kbps")
	}
	burstVal, burstSet, err := intParam(params, "burst_kb")
	if err != nil {
		return "", err
	}
	if burstSet && burstVal < 0 {
		return "", fmt.Errorf("invalid_burst_kb")
	}
	durationVal, durationSet, err := intParam(params, "duration_ms")
	if err != nil {
		return "", err
	}
	if durationSet && durationVal <= 0 {
		return "", fmt.Errorf("invalid_duration_ms")
	}

	parts := []string{"dry_run: network_rate_limit", "target=" + target}
	if rateSet {
		parts = append(parts, fmt.Sprintf("rate_kbps=%d", rateVal))
	}
	if burstSet {
		parts = append(parts, fmt.Sprintf("burst_kb=%d", burstVal))
	}
	if durationSet {
		parts = append(parts, fmt.Sprintf("duration_ms=%d", durationVal))
	}
	return strings.Join(parts, " "), nil
}

func stringParam(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	val, ok := params[key]
	if !ok {
		return ""
	}
	str, ok := val.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(str)
}

func intParam(params map[string]any, key string) (int64, bool, error) {
	if params == nil {
		return 0, false, nil
	}
	val, ok := params[key]
	if !ok {
		return 0, false, nil
	}
	switch typed := val.(type) {
	case int:
		return int64(typed), true, nil
	case int64:
		return typed, true, nil
	case int32:
		return int64(typed), true, nil
	case uint:
		return int64(typed), true, nil
	case uint64:
		return int64(typed), true, nil
	case float64:
		return int64(typed), true, nil
	case float32:
		return int64(typed), true, nil
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, true, fmt.Errorf("invalid_%s", key)
		}
		parsed, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return 0, true, fmt.Errorf("invalid_%s", key)
		}
		return parsed, true, nil
	default:
		return 0, true, fmt.Errorf("invalid_%s", key)
	}
}

func validIPOrCIDR(value string) bool {
	if net.ParseIP(value) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

func validPingTarget(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" || strings.IndexFunc(target, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) >= 0 {
		return false
	}
	if net.ParseIP(target) != nil {
		return true
	}
	if strings.Contains(target, ":") {
		return false
	}
	return validHostname(target)
}

func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return false
		}
	}
	return true
}
