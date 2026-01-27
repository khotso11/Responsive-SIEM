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
}

func newCommandExecutor(logger *slog.Logger) *commandExecutor {
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
		},
		outputLimit: outputLimit,
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

	e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_start",
		slog.String("run_id", runID),
		slog.String("step_id", stepID),
		slog.String("command_id", actionKey),
	)

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

func runCommandListener(ctx context.Context, logger *slog.Logger, natsURL string) error {
	nc, err := nats.Connect(natsURL, nats.Name("r-siem-agent"))
	if err != nil {
		return err
	}
	defer nc.Close()

	executor := newCommandExecutor(logger)
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
