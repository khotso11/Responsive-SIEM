package main

import (
	"context"
	"crypto/sha256"
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
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	agentCommandSubject          = "rsiem.agent.command"
	defaultAgentNatsURL          = "nats://127.0.0.1:4222"
	defaultCmdTimeoutMs          = 3000
	defaultOutputLimitByte       = 4096
	safeDeniedClass              = "SAFE_DENIED"
	defaultAuthControlRoot       = "/var/lib/rsiem/auth_controls"
	defaultScopedContainmentRoot = "/var/lib/rsiem/containment_controls"
	defaultCommandResultRoot     = "/var/lib/rsiem/command_results"
	defaultCommandReplySpoolRoot = "/var/lib/rsiem/command_reply_spool"
	defaultResponseActionRoot    = "/var/lib/rsiem/response_actions"
	defaultHostsPath             = "/etc/hosts"
)

var execLookPath = exec.LookPath

type commandRequest struct {
	RunID         string         `json:"run_id"`
	StepID        string         `json:"step_id"`
	Lane          string         `json:"lane"`
	ActionType    string         `json:"action_type"`
	Target        string         `json:"target"`
	TargetAgentID string         `json:"target_agent_id,omitempty"`
	Params        map[string]any `json:"params"`
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

type commandResultCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]*commandResultCacheEntry
}

type commandResultStore struct {
	root string
}

type commandReplySpool struct {
	root string
}

type commandResultCacheEntry struct {
	reply     []byte
	ready     chan struct{}
	createdAt time.Time
}

type persistedCommandResult struct {
	Version         int             `json:"version"`
	Key             string          `json:"key"`
	RunID           string          `json:"run_id,omitempty"`
	StepID          string          `json:"step_id,omitempty"`
	Reply           json.RawMessage `json:"reply"`
	CreatedAtUnixMs int64           `json:"created_at_unix_ms"`
}

type persistedCommandReplyEnvelope struct {
	Version         int             `json:"version"`
	Key             string          `json:"key"`
	RunID           string          `json:"run_id,omitempty"`
	StepID          string          `json:"step_id,omitempty"`
	ReplySubject    string          `json:"reply_subject"`
	Reply           json.RawMessage `json:"reply"`
	CreatedAtUnixMs int64           `json:"created_at_unix_ms"`
}

func newCommandResultCache(ttl time.Duration) *commandResultCache {
	return &commandResultCache{
		ttl:     ttl,
		entries: make(map[string]*commandResultCacheEntry),
	}
}

func (c *commandResultCache) begin(key string) (reply []byte, wait <-chan struct{}, execute bool) {
	if c == nil || key == "" {
		return nil, nil, true
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, entry := range c.entries {
		if entry == nil {
			delete(c.entries, k)
			continue
		}
		if entry.reply != nil && now.Sub(entry.createdAt) > c.ttl {
			delete(c.entries, k)
		}
	}
	if entry, ok := c.entries[key]; ok && entry != nil {
		if entry.reply != nil {
			out := make([]byte, len(entry.reply))
			copy(out, entry.reply)
			return out, nil, false
		}
		return nil, entry.ready, false
	}
	c.entries[key] = &commandResultCacheEntry{
		ready:     make(chan struct{}),
		createdAt: now,
	}
	return nil, nil, true
}

func (c *commandResultCache) finish(key string, reply []byte) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || entry == nil {
		return
	}
	if entry.reply == nil {
		entry.reply = make([]byte, len(reply))
		copy(entry.reply, reply)
		close(entry.ready)
	}
	entry.createdAt = time.Now()
}

func (c *commandResultCache) lookup(key string) []byte {
	if c == nil || key == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || entry == nil || entry.reply == nil {
		return nil
	}
	out := make([]byte, len(entry.reply))
	copy(out, entry.reply)
	return out
}

func (c *commandResultCache) abort(key string) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		if entry != nil && entry.reply == nil {
			close(entry.ready)
		}
		delete(c.entries, key)
	}
}

func newCommandResultStore() *commandResultStore {
	root := strings.TrimSpace(os.Getenv("RSIEM_AGENT_COMMAND_RESULT_ROOT"))
	if root == "" {
		root = defaultCommandResultRoot
	}
	return &commandResultStore{root: root}
}

func (s *commandResultStore) enabled() bool {
	return s != nil && strings.TrimSpace(s.root) != ""
}

func (s *commandResultStore) load(key string) ([]byte, error) {
	if !s.enabled() || strings.TrimSpace(key) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(s.pathFor(key))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var record persistedCommandResult
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	if record.Key != key || len(record.Reply) == 0 {
		return nil, nil
	}
	out := make([]byte, len(record.Reply))
	copy(out, record.Reply)
	return out, nil
}

func (s *commandResultStore) save(key, runID, stepID string, reply []byte) error {
	if !s.enabled() || strings.TrimSpace(key) == "" || len(reply) == 0 {
		return nil
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return err
	}
	record := persistedCommandResult{
		Version:         1,
		Key:             key,
		RunID:           strings.TrimSpace(runID),
		StepID:          strings.TrimSpace(stepID),
		Reply:           append(json.RawMessage(nil), reply...),
		CreatedAtUnixMs: time.Now().UnixMilli(),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.root, "cmd-result-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.pathFor(key))
}

func (s *commandResultStore) pathFor(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(s.root, fmt.Sprintf("%x.json", sum))
}

func newCommandReplySpool() *commandReplySpool {
	root := strings.TrimSpace(os.Getenv("RSIEM_AGENT_COMMAND_REPLY_SPOOL_ROOT"))
	if root == "" {
		root = defaultCommandReplySpoolRoot
	}
	return &commandReplySpool{root: root}
}

func (s *commandReplySpool) enabled() bool {
	return s != nil && strings.TrimSpace(s.root) != ""
}

func (s *commandReplySpool) enqueue(key, runID, stepID, replySubject string, reply []byte) error {
	if !s.enabled() || strings.TrimSpace(key) == "" || strings.TrimSpace(replySubject) == "" || len(reply) == 0 {
		return nil
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return err
	}
	record := persistedCommandReplyEnvelope{
		Version:         1,
		Key:             key,
		RunID:           strings.TrimSpace(runID),
		StepID:          strings.TrimSpace(stepID),
		ReplySubject:    strings.TrimSpace(replySubject),
		Reply:           append(json.RawMessage(nil), reply...),
		CreatedAtUnixMs: time.Now().UnixMilli(),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.root, "cmd-reply-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.pathFor(key))
}

func (s *commandReplySpool) flush(publish func(subject string, data []byte) error) error {
	if !s.enabled() {
		return nil
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.root, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var env persistedCommandReplyEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			return err
		}
		if strings.TrimSpace(env.ReplySubject) == "" || len(env.Reply) == 0 {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		if err := publish(env.ReplySubject, env.Reply); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (s *commandReplySpool) pathFor(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(s.root, fmt.Sprintf("%x.json", sum))
}

func publishReply(logger *slog.Logger, spool *commandReplySpool, publish func(subject string, data []byte) error, replySubject, cacheKey, runID, stepID string, data []byte) {
	if strings.TrimSpace(replySubject) == "" || len(data) == 0 {
		return
	}
	if err := publish(replySubject, data); err != nil {
		if logger != nil {
			logger.LogAttrs(context.Background(), slog.LevelWarn, "agent_command_reply_publish_failed",
				slog.String("run_id", strings.TrimSpace(runID)),
				slog.String("step_id", strings.TrimSpace(stepID)),
				slog.String("error", err.Error()),
			)
		}
		if spoolErr := spool.enqueue(cacheKey, runID, stepID, replySubject, data); spoolErr != nil && logger != nil {
			logger.LogAttrs(context.Background(), slog.LevelWarn, "agent_command_reply_spool_enqueue_failed",
				slog.String("run_id", strings.TrimSpace(runID)),
				slog.String("step_id", strings.TrimSpace(stepID)),
				slog.String("error", spoolErr.Error()),
			)
		}
	}
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

type authControlRecord struct {
	Version               int    `json:"version"`
	RunID                 string `json:"run_id"`
	NodeID                string `json:"node_id,omitempty"`
	UserName              string `json:"user_name,omitempty"`
	SrcIP                 string `json:"src_ip,omitempty"`
	Status                string `json:"status"`
	Reason                string `json:"reason,omitempty"`
	ContainedSrcIP        bool   `json:"contained_src_ip"`
	ContainedUserAccess   bool   `json:"contained_user_access"`
	RestoredSrcIP         bool   `json:"restored_src_ip"`
	RestoredUserAccess    bool   `json:"restored_user_access"`
	ContainedAtUnixMs     int64  `json:"contained_at_unix_ms,omitempty"`
	ExpiresAtUnixMs       int64  `json:"expires_at_unix_ms,omitempty"`
	Verified              bool   `json:"verified"`
	VerifiedBy            string `json:"verified_by,omitempty"`
	VerificationMethod    string `json:"verification_method,omitempty"`
	VerificationReference string `json:"verification_reference,omitempty"`
	VerificationNotes     string `json:"verification_notes,omitempty"`
	VerifiedAtUnixMs      int64  `json:"verified_at_unix_ms,omitempty"`
	RestoredAtUnixMs      int64  `json:"restored_at_unix_ms,omitempty"`
	LastUpdatedAtUnixMs   int64  `json:"last_updated_at_unix_ms,omitempty"`
}

type scopedContainmentRecord struct {
	Version             int    `json:"version"`
	RunID               string `json:"run_id"`
	Kind                string `json:"kind"`
	NodeID              string `json:"node_id,omitempty"`
	DstIP               string `json:"dst_ip,omitempty"`
	ExecPath            string `json:"exec_path,omitempty"`
	Comm                string `json:"comm,omitempty"`
	Cmdline             string `json:"cmdline,omitempty"`
	ExecSHA256          string `json:"exec_sha256,omitempty"`
	SignerHint          string `json:"signer_hint,omitempty"`
	Reason              string `json:"reason,omitempty"`
	Status              string `json:"status"`
	Contained           bool   `json:"contained"`
	Restored            bool   `json:"restored"`
	ContainedAtUnixMs   int64  `json:"contained_at_unix_ms,omitempty"`
	ExpiresAtUnixMs     int64  `json:"expires_at_unix_ms,omitempty"`
	RestoredAtUnixMs    int64  `json:"restored_at_unix_ms,omitempty"`
	LastUpdatedAtUnixMs int64  `json:"last_updated_at_unix_ms,omitempty"`
}

type lateralContainmentRecord struct {
	Version             int      `json:"version"`
	RunID               string   `json:"run_id"`
	StepID              string   `json:"step_id,omitempty"`
	NodeID              string   `json:"node_id,omitempty"`
	ProtocolFamily      string   `json:"protocol_family,omitempty"`
	Reason              string   `json:"reason,omitempty"`
	Mode                string   `json:"mode"`
	Backend             string   `json:"backend,omitempty"`
	Targets             []string `json:"targets,omitempty"`
	ContainedAtUnixMs   int64    `json:"contained_at_unix_ms,omitempty"`
	ExpiresAtUnixMs     int64    `json:"expires_at_unix_ms,omitempty"`
	LastUpdatedAtUnixMs int64    `json:"last_updated_at_unix_ms,omitempty"`
}

type networkBlockRecord struct {
	Version             int      `json:"version"`
	ActionID            string   `json:"action_id"`
	RunID               string   `json:"run_id"`
	StepID              string   `json:"step_id,omitempty"`
	NodeID              string   `json:"node_id,omitempty"`
	Direction           string   `json:"direction"`
	Target              string   `json:"target"`
	Targets             []string `json:"targets,omitempty"`
	Hostnames           []string `json:"hostnames,omitempty"`
	Reason              string   `json:"reason,omitempty"`
	Backend             string   `json:"backend,omitempty"`
	Status              string   `json:"status"`
	Applied             bool     `json:"applied"`
	Cleared             bool     `json:"cleared"`
	AppliedAtUnixMs     int64    `json:"applied_at_unix_ms,omitempty"`
	ExpiresAtUnixMs     int64    `json:"expires_at_unix_ms,omitempty"`
	ClearedAtUnixMs     int64    `json:"cleared_at_unix_ms,omitempty"`
	LastUpdatedAtUnixMs int64    `json:"last_updated_at_unix_ms,omitempty"`
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
			"ping":                           {Command: "ping", Args: pingBaseArgs, RequiresTarget: true},
			"uname":                          {Command: "uname", Args: []string{"-a"}},
			"quarantine_move":                {},
			"quarantine_restore":             {},
			"auth_contain_src_ip":            {},
			"auth_contain_user_access":       {},
			"auth_mark_user_verified":        {},
			"auth_restore_src_ip":            {},
			"auth_restore_user_access":       {},
			"contain_destination_ip":         {},
			"restore_destination_ip":         {},
			"contain_process_exec":           {},
			"restore_process_exec":           {},
			"contain_bruteforce_ip":          {},
			"lockdown_privesc":               {},
			"halt_lateral_movement":          {},
			"block_c2_beacon":                {},
			"kill_chain_stage":               {},
			"kill_chain_stop":                {},
			"throttle_exfil":                 {},
			"protect_critical_service_stage": {},
			"protect_critical_service":       {},
			"detector_self_protect":          {},
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
		reply := e.executeNetworkBlockCommand(ctx, req)
		e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_done",
			slog.String("run_id", runID),
			slog.String("step_id", stepID),
			slog.String("command_id", "network_block"),
			slog.Int("exit_code", reply.ExitCode),
			slog.Int64("duration_ms", reply.DurationMs),
			slog.Bool("stdout_truncated", reply.TruncatedStdout),
			slog.Bool("stderr_truncated", reply.TruncatedStderr),
		)
		return reply
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

	if isAuthControlCommand(actionKey) {
		reply := e.executeAuthControlCommand(req, actionKey)
		e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_done",
			slog.String("run_id", runID),
			slog.String("step_id", stepID),
			slog.String("command_id", actionKey),
			slog.Int("exit_code", reply.ExitCode),
			slog.Int64("duration_ms", reply.DurationMs),
			slog.Bool("stdout_truncated", reply.TruncatedStdout),
			slog.Bool("stderr_truncated", reply.TruncatedStderr),
		)
		return reply
	}

	if isScopedContainmentCommand(actionKey) {
		reply := e.executeScopedContainmentCommand(req, actionKey)
		e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_done",
			slog.String("run_id", runID),
			slog.String("step_id", stepID),
			slog.String("command_id", actionKey),
			slog.Int("exit_code", reply.ExitCode),
			slog.Int64("duration_ms", reply.DurationMs),
			slog.Bool("stdout_truncated", reply.TruncatedStdout),
			slog.Bool("stderr_truncated", reply.TruncatedStderr),
		)
		return reply
	}

	if actionKey == "halt_lateral_movement" {
		reply := e.executeLateralMovementCommand(ctx, req)
		e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_done",
			slog.String("run_id", runID),
			slog.String("step_id", stepID),
			slog.String("command_id", actionKey),
			slog.Int("exit_code", reply.ExitCode),
			slog.Int64("duration_ms", reply.DurationMs),
			slog.Bool("stdout_truncated", reply.TruncatedStdout),
			slog.Bool("stderr_truncated", reply.TruncatedStderr),
		)
		return reply
	}

	if category, ok := markerCommandCategory(actionKey); ok {
		reply := e.executeMarkerCommand(req, actionKey, category)
		e.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_exec_done",
			slog.String("run_id", runID),
			slog.String("step_id", stepID),
			slog.String("command_id", actionKey),
			slog.Int("exit_code", reply.ExitCode),
			slog.Int64("duration_ms", reply.DurationMs),
			slog.Bool("stdout_truncated", reply.TruncatedStdout),
			slog.Bool("stderr_truncated", reply.TruncatedStderr),
		)
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

func runCommandListener(ctx context.Context, logger *slog.Logger, natsURL string, localAgentID string, policy quarantinePolicy) error {
	nc, err := nats.Connect(natsURL, nats.Name("r-siem-agent"))
	if err != nil {
		return err
	}
	defer nc.Close()

	executor := newCommandExecutor(logger, policy)
	cache := newCommandResultCache(2 * time.Minute)
	store := newCommandResultStore()
	replySpool := newCommandReplySpool()
	publishFn := func(subject string, data []byte) error {
		if err := nc.Publish(subject, data); err != nil {
			return err
		}
		return nc.Flush()
	}
	localAgentID = strings.TrimSpace(localAgentID)
	subjects := []string{agentCommandSubject}
	if localAgentID != "" {
		subjects = append(subjects, agentCommandSubject+"."+localAgentID)
	}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := replySpool.flush(publishFn); err != nil && logger != nil {
					logger.LogAttrs(context.Background(), slog.LevelDebug, "agent_command_reply_spool_flush_retry",
						slog.String("error", err.Error()),
					)
				}
			}
		}
	}()

	handler := func(msg *nats.Msg) {
		if msg.Reply == "" {
			return
		}
		var req commandRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			return
		}
		targetAgentID := strings.TrimSpace(req.TargetAgentID)
		if targetAgentID != "" && localAgentID != "" && targetAgentID != localAgentID {
			return
		}
		cacheKey := ""
		if strings.TrimSpace(req.RunID) != "" && strings.TrimSpace(req.StepID) != "" {
			cacheKey = strings.TrimSpace(req.RunID) + "|" + strings.TrimSpace(req.StepID)
		}
		if persistedReply, err := store.load(cacheKey); err != nil {
			logger.LogAttrs(context.Background(), slog.LevelWarn, "agent_command_result_store_load_failed",
				slog.String("run_id", strings.TrimSpace(req.RunID)),
				slog.String("step_id", strings.TrimSpace(req.StepID)),
				slog.String("error", err.Error()),
			)
		} else if len(persistedReply) > 0 {
			cache.finish(cacheKey, persistedReply)
			publishReply(logger, replySpool, publishFn, msg.Reply, cacheKey, req.RunID, req.StepID, persistedReply)
			return
		}
		cachedReply, wait, execute := cache.begin(cacheKey)
		if !execute {
			if cachedReply != nil {
				publishReply(logger, replySpool, publishFn, msg.Reply, cacheKey, req.RunID, req.StepID, cachedReply)
				return
			}
			if wait != nil {
				<-wait
				cachedReply = cache.lookup(cacheKey)
				if cachedReply != nil {
					publishReply(logger, replySpool, publishFn, msg.Reply, cacheKey, req.RunID, req.StepID, cachedReply)
				}
				return
			}
		}
		reply := executor.handle(ctx, req)
		data, err := json.Marshal(reply)
		if err != nil {
			cache.abort(cacheKey)
			return
		}
		if err := store.save(cacheKey, req.RunID, req.StepID, data); err != nil {
			logger.LogAttrs(context.Background(), slog.LevelWarn, "agent_command_result_store_save_failed",
				slog.String("run_id", strings.TrimSpace(req.RunID)),
				slog.String("step_id", strings.TrimSpace(req.StepID)),
				slog.String("error", err.Error()),
			)
		}
		cache.finish(cacheKey, data)
		publishReply(logger, replySpool, publishFn, msg.Reply, cacheKey, req.RunID, req.StepID, data)
	}
	subs := make([]*nats.Subscription, 0, len(subjects))
	for _, subject := range subjects {
		sub, subErr := nc.Subscribe(subject, handler)
		if subErr != nil {
			for _, existing := range subs {
				_ = existing.Unsubscribe()
			}
			return subErr
		}
		subs = append(subs, sub)
	}

	if err := nc.Flush(); err != nil {
		for _, sub := range subs {
			_ = sub.Unsubscribe()
		}
		return err
	}

	logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_subscribe",
		slog.Any("subjects", subjects),
	)

	<-ctx.Done()
	for _, sub := range subs {
		_ = sub.Unsubscribe()
	}
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

func markerCommandCategory(commandID string) (string, bool) {
	switch commandID {
	case "contain_bruteforce_ip":
		return "containment", true
	case "lockdown_privesc":
		return "lockdown", true
	case "halt_lateral_movement":
		return "lateral", true
	case "block_c2_beacon":
		return "c2", true
	case "kill_chain_stage", "kill_chain_stop":
		return "ransomware", true
	case "throttle_exfil":
		return "exfil", true
	case "protect_critical_service_stage", "protect_critical_service":
		return "service_abuse", true
	case "detector_self_protect":
		return "detector", true
	default:
		return "", false
	}
}

func isAuthControlCommand(commandID string) bool {
	switch commandID {
	case "auth_contain_src_ip", "auth_contain_user_access", "auth_mark_user_verified", "auth_restore_src_ip", "auth_restore_user_access":
		return true
	default:
		return false
	}
}

func isScopedContainmentCommand(commandID string) bool {
	switch commandID {
	case "contain_destination_ip", "restore_destination_ip", "contain_process_exec", "restore_process_exec":
		return true
	default:
		return false
	}
}

func authControlRoot() string {
	val := strings.TrimSpace(os.Getenv("RSIEM_AGENT_AUTH_CONTROL_ROOT"))
	if val == "" {
		return defaultAuthControlRoot
	}
	return val
}

func scopedContainmentRoot() string {
	val := strings.TrimSpace(os.Getenv("RSIEM_AGENT_SCOPED_CONTAINMENT_ROOT"))
	if val == "" {
		return defaultScopedContainmentRoot
	}
	return val
}

func responseActionRoot() string {
	val := strings.TrimSpace(os.Getenv("RSIEM_AGENT_RESPONSE_ACTION_ROOT"))
	if val == "" {
		return defaultResponseActionRoot
	}
	return val
}

func lateralControlMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RSIEM_AGENT_LATERAL_CONTROL_MODE"))) {
	case "", "marker":
		return "marker"
	case "firewall":
		return "firewall"
	default:
		return "marker"
	}
}

func (e *commandExecutor) executeAuthControlCommand(req commandRequest, commandID string) commandReply {
	start := time.Now()
	runID := strings.TrimSpace(req.RunID)
	if runID == "" || runID != filepath.Base(runID) || strings.Contains(runID, string(filepath.Separator)) {
		return commandReply{
			Status:     "error",
			ExitCode:   3,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     "safe_denied:invalid_run_id",
			ErrorClass: safeDeniedClass,
		}
	}

	root, err := ensureResolvedDirectoryAllowAbs(authControlRoot(), "", true)
	if err != nil {
		return commandReply{
			Status:     "error",
			ExitCode:   3,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     "safe_denied:invalid_auth_control_root",
			ErrorClass: safeDeniedClass,
		}
	}

	nowMs := time.Now().UnixMilli()
	record, recordPath, err := loadOrFindAuthControlRecord(root, req, commandID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return commandReply{
			Status:     "error",
			ExitCode:   3,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     err.Error(),
			ErrorClass: safeDeniedClass,
		}
	}
	if recordPath == "" {
		recordPath = filepath.Join(root, runID+".json")
	}
	if record.RunID == "" {
		record = authControlRecord{
			Version: 1,
			RunID:   runID,
			NodeID:  strings.TrimSpace(stringParam(req.Params, "node_id")),
			UserName: strings.TrimSpace(
				chooseFirstNonEmpty(
					stringParam(req.Params, "user_name"),
					stringParam(req.Params, "user"),
				),
			),
			SrcIP: strings.TrimSpace(stringParam(req.Params, "src_ip")),
		}
	}
	if record.NodeID == "" {
		record.NodeID = strings.TrimSpace(stringParam(req.Params, "node_id"))
	}
	if record.UserName == "" {
		record.UserName = strings.TrimSpace(chooseFirstNonEmpty(stringParam(req.Params, "user_name"), stringParam(req.Params, "user")))
	}
	if record.SrcIP == "" {
		record.SrcIP = strings.TrimSpace(stringParam(req.Params, "src_ip"))
	}

	switch commandID {
	case "auth_contain_src_ip":
		if record.SrcIP == "" {
			record.SrcIP = strings.TrimSpace(req.Target)
		}
		if record.SrcIP == "" || net.ParseIP(record.SrcIP) == nil {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_src_ip", ErrorClass: safeDeniedClass}
		}
		durationMs, set, err := intParam(req.Params, "duration_ms")
		if err != nil || (set && durationMs <= 0) {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_duration_ms", ErrorClass: safeDeniedClass}
		}
		if !set {
			durationMs = 900000
		}
		record.ContainedSrcIP = true
		record.Status = "contained"
		record.Reason = chooseFirstNonEmpty(stringParam(req.Params, "reason"), record.Reason)
		if record.ContainedAtUnixMs == 0 {
			record.ContainedAtUnixMs = nowMs
		}
		record.ExpiresAtUnixMs = nowMs + durationMs
	case "auth_contain_user_access":
		if record.UserName == "" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:missing_user_name", ErrorClass: safeDeniedClass}
		}
		durationMs, set, err := intParam(req.Params, "duration_ms")
		if err != nil || (set && durationMs <= 0) {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_duration_ms", ErrorClass: safeDeniedClass}
		}
		if !set {
			durationMs = 900000
		}
		record.ContainedUserAccess = true
		record.Status = "contained"
		record.Reason = chooseFirstNonEmpty(stringParam(req.Params, "reason"), record.Reason)
		if record.ContainedAtUnixMs == 0 {
			record.ContainedAtUnixMs = nowMs
		}
		record.ExpiresAtUnixMs = nowMs + durationMs
	case "auth_mark_user_verified":
		if record.RunID == "" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:containment_record_missing", ErrorClass: safeDeniedClass}
		}
		method := strings.TrimSpace(stringParam(req.Params, "verification_method"))
		ref := strings.TrimSpace(stringParam(req.Params, "verification_reference"))
		if method == "" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:missing_verification_method", ErrorClass: safeDeniedClass}
		}
		if ref == "" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:missing_verification_reference", ErrorClass: safeDeniedClass}
		}
		record.Verified = true
		record.VerifiedBy = chooseFirstNonEmpty(stringParam(req.Params, "verified_by"), stringParam(req.Params, "actor"), record.VerifiedBy)
		record.VerificationMethod = method
		record.VerificationReference = ref
		record.VerificationNotes = chooseFirstNonEmpty(stringParam(req.Params, "notes"), record.VerificationNotes)
		record.VerifiedAtUnixMs = nowMs
		if record.Status == "" {
			record.Status = "verified"
		}
	case "auth_restore_src_ip":
		if record.RunID == "" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:containment_record_missing", ErrorClass: safeDeniedClass}
		}
		if !record.Verified {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:verification_required", ErrorClass: safeDeniedClass}
		}
		if !record.ContainedSrcIP {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:src_ip_not_contained", ErrorClass: safeDeniedClass}
		}
		record.RestoredSrcIP = true
	case "auth_restore_user_access":
		if record.RunID == "" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:containment_record_missing", ErrorClass: safeDeniedClass}
		}
		if !record.Verified {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:verification_required", ErrorClass: safeDeniedClass}
		}
		if !record.ContainedUserAccess {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:user_access_not_contained", ErrorClass: safeDeniedClass}
		}
		record.RestoredUserAccess = true
	}

	if (record.ContainedSrcIP && record.RestoredSrcIP || !record.ContainedSrcIP) &&
		(record.ContainedUserAccess && record.RestoredUserAccess || !record.ContainedUserAccess) &&
		(record.RestoredSrcIP || record.RestoredUserAccess) {
		record.Status = "restored"
		record.RestoredAtUnixMs = nowMs
	} else if record.Verified && record.Status == "contained" {
		record.Status = "verified"
	}
	record.LastUpdatedAtUnixMs = nowMs

	if err := writeAuthControlRecord(recordPath, record); err != nil {
		return commandReply{
			Status:     "error",
			ExitCode:   1,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     err.Error(),
			ErrorClass: "exec_failed",
		}
	}
	return commandReply{
		Status:     "ok",
		ExitCode:   0,
		DurationMs: time.Since(start).Milliseconds(),
		Stdout:     recordPath,
	}
}

func loadOrFindAuthControlRecord(root string, req commandRequest, commandID string) (authControlRecord, string, error) {
	containmentRunID := strings.TrimSpace(stringParam(req.Params, "containment_run_id"))
	if containmentRunID == "" {
		containmentRunID = strings.TrimSpace(req.RunID)
	}
	if containmentRunID != "" && containmentRunID == filepath.Base(containmentRunID) && !strings.Contains(containmentRunID, string(filepath.Separator)) {
		path := filepath.Join(root, containmentRunID+".json")
		rec, err := readAuthControlRecord(path)
		if err == nil {
			return rec, path, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return authControlRecord{}, "", err
		}
		if strings.HasPrefix(commandID, "auth_contain_") {
			return authControlRecord{}, path, os.ErrNotExist
		}
	}

	userName := strings.TrimSpace(chooseFirstNonEmpty(stringParam(req.Params, "user_name"), stringParam(req.Params, "user")))
	srcIP := strings.TrimSpace(stringParam(req.Params, "src_ip"))
	if srcIP == "" {
		srcIP = strings.TrimSpace(req.Target)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return authControlRecord{}, "", os.ErrNotExist
		}
		return authControlRecord{}, "", err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		rec, err := readAuthControlRecord(path)
		if err != nil {
			continue
		}
		if rec.Status == "restored" {
			continue
		}
		if userName != "" && rec.UserName == userName {
			return rec, path, nil
		}
		if srcIP != "" && rec.SrcIP == srcIP {
			return rec, path, nil
		}
	}
	return authControlRecord{}, "", os.ErrNotExist
}

func readAuthControlRecord(path string) (authControlRecord, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return authControlRecord{}, denySafe("auth_control_symlink_not_allowed")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return authControlRecord{}, err
	}
	var rec authControlRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return authControlRecord{}, denySafe("auth_control_record_invalid")
	}
	return rec, nil
}

func writeAuthControlRecord(path string, rec authControlRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return denySafe("auth_control_symlink_not_allowed")
		}
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (e *commandExecutor) executeScopedContainmentCommand(req commandRequest, commandID string) commandReply {
	start := time.Now()
	runID := strings.TrimSpace(req.RunID)
	if runID == "" || runID != filepath.Base(runID) || strings.Contains(runID, string(filepath.Separator)) {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_run_id", ErrorClass: safeDeniedClass}
	}
	root, err := ensureResolvedDirectoryAllowAbs(scopedContainmentRoot(), "", true)
	if err != nil {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_scoped_containment_root", ErrorClass: safeDeniedClass}
	}
	nowMs := time.Now().UnixMilli()
	record, recordPath, err := loadOrFindScopedContainmentRecord(root, req, commandID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: safeDeniedClass}
	}
	if recordPath == "" {
		recordPath = filepath.Join(root, runID+".json")
	}
	if record.RunID == "" {
		record = scopedContainmentRecord{
			Version:    1,
			RunID:      runID,
			NodeID:     strings.TrimSpace(stringParam(req.Params, "node_id")),
			DstIP:      strings.TrimSpace(stringParam(req.Params, "dst_ip")),
			ExecPath:   strings.TrimSpace(stringParam(req.Params, "exec_path")),
			Comm:       strings.TrimSpace(stringParam(req.Params, "comm")),
			Cmdline:    strings.TrimSpace(stringParam(req.Params, "cmdline")),
			ExecSHA256: strings.TrimSpace(stringParam(req.Params, "exec_sha256")),
			SignerHint: strings.TrimSpace(stringParam(req.Params, "signer_hint")),
		}
	}
	if record.NodeID == "" {
		record.NodeID = strings.TrimSpace(stringParam(req.Params, "node_id"))
	}
	if record.DstIP == "" {
		record.DstIP = strings.TrimSpace(chooseFirstNonEmpty(stringParam(req.Params, "dst_ip"), req.Target))
	}
	if record.ExecPath == "" {
		record.ExecPath = strings.TrimSpace(stringParam(req.Params, "exec_path"))
	}
	if record.Comm == "" {
		record.Comm = strings.TrimSpace(stringParam(req.Params, "comm"))
	}
	if record.Cmdline == "" {
		record.Cmdline = strings.TrimSpace(stringParam(req.Params, "cmdline"))
	}
	if record.ExecSHA256 == "" {
		record.ExecSHA256 = strings.TrimSpace(stringParam(req.Params, "exec_sha256"))
	}
	if record.SignerHint == "" {
		record.SignerHint = strings.TrimSpace(stringParam(req.Params, "signer_hint"))
	}

	switch commandID {
	case "contain_destination_ip":
		record.Kind = "destination_ip"
		if record.DstIP == "" || net.ParseIP(record.DstIP) == nil {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_dst_ip", ErrorClass: safeDeniedClass}
		}
		durationMs, set, err := intParam(req.Params, "duration_ms")
		if err != nil || (set && durationMs <= 0) {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_duration_ms", ErrorClass: safeDeniedClass}
		}
		if !set {
			durationMs = 900000
		}
		record.Contained = true
		record.Status = "contained"
		record.Reason = chooseFirstNonEmpty(stringParam(req.Params, "reason"), record.Reason)
		if record.ContainedAtUnixMs == 0 {
			record.ContainedAtUnixMs = nowMs
		}
		record.ExpiresAtUnixMs = nowMs + durationMs
	case "contain_process_exec":
		record.Kind = "process_exec"
		if record.ExecPath == "" && record.Comm == "" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:missing_exec_identity", ErrorClass: safeDeniedClass}
		}
		durationMs, set, err := intParam(req.Params, "duration_ms")
		if err != nil || (set && durationMs <= 0) {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_duration_ms", ErrorClass: safeDeniedClass}
		}
		if !set {
			durationMs = 900000
		}
		record.Contained = true
		record.Status = "contained"
		record.Reason = chooseFirstNonEmpty(stringParam(req.Params, "reason"), record.Reason)
		if record.ContainedAtUnixMs == 0 {
			record.ContainedAtUnixMs = nowMs
		}
		record.ExpiresAtUnixMs = nowMs + durationMs
	case "restore_destination_ip":
		if record.RunID == "" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:containment_record_missing", ErrorClass: safeDeniedClass}
		}
		if record.Kind != "destination_ip" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:containment_kind_mismatch", ErrorClass: safeDeniedClass}
		}
		if !record.Contained || record.DstIP == "" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:destination_not_contained", ErrorClass: safeDeniedClass}
		}
		record.Restored = true
		record.Status = "restored"
		record.RestoredAtUnixMs = nowMs
	case "restore_process_exec":
		if record.RunID == "" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:containment_record_missing", ErrorClass: safeDeniedClass}
		}
		if record.Kind != "process_exec" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:containment_kind_mismatch", ErrorClass: safeDeniedClass}
		}
		if !record.Contained || (record.ExecPath == "" && record.Comm == "") {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:process_not_contained", ErrorClass: safeDeniedClass}
		}
		record.Restored = true
		record.Status = "restored"
		record.RestoredAtUnixMs = nowMs
	}
	record.LastUpdatedAtUnixMs = nowMs
	if err := writeScopedContainmentRecord(recordPath, record); err != nil {
		return commandReply{Status: "error", ExitCode: 1, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: "exec_failed"}
	}
	return commandReply{Status: "ok", ExitCode: 0, DurationMs: time.Since(start).Milliseconds(), Stdout: recordPath}
}

func loadOrFindScopedContainmentRecord(root string, req commandRequest, commandID string) (scopedContainmentRecord, string, error) {
	containmentRunID := strings.TrimSpace(stringParam(req.Params, "containment_run_id"))
	if containmentRunID == "" {
		containmentRunID = strings.TrimSpace(req.RunID)
	}
	if containmentRunID != "" && containmentRunID == filepath.Base(containmentRunID) && !strings.Contains(containmentRunID, string(filepath.Separator)) {
		path := filepath.Join(root, containmentRunID+".json")
		rec, err := readScopedContainmentRecord(path)
		if err == nil {
			return rec, path, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return scopedContainmentRecord{}, "", err
		}
		if strings.HasPrefix(commandID, "contain_") {
			return scopedContainmentRecord{}, path, os.ErrNotExist
		}
	}
	dstIP := strings.TrimSpace(chooseFirstNonEmpty(stringParam(req.Params, "dst_ip"), req.Target))
	execPath := strings.TrimSpace(stringParam(req.Params, "exec_path"))
	comm := strings.TrimSpace(stringParam(req.Params, "comm"))
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return scopedContainmentRecord{}, "", os.ErrNotExist
		}
		return scopedContainmentRecord{}, "", err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		rec, err := readScopedContainmentRecord(path)
		if err != nil || rec.Status == "restored" {
			continue
		}
		if dstIP != "" && rec.DstIP == dstIP {
			return rec, path, nil
		}
		if execPath != "" && rec.ExecPath == execPath {
			return rec, path, nil
		}
		if comm != "" && rec.Comm == comm {
			return rec, path, nil
		}
	}
	return scopedContainmentRecord{}, "", os.ErrNotExist
}

func readScopedContainmentRecord(path string) (scopedContainmentRecord, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return scopedContainmentRecord{}, denySafe("containment_symlink_not_allowed")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return scopedContainmentRecord{}, err
	}
	var rec scopedContainmentRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return scopedContainmentRecord{}, denySafe("containment_record_invalid")
	}
	return rec, nil
}

func writeScopedContainmentRecord(path string, rec scopedContainmentRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return denySafe("containment_symlink_not_allowed")
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func writeLateralContainmentRecord(path string, rec lateralContainmentRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return denySafe("lateral_containment_symlink_not_allowed")
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func readNetworkBlockRecord(path string) (networkBlockRecord, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return networkBlockRecord{}, denySafe("network_block_symlink_not_allowed")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return networkBlockRecord{}, err
	}
	var rec networkBlockRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return networkBlockRecord{}, denySafe("network_block_record_invalid")
	}
	return rec, nil
}

func writeNetworkBlockRecord(path string, rec networkBlockRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return denySafe("network_block_symlink_not_allowed")
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func chooseFirstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func uniqueStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func splitCSVValues(input string) []string {
	fields := strings.FieldsFunc(strings.TrimSpace(input), func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		out = append(out, field)
	}
	return out
}

func uniqueValidPrivateIPs(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			return nil, denySafe("invalid_lateral_target")
		}
		if !ip.IsPrivate() {
			return nil, denySafe("lateral_target_not_private")
		}
		canonical := ip.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out, nil
}

func uniquePrivateIPsBestEffort(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || !ip.IsPrivate() {
			continue
		}
		canonical := ip.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out
}

func nftTimeoutString(durationMs int64) string {
	if durationMs <= 0 {
		durationMs = 900000
	}
	seconds := (durationMs + 999) / 1000
	switch {
	case seconds%3600 == 0:
		return fmt.Sprintf("%dh", seconds/3600)
	case seconds%60 == 0:
		return fmt.Sprintf("%dm", seconds/60)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}

func ignorableNFTError(result execResult, fragments ...string) bool {
	if result.Err == nil {
		return false
	}
	text := result.Stderr + "\n" + result.Stdout
	for _, fragment := range fragments {
		if strings.Contains(text, fragment) {
			return true
		}
	}
	return false
}

func (e *commandExecutor) runFirewallSpec(ctx context.Context, spec execSpec) execResult {
	if e.runner != nil {
		return e.runner.Run(ctx, spec)
	}
	return osExecRunner{outputLimit: e.outputLimit}.Run(ctx, spec)
}

func (e *commandExecutor) ensureNFTBase(ctx context.Context, nftBin string) error {
	createTable := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: []string{"add", "table", "inet", "rsiem_contain"}})
	if createTable.Err != nil && !ignorableNFTError(createTable, "File exists") {
		return fmt.Errorf("nft add table: %w", createTable.Err)
	}

	setSpecs := []struct {
		name string
		spec string
	}{
		{name: "lateral_block_v4", spec: "{ type ipv4_addr; flags timeout; }"},
		{name: "lateral_block_v6", spec: "{ type ipv6_addr; flags timeout; }"},
		{name: "network_block_ingress_v4", spec: "{ type ipv4_addr; flags interval,timeout; }"},
		{name: "network_block_ingress_v6", spec: "{ type ipv6_addr; flags interval,timeout; }"},
		{name: "network_block_egress_v4", spec: "{ type ipv4_addr; flags interval,timeout; }"},
		{name: "network_block_egress_v6", spec: "{ type ipv6_addr; flags interval,timeout; }"},
	}
	for _, item := range setSpecs {
		createSet := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: []string{"add", "set", "inet", "rsiem_contain", item.name, item.spec}})
		if createSet.Err != nil && !ignorableNFTError(createSet, "File exists") {
			return fmt.Errorf("nft add set %s: %w", item.name, createSet.Err)
		}
	}

	chainSpecs := []struct {
		name string
		spec string
	}{
		{name: "rsiem_input", spec: "{ type filter hook input priority 0; policy accept; }"},
		{name: "rsiem_output", spec: "{ type filter hook output priority 0; policy accept; }"},
	}
	for _, item := range chainSpecs {
		createChain := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: []string{"add", "chain", "inet", "rsiem_contain", item.name, item.spec}})
		if createChain.Err != nil && !ignorableNFTError(createChain, "File exists") {
			return fmt.Errorf("nft add chain %s: %w", item.name, createChain.Err)
		}
	}

	listOutput := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: []string{"list", "chain", "inet", "rsiem_contain", "rsiem_output"}})
	if listOutput.Err != nil {
		return fmt.Errorf("nft list chain rsiem_output: %w", listOutput.Err)
	}
	outputText := listOutput.Stdout + "\n" + listOutput.Stderr
	outputRules := []struct {
		marker string
		args   []string
	}{
		{marker: "@lateral_block_v4", args: []string{"add", "rule", "inet", "rsiem_contain", "rsiem_output", "ip", "daddr", "@lateral_block_v4", "drop"}},
		{marker: "@lateral_block_v6", args: []string{"add", "rule", "inet", "rsiem_contain", "rsiem_output", "ip6", "daddr", "@lateral_block_v6", "drop"}},
		{marker: "@network_block_egress_v4", args: []string{"add", "rule", "inet", "rsiem_contain", "rsiem_output", "oifname", "!=", "lo", "ip", "daddr", "@network_block_egress_v4", "drop"}},
		{marker: "@network_block_egress_v6", args: []string{"add", "rule", "inet", "rsiem_contain", "rsiem_output", "oifname", "!=", "lo", "ip6", "daddr", "@network_block_egress_v6", "drop"}},
	}
	for _, item := range outputRules {
		if strings.Contains(outputText, item.marker) {
			continue
		}
		addRule := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: item.args})
		if addRule.Err != nil && !ignorableNFTError(addRule, "File exists") {
			return fmt.Errorf("nft add output rule %s: %w", item.marker, addRule.Err)
		}
	}

	listInput := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: []string{"list", "chain", "inet", "rsiem_contain", "rsiem_input"}})
	if listInput.Err != nil {
		return fmt.Errorf("nft list chain rsiem_input: %w", listInput.Err)
	}
	inputText := listInput.Stdout + "\n" + listInput.Stderr
	inputRules := []struct {
		marker string
		args   []string
	}{
		{marker: "@network_block_ingress_v4", args: []string{"add", "rule", "inet", "rsiem_contain", "rsiem_input", "iifname", "!=", "lo", "ip", "saddr", "@network_block_ingress_v4", "drop"}},
		{marker: "@network_block_ingress_v6", args: []string{"add", "rule", "inet", "rsiem_contain", "rsiem_input", "iifname", "!=", "lo", "ip6", "saddr", "@network_block_ingress_v6", "drop"}},
	}
	for _, item := range inputRules {
		if strings.Contains(inputText, item.marker) {
			continue
		}
		addRule := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: item.args})
		if addRule.Err != nil && !ignorableNFTError(addRule, "File exists") {
			return fmt.Errorf("nft add input rule %s: %w", item.marker, addRule.Err)
		}
	}
	return nil
}

func (e *commandExecutor) applyLateralFirewallTargets(ctx context.Context, nftBin string, targets []string, durationMs int64) error {
	timeoutValue := nftTimeoutString(durationMs)
	for _, target := range targets {
		ip := net.ParseIP(target)
		if ip == nil {
			return denySafe("invalid_lateral_target")
		}
		setName := "lateral_block_v6"
		if ip.To4() != nil {
			setName = "lateral_block_v4"
		}
		deleteResult := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: []string{"delete", "element", "inet", "rsiem_contain", setName, fmt.Sprintf("{ %s }", target)}})
		if deleteResult.Err != nil && !ignorableNFTError(deleteResult, "No such file or directory", "No such element") {
			return fmt.Errorf("nft delete element %s %s: %w", setName, target, deleteResult.Err)
		}
		addResult := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: []string{"add", "element", "inet", "rsiem_contain", setName, fmt.Sprintf("{ %s timeout %s }", target, timeoutValue)}})
		if addResult.Err != nil && !ignorableNFTError(addResult, "File exists") {
			return fmt.Errorf("nft add element %s %s: %w", setName, target, addResult.Err)
		}
	}
	return nil
}

func networkBlockActionID(req commandRequest) string {
	for _, candidate := range []string{
		strings.TrimSpace(stringParam(req.Params, "response_action_id")),
		strings.TrimSpace(stringParam(req.Params, "containment_run_id")),
		strings.TrimSpace(req.RunID),
	} {
		if candidate == "" {
			continue
		}
		if candidate != filepath.Base(candidate) || strings.Contains(candidate, string(filepath.Separator)) {
			return ""
		}
		return candidate
	}
	return ""
}

func normalizeNetworkBlockDirection(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "both":
		return "both"
	case "ingress", "egress":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

func canonicalNetworkBlockTargets(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !validIPOrCIDR(raw) {
		return nil, denySafe("invalid_network_block_target")
	}
	if raw == "0.0.0.0/0" {
		return []string{"0.0.0.0/0", "::/0"}, nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		return []string{ip.String()}, nil
	}
	_, network, err := net.ParseCIDR(raw)
	if err != nil || network == nil {
		return nil, denySafe("invalid_network_block_target")
	}
	return []string{network.String()}, nil
}

func canonicalNetworkBlockHostnames(raw string) ([]string, error) {
	host := strings.ToLower(strings.TrimSpace(raw))
	if host == "" || !validHostname(host) {
		return nil, denySafe("invalid_network_block_target")
	}
	return []string{host}, nil
}

func optionalResolvedTargets(raw string) ([]string, error) {
	parts := splitCSVValues(raw)
	if len(parts) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		targets, err := canonicalNetworkBlockTargets(part)
		if err != nil {
			return nil, err
		}
		out = append(out, targets...)
	}
	return uniqueStrings(out), nil
}

func resolveHostnameTargets(ctx context.Context, hostnames []string) []string {
	resolver := net.DefaultResolver
	out := make([]string, 0, len(hostnames)*2)
	for _, hostname := range hostnames {
		ips, err := resolver.LookupIP(ctx, "ip", hostname)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip == nil {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return uniqueStrings(out)
}

func hostsFilePath() string {
	path := strings.TrimSpace(os.Getenv("RSIEM_AGENT_HOSTS_PATH"))
	if path == "" {
		path = defaultHostsPath
	}
	return path
}

func networkBlockHostsMarker(actionID string) string {
	return "# rsiem-network-block:" + strings.TrimSpace(actionID)
}

func loadHostsFile(path string) (string, os.FileMode, error) {
	if err := ensureNoSymlinkPath(path, true); err != nil {
		return "", 0, denySafe("hosts_path_symlink_not_allowed")
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", 0o644, nil
		}
		return "", 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	return string(data), info.Mode().Perm(), nil
}

func writeHostsFile(path, content string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "rsiem-hosts-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func applyHostsBlockEntries(path, actionID string, hostnames []string) error {
	if len(hostnames) == 0 {
		return nil
	}
	content, mode, err := loadHostsFile(path)
	if err != nil {
		return err
	}
	lines := []string{}
	if content != "" {
		lines = strings.Split(strings.TrimRight(content, "\n"), "\n")
	}
	marker := networkBlockHostsMarker(actionID)
	existing := strings.Join(lines, "\n")
	for _, hostname := range uniqueStrings(hostnames) {
		for _, entry := range []string{
			fmt.Sprintf("127.0.0.1 %s %s", hostname, marker),
			fmt.Sprintf("::1 %s %s", hostname, marker),
		} {
			if strings.Contains(existing, entry) {
				continue
			}
			lines = append(lines, entry)
		}
	}
	next := strings.Join(lines, "\n")
	if next != "" {
		next += "\n"
	}
	return writeHostsFile(path, next, mode)
}

func clearHostsBlockEntries(path, actionID string) error {
	content, mode, err := loadHostsFile(path)
	if err != nil {
		return err
	}
	if content == "" {
		return nil
	}
	marker := networkBlockHostsMarker(actionID)
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, marker) {
			continue
		}
		filtered = append(filtered, line)
	}
	next := strings.Join(filtered, "\n")
	if next != "" {
		next += "\n"
	}
	return writeHostsFile(path, next, mode)
}

func networkBlockSetNames(direction, target string) []string {
	ip := net.ParseIP(target)
	isV4 := ip != nil && ip.To4() != nil
	if ip == nil {
		_, network, _ := net.ParseCIDR(target)
		if network != nil && network.IP.To4() != nil {
			isV4 = true
		}
	}
	suffix := "v6"
	if isV4 {
		suffix = "v4"
	}
	switch direction {
	case "ingress":
		return []string{"network_block_ingress_" + suffix}
	case "egress":
		return []string{"network_block_egress_" + suffix}
	default:
		return []string{"network_block_ingress_" + suffix, "network_block_egress_" + suffix}
	}
}

func (e *commandExecutor) applyNetworkBlockTargets(ctx context.Context, nftBin, direction string, targets []string, durationMs int64) error {
	timeoutValue := nftTimeoutString(durationMs)
	for _, target := range targets {
		for _, setName := range networkBlockSetNames(direction, target) {
			addResult := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: []string{"add", "element", "inet", "rsiem_contain", setName, fmt.Sprintf("{ %s timeout %s }", target, timeoutValue)}})
			if addResult.Err == nil || ignorableNFTError(addResult, "File exists") {
				if addResult.Err == nil {
					continue
				}
				deleteResult := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: []string{"delete", "element", "inet", "rsiem_contain", setName, fmt.Sprintf("{ %s }", target)}})
				if deleteResult.Err != nil && !ignorableNFTError(deleteResult, "No such file or directory", "No such element", "No such file") {
					return fmt.Errorf("nft delete element %s %s: %w", setName, target, deleteResult.Err)
				}
				retryAdd := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: []string{"add", "element", "inet", "rsiem_contain", setName, fmt.Sprintf("{ %s timeout %s }", target, timeoutValue)}})
				if retryAdd.Err != nil && !ignorableNFTError(retryAdd, "File exists") {
					return fmt.Errorf("nft add element %s %s: %w", setName, target, retryAdd.Err)
				}
				continue
			}
			if addResult.Err != nil {
				return fmt.Errorf("nft add element %s %s: %w", setName, target, addResult.Err)
			}
		}
	}
	return nil
}

func (e *commandExecutor) clearNetworkBlockTargets(ctx context.Context, nftBin, direction string, targets []string) error {
	for _, target := range targets {
		for _, setName := range networkBlockSetNames(direction, target) {
			deleteResult := e.runFirewallSpec(ctx, execSpec{Command: nftBin, Args: []string{"delete", "element", "inet", "rsiem_contain", setName, fmt.Sprintf("{ %s }", target)}})
			if deleteResult.Err != nil && !ignorableNFTError(deleteResult, "No such file or directory", "No such element", "No such file") {
				return fmt.Errorf("nft delete element %s %s: %w", setName, target, deleteResult.Err)
			}
		}
	}
	return nil
}

func loadNetworkBlockRecord(root string, req commandRequest) (networkBlockRecord, string, error) {
	if actionID := networkBlockActionID(req); actionID != "" {
		path := filepath.Join(root, "network", actionID, "state.json")
		rec, err := readNetworkBlockRecord(path)
		if err == nil {
			return rec, path, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return networkBlockRecord{}, "", err
		}
		if strings.EqualFold(strings.TrimSpace(stringParam(req.Params, "mode")), "clear") {
			return networkBlockRecord{}, "", os.ErrNotExist
		}
		return networkBlockRecord{}, path, os.ErrNotExist
	}
	return networkBlockRecord{}, "", os.ErrNotExist
}

func (e *commandExecutor) executeNetworkBlockCommand(ctx context.Context, req commandRequest) commandReply {
	start := time.Now()
	runID := strings.TrimSpace(req.RunID)
	stepID := strings.TrimSpace(req.StepID)
	if runID == "" || runID != filepath.Base(runID) || strings.Contains(runID, string(filepath.Separator)) {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_run_id", ErrorClass: safeDeniedClass}
	}
	direction := normalizeNetworkBlockDirection(stringParam(req.Params, "direction"))
	if direction == "" {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_direction", ErrorClass: safeDeniedClass}
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		target = strings.TrimSpace(stringParam(req.Params, "target"))
	}
	target = strings.TrimSpace(target)
	var targets []string
	var hostnames []string
	var err error
	if validIPOrCIDR(target) {
		targets, err = canonicalNetworkBlockTargets(target)
		if err != nil {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: safeDeniedClass}
		}
	} else {
		hostnames, err = canonicalNetworkBlockHostnames(target)
		if err != nil {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: safeDeniedClass}
		}
	}
	mode := strings.ToLower(strings.TrimSpace(stringParam(req.Params, "mode")))
	if mode == "" {
		mode = "apply"
	}
	if mode != "apply" && mode != "clear" {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_mode", ErrorClass: safeDeniedClass}
	}
	resolvedTargets, err := optionalResolvedTargets(stringParam(req.Params, "resolved_targets"))
	if err != nil {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: safeDeniedClass}
	}
	actionID := networkBlockActionID(req)
	if actionID == "" {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_response_action_id", ErrorClass: safeDeniedClass}
	}
	root, err := ensureResolvedDirectoryAllowAbs(responseActionRoot(), "", true)
	if err != nil {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_response_action_root", ErrorClass: safeDeniedClass}
	}
	record, recordPath, err := loadNetworkBlockRecord(root, req)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: safeDeniedClass}
	}
	if recordPath == "" {
		recordPath = filepath.Join(root, "network", actionID, "state.json")
	}

	nftBin, err := execLookPath("nft")
	if err != nil {
		return commandReply{Status: "error", ExitCode: 1, DurationMs: time.Since(start).Milliseconds(), Stderr: "nft_not_found", ErrorClass: "exec_failed"}
	}
	cmdCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	if err := e.ensureNFTBase(cmdCtx, nftBin); err != nil {
		return commandReply{Status: "error", ExitCode: 1, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: "exec_failed"}
	}

	nowMs := time.Now().UnixMilli()
	if mode == "clear" {
		if record.RunID == "" {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:containment_record_missing", ErrorClass: safeDeniedClass}
		}
		if record.ActionID != actionID {
			return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:containment_record_mismatch", ErrorClass: safeDeniedClass}
		}
		if len(record.Targets) > 0 {
			if err := e.clearNetworkBlockTargets(cmdCtx, nftBin, record.Direction, record.Targets); err != nil {
				return commandReply{Status: "error", ExitCode: 1, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: "exec_failed"}
			}
		}
		if len(record.Hostnames) > 0 {
			if err := clearHostsBlockEntries(hostsFilePath(), actionID); err != nil {
				return commandReply{Status: "error", ExitCode: 1, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: "exec_failed"}
			}
		}
		record.Status = "cleared"
		record.Cleared = true
		record.ClearedAtUnixMs = nowMs
		record.LastUpdatedAtUnixMs = nowMs
		if err := writeNetworkBlockRecord(recordPath, record); err != nil {
			return commandReply{Status: "error", ExitCode: 1, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: "exec_failed"}
		}
		return commandReply{Status: "ok", ExitCode: 0, DurationMs: time.Since(start).Milliseconds(), Stdout: recordPath}
	}

	durationMs, set, err := intParam(req.Params, "duration_ms")
	if err != nil || (set && durationMs <= 0) {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_duration_ms", ErrorClass: safeDeniedClass}
	}
	if !set {
		durationMs = int64(2 * time.Hour / time.Millisecond)
	}
	if len(hostnames) > 0 {
		if len(resolvedTargets) == 0 {
			resolveCtx, resolveCancel := context.WithTimeout(ctx, 2*time.Second)
			resolvedTargets = resolveHostnameTargets(resolveCtx, hostnames)
			resolveCancel()
		}
		if err := applyHostsBlockEntries(hostsFilePath(), actionID, hostnames); err != nil {
			return commandReply{Status: "error", ExitCode: 1, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: "exec_failed"}
		}
		targets = append(targets, resolvedTargets...)
	}
	targets = uniqueStrings(targets)
	if len(targets) > 0 {
		if err := e.applyNetworkBlockTargets(cmdCtx, nftBin, direction, targets, durationMs); err != nil {
			return commandReply{Status: "error", ExitCode: 1, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: "exec_failed"}
		}
	}
	record = networkBlockRecord{
		Version:             1,
		ActionID:            actionID,
		RunID:               runID,
		StepID:              stepID,
		NodeID:              strings.TrimSpace(stringParam(req.Params, "node_id")),
		Direction:           direction,
		Target:              target,
		Targets:             append([]string(nil), targets...),
		Hostnames:           append([]string(nil), hostnames...),
		Reason:              strings.TrimSpace(stringParam(req.Params, "reason")),
		Backend:             "nft",
		Status:              "applied",
		Applied:             true,
		AppliedAtUnixMs:     nowMs,
		ExpiresAtUnixMs:     nowMs + durationMs,
		LastUpdatedAtUnixMs: nowMs,
	}
	if err := writeNetworkBlockRecord(recordPath, record); err != nil {
		return commandReply{Status: "error", ExitCode: 1, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: "exec_failed"}
	}
	return commandReply{Status: "ok", ExitCode: 0, DurationMs: time.Since(start).Milliseconds(), Stdout: recordPath}
}

func (e *commandExecutor) lateralTargetsFromRequest(req commandRequest) ([]string, error) {
	candidates := make([]string, 0, 8)
	candidates = append(candidates, splitCSVValues(stringParam(req.Params, "top_destinations"))...)
	if dstIP := strings.TrimSpace(stringParam(req.Params, "dst_ip")); dstIP != "" {
		candidates = append(candidates, dstIP)
	}
	if target := strings.TrimSpace(req.Target); target != "" && net.ParseIP(target) != nil {
		candidates = append(candidates, target)
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	return uniquePrivateIPsBestEffort(candidates), nil
}

func (e *commandExecutor) executeLateralMovementCommand(ctx context.Context, req commandRequest) commandReply {
	start := time.Now()
	runID := strings.TrimSpace(req.RunID)
	stepID := strings.TrimSpace(req.StepID)
	if runID == "" || runID != filepath.Base(runID) || strings.Contains(runID, string(filepath.Separator)) {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_run_id", ErrorClass: safeDeniedClass}
	}

	targets, err := e.lateralTargetsFromRequest(req)
	if err != nil {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: err.Error(), ErrorClass: safeDeniedClass}
	}

	mode := lateralControlMode()
	if mode == "marker" || len(targets) == 0 {
		reply := e.executeMarkerCommand(req, "halt_lateral_movement", "lateral")
		if reply.Status == "ok" && len(targets) == 0 {
			reply.Stdout = strings.TrimSpace(reply.Stdout + "\nmode=marker reason=no_scoped_targets")
		}
		return reply
	}

	nftBin, err := execLookPath("nft")
	if err != nil {
		return commandReply{
			Status:     "error",
			ExitCode:   1,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     "nft_not_found",
			ErrorClass: "exec_failed",
		}
	}

	durationMs, set, err := intParam(req.Params, "duration_ms")
	if err != nil || (set && durationMs <= 0) {
		return commandReply{Status: "error", ExitCode: 3, DurationMs: time.Since(start).Milliseconds(), Stderr: "safe_denied:invalid_duration_ms", ErrorClass: safeDeniedClass}
	}
	if !set {
		durationMs = 900000
	}

	cmdCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	if err := e.ensureNFTBase(cmdCtx, nftBin); err != nil {
		return commandReply{
			Status:     "error",
			ExitCode:   1,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     err.Error(),
			ErrorClass: "exec_failed",
		}
	}
	if err := e.applyLateralFirewallTargets(cmdCtx, nftBin, targets, int64(durationMs)); err != nil {
		return commandReply{
			Status:     "error",
			ExitCode:   1,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     err.Error(),
			ErrorClass: "exec_failed",
		}
	}

	root, err := ensureResolvedDirectoryAllowAbs(responseActionRoot(), "", true)
	if err != nil {
		return commandReply{
			Status:     "error",
			ExitCode:   3,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     "safe_denied:invalid_response_action_root",
			ErrorClass: safeDeniedClass,
		}
	}
	statePath := filepath.Join(root, "lateral", runID, "state.json")
	nowMs := time.Now().UnixMilli()
	record := lateralContainmentRecord{
		Version:             1,
		RunID:               runID,
		StepID:              stepID,
		NodeID:              strings.TrimSpace(stringParam(req.Params, "node_id")),
		ProtocolFamily:      strings.TrimSpace(stringParam(req.Params, "protocol_family")),
		Reason:              strings.TrimSpace(stringParam(req.Params, "reason")),
		Mode:                mode,
		Backend:             "nft",
		Targets:             append([]string(nil), targets...),
		ContainedAtUnixMs:   nowMs,
		ExpiresAtUnixMs:     nowMs + int64(durationMs),
		LastUpdatedAtUnixMs: nowMs,
	}
	if err := writeLateralContainmentRecord(statePath, record); err != nil {
		return commandReply{
			Status:     "error",
			ExitCode:   1,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     err.Error(),
			ErrorClass: "exec_failed",
		}
	}

	return commandReply{
		Status:     "ok",
		ExitCode:   0,
		DurationMs: time.Since(start).Milliseconds(),
		Stdout:     statePath,
	}
}

func (e *commandExecutor) executeMarkerCommand(req commandRequest, commandID, category string) commandReply {
	start := time.Now()
	runID := strings.TrimSpace(req.RunID)
	stepID := strings.TrimSpace(req.StepID)
	if runID == "" || runID != filepath.Base(runID) || strings.Contains(runID, string(filepath.Separator)) {
		return commandReply{
			Status:     "error",
			ExitCode:   3,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     "safe_denied:invalid_run_id",
			ErrorClass: safeDeniedClass,
		}
	}
	if denied, set, err := boolParam(req.Params, "simulate_safe_denied"); err != nil {
		return commandReply{
			Status:     "error",
			ExitCode:   3,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     err.Error(),
			ErrorClass: safeDeniedClass,
		}
	} else if set && denied {
		return commandReply{
			Status:     "error",
			ExitCode:   3,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     "safe_denied:simulated_" + commandID,
			ErrorClass: safeDeniedClass,
		}
	}
	markerFile := strings.TrimSpace(stringParam(req.Params, "marker_file"))
	if markerFile == "" {
		markerFile = commandID + ".txt"
	}
	if markerFile != filepath.Base(markerFile) || markerFile == "." || markerFile == ".." {
		return commandReply{
			Status:     "error",
			ExitCode:   3,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     "safe_denied:invalid_marker_file",
			ErrorClass: safeDeniedClass,
		}
	}
	root, err := ensureResolvedDirectoryAllowAbs(responseActionRoot(), "", true)
	if err != nil {
		return commandReply{
			Status:     "error",
			ExitCode:   3,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     "safe_denied:invalid_response_action_root",
			ErrorClass: safeDeniedClass,
		}
	}
	markerDir := filepath.Join(root, category, runID)
	if err := os.MkdirAll(markerDir, 0o755); err != nil {
		return commandReply{
			Status:     "error",
			ExitCode:   1,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     err.Error(),
			ErrorClass: "exec_failed",
		}
	}
	markerPath := filepath.Join(markerDir, markerFile)
	content := fmt.Sprintf("command_id=%s\nrun_id=%s\nstep_id=%s\ntarget=%s\nwritten_at_unix_ms=%d\n",
		commandID,
		runID,
		stepID,
		strings.TrimSpace(req.Target),
		time.Now().UnixMilli(),
	)
	if err := os.WriteFile(markerPath, []byte(content), 0o644); err != nil {
		return commandReply{
			Status:     "error",
			ExitCode:   1,
			DurationMs: time.Since(start).Milliseconds(),
			Stderr:     err.Error(),
			ErrorClass: "exec_failed",
		}
	}
	return commandReply{
		Status:     "ok",
		ExitCode:   0,
		DurationMs: time.Since(start).Milliseconds(),
		Stdout:     markerPath,
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
	return ensureResolvedDirectoryAllowAbs(raw, wd, false)
}

func ensureResolvedDirectoryAllowAbs(raw, wd string, allowAbs bool) (string, error) {
	path, err := normalizeUserPath(raw, wd, allowAbs)
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

func boolParam(params map[string]any, key string) (bool, bool, error) {
	if params == nil {
		return false, false, nil
	}
	val, ok := params[key]
	if !ok {
		return false, false, nil
	}
	switch typed := val.(type) {
	case bool:
		return typed, true, nil
	case string:
		trimmed := strings.ToLower(strings.TrimSpace(typed))
		switch trimmed {
		case "true", "1", "yes", "on":
			return true, true, nil
		case "false", "0", "no", "off":
			return false, true, nil
		default:
			return false, true, fmt.Errorf("safe_denied:invalid_%s", key)
		}
	case int:
		return typed != 0, true, nil
	case int64:
		return typed != 0, true, nil
	case float64:
		return typed != 0, true, nil
	default:
		return false, true, fmt.Errorf("safe_denied:invalid_%s", key)
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
