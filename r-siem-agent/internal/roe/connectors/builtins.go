package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

type BuiltinOptions struct {
	Logger *slog.Logger
	NATS   *nats.Conn
}

type notifyConnector struct {
	logger     *slog.Logger
	webhookURL string
	timeout    time.Duration
	client     *http.Client
}

func newNotifyConnector(opts BuiltinOptions) *notifyConnector {
	timeoutMs := envInt("RSIEM_NOTIFY_TIMEOUT_MS", 2000)
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &notifyConnector{
		logger:     logger,
		webhookURL: strings.TrimSpace(os.Getenv("RSIEM_NOTIFY_WEBHOOK_URL")),
		timeout:    time.Duration(timeoutMs) * time.Millisecond,
		client:     &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond},
	}
}

func (c *notifyConnector) Name() string {
	return "notify"
}

func (c *notifyConnector) ActionType() string {
	return "notify"
}

func (c *notifyConnector) RequiredParams() []string {
	return nil
}

func (c *notifyConnector) OptionalParams() []string {
	return nil
}

func (c *notifyConnector) Execute(ctx context.Context, step Step) (map[string]any, error) {
	if c.webhookURL == "" {
		return nil, fmt.Errorf("notify_webhook_missing")
	}
	payload := map[string]any{
		"run_id":      step.RunID,
		"step_id":     step.StepID,
		"lane":        step.Lane,
		"action_type": step.ActionType,
		"params":      step.Params,
		"timestamp":   time.Now().UnixMilli(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	reqCtx, cancel := withOptionalTimeout(ctx, c.timeout)
	if cancel != nil {
		defer cancel()
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.webhookURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "notify_webhook_attempt",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
	)
	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "notify_webhook_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "retryable"),
		)
		return nil, Retryable(err)
	}
	defer resp.Body.Close()
	status := resp.StatusCode
	if status >= 200 && status < 300 {
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "notify_webhook_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "succeeded"),
			slog.Int("http_code", status),
		)
		return map[string]any{"message": "notified"}, nil
	}
	if status >= 400 && status < 500 {
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "notify_webhook_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "failed_safe"),
			slog.Int("http_code", status),
		)
		return nil, fmt.Errorf("notify_webhook_http_%d", status)
	}
	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "notify_webhook_terminal",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("status", "retryable"),
		slog.Int("http_code", status),
	)
	return nil, Retryable(fmt.Errorf("notify_webhook_http_%d", status))
}

type agentCommandStubConnector struct {
	logger  *slog.Logger
	nats    *nats.Conn
	subject string
	timeout time.Duration
}

func newAgentCommandConnector(opts BuiltinOptions) *agentCommandStubConnector {
	timeoutMs := envInt("RSIEM_AGENT_CMD_TIMEOUT_MS", 2000)
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	subject := strings.TrimSpace(os.Getenv("RSIEM_AGENT_CMD_SUBJECT"))
	if subject == "" {
		subject = "rsiem.agent.command"
	}
	return &agentCommandStubConnector{
		logger:  logger,
		nats:    opts.NATS,
		subject: subject,
		timeout: time.Duration(timeoutMs) * time.Millisecond,
	}
}

func (c *agentCommandStubConnector) Name() string {
	return "agent_command"
}

func (c *agentCommandStubConnector) ActionType() string {
	return "agent_command"
}

func (c *agentCommandStubConnector) RequiredParams() []string {
	return nil
}

func (c *agentCommandStubConnector) OptionalParams() []string {
	return []string{"command", "name", "force"}
}

func (c *agentCommandStubConnector) Execute(ctx context.Context, step Step) (map[string]any, error) {
	if c.nats == nil {
		return nil, fmt.Errorf("agent_command_nats_missing")
	}
	payload := map[string]any{
		"run_id":      step.RunID,
		"step_id":     step.StepID,
		"lane":        step.Lane,
		"action_type": "agent_command",
		"params":      step.Params,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	timeout := c.timeout
	if step.TimeoutMs != nil && *step.TimeoutMs > 0 {
		timeout = time.Duration(*step.TimeoutMs) * time.Millisecond
	}
	reqCtx, cancel := withOptionalTimeout(ctx, timeout)
	if cancel != nil {
		defer cancel()
	}
	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_request",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("subject", c.subject),
	)
	msg := nats.NewMsg(c.subject)
	msg.Data = data
	reply, err := c.nats.RequestMsgWithContext(reqCtx, msg)
	if err != nil {
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "retryable"),
		)
		return nil, Retryable(err)
	}
	resp := struct {
		Status  string `json:"status"`
		Message string `json:"message,omitempty"`
	}{}
	if err := json.Unmarshal(reply.Data, &resp); err != nil {
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "failed_safe"),
		)
		return nil, fmt.Errorf("agent_command_bad_reply")
	}
	status := strings.ToLower(strings.TrimSpace(resp.Status))
	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_reply",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("status", status),
	)
	switch status {
	case "ok":
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "succeeded"),
		)
		return map[string]any{"message": "command_sent_stub"}, nil
	case "fail_safe":
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "failed_safe"),
		)
		return nil, fmt.Errorf("agent_command_fail_safe")
	case "fail_transient":
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "retryable"),
		)
		return nil, Retryable(fmt.Errorf("agent_command_fail_transient"))
	default:
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_command_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "failed_safe"),
		)
		return nil, fmt.Errorf("agent_command_unknown_status")
	}
}

type networkBlockStubConnector struct {
	logger  *slog.Logger
	nats    *nats.Conn
	subject string
	timeout time.Duration
}

func newNetworkBlockConnector(opts BuiltinOptions) *networkBlockStubConnector {
	timeoutMs := envInt("RSIEM_AGENT_CMD_TIMEOUT_MS", 2000)
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	subject := strings.TrimSpace(os.Getenv("RSIEM_AGENT_CMD_SUBJECT"))
	if subject == "" {
		subject = "rsiem.agent.command"
	}
	return &networkBlockStubConnector{
		logger:  logger,
		nats:    opts.NATS,
		subject: subject,
		timeout: time.Duration(timeoutMs) * time.Millisecond,
	}
}

func (networkBlockStubConnector) Name() string {
	return "network_block"
}

func (networkBlockStubConnector) ActionType() string {
	return "network_block"
}

func (networkBlockStubConnector) RequiredParams() []string {
	return nil
}

func (networkBlockStubConnector) OptionalParams() []string {
	return []string{"direction"}
}

func (c networkBlockStubConnector) Execute(ctx context.Context, step Step) (map[string]any, error) {
	if c.nats == nil {
		return nil, fmt.Errorf("network_block_nats_missing")
	}
	payload := map[string]any{
		"run_id":      step.RunID,
		"step_id":     step.StepID,
		"lane":        step.Lane,
		"action_type": "network_block",
		"target":      step.Target,
		"params":      step.Params,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	timeout := c.timeout
	if step.TimeoutMs != nil && *step.TimeoutMs > 0 {
		timeout = time.Duration(*step.TimeoutMs) * time.Millisecond
	}
	reqCtx, cancel := withOptionalTimeout(ctx, timeout)
	if cancel != nil {
		defer cancel()
	}
	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_block_request",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("subject", c.subject),
	)
	msg := nats.NewMsg(c.subject)
	msg.Data = data
	reply, err := c.nats.RequestMsgWithContext(reqCtx, msg)
	if err != nil {
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_block_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "retryable"),
		)
		return nil, Retryable(err)
	}
	resp := struct {
		Status  string `json:"status"`
		Message string `json:"message,omitempty"`
	}{}
	if err := json.Unmarshal(reply.Data, &resp); err != nil {
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_block_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "failed_safe"),
		)
		return nil, fmt.Errorf("network_block_bad_reply")
	}
	status := strings.ToLower(strings.TrimSpace(resp.Status))
	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_block_reply",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("status", status),
	)
	switch status {
	case "ok":
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_block_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "succeeded"),
		)
		if resp.Message == "" {
			return map[string]any{"message": "dry_run"}, nil
		}
		return map[string]any{"message": resp.Message}, nil
	case "fail_safe":
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_block_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "failed_safe"),
		)
		if resp.Message != "" {
			return nil, fmt.Errorf("%s", resp.Message)
		}
		return nil, fmt.Errorf("network_block_fail_safe")
	case "fail_transient":
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_block_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "retryable"),
		)
		if resp.Message != "" {
			return nil, Retryable(fmt.Errorf("%s", resp.Message))
		}
		return nil, Retryable(fmt.Errorf("network_block_fail_transient"))
	default:
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_block_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "failed_safe"),
		)
		return nil, fmt.Errorf("network_block_unknown_status")
	}
}

type networkRateLimitStubConnector struct {
	logger  *slog.Logger
	nats    *nats.Conn
	subject string
	timeout time.Duration
}

func newNetworkRateLimitConnector(opts BuiltinOptions) *networkRateLimitStubConnector {
	timeoutMs := envInt("RSIEM_AGENT_CMD_TIMEOUT_MS", 2000)
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	subject := strings.TrimSpace(os.Getenv("RSIEM_AGENT_CMD_SUBJECT"))
	if subject == "" {
		subject = "rsiem.agent.command"
	}
	return &networkRateLimitStubConnector{
		logger:  logger,
		nats:    opts.NATS,
		subject: subject,
		timeout: time.Duration(timeoutMs) * time.Millisecond,
	}
}

func (networkRateLimitStubConnector) Name() string {
	return "network_rate_limit"
}

func (networkRateLimitStubConnector) ActionType() string {
	return "network_rate_limit"
}

func (networkRateLimitStubConnector) RequiredParams() []string {
	return nil
}

func (networkRateLimitStubConnector) OptionalParams() []string {
	return []string{"rate_kbps", "burst_kb", "duration_ms"}
}

func (c networkRateLimitStubConnector) Execute(ctx context.Context, step Step) (map[string]any, error) {
	if c.nats == nil {
		return nil, fmt.Errorf("network_rate_limit_nats_missing")
	}
	payload := map[string]any{
		"run_id":      step.RunID,
		"step_id":     step.StepID,
		"lane":        step.Lane,
		"action_type": "network_rate_limit",
		"target":      step.Target,
		"params":      step.Params,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	timeout := c.timeout
	if step.TimeoutMs != nil && *step.TimeoutMs > 0 {
		timeout = time.Duration(*step.TimeoutMs) * time.Millisecond
	}
	reqCtx, cancel := withOptionalTimeout(ctx, timeout)
	if cancel != nil {
		defer cancel()
	}
	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_rate_limit_request",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("subject", c.subject),
	)
	msg := nats.NewMsg(c.subject)
	msg.Data = data
	reply, err := c.nats.RequestMsgWithContext(reqCtx, msg)
	if err != nil {
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_rate_limit_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "retryable"),
		)
		return nil, Retryable(err)
	}
	resp := struct {
		Status  string `json:"status"`
		Message string `json:"message,omitempty"`
	}{}
	if err := json.Unmarshal(reply.Data, &resp); err != nil {
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_rate_limit_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "failed_safe"),
		)
		return nil, fmt.Errorf("network_rate_limit_bad_reply")
	}
	status := strings.ToLower(strings.TrimSpace(resp.Status))
	c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_rate_limit_reply",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("status", status),
	)
	switch status {
	case "ok":
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_rate_limit_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "succeeded"),
		)
		if resp.Message == "" {
			return map[string]any{"message": "dry_run"}, nil
		}
		return map[string]any{"message": resp.Message}, nil
	case "fail_safe":
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_rate_limit_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "failed_safe"),
		)
		if resp.Message != "" {
			return nil, fmt.Errorf("%s", resp.Message)
		}
		return nil, fmt.Errorf("network_rate_limit_fail_safe")
	case "fail_transient":
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_rate_limit_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "retryable"),
		)
		if resp.Message != "" {
			return nil, Retryable(fmt.Errorf("%s", resp.Message))
		}
		return nil, Retryable(fmt.Errorf("network_rate_limit_fail_transient"))
	default:
		c.logger.LogAttrs(context.Background(), slog.LevelInfo, "network_rate_limit_terminal",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", "failed_safe"),
		)
		return nil, fmt.Errorf("network_rate_limit_unknown_status")
	}
}

func Builtins(opts BuiltinOptions) []Connector {
	return []Connector{
		newNotifyConnector(opts),
		newAgentCommandConnector(opts),
		newNetworkBlockConnector(opts),
		newNetworkRateLimitConnector(opts),
	}
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
	if parsed <= 0 {
		return fallback
	}
	return parsed
}

func withOptionalTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, nil
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 && remaining <= timeout {
			return ctx, nil
		}
	}
	return context.WithTimeout(ctx, timeout)
}
