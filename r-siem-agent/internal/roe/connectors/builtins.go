package connectors

import "context"

type notifyConnector struct{}

func (notifyConnector) Name() string {
	return "notify"
}

func (notifyConnector) ActionType() string {
	return "notify"
}

func (notifyConnector) Execute(ctx context.Context, step Step) (map[string]any, error) {
	return map[string]any{"message": "notified"}, nil
}

type agentCommandStubConnector struct{}

func (agentCommandStubConnector) Name() string {
	return "agent_command_stub"
}

func (agentCommandStubConnector) ActionType() string {
	return "agent_command_stub"
}

func (agentCommandStubConnector) Execute(ctx context.Context, step Step) (map[string]any, error) {
	return map[string]any{"message": "command_sent_stub"}, nil
}

type networkBlockStubConnector struct{}

func (networkBlockStubConnector) Name() string {
	return "network_block_stub"
}

func (networkBlockStubConnector) ActionType() string {
	return "network_block_stub"
}

func (networkBlockStubConnector) Execute(ctx context.Context, step Step) (map[string]any, error) {
	return map[string]any{"message": "blocked_stub"}, nil
}

type networkRateLimitStubConnector struct{}

func (networkRateLimitStubConnector) Name() string {
	return "network_rate_limit_stub"
}

func (networkRateLimitStubConnector) ActionType() string {
	return "network_rate_limit_stub"
}

func (networkRateLimitStubConnector) Execute(ctx context.Context, step Step) (map[string]any, error) {
	return map[string]any{"message": "rate_limited_stub"}, nil
}

func Builtins() []Connector {
	return []Connector{
		notifyConnector{},
		agentCommandStubConnector{},
		networkBlockStubConnector{},
		networkRateLimitStubConnector{},
	}
}
