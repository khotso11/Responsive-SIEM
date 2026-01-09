package connectors

import (
	"fmt"
	"strings"
)

type Manager struct {
	byAction map[string]Connector
}

func NewManager(connectors ...Connector) *Manager {
	manager := &Manager{
		byAction: make(map[string]Connector),
	}
	for _, connector := range connectors {
		_ = manager.Register(connector)
	}
	return manager
}

func (m *Manager) Register(connector Connector) error {
	if connector == nil {
		return fmt.Errorf("connector_nil")
	}
	action := strings.TrimSpace(connector.ActionType())
	if action == "" {
		return fmt.Errorf("connector_missing_action")
	}
	if _, exists := m.byAction[action]; exists {
		return fmt.Errorf("connector_duplicate_action")
	}
	m.byAction[action] = connector
	return nil
}

func (m *Manager) Select(action string) (Connector, error) {
	action = strings.TrimSpace(action)
	if action == "" {
		return nil, fmt.Errorf("missing_action_type")
	}
	connector, ok := m.byAction[action]
	if !ok {
		return nil, fmt.Errorf("unknown_action_type")
	}
	return connector, nil
}

func (m *Manager) Count() int {
	return len(m.byAction)
}
