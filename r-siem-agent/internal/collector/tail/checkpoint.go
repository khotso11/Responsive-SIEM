package tail

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type checkpointState struct {
	Offset uint64 `json:"offset"`
}

func loadCheckpoint(path string) (checkpointState, error) {
	if path == "" {
		return checkpointState{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return checkpointState{}, nil
		}
		return checkpointState{}, fmt.Errorf("read checkpoint: %w", err)
	}
	var state checkpointState
	if err := json.Unmarshal(data, &state); err != nil {
		return checkpointState{}, fmt.Errorf("parse checkpoint: %w", err)
	}
	return state, nil
}

func writeCheckpoint(path string, state checkpointState) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir checkpoint dir: %w", err)
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0644); err != nil {
		return fmt.Errorf("write checkpoint tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename checkpoint: %w", err)
	}
	return nil
}
