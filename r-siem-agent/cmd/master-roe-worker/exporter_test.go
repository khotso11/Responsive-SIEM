package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkerExporterLatestSnapshot(t *testing.T) {
	dir := t.TempDir()
	stepsPath := filepath.Join(dir, "roe_steps.jsonl")
	latestPath := filepath.Join(dir, "roe_steps_latest.jsonl")

	exporter, err := newWorkerExporter(nil, workerExportConfig{
		Enabled:         true,
		StepsPath:       stepsPath,
		StepsLatestPath: latestPath,
	})
	if err != nil {
		t.Fatalf("newWorkerExporter: %v", err)
	}
	defer exporter.Close()

	failed := map[string]any{
		"msg":                 "response_step_result",
		"run_id":              "run-1",
		"step_id":             "step-1",
		"step_index":          0,
		"action_type":         "agent_command",
		"lane":                "FAST",
		"status":              "FAILED_SAFE",
		"attempt":             1,
		"finished_at_unix_ms": int64(1000),
		"step_key":            "step.run-1.step-1",
		"last_error":          "unknown_param:target",
	}
	failedPayload, err := json.Marshal(failed)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := exporter.WriteJSONL(failedPayload); err != nil {
		t.Fatalf("WriteJSONL failed: %v", err)
	}

	succeeded := map[string]any{
		"msg":                 "response_step_result",
		"run_id":              "run-1",
		"step_id":             "step-1",
		"step_index":          0,
		"action_type":         "agent_command",
		"lane":                "FAST",
		"status":              "SUCCEEDED",
		"attempt":             2,
		"finished_at_unix_ms": int64(2000),
		"step_key":            "step.run-1.step-1",
		"receipt": map[string]any{
			"message": "agent_command: ping exit=0 dur_ms=1 stdout_trunc=false stderr_trunc=false",
		},
	}
	succeededPayload, err := json.Marshal(succeeded)
	if err != nil {
		t.Fatalf("marshal succeeded: %v", err)
	}
	if err := exporter.WriteJSONL(succeededPayload); err != nil {
		t.Fatalf("WriteJSONL succeeded: %v", err)
	}

	stepsLines := readJSONLLines(t, stepsPath)
	if got := len(stepsLines); got != 2 {
		t.Fatalf("roe_steps.jsonl lines=%d, want 2", got)
	}

	latestLines := readJSONLLines(t, latestPath)
	if got := len(latestLines); got != 1 {
		t.Fatalf("roe_steps_latest.jsonl lines=%d, want 1", got)
	}

	var latest map[string]any
	if err := json.Unmarshal([]byte(latestLines[0]), &latest); err != nil {
		t.Fatalf("unmarshal latest: %v", err)
	}
	if latest["status"] != "SUCCEEDED" {
		t.Fatalf("latest status=%v, want SUCCEEDED", latest["status"])
	}
	if latest["step_key"] != "step.run-1.step-1" {
		t.Fatalf("latest step_key=%v, want step.run-1.step-1", latest["step_key"])
	}
}

func readJSONLLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

func TestWorkerExporterLatestSnapshotOnInit(t *testing.T) {
	dir := t.TempDir()
	stepsPath := filepath.Join(dir, "roe_steps.jsonl")
	latestPath := filepath.Join(dir, "roe_steps_latest.jsonl")

	lines := []string{
		`{"msg":"response_step_result","run_id":"run-1","step_id":"step-1","step_index":0,"action_type":"agent_command","lane":"FAST","status":"FAILED_SAFE","attempt":1,"finished_at_unix_ms":1000,"step_key":"step.run-1.step-1","last_error":"unknown_param:target"}`,
		`{"msg":"response_step_result","run_id":"run-1","step_id":"step-1","step_index":0,"action_type":"agent_command","lane":"FAST","status":"SUCCEEDED","attempt":2,"finished_at_unix_ms":2000,"step_key":"step.run-1.step-1","receipt":{"message":"agent_command: ping exit=0 dur_ms=1 stdout_trunc=false stderr_trunc=false"}}`,
	}
	if err := os.WriteFile(stepsPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatalf("write steps: %v", err)
	}

	exporter, err := newWorkerExporter(nil, workerExportConfig{
		Enabled:         true,
		StepsPath:       stepsPath,
		StepsLatestPath: latestPath,
	})
	if err != nil {
		t.Fatalf("newWorkerExporter: %v", err)
	}
	exporter.Close()

	latestLines := readJSONLLines(t, latestPath)
	if got := len(latestLines); got != 1 {
		t.Fatalf("roe_steps_latest.jsonl lines=%d, want 1", got)
	}
	var latest map[string]any
	if err := json.Unmarshal([]byte(latestLines[0]), &latest); err != nil {
		t.Fatalf("unmarshal latest: %v", err)
	}
	if latest["status"] != "SUCCEEDED" {
		t.Fatalf("latest status=%v, want SUCCEEDED", latest["status"])
	}
}

func TestWorkerExporterDefaultLatestPath(t *testing.T) {
	cfg := workerExportConfig{
		Enabled:   true,
		StepsPath: "exports/roe_steps.jsonl",
	}
	wcfg := roeWorkerConfig{Export: cfg}
	applyWorkerDefaults(&wcfg)
	if wcfg.Export.StepsLatestPath != filepath.Join("exports", "roe_steps_latest.jsonl") {
		t.Fatalf("steps_latest_path=%q, want %q", wcfg.Export.StepsLatestPath, filepath.Join("exports", "roe_steps_latest.jsonl"))
	}
}

func TestWorkerExporterCreatesPaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	stepsPath := filepath.Join(dir, "roe_steps.jsonl")
	latestPath := filepath.Join(dir, "roe_steps_latest.jsonl")

	exporter, err := newWorkerExporter(nil, workerExportConfig{
		Enabled:         true,
		StepsPath:       stepsPath,
		StepsLatestPath: latestPath,
	})
	if err != nil {
		t.Fatalf("newWorkerExporter: %v", err)
	}
	exporter.Close()

	if _, err := os.Stat(stepsPath); err != nil {
		t.Fatalf("steps file missing: %v", err)
	}
	if _, err := os.Stat(latestPath); err != nil {
		t.Fatalf("latest file missing: %v", err)
	}
}
