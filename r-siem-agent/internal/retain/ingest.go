package retain

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func Ingest(opts IngestOptions) (IngestStats, error) {
	stats := IngestStats{}
	retainedDir := strings.TrimSpace(opts.RetainedDir)
	if retainedDir == "" {
		retainedDir = "retained"
	}
	if err := ensureRetainedDir(retainedDir); err != nil {
		return stats, err
	}

	if strings.TrimSpace(opts.RunsPath) != "" {
		count, err := ingestRuns(retainedDir, opts.RunsPath)
		if err != nil {
			return stats, err
		}
		stats.Runs = count
	}
	if strings.TrimSpace(opts.StepsPath) != "" {
		count, err := ingestSteps(retainedDir, opts.StepsPath)
		if err != nil {
			return stats, err
		}
		stats.Steps = count
	}
	if strings.TrimSpace(opts.DetectorLog) != "" {
		count, err := ingestAlerts(retainedDir, opts.DetectorLog)
		if err != nil {
			return stats, err
		}
		stats.Alerts = count
	}
	if strings.TrimSpace(opts.CollectorLog) != "" {
		count, err := ingestTelemetry(retainedDir, opts.CollectorLog)
		if err != nil {
			return stats, err
		}
		stats.Telemetry = count
	}
	if strings.TrimSpace(opts.MasterLog) != "" {
		count, err := ingestMasterRuns(retainedDir, opts.MasterLog)
		if err != nil {
			return stats, err
		}
		stats.Runs += count
	}
	return stats, nil
}

func ingestRuns(retainedDir, path string) (int, error) {
	if _, err := os.Stat(path); err != nil {
		return 0, fmt.Errorf("runs path %s: %w", path, err)
	}
	nowMs := time.Now().UnixMilli()
	count := 0
	err := scanJSONL(path, func(line string, raw map[string]any) error {
		ts := pickInt64(raw,
			"last_updated_at_unix_ms",
			"created_at_unix_ms",
			"approval_requested_at_unix_ms",
			"started_at_unix_ms",
			"finished_at_unix_ms",
		)
		if ts <= 0 {
			ts = nowMs
		}
		record := map[string]any{
			"ts_unix_ms":  ts,
			"type":        TypeRuns,
			"source":      path,
			"run_id":      asString(raw["run_id"]),
			"playbook_id": asString(raw["playbook_id"]),
			"status":      asString(raw["status"]),
			"event":       asString(raw["msg"]),
			"line":        line,
		}
		if err := appendRecord(retainedDir, TypeRuns, record); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, err
}

func ingestSteps(retainedDir, path string) (int, error) {
	if _, err := os.Stat(path); err != nil {
		return 0, fmt.Errorf("steps path %s: %w", path, err)
	}
	nowMs := time.Now().UnixMilli()
	count := 0
	err := scanJSONL(path, func(line string, raw map[string]any) error {
		ts := pickInt64(raw,
			"finished_at_unix_ms",
			"started_at_unix_ms",
		)
		if ts <= 0 {
			ts = nowMs
		}
		record := map[string]any{
			"ts_unix_ms":  ts,
			"type":        TypeSteps,
			"source":      path,
			"run_id":      asString(raw["run_id"]),
			"step_id":     asString(raw["step_id"]),
			"playbook_id": asString(raw["playbook_id"]),
			"status":      asString(raw["status"]),
			"event":       asString(raw["msg"]),
			"line":        line,
		}
		if err := appendRecord(retainedDir, TypeSteps, record); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, err
}

func ingestAlerts(retainedDir, path string) (int, error) {
	if _, err := os.Stat(path); err != nil {
		return 0, fmt.Errorf("detector log %s: %w", path, err)
	}
	count := 0
	err := parseLogJSON(path, func(line string, raw map[string]any) error {
		if asString(raw["msg"]) != "detector_rule_matched" {
			return nil
		}
		ts := parseRFC3339ToUnixMs(asString(raw["time"]))
		if ts <= 0 {
			ts = time.Now().UnixMilli()
		}
		record := map[string]any{
			"ts_unix_ms":  ts,
			"type":        TypeAlerts,
			"source":      path,
			"rule_id":     asString(raw["rule_id"]),
			"playbook_id": asString(raw["playbook_id"]),
			"severity":    asString(raw["severity"]),
			"event":       asString(raw["msg"]),
			"line":        line,
		}
		if err := appendRecord(retainedDir, TypeAlerts, record); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, err
}

func ingestTelemetry(retainedDir, path string) (int, error) {
	if _, err := os.Stat(path); err != nil {
		return 0, fmt.Errorf("collector log %s: %w", path, err)
	}
	allowed := map[string]struct{}{
		"collector_tail_input_path_resolved": {},
		"collector_tail_checkpoint_state":    {},
		"collector_event_published":          {},
	}
	count := 0
	err := parseLogJSON(path, func(line string, raw map[string]any) error {
		msg := asString(raw["msg"])
		if _, ok := allowed[msg]; !ok {
			return nil
		}
		ts := parseRFC3339ToUnixMs(asString(raw["time"]))
		if ts <= 0 {
			ts = time.Now().UnixMilli()
		}
		record := map[string]any{
			"ts_unix_ms": ts,
			"type":       TypeTelemetry,
			"source":     path,
			"event":      msg,
			"path":       asString(raw["path"]),
			"offset":     asInt64(raw["offset"]),
			"line":       line,
		}
		if err := appendRecord(retainedDir, TypeTelemetry, record); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, err
}

func ingestMasterRuns(retainedDir, path string) (int, error) {
	if _, err := os.Stat(path); err != nil {
		return 0, fmt.Errorf("master log %s: %w", path, err)
	}
	allowed := map[string]struct{}{
		"response_run_created": {},
		"response_run_updated": {},
	}
	count := 0
	err := parseLogJSON(path, func(line string, raw map[string]any) error {
		msg := asString(raw["msg"])
		if _, ok := allowed[msg]; !ok {
			return nil
		}
		ts := parseRFC3339ToUnixMs(asString(raw["time"]))
		if ts <= 0 {
			ts = time.Now().UnixMilli()
		}
		record := map[string]any{
			"ts_unix_ms":         ts,
			"type":               TypeRuns,
			"source":             path,
			"run_id":             asString(raw["run_id"]),
			"playbook_id":        asString(raw["playbook_id"]),
			"status":             asString(raw["status"]),
			"event":              msg,
			"operator_action":    asString(raw["operator_action"]),
			"failed_safe_reason": asString(raw["failed_safe_reason"]),
			"line":               line,
		}
		if err := appendRecord(retainedDir, TypeRuns, record); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, err
}
