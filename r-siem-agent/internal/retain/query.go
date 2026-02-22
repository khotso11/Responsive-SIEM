package retain

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func Query(opts QueryOptions, out io.Writer) (QueryResult, error) {
	result := QueryResult{
		CountsByType:   map[string]int64{},
		CountsByStatus: map[string]int64{},
	}
	retainedDir := strings.TrimSpace(opts.RetainedDir)
	if retainedDir == "" {
		retainedDir = "retained"
	}
	if err := ensureRetainedDir(retainedDir); err != nil {
		return result, err
	}
	if out == nil {
		out = io.Discard
	}
	writer := bufio.NewWriter(out)
	defer writer.Flush()

	targetTypes, err := resolveTypes(opts.Type)
	if err != nil {
		return result, err
	}
	for _, recordType := range targetTypes {
		path, err := filePathForType(retainedDir, recordType)
		if err != nil {
			return result, err
		}
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return result, err
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if opts.Contains != "" && !strings.Contains(line, opts.Contains) {
				continue
			}
			var raw map[string]any
			if err := json.Unmarshal([]byte(line), &raw); err != nil {
				continue
			}
			ts := asInt64(raw["ts_unix_ms"])
			if opts.SinceUnixMs > 0 && ts > 0 && ts < opts.SinceUnixMs {
				continue
			}
			if opts.UntilUnixMs > 0 && ts > 0 && ts > opts.UntilUnixMs {
				continue
			}
			if opts.RunID != "" && asString(raw["run_id"]) != opts.RunID {
				continue
			}
			if opts.PlaybookID != "" && asString(raw["playbook_id"]) != opts.PlaybookID {
				continue
			}
			if opts.Status != "" && !strings.EqualFold(asString(raw["status"]), opts.Status) {
				continue
			}
			if _, err := writer.WriteString(line + "\n"); err != nil {
				f.Close()
				return result, err
			}
			result.Count++
			t := asString(raw["type"])
			if t == "" {
				t = recordType
			}
			result.CountsByType[t]++
			status := asString(raw["status"])
			if status != "" {
				result.CountsByStatus[strings.ToUpper(status)]++
			}
			if ts > 0 {
				if result.FirstTSUnixMs == 0 || ts < result.FirstTSUnixMs {
					result.FirstTSUnixMs = ts
				}
				if ts > result.LastTSUnixMs {
					result.LastTSUnixMs = ts
				}
			}
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			return result, err
		}
		f.Close()
	}
	return result, nil
}

func WriteSummary(summaryPath string, result QueryResult) error {
	if strings.TrimSpace(summaryPath) == "" {
		return nil
	}
	summary := map[string]any{
		"generated_at":     time.Now().UTC().Format(time.RFC3339),
		"count":            result.Count,
		"first_ts_unix_ms": result.FirstTSUnixMs,
		"last_ts_unix_ms":  result.LastTSUnixMs,
		"counts_by_type":   result.CountsByType,
		"counts_by_status": result.CountsByStatus,
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(summaryPath, append(data, '\n'), 0o644)
}

func resolveTypes(raw string) ([]string, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" || value == "all" {
		return SupportedTypes(), nil
	}
	for _, t := range SupportedTypes() {
		if value == t {
			return []string{t}, nil
		}
	}
	return nil, fmt.Errorf("unsupported type: %s", raw)
}
