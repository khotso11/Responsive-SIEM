package retain

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func ensureRetainedDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("retained_dir is required")
	}
	return os.MkdirAll(dir, 0o755)
}

func filePathForType(dir, recordType string) (string, error) {
	name, ok := typeFileNames[recordType]
	if !ok {
		return "", fmt.Errorf("unsupported type: %s", recordType)
	}
	return filepath.Join(dir, name), nil
}

func appendRecord(dir, recordType string, record map[string]any) error {
	path, err := filePathForType(dir, recordType)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(data, '\n'))
	return err
}

func scanJSONL(path string, fn func(line string, raw map[string]any) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		if err := fn(line, raw); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func parseLogJSON(path string, fn func(line string, raw map[string]any) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				var raw map[string]any
				if json.Unmarshal([]byte(trimmed), &raw) == nil {
					if callErr := fn(trimmed, raw); callErr != nil {
						return callErr
					}
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case int:
		return strconv.Itoa(t)
	default:
		return ""
	}
}

func asInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case json.Number:
		n, _ := t.Int64()
		return n
	case string:
		if t == "" {
			return 0
		}
		if parsed, err := strconv.ParseInt(t, 10, 64); err == nil {
			return parsed
		}
	}
	return 0
}

func pickInt64(raw map[string]any, keys ...string) int64 {
	for _, key := range keys {
		if val, ok := raw[key]; ok {
			if parsed := asInt64(val); parsed > 0 {
				return parsed
			}
		}
	}
	return 0
}

func parseRFC3339ToUnixMs(raw string) int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return parsed.UnixMilli()
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed.UnixMilli()
	}
	return 0
}

func dirSizeAndRecords(dir string) (int64, int, error) {
	var totalBytes int64
	totalRecords := 0
	for _, recordType := range SupportedTypes() {
		path, err := filePathForType(dir, recordType)
		if err != nil {
			return 0, 0, err
		}
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, 0, err
		}
		totalBytes += info.Size()
		f, err := os.Open(path)
		if err != nil {
			return 0, 0, err
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) != "" {
				totalRecords++
			}
		}
		f.Close()
	}
	return totalBytes, totalRecords, nil
}
