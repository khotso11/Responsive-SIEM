package retain

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type retainedLine struct {
	Raw string
	TS  int64
}

func Prune(opts PruneOptions) (PruneResult, error) {
	result := PruneResult{}
	retainedDir := strings.TrimSpace(opts.RetainedDir)
	if retainedDir == "" {
		retainedDir = "retained"
	}
	if err := ensureRetainedDir(retainedDir); err != nil {
		return result, err
	}

	beforeBytes, beforeRecords, err := dirSizeAndRecords(retainedDir)
	if err != nil {
		return result, err
	}
	result.BeforeBytes = beforeBytes
	result.BeforeRecords = beforeRecords

	policy := opts.Policy
	if policy.MaxAgeSeconds == 0 && policy.MaxBytes == 0 {
		policy = DefaultPolicy()
	}

	files := map[string][]retainedLine{}
	for _, recordType := range SupportedTypes() {
		path, err := filePathForType(retainedDir, recordType)
		if err != nil {
			return result, err
		}
		lines, err := readRetainedLines(path)
		if err != nil {
			return result, err
		}
		files[path] = lines
	}

	if policy.MaxAgeSeconds > 0 {
		cutoffMs := time.Now().Add(-time.Duration(policy.MaxAgeSeconds) * time.Second).UnixMilli()
		for path, lines := range files {
			kept := make([]retainedLine, 0, len(lines))
			for _, line := range lines {
				if line.TS > 0 && line.TS < cutoffMs {
					continue
				}
				kept = append(kept, line)
			}
			files[path] = kept
		}
	}

	if policy.MaxBytes > 0 {
		total := int64(0)
		type candidate struct {
			Path  string
			Index int
			TS    int64
			Size  int64
		}
		candidates := make([]candidate, 0)
		keep := map[string][]bool{}
		for path, lines := range files {
			keep[path] = make([]bool, len(lines))
			for idx, line := range lines {
				size := int64(len(line.Raw) + 1)
				total += size
				keep[path][idx] = true
				candidates = append(candidates, candidate{
					Path:  path,
					Index: idx,
					TS:    line.TS,
					Size:  size,
				})
			}
		}
		if total > policy.MaxBytes {
			sort.Slice(candidates, func(i, j int) bool {
				if candidates[i].TS == candidates[j].TS {
					if candidates[i].Path == candidates[j].Path {
						return candidates[i].Index < candidates[j].Index
					}
					return candidates[i].Path < candidates[j].Path
				}
				return candidates[i].TS < candidates[j].TS
			})
			for _, c := range candidates {
				if total <= policy.MaxBytes {
					break
				}
				if keep[c.Path][c.Index] {
					keep[c.Path][c.Index] = false
					total -= c.Size
				}
			}
			for path, lines := range files {
				filtered := make([]retainedLine, 0, len(lines))
				for idx, line := range lines {
					if keep[path][idx] {
						filtered = append(filtered, line)
					}
				}
				files[path] = filtered
			}
		}
	}

	for path, lines := range files {
		if err := writeRetainedLines(path, lines); err != nil {
			return result, err
		}
	}

	afterBytes, afterRecords, err := dirSizeAndRecords(retainedDir)
	if err != nil {
		return result, err
	}
	result.AfterBytes = afterBytes
	result.AfterRecords = afterRecords
	return result, nil
}

func readRetainedLines(path string) ([]retainedLine, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	out := make([]retainedLine, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var raw map[string]any
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		out = append(out, retainedLine{
			Raw: line,
			TS:  asInt64(raw["ts_unix_ms"]),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func writeRetainedLines(path string, lines []retainedLine) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, line := range lines {
		if _, err := f.WriteString(line.Raw + "\n"); err != nil {
			return err
		}
	}
	return nil
}
