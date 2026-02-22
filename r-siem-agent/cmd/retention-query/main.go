package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"r-siem-agent/internal/retain"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "ingest":
		err = runIngest(os.Args[2:])
	case "query":
		err = runQuery(os.Args[2:])
	case "prune":
		err = runPrune(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <ingest|query|prune> [flags]\n", filepath.Base(os.Args[0]))
}

func runIngest(args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	retainedDir := fs.String("retained_dir", "retained", "Retained directory")
	runsPath := fs.String("runs_path", "exports/roe_runs.jsonl", "Runs export path")
	stepsPath := fs.String("steps_path", "exports/roe_steps.jsonl", "Steps export path")
	detectorLog := fs.String("detector_log", "logs/detector.log", "Detector log path")
	collectorLog := fs.String("collector_log", "logs/collector.log", "Collector log path")
	masterLog := fs.String("master_log", "", "Master ROE log path for run lifecycle ingestion")
	p := retain.PolicyFromEnv()
	maxAge := fs.Int64("max_age_seconds", p.MaxAgeSeconds, "Retention max age in seconds")
	maxBytes := fs.Int64("max_bytes", p.MaxBytes, "Retention max bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}

	stats, err := retain.Ingest(retain.IngestOptions{
		RetainedDir:  *retainedDir,
		RunsPath:     *runsPath,
		StepsPath:    *stepsPath,
		DetectorLog:  *detectorLog,
		CollectorLog: *collectorLog,
		MasterLog:    *masterLog,
	})
	if err != nil {
		return err
	}
	pruneResult, err := retain.Prune(retain.PruneOptions{
		RetainedDir: *retainedDir,
		Policy: retain.Policy{
			MaxAgeSeconds: *maxAge,
			MaxBytes:      *maxBytes,
		},
	})
	if err != nil {
		return err
	}

	fmt.Printf("INGEST_ALERTS=%d\n", stats.Alerts)
	fmt.Printf("INGEST_RUNS=%d\n", stats.Runs)
	fmt.Printf("INGEST_STEPS=%d\n", stats.Steps)
	fmt.Printf("INGEST_TELEMETRY=%d\n", stats.Telemetry)
	fmt.Printf("PRUNE_BEFORE_BYTES=%d\n", pruneResult.BeforeBytes)
	fmt.Printf("PRUNE_AFTER_BYTES=%d\n", pruneResult.AfterBytes)
	fmt.Printf("PRUNE_BEFORE_RECORDS=%d\n", pruneResult.BeforeRecords)
	fmt.Printf("PRUNE_AFTER_RECORDS=%d\n", pruneResult.AfterRecords)
	return nil
}

func runQuery(args []string) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	retainedDir := fs.String("retained_dir", "retained", "Retained directory")
	recordType := fs.String("type", "all", "Record type: alerts|runs|steps|telemetry|all")
	sinceRaw := fs.String("since", "", "Since timestamp (RFC3339 or unix sec/ms)")
	untilRaw := fs.String("until", "", "Until timestamp (RFC3339 or unix sec/ms)")
	runID := fs.String("run_id", "", "Filter by run_id")
	playbookID := fs.String("playbook_id", "", "Filter by playbook_id")
	status := fs.String("status", "", "Filter by status")
	contains := fs.String("contains", "", "Substring filter")
	outPath := fs.String("out", "", "Output JSONL path (default stdout)")
	summaryOut := fs.String("summary_out", "", "Summary JSON output path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sinceMs, err := parseTimeArg(*sinceRaw)
	if err != nil {
		return fmt.Errorf("parse --since: %w", err)
	}
	untilMs, err := parseTimeArg(*untilRaw)
	if err != nil {
		return fmt.Errorf("parse --until: %w", err)
	}

	out := os.Stdout
	var closeFn func() error
	if strings.TrimSpace(*outPath) != "" {
		if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(*outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		out = f
		closeFn = f.Close
	}
	if closeFn != nil {
		defer closeFn()
	}

	result, err := retain.Query(retain.QueryOptions{
		RetainedDir: *retainedDir,
		Type:        *recordType,
		SinceUnixMs: sinceMs,
		UntilUnixMs: untilMs,
		RunID:       strings.TrimSpace(*runID),
		PlaybookID:  strings.TrimSpace(*playbookID),
		Status:      strings.TrimSpace(*status),
		Contains:    *contains,
	}, out)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*summaryOut) != "" {
		if err := os.MkdirAll(filepath.Dir(*summaryOut), 0o755); err != nil {
			return err
		}
		if err := retain.WriteSummary(*summaryOut, result); err != nil {
			return err
		}
	}
	fmt.Printf("QUERY_COUNT=%d\n", result.Count)
	return nil
}

func runPrune(args []string) error {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	retainedDir := fs.String("retained_dir", "retained", "Retained directory")
	p := retain.PolicyFromEnv()
	maxAge := fs.Int64("max_age_seconds", p.MaxAgeSeconds, "Retention max age in seconds")
	maxBytes := fs.Int64("max_bytes", p.MaxBytes, "Retention max bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	result, err := retain.Prune(retain.PruneOptions{
		RetainedDir: *retainedDir,
		Policy: retain.Policy{
			MaxAgeSeconds: *maxAge,
			MaxBytes:      *maxBytes,
		},
	})
	if err != nil {
		return err
	}
	fmt.Printf("PRUNE_BEFORE_BYTES=%d\n", result.BeforeBytes)
	fmt.Printf("PRUNE_AFTER_BYTES=%d\n", result.AfterBytes)
	fmt.Printf("PRUNE_BEFORE_RECORDS=%d\n", result.BeforeRecords)
	fmt.Printf("PRUNE_AFTER_RECORDS=%d\n", result.AfterRecords)
	return nil
}

func parseTimeArg(raw string) (int64, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(value, 10, 64); err == nil {
		if n > 1_000_000_000_000 {
			return n, nil
		}
		return n * 1000, nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UnixMilli(), nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UnixMilli(), nil
	}
	return 0, fmt.Errorf("unsupported time format: %s", value)
}
