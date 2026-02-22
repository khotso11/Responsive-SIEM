package retain

import (
	"os"
	"strconv"
	"strings"
)

const (
	TypeAlerts    = "alerts"
	TypeRuns      = "runs"
	TypeSteps     = "steps"
	TypeTelemetry = "telemetry"
)

var typeFileNames = map[string]string{
	TypeAlerts:    "alerts.jsonl",
	TypeRuns:      "runs.jsonl",
	TypeSteps:     "steps.jsonl",
	TypeTelemetry: "telemetry.jsonl",
}

func SupportedTypes() []string {
	return []string{TypeAlerts, TypeRuns, TypeSteps, TypeTelemetry}
}

type Policy struct {
	MaxAgeSeconds int64
	MaxBytes      int64
}

func DefaultPolicy() Policy {
	return Policy{
		MaxAgeSeconds: 86400,
		MaxBytes:      50 * 1024 * 1024,
	}
}

func PolicyFromEnv() Policy {
	p := DefaultPolicy()
	if parsed, ok := parseEnvInt64("RETAIN_MAX_AGE_SECONDS"); ok {
		p.MaxAgeSeconds = parsed
	}
	if parsed, ok := parseEnvInt64("RETAIN_MAX_BYTES"); ok {
		p.MaxBytes = parsed
	}
	return p
}

type IngestOptions struct {
	RetainedDir  string
	RunsPath     string
	StepsPath    string
	DetectorLog  string
	CollectorLog string
	MasterLog    string
}

type IngestStats struct {
	Alerts    int
	Runs      int
	Steps     int
	Telemetry int
}

type QueryOptions struct {
	RetainedDir string
	Type        string
	SinceUnixMs int64
	UntilUnixMs int64
	RunID       string
	PlaybookID  string
	Status      string
	Contains    string
}

type QueryResult struct {
	Count          int64            `json:"count"`
	FirstTSUnixMs  int64            `json:"first_ts_unix_ms"`
	LastTSUnixMs   int64            `json:"last_ts_unix_ms"`
	CountsByType   map[string]int64 `json:"counts_by_type"`
	CountsByStatus map[string]int64 `json:"counts_by_status"`
}

type PruneOptions struct {
	RetainedDir string
	Policy      Policy
}

type PruneResult struct {
	BeforeBytes   int64 `json:"before_bytes"`
	AfterBytes    int64 `json:"after_bytes"`
	BeforeRecords int   `json:"before_records"`
	AfterRecords  int   `json:"after_records"`
}

func parseEnvInt64(name string) (int64, bool) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0, false
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}
