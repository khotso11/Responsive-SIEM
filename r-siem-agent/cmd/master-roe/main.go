package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/nats-io/nats.go"
	"gopkg.in/yaml.v3"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
)

type roeWorkersConfig struct {
	FastWorkers     int `yaml:"fast_workers"`
	StandardWorkers int `yaml:"standard_workers"`
	PullBatch       int `yaml:"pull_batch"`
	PullTimeoutMs   int `yaml:"pull_timeout_ms"`
}

type roeDispatchQueueConfig struct {
	Size                 int `yaml:"size"`
	DegradeHighWatermark int `yaml:"degrade_high_watermark_pct"`
	DegradeLowWatermark  int `yaml:"degrade_low_watermark_pct"`
}

type roeSelectors struct {
	RuleIDs []string `yaml:"rule_ids"`
}

type roeStep struct {
	ActionType string         `yaml:"action_type"`
	TargetFrom string         `yaml:"target_from"`
	Params     map[string]any `yaml:"params"`
}

type roePolicyRequirements struct {
	Approval       string `yaml:"approval"`
	MaxBlastRadius int    `yaml:"max_blast_radius"`
}

type roePlaybook struct {
	ID                 string                `yaml:"id"`
	Version            playbookVersion       `yaml:"version"`
	Enabled            bool                  `yaml:"enabled"`
	Selectors          roeSelectors          `yaml:"selectors"`
	Steps              []roeStep             `yaml:"steps"`
	PolicyRequirements roePolicyRequirements `yaml:"policy_requirements"`
}

type playbookVersion struct {
	Value string
}

func (v *playbookVersion) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		return nil
	}
	switch value.Kind {
	case yaml.ScalarNode:
		v.Value = strings.TrimSpace(value.Value)
		return nil
	default:
		return fmt.Errorf("unsupported playbook version")
	}
}

type roeActionAllowlist struct {
	AllowedActionTypes []string `yaml:"allowed_action_types"`
}

type roeApprovals struct {
	TimeoutMs int64 `yaml:"timeout_ms"`
}

type roeSafeMode struct {
	RequireApprovalWhenDegraded bool `yaml:"require_approval_when_degraded"`
}

type roeBlastRadius struct {
	DefaultMax int `yaml:"default_max"`
}

type roePolicies struct {
	ActionAllowlist roeActionAllowlist `yaml:"action_allowlist"`
	Approvals       roeApprovals       `yaml:"approvals"`
	SafeMode        roeSafeMode        `yaml:"safe_mode"`
	BlastRadius     roeBlastRadius     `yaml:"blast_radius"`
}

type roeExportTarget struct {
	Enabled  bool   `yaml:"enabled"`
	Required *bool  `yaml:"required"`
	Path     string `yaml:"path"`
	Flush    *bool  `yaml:"flush"`
}

type roeExportConfig struct {
	Runs      roeExportTarget `yaml:"runs"`
	Steps     roeExportTarget `yaml:"steps"`
	Approvals roeExportTarget `yaml:"approvals"`
	Enabled   bool            `yaml:"enabled"`
	Required  *bool           `yaml:"required"`
	RunsPath  string          `yaml:"runs_path"`
	Flush     *bool           `yaml:"flush"`
}

type roeLocksConfig struct {
	GroupTTLms int64 `yaml:"group_ttl_ms"`
}

type roeWorkerLockConfig struct {
	LockTTLms int64 `yaml:"lock_ttl_ms"`
}

type roeJetstreamConfig struct {
	SubjectTriggersFast     string `yaml:"subject_triggers_fast"`
	SubjectTriggersStandard string `yaml:"subject_triggers_standard"`
	SubjectStepsFast        string `yaml:"subject_steps_fast"`
	SubjectStepsStandard    string `yaml:"subject_steps_standard"`
	SubjectResultsFast      string `yaml:"subject_results_fast"`
	SubjectResultsStandard  string `yaml:"subject_results_standard"`
	SubjectApprovals        string `yaml:"subject_approvals"`
	SubjectApprovalRequests string `yaml:"subject_approval_requests"`
}

type roeKVConfig struct {
	BucketIdemp     string `yaml:"bucket_idemp"`
	BucketRuns      string `yaml:"bucket_runs"`
	BucketSteps     string `yaml:"bucket_steps"`
	BucketLocks     string `yaml:"bucket_locks"`
	BucketApprovals string `yaml:"bucket_approvals"`
	BucketResults   string `yaml:"bucket_results"`
}

type roeConfig struct {
	Workers       roeWorkersConfig       `yaml:"workers"`
	DispatchQueue roeDispatchQueueConfig `yaml:"dispatch_queue"`
	Playbooks     []roePlaybook          `yaml:"playbooks"`
	Policies      roePolicies            `yaml:"policies"`
	Export        roeExportConfig        `yaml:"export"`
	Locks         roeLocksConfig         `yaml:"locks"`
	Worker        roeWorkerLockConfig    `yaml:"worker"`
	Jetstream     roeJetstreamConfig     `yaml:"jetstream"`
	KV            roeKVConfig            `yaml:"kv"`
}

type roeConfigWrapper struct {
	ROE       *roeConfig    `yaml:"roe"`
	Playbooks []roePlaybook `yaml:"playbooks"`
	Policies  *roePolicies  `yaml:"policies"`
}

type responseTrigger struct {
	TriggerIdemKey   string
	AlertKey         string
	RuleID           string
	RuleKind         string
	Severity         string
	EventType        string
	SourceType       string
	SrcIP            string
	UserName         string
	Lane             string
	GroupBy          string
	GroupKey         string
	AgentID          string
	EventTsUnixMs    int64
	ObservedAtUnixMs int64
	Stream           string
	Consumer         string
	Subject          string
	JSSeq            *uint64
	BatchKey         string
}

type runRecord struct {
	RunID                     string            `json:"run_id"`
	TriggerIdemKey            string            `json:"trigger_idem_key"`
	AlertKey                  string            `json:"alert_key"`
	RuleID                    string            `json:"rule_id"`
	RuleKind                  string            `json:"rule_kind"`
	Severity                  string            `json:"severity"`
	Lane                      string            `json:"lane"`
	GroupBy                   string            `json:"group_by,omitempty"`
	GroupKey                  string            `json:"group_key,omitempty"`
	Target                    string            `json:"target,omitempty"`
	PlaybookID                string            `json:"playbook_id"`
	PlaybookVersion           string            `json:"playbook_version"`
	Status                    string            `json:"status"`
	CreatedAtUnixMs           int64             `json:"created_at_unix_ms"`
	CurrentStepIndex          int               `json:"current_step_index"`
	StepTotal                 int               `json:"step_total"`
	StepSucceededCount        int               `json:"step_succeeded_count"`
	StepFailedSafeCount       int               `json:"step_failed_safe_count"`
	StepFailedTransientCount  int               `json:"step_failed_transient_count"`
	FailedSafeReason          string            `json:"failed_safe_reason,omitempty"`
	LastUpdatedAtUnixMs       int64             `json:"last_updated_at_unix_ms"`
	ApprovalRequired          bool              `json:"approval_required,omitempty"`
	ApprovalRequestedAtUnixMs int64             `json:"approval_requested_at_unix_ms,omitempty"`
	ApprovalTimeoutMs         int64             `json:"approval_timeout_ms,omitempty"`
	ApprovalDecision          string            `json:"approval_decision,omitempty"`
	ApprovalDecidedAtUnixMs   int64             `json:"approval_decided_at_unix_ms,omitempty"`
	ApprovalActor             string            `json:"approval_actor,omitempty"`
	StepStatuses              map[string]string `json:"step_statuses,omitempty"`
}

type stepRecord struct {
	StepID      string         `json:"step_id"`
	StepIdemKey string         `json:"step_idem_key"`
	RunID       string         `json:"run_id"`
	StepIndex   int            `json:"step_index"`
	ActionType  string         `json:"action_type"`
	Target      string         `json:"target,omitempty"`
	Actor       string         `json:"actor,omitempty"`
	Params      map[string]any `json:"params"`
	Status      string         `json:"status"`
	Attempt     int            `json:"attempt"`
	Lane        string         `json:"lane"`
}

type stepResult struct {
	RunID            string         `json:"run_id"`
	StepID           string         `json:"step_id"`
	StepIndex        int            `json:"step_index"`
	ActionType       string         `json:"action_type"`
	Lane             string         `json:"lane"`
	Target           string         `json:"target,omitempty"`
	Actor            string         `json:"actor,omitempty"`
	Status           string         `json:"status"`
	Attempt          int            `json:"attempt"`
	FinishedAtUnixMs int64          `json:"finished_at_unix_ms"`
	Receipt          map[string]any `json:"receipt,omitempty"`
	LastError        string         `json:"last_error,omitempty"`
	StepKey          string         `json:"step_key"`
}

type roeJournal struct {
	logger *slog.Logger
	cfg    roeExportTarget
	mu     sync.Mutex
	file   *os.File
}

type roeResultsExporter struct {
	logger *slog.Logger
	cfg    roeExportConfig
	mu     sync.Mutex
	file   *os.File
}

type roeRuntime struct {
	logger             *slog.Logger
	js                 nats.JetStreamContext
	cfg                roeConfig
	idempKV            nats.KeyValue
	runsKV             nats.KeyValue
	stepsKV            nats.KeyValue
	resultsKV          nats.KeyValue
	locksKV            nats.KeyValue
	approvalsKV        nats.KeyValue
	degraded           atomic.Bool
	dispatchSize       int
	dispatchHighPct    int
	dispatchLowPct     int
	resultsExport      *roeResultsExporter
	approvalsExport    *roeJournal
	dbSink             *roeDBSink
	resultLockHolderID string
}

type roeDBRecord struct {
	EventTsUnixMs int64
	RecvTsUnixMs  int64
	NodeID        string
	SourceType    string
	EventType     string
	SrcIP         string
	UserName      string
	Severity      string
	RuleID        string
	EventIdemKey  string
	RawLineSHA256 string
}

type roeDBSink struct {
	logger *slog.Logger
	cfg    config.MasterDBConfig
	db     *sql.DB
}

var errResultNoAck = errors.New("result_nak")

const (
	responseStream           = "RSIEM_RESPONSE"
	responseTriggerFast      = "rsiem.response.triggers.fast"
	responseTriggerStd       = "rsiem.response.triggers.standard"
	responseStepsFast        = "rsiem.response.steps.fast"
	responseStepsStd         = "rsiem.response.steps.standard"
	responseResultsFast      = "rsiem.response.results.fast"
	responseResultsStd       = "rsiem.response.results.standard"
	responseApprovals        = "rsiem.response.approvals"
	responseApprovalRequests = "rsiem.response.approval_requests"
	defaultWorkers           = 1
	defaultPullBatch         = 10
	defaultPullTimeoutMs     = 500
	defaultQueueSize         = 1024
	defaultHighPct           = 80
	defaultLowPct            = 50
	defaultGroupLockTTL      = int64(600000)
	defaultApprovalTimeoutMs = int64(60000)
	defaultResultLockTTL     = int64(30000)
)

func main() {
	configPath := flag.String("config", "configs/master.yaml", "Path to master config")
	flag.Parse()

	baseCfg, err := config.LoadMaster(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := logging.NewLogger(baseCfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}

	roeCfg, err := loadROEConfig(*configPath)
	if err != nil {
		logger.Error("roe_config_load_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logROEConfigLoaded(logger, *configPath, roeCfg)
	logROEApprovalsTimeoutLoaded(logger, *configPath, roeCfg)

	nc, err := nats.Connect(baseCfg.JetStream.URL, nats.Name("r-siem-master-roe"))
	if err != nil {
		logger.Error("nats_connect_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		logger.Error("jetstream_context_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if err := ensureResponseStream(js, roeCfg); err != nil {
		logger.Error("ensure_response_stream_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logStreamInfo(logger, js)

	idempKV, err := ensureKV(js, firstNonEmpty(roeCfg.KV.BucketIdemp, "RSIEM_RSP_IDEMP"))
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_IDEMP"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	runsKV, err := ensureKV(js, firstNonEmpty(roeCfg.KV.BucketRuns, "RSIEM_RSP_RUNS"))
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_RUNS"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	stepsKV, err := ensureKV(js, firstNonEmpty(roeCfg.KV.BucketSteps, "RSIEM_RSP_STEPS"))
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_STEPS"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	resultsKV, err := ensureKV(js, firstNonEmpty(roeCfg.KV.BucketResults, "RSIEM_RSP_RESULTS"))
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_RESULTS"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	locksKV, err := ensureKV(js, firstNonEmpty(roeCfg.KV.BucketLocks, "RSIEM_RSP_LOCKS"))
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_LOCKS"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	approvalsKV, err := ensureKV(js, firstNonEmpty(roeCfg.KV.BucketApprovals, "RSIEM_RSP_APPROVALS"))
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_APPROVALS"), slog.String("error", err.Error()))
		os.Exit(1)
	}

	runJournal, err := newRoeJournal(logger, roeCfg.Export.Runs)
	if err != nil {
		logger.Error("roe_export_init_failed", slog.String("target", "runs"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if runJournal != nil {
		defer runJournal.Close()
	}
	stepJournal, err := newRoeJournal(logger, roeCfg.Export.Steps)
	if err != nil {
		logger.Error("roe_export_init_failed", slog.String("target", "steps"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if stepJournal != nil {
		defer stepJournal.Close()
	}
	resultsExporter, err := newRoeResultsExporter(logger, roeCfg.Export)
	if err != nil {
		logger.Error("roe_export_init_failed", slog.String("target", "runs"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if resultsExporter != nil {
		defer resultsExporter.Close()
	}
	approvalsJournal, err := newRoeJournal(logger, roeCfg.Export.Approvals)
	if err != nil {
		logger.Error("roe_export_init_failed", slog.String("target", "approvals"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if approvalsJournal != nil {
		defer approvalsJournal.Close()
	}

	runtime := &roeRuntime{
		logger:             logger,
		js:                 js,
		cfg:                roeCfg,
		idempKV:            idempKV,
		runsKV:             runsKV,
		stepsKV:            stepsKV,
		resultsKV:          resultsKV,
		locksKV:            locksKV,
		approvalsKV:        approvalsKV,
		dispatchSize:       roeCfg.DispatchQueue.Size,
		dispatchHighPct:    roeCfg.DispatchQueue.DegradeHighWatermark,
		dispatchLowPct:     roeCfg.DispatchQueue.DegradeLowWatermark,
		resultsExport:      resultsExporter,
		approvalsExport:    approvalsJournal,
		resultLockHolderID: newRuntimeID("master-roe-results"),
	}

	dbSink, err := newROEDBSink(logger, baseCfg.DB)
	if err != nil {
		logger.Error("db_sink_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if dbSink != nil {
		runtime.dbSink = dbSink
		defer dbSink.Close()
		logger.LogAttrs(context.Background(), slog.LevelInfo, "db_sink_enabled",
			slog.String("dsn", baseCfg.DB.DSN),
			slog.Bool("fail_closed", baseCfg.DB.FailClosed),
		)
	}

	ctx, cancel := signalContext()
	defer cancel()

	fastQueue := make(chan *nats.Msg, roeCfg.DispatchQueue.Size)
	standardQueue := make(chan *nats.Msg, roeCfg.DispatchQueue.Size)
	resultsFastQueue := make(chan *nats.Msg, roeCfg.DispatchQueue.Size)
	resultsStandardQueue := make(chan *nats.Msg, roeCfg.DispatchQueue.Size)
	approvalsQueue := make(chan *nats.Msg, roeCfg.DispatchQueue.Size)

	if err := ensureConsumer(js, responseStream, runtime.subjectTriggersFast(), "roe-trig-fast"); err != nil {
		logger.Error("ensure_consumer_failed", slog.String("lane", "FAST"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := ensureConsumer(js, responseStream, runtime.subjectTriggersStandard(), "roe-trig-standard"); err != nil {
		logger.Error("ensure_consumer_failed", slog.String("lane", "STANDARD"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := ensureConsumer(js, responseStream, runtime.subjectResultsFast(), "roe-results-fast"); err != nil {
		logger.Error("ensure_consumer_failed", slog.String("lane", "FAST"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := ensureConsumer(js, responseStream, runtime.subjectResultsStandard(), "roe-results-standard"); err != nil {
		logger.Error("ensure_consumer_failed", slog.String("lane", "STANDARD"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := ensureConsumer(js, responseStream, runtime.subjectApprovals(), "roe-approvals"); err != nil {
		logger.Error("ensure_consumer_failed", slog.String("lane", "APPROVALS"), slog.String("error", err.Error()))
		os.Exit(1)
	}

	fastSub, err := js.PullSubscribe(runtime.subjectTriggersFast(), "roe-trig-fast", nats.BindStream(responseStream))
	if err != nil {
		logger.Error("subscribe_failed", slog.String("lane", "FAST"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	standardSub, err := js.PullSubscribe(runtime.subjectTriggersStandard(), "roe-trig-standard", nats.BindStream(responseStream))
	if err != nil {
		logger.Error("subscribe_failed", slog.String("lane", "STANDARD"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	resultsFastSub, err := js.PullSubscribe(runtime.subjectResultsFast(), "roe-results-fast", nats.BindStream(responseStream))
	if err != nil {
		logger.Error("subscribe_failed", slog.String("lane", "FAST"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	resultsStandardSub, err := js.PullSubscribe(runtime.subjectResultsStandard(), "roe-results-standard", nats.BindStream(responseStream))
	if err != nil {
		logger.Error("subscribe_failed", slog.String("lane", "STANDARD"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	approvalsSub, err := js.PullSubscribe(runtime.subjectApprovals(), "roe-approvals", nats.BindStream(responseStream))
	if err != nil {
		logger.Error("subscribe_failed", slog.String("lane", "APPROVALS"), slog.String("error", err.Error()))
		os.Exit(1)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runFetchLoop(ctx, runtime, fastSub, "FAST", fastQueue, nil)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		runFetchLoop(ctx, runtime, standardSub, "STANDARD", standardQueue, runtime)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		runResultFetchLoop(ctx, runtime, resultsFastSub, "FAST", resultsFastQueue, nil)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		runResultFetchLoop(ctx, runtime, resultsStandardSub, "STANDARD", resultsStandardQueue, runtime)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		runFetchLoop(ctx, runtime, approvalsSub, "APPROVALS", approvalsQueue, nil)
	}()

	for i := 0; i < roeCfg.Workers.FastWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runWorker(ctx, runtime, fastQueue, "FAST", runJournal, stepJournal)
		}()
	}
	for i := 0; i < roeCfg.Workers.StandardWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runWorker(ctx, runtime, standardQueue, "STANDARD", runJournal, stepJournal)
		}()
	}
	for i := 0; i < roeCfg.Workers.FastWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runResultWorker(ctx, runtime, resultsFastQueue, "FAST")
		}()
	}
	for i := 0; i < roeCfg.Workers.StandardWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runResultWorker(ctx, runtime, resultsStandardQueue, "STANDARD")
		}()
	}
	for i := 0; i < roeCfg.Workers.StandardWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runApprovalWorker(ctx, runtime, approvalsQueue)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		runApprovalTimeoutScanner(ctx, runtime)
	}()

	wg.Wait()
	logger.Info("master_roe_stopped")
}

func loadROEConfig(path string) (roeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return roeConfig{}, fmt.Errorf("read config: %w", err)
	}
	return parseROEConfig(data)
}

func parseROEConfig(data []byte) (roeConfig, error) {
	var wrapper roeConfigWrapper
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return roeConfig{}, fmt.Errorf("parse roe config: %w", err)
	}
	cfg := roeConfig{}
	if wrapper.ROE != nil {
		cfg = *wrapper.ROE
	}
	if len(wrapper.Playbooks) > 0 {
		cfg.Playbooks = wrapper.Playbooks
	}
	if wrapper.Policies != nil {
		cfg.Policies = *wrapper.Policies
	}
	applyROEDefaults(&cfg)
	return cfg, nil
}

func applyROEDefaults(cfg *roeConfig) {
	if cfg.Workers.FastWorkers <= 0 {
		cfg.Workers.FastWorkers = defaultWorkers
	}
	if cfg.Workers.StandardWorkers <= 0 {
		cfg.Workers.StandardWorkers = defaultWorkers
	}
	if cfg.Workers.PullBatch <= 0 {
		cfg.Workers.PullBatch = defaultPullBatch
	}
	if cfg.Workers.PullTimeoutMs <= 0 {
		cfg.Workers.PullTimeoutMs = defaultPullTimeoutMs
	}
	if cfg.DispatchQueue.Size <= 0 {
		cfg.DispatchQueue.Size = defaultQueueSize
	}
	if cfg.DispatchQueue.DegradeHighWatermark <= 0 {
		cfg.DispatchQueue.DegradeHighWatermark = defaultHighPct
	}
	if cfg.DispatchQueue.DegradeLowWatermark <= 0 {
		cfg.DispatchQueue.DegradeLowWatermark = defaultLowPct
	}
	if cfg.Policies.Approvals.TimeoutMs <= 0 {
		cfg.Policies.Approvals.TimeoutMs = defaultApprovalTimeoutMs
	}
	if cfg.Locks.GroupTTLms <= 0 {
		cfg.Locks.GroupTTLms = defaultGroupLockTTL
	}
	if cfg.Worker.LockTTLms <= 0 {
		cfg.Worker.LockTTLms = defaultResultLockTTL
	}
	applyROEJetstreamDefaults(&cfg.Jetstream)
	applyROEKVDefaults(&cfg.KV)
}

func logROEConfigLoaded(logger *slog.Logger, configPath string, cfg roeConfig) {
	playbookIDs := make([]string, 0, len(cfg.Playbooks))
	for _, pb := range cfg.Playbooks {
		playbookIDs = append(playbookIDs, pb.ID)
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_config_loaded",
		slog.String("config_path", configPath),
		slog.Int("playbooks_count", len(cfg.Playbooks)),
		slog.Any("playbook_ids", playbookIDs),
		slog.Any("playbook_rule_ids", playbookRuleMap(cfg.Playbooks)),
	)
}

func logROEApprovalsTimeoutLoaded(logger *slog.Logger, configPath string, cfg roeConfig) {
	logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_approvals_timeout_loaded",
		slog.Int64("timeout_ms", cfg.Policies.Approvals.TimeoutMs),
		slog.String("source", "policies.approvals.timeout_ms"),
		slog.String("config_path", configPath),
	)
}

func playbookRuleMap(playbooks []roePlaybook) map[string][]string {
	result := make(map[string][]string, len(playbooks))
	for _, pb := range playbooks {
		ruleIDs := make([]string, 0, len(pb.Selectors.RuleIDs))
		for _, id := range pb.Selectors.RuleIDs {
			ruleIDs = append(ruleIDs, strings.TrimSpace(id))
		}
		result[pb.ID] = ruleIDs
	}
	return result
}

func ensureResponseStream(js nats.JetStreamContext, cfg roeConfig) error {
	required := []string{
		firstNonEmpty(cfg.Jetstream.SubjectTriggersFast, responseTriggerFast),
		firstNonEmpty(cfg.Jetstream.SubjectTriggersStandard, responseTriggerStd),
		firstNonEmpty(cfg.Jetstream.SubjectStepsFast, responseStepsFast),
		firstNonEmpty(cfg.Jetstream.SubjectStepsStandard, responseStepsStd),
		firstNonEmpty(cfg.Jetstream.SubjectResultsFast, responseResultsFast),
		firstNonEmpty(cfg.Jetstream.SubjectResultsStandard, responseResultsStd),
		firstNonEmpty(cfg.Jetstream.SubjectApprovals, responseApprovals),
		firstNonEmpty(cfg.Jetstream.SubjectApprovalRequests, responseApprovalRequests),
	}
	info, err := js.StreamInfo(responseStream)
	if err != nil {
		if errors.Is(err, nats.ErrStreamNotFound) {
			_, err = js.AddStream(&nats.StreamConfig{
				Name:     responseStream,
				Subjects: required,
			})
			return err
		}
		return err
	}
	merged := mergeSubjects(info.Config.Subjects, required)
	if equalSubjects(info.Config.Subjects, merged) {
		return nil
	}
	streamCfg := info.Config
	streamCfg.Subjects = merged
	_, err = js.UpdateStream(&streamCfg)
	return err
}

func logStreamInfo(logger *slog.Logger, js nats.JetStreamContext) {
	info, err := js.StreamInfo(responseStream)
	if err != nil {
		logger.Error("roe_stream_info_failed", slog.String("error", err.Error()))
		return
	}
	cfg := info.Config
	logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_stream_info",
		slog.String("stream", cfg.Name),
		slog.String("retention", cfg.Retention.String()),
		slog.Int64("max_age", int64(cfg.MaxAge)),
		slog.Int64("max_msgs", cfg.MaxMsgs),
		slog.Int64("max_bytes", cfg.MaxBytes),
		slog.Any("subjects", cfg.Subjects),
	)
}

func mergeSubjects(existing []string, required []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(required))
	out := make([]string, 0, len(existing)+len(required))
	for _, subj := range existing {
		if strings.TrimSpace(subj) == "" {
			continue
		}
		if _, ok := seen[subj]; ok {
			continue
		}
		seen[subj] = struct{}{}
		out = append(out, subj)
	}
	for _, subj := range required {
		if strings.TrimSpace(subj) == "" {
			continue
		}
		if _, ok := seen[subj]; ok {
			continue
		}
		seen[subj] = struct{}{}
		out = append(out, subj)
	}
	return out
}

func equalSubjects(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ensureKV(js nats.JetStreamContext, bucket string) (nats.KeyValue, error) {
	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: bucket})
	if err == nil {
		return kv, nil
	}
	existing, existingErr := js.KeyValue(bucket)
	if existingErr == nil {
		return existing, nil
	}
	return nil, err
}

func ensureConsumer(js nats.JetStreamContext, stream, subject, durable string) error {
	_, err := js.AddConsumer(stream, &nats.ConsumerConfig{
		Durable:       durable,
		FilterSubject: subject,
		AckPolicy:     nats.AckExplicitPolicy,
	})
	if err != nil && !errors.Is(err, nats.ErrConsumerNameAlreadyInUse) {
		return err
	}
	return nil
}

func runFetchLoop(ctx context.Context, runtime *roeRuntime, sub *nats.Subscription, lane string, queue chan *nats.Msg, backpressure *roeRuntime) {
	timeout := time.Duration(runtime.cfg.Workers.PullTimeoutMs) * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if backpressure != nil {
			if backpressure.shouldDegrade(len(queue)) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		msgs, err := sub.Fetch(runtime.cfg.Workers.PullBatch, nats.MaxWait(timeout))
		if err != nil {
			if err == nats.ErrTimeout {
				continue
			}
			runtime.logger.Error("roe_fetch_failed", slog.String("lane", lane), slog.String("error", err.Error()))
			continue
		}
		for _, msg := range msgs {
			queue <- msg
		}
	}
}

func runResultFetchLoop(ctx context.Context, runtime *roeRuntime, sub *nats.Subscription, lane string, queue chan *nats.Msg, backpressure *roeRuntime) {
	timeout := time.Duration(runtime.cfg.Workers.PullTimeoutMs) * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if backpressure != nil {
			if backpressure.shouldDegrade(len(queue)) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		msgs, err := sub.Fetch(runtime.cfg.Workers.PullBatch, nats.MaxWait(timeout))
		if err != nil {
			if err == nats.ErrTimeout {
				continue
			}
			runtime.logger.Error("roe_fetch_failed", slog.String("lane", lane), slog.String("error", err.Error()))
			continue
		}
		for _, msg := range msgs {
			runID, stepID, jsSeq, decodeErr := decodeResultLogFields(msg)
			if decodeErr != nil {
				runtime.logger.LogAttrs(context.Background(), slog.LevelError, "result_apply_enqueue_failed",
					slog.String("lane", lane),
					slog.String("reason", fmt.Sprintf("decode_failed: %v", decodeErr)),
				)
				continue
			}
			select {
			case queue <- msg:
				runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "result_apply_enqueued",
					slog.String("lane", lane),
					slog.String("run_id", runID),
					slog.String("step_id", stepID),
					slog.Uint64("js_seq", jsSeq),
				)
			default:
				runtime.logger.LogAttrs(context.Background(), slog.LevelError, "result_apply_enqueue_failed",
					slog.String("lane", lane),
					slog.String("run_id", runID),
					slog.String("step_id", stepID),
					slog.Uint64("js_seq", jsSeq),
					slog.String("reason", "queue_full"),
				)
				if err := msg.NakWithDelay(250 * time.Millisecond); err != nil {
					runtime.logger.Error("roe_result_nak_failed", slog.String("error", err.Error()))
				}
			}
		}
	}
}

func (r *roeRuntime) shouldDegrade(queueLen int) bool {
	total := queueLen
	threshold := r.dispatchHighPct * r.dispatchSize / 100
	if total >= threshold {
		if r.degraded.CompareAndSwap(false, true) {
			r.logger.LogAttrs(context.Background(), slog.LevelWarn, "roe_degraded_mode_on",
				slog.Int("queue_len", total),
				slog.Int("threshold", threshold),
			)
		}
		return true
	}
	low := r.dispatchLowPct * r.dispatchSize / 100
	if total <= low && r.degraded.CompareAndSwap(true, false) {
		r.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_degraded_mode_off",
			slog.Int("queue_len", total),
			slog.Int("threshold", low),
		)
	}
	return r.degraded.Load()
}

func runWorker(ctx context.Context, runtime *roeRuntime, queue chan *nats.Msg, lane string, runJournal *roeJournal, stepJournal *roeJournal) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-queue:
			if msg == nil {
				continue
			}
			if err := processTrigger(runtime, msg, lane, runJournal, stepJournal); err != nil {
				runtime.logger.Error("roe_trigger_process_failed", slog.String("lane", lane), slog.String("error", err.Error()))
				continue
			}
			if err := msg.Ack(); err != nil {
				runtime.logger.Error("roe_ack_failed", slog.String("lane", lane), slog.String("error", err.Error()))
			}
		}
	}
}

func runResultWorker(ctx context.Context, runtime *roeRuntime, queue chan *nats.Msg, lane string) {
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "result_apply_worker_started",
		slog.String("lane", lane),
	)
	defer func() {
		if rec := recover(); rec != nil {
			runtime.logger.LogAttrs(context.Background(), slog.LevelError, "result_apply_worker_panicked",
				slog.String("lane", lane),
				slog.String("panic", fmt.Sprintf("%v", rec)),
			)
			return
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "result_apply_worker_stopped",
			slog.String("lane", lane),
		)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-queue:
			if msg == nil {
				continue
			}
			runID, stepID, jsSeq, _ := decodeResultLogFields(msg)
			runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "result_apply_attempt",
				slog.String("lane", lane),
				slog.String("run_id", runID),
				slog.String("step_id", stepID),
				slog.Uint64("js_seq", jsSeq),
			)
			if err := processResult(runtime, msg, lane); err != nil {
				runtime.logger.LogAttrs(context.Background(), slog.LevelError, "result_apply_error",
					slog.String("lane", lane),
					slog.String("run_id", runID),
					slog.String("step_id", stepID),
					slog.Uint64("js_seq", jsSeq),
					slog.String("error", err.Error()),
				)
				if errors.Is(err, errResultNoAck) {
					continue
				}
				runtime.logger.Error("roe_result_process_failed", slog.String("lane", lane), slog.String("error", err.Error()))
				continue
			}
			runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "result_apply_success",
				slog.String("lane", lane),
				slog.String("run_id", runID),
				slog.String("step_id", stepID),
				slog.Uint64("js_seq", jsSeq),
			)
			if err := msg.Ack(); err != nil {
				runtime.logger.Error("roe_result_ack_failed", slog.String("lane", lane), slog.String("error", err.Error()))
				continue
			}
			runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "result_ack",
				slog.String("lane", lane),
				slog.String("run_id", runID),
				slog.String("step_id", stepID),
				slog.Uint64("js_seq", jsSeq),
			)
		}
	}
}

func runApprovalWorker(ctx context.Context, runtime *roeRuntime, queue chan *nats.Msg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-queue:
			if msg == nil {
				continue
			}
			if err := processApproval(runtime, msg); err != nil {
				runtime.logger.Error("roe_approval_process_failed", slog.String("error", err.Error()))
				continue
			}
			if err := msg.Ack(); err != nil {
				runtime.logger.Error("roe_approval_ack_failed", slog.String("error", err.Error()))
			}
		}
	}
}

func runApprovalTimeoutScanner(ctx context.Context, runtime *roeRuntime) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := scanForApprovalTimeouts(runtime, 100); err != nil {
				runtime.logger.Error("roe_approval_timeout_scan_failed", slog.String("error", err.Error()))
			}
		}
	}
}

func processTrigger(runtime *roeRuntime, msg *nats.Msg, lane string, runJournal *roeJournal, stepJournal *roeJournal) error {
	trigger, err := decodeTrigger(msg.Data)
	if err != nil {
		runtime.logger.Error("response_trigger_decode_failed", slog.String("lane", lane), slog.String("error", err.Error()))
		return nil
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_trigger_received",
		slog.String("lane", trigger.Lane),
		slog.String("trigger_idem_key", trigger.TriggerIdemKey),
		slog.String("alert_key", trigger.AlertKey),
		slog.String("rule_id", trigger.RuleID),
		slog.String("severity", trigger.Severity),
	)
	if err := runtime.persistNormalizedEvent(trigger, msg.Data); err != nil {
		return err
	}

	if entry, err := runtime.idempKV.Get(trigger.TriggerIdemKey); err == nil {
		runID := extractRunID(entry.Value())
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_trigger_duplicate",
			slog.String("trigger_idem_key", trigger.TriggerIdemKey),
			slog.String("alert_key", trigger.AlertKey),
			slog.String("rule_id", trigger.RuleID),
			slog.String("run_id", runID),
		)
		return nil
	} else if !errors.Is(err, nats.ErrKeyNotFound) {
		return err
	}

	playbook, ok := selectPlaybook(runtime.cfg.Playbooks, trigger.RuleID)
	if !ok {
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_no_playbook",
			slog.String("rule_id", trigger.RuleID),
			slog.String("alert_key", trigger.AlertKey),
			slog.Int("playbooks_count", len(runtime.cfg.Playbooks)),
			slog.Any("playbook_rule_ids", playbookRuleMap(runtime.cfg.Playbooks)),
		)
		return nil
	}

	runID := shortHash(fmt.Sprintf("%s|%s|%s", trigger.TriggerIdemKey, playbook.ID, playbook.Version.Value))
	runKey := fmt.Sprintf("run.%s", runID)

	run := runRecord{
		RunID:           runID,
		TriggerIdemKey:  trigger.TriggerIdemKey,
		AlertKey:        trigger.AlertKey,
		RuleID:          trigger.RuleID,
		RuleKind:        trigger.RuleKind,
		Severity:        trigger.Severity,
		Lane:            trigger.Lane,
		GroupBy:         trigger.GroupBy,
		GroupKey:        trigger.GroupKey,
		Target:          deriveRunTarget(trigger),
		PlaybookID:      playbook.ID,
		PlaybookVersion: playbook.Version.Value,
		Status:          "CREATED",
		CreatedAtUnixMs: trigger.ObservedAtUnixMs,
		ApprovalActor:   auditActor(""),
	}

	if ok, err := runtime.tryAcquireGroupLock(trigger, runID); err != nil {
		return err
	} else if !ok {
		return nil
	}

	if err := runtime.persistRun(runKey, run); err != nil {
		return err
	}
	if err := runtime.persistIdempotency(trigger, runID, playbook); err != nil {
		return err
	}
	if runJournal != nil {
		if err := runJournal.Write("response_run_created", run); err != nil {
			return err
		}
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_run_created",
		slog.String("run_id", runID),
		slog.String("rule_id", trigger.RuleID),
		slog.String("playbook_id", playbook.ID),
		slog.String("playbook_version", playbook.Version.Value),
	)

	if err := runtime.applyAllowlist(playbook); err != nil {
		run.Status = "FAILED_SAFE"
		run.FailedSafeReason = "policy_rejected"
		if err := runtime.persistRun(runKey, run); err != nil {
			return err
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelWarn, "response_run_rejected",
			slog.String("run_id", runID),
			slog.String("reason", err.Error()),
		)
		return nil
	}

	steps, err := compileSteps(runID, trigger, playbook)
	if err != nil {
		run.Status = "FAILED_SAFE"
		run.FailedSafeReason = "plan_compile_failed"
		if err := runtime.persistRun(runKey, run); err != nil {
			return err
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelWarn, "response_run_rejected",
			slog.String("run_id", runID),
			slog.String("reason", err.Error()),
		)
		return nil
	}

	for _, step := range steps {
		if err := runtime.persistStep(step); err != nil {
			return err
		}
	}

	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_plan_compiled",
		slog.String("run_id", runID),
		slog.Int("step_count", len(steps)),
	)
	if runJournal != nil {
		if err := runJournal.Write("response_plan_compiled", map[string]any{
			"run_id":     runID,
			"step_count": len(steps),
		}); err != nil {
			return err
		}
	}

	requiresApproval := runtime.requiresApproval(playbook, trigger.Severity)
	if requiresApproval {
		run.Status = "WAITING_APPROVAL"
		run.ApprovalRequired = true
		run.ApprovalRequestedAtUnixMs = time.Now().UnixMilli()
		run.ApprovalTimeoutMs = runtime.cfg.Policies.Approvals.TimeoutMs
		run.StepTotal = len(steps)
		run.CurrentStepIndex = 0
		if err := runtime.persistRun(runKey, run); err != nil {
			return err
		}
		if err := runtime.publishApprovalRequest(run); err != nil {
			return err
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "approval_request_published",
			slog.String("run_id", runID),
			slog.String("rule_id", trigger.RuleID),
			slog.String("playbook_id", playbook.ID),
			slog.String("subject", runtime.subjectApprovalRequests()),
		)
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "approval_requested",
			slog.String("run_id", runID),
			slog.String("rule_id", trigger.RuleID),
			slog.String("playbook_id", playbook.ID),
			slog.String("playbook_version", playbook.Version.Value),
			slog.Int64("timeout_ms", runtime.cfg.Policies.Approvals.TimeoutMs),
		)
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_run_waiting_approval",
			slog.String("run_id", runID),
			slog.String("rule_id", trigger.RuleID),
			slog.String("playbook_id", playbook.ID),
			slog.Int64("timeout_ms", runtime.cfg.Policies.Approvals.TimeoutMs),
		)
		return nil
	}

	for _, step := range steps {
		step.Actor = auditActor(run.ApprovalActor)
		subject, err := runtime.publishStep(trigger.Lane, step)
		if err != nil {
			return err
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_step_published",
			slog.String("run_id", runID),
			slog.String("step_id", step.StepID),
			slog.Int("step_index", step.StepIndex),
			slog.String("action_type", step.ActionType),
			slog.String("step_subject", subject),
		)
		if stepJournal != nil {
			if err := stepJournal.Write("response_step_published", step); err != nil {
				return err
			}
		}
	}

	run.Status = "PLANNED"
	run.CurrentStepIndex = 0
	run.StepTotal = len(steps)
	return runtime.persistRun(runKey, run)
}

func processResult(runtime *roeRuntime, msg *nats.Msg, lane string) error {
	meta, _ := msg.Metadata()
	jsSeq := uint64(0)
	if meta != nil {
		jsSeq = meta.Sequence.Stream
	}
	result, err := decodeStepResult(msg.Data)
	if err != nil {
		runtime.logger.Error("response_step_result_decode_failed", slog.String("lane", lane), slog.String("error", err.Error()))
		return nil
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_step_result_received",
		slog.String("run_id", result.RunID),
		slog.String("step_id", result.StepID),
		slog.String("status", result.Status),
		slog.Uint64("js_seq", jsSeq),
	)
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "result_consumer_after_received",
		slog.String("run_id", result.RunID),
		slog.String("step_id", result.StepID),
		slog.Uint64("js_seq", jsSeq),
	)
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "result_apply_begin",
		slog.String("lane", lane),
		slog.String("run_id", result.RunID),
		slog.String("step_id", result.StepID),
		slog.Uint64("js_seq", jsSeq),
	)
	outcome := "applied"
	defer func() {
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "result_apply_done",
			slog.String("lane", lane),
			slog.String("run_id", result.RunID),
			slog.String("step_id", result.StepID),
			slog.Uint64("js_seq", jsSeq),
			slog.String("outcome", outcome),
		)
	}()

	lockKey := fmt.Sprintf("lock.run.%s", result.RunID)
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "result_apply_lock_attempt",
		slog.String("run_id", result.RunID),
		slog.String("step_id", result.StepID),
		slog.String("lock_key", lockKey),
		slog.Uint64("js_seq", jsSeq),
	)
	locked, err := runtime.acquireResultLock(lockKey, result)
	if err != nil {
		outcome = "lock_error"
		return err
	}
	if !locked {
		outcome = "lock_contended_retry"
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_lock_contended_result",
			slog.String("run_id", result.RunID),
			slog.String("step_id", result.StepID),
			slog.String("lock_key", lockKey),
		)
		if err := msg.NakWithDelay(250 * time.Millisecond); err != nil {
			runtime.logger.Error("roe_result_nak_failed", slog.String("error", err.Error()))
		}
		return errResultNoAck
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_lock_acquired_result",
		slog.String("run_id", result.RunID),
		slog.String("step_id", result.StepID),
		slog.String("lock_key", lockKey),
	)
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "result_apply_lock_acquired",
		slog.String("run_id", result.RunID),
		slog.String("step_id", result.StepID),
		slog.String("lock_key", lockKey),
		slog.Uint64("js_seq", jsSeq),
	)
	defer runtime.releaseResultLock(lockKey, result)

	resultKey := fmt.Sprintf("result.%s.%s", result.RunID, result.StepID)
	resultDuplicate := false
	if entry, err := runtime.resultsKV.Get(resultKey); err == nil {
		_ = entry
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_result_duplicate",
			slog.String("run_id", result.RunID),
			slog.String("step_id", result.StepID),
			slog.String("result_key", resultKey),
		)
		resultDuplicate = true
		outcome = "duplicate_reconciled"
	} else if !errors.Is(err, nats.ErrKeyNotFound) {
		outcome = "dedupe_get_error"
		return err
	}
	if !resultDuplicate {
		if err := runtime.persistResultDedupe(resultKey, result, jsSeq); err != nil {
			outcome = "dedupe_put_error"
			return err
		}
	}
	applied := false
	defer func() {
		if applied {
			return
		}
		if !resultDuplicate {
			_ = runtime.resultsKV.Delete(resultKey)
		}
	}()

	runKey := fmt.Sprintf("run.%s", result.RunID)
	run, err := runtime.getRun(runKey, result)
	if err != nil {
		outcome = "load_run_error"
		return err
	}
	prevStatus := run.Status
	updateRunWithResult(&run, result)
	if err := runtime.reconcileRunProgress(&run); err != nil {
		outcome = "reconcile_error"
		return err
	}
	if err := runtime.persistRun(runKey, run); err != nil {
		outcome = "persist_run_error"
		return err
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_result_applied",
		slog.String("run_id", result.RunID),
		slog.String("step_id", result.StepID),
		slog.String("status", result.Status),
		slog.String("result_key", resultKey),
		slog.Int("step_total", run.StepTotal),
		slog.Int("step_succeeded_count", run.StepSucceededCount),
		slog.Int("step_failed_safe_count", run.StepFailedSafeCount),
		slog.Int("step_failed_transient_count", run.StepFailedTransientCount),
	)
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_run_updated",
		slog.String("run_id", run.RunID),
		slog.String("status", run.Status),
		slog.Int("step_succeeded_count", run.StepSucceededCount),
		slog.Int("step_failed_safe_count", run.StepFailedSafeCount),
		slog.Int("step_failed_transient_count", run.StepFailedTransientCount),
		slog.String("failed_safe_reason", run.FailedSafeReason),
	)
	if (run.Status == "FAILED_SAFE" || run.Status == "FAILED_TRANSIENT") && prevStatus != run.Status {
		runtime.logger.LogAttrs(context.Background(), slog.LevelWarn, "response_run_recovery_hint",
			slog.String("run_id", run.RunID),
			slog.String("status", run.Status),
			slog.String("failed_step_id", result.StepID),
			slog.String("hint", "If quarantine move succeeded and restore did not run, re-run PB-QUARANTINE-ROLLBACK-DEMO for run_id or execute restore using tmp/quarantine/<run_id>."),
		)
	}
	operatorAction := operatorActionForRun(run)
	if operatorAction != "" {
		runtime.logger.LogAttrs(context.Background(), slog.LevelWarn, "response_run_partial_completion",
			slog.String("run_id", run.RunID),
			slog.String("status", run.Status),
			slog.Int("step_succeeded_count", run.StepSucceededCount),
			slog.Int("step_total", run.StepTotal),
			slog.String("failed_safe_reason", run.FailedSafeReason),
			slog.String("operator_action", operatorAction),
		)
	}
	if err := runtime.exportRunUpdate(run); err != nil {
		outcome = "export_run_error"
		return err
	}
	if resultDuplicate {
		outcome = "duplicate_finalized"
	} else {
		outcome = "applied"
	}
	applied = true
	return nil
}

func decodeResultLogFields(msg *nats.Msg) (string, string, uint64, error) {
	jsSeq := uint64(0)
	if meta, _ := msg.Metadata(); meta != nil {
		jsSeq = meta.Sequence.Stream
	}
	var raw map[string]any
	if err := json.Unmarshal(msg.Data, &raw); err != nil {
		return "", "", jsSeq, err
	}
	runID := strings.TrimSpace(stringFieldRaw(raw, "run_id"))
	stepID := strings.TrimSpace(stringFieldRaw(raw, "step_id"))
	if runID == "" || stepID == "" {
		return runID, stepID, jsSeq, fmt.Errorf("missing run_id/step_id")
	}
	return runID, stepID, jsSeq, nil
}

func processApproval(runtime *roeRuntime, msg *nats.Msg) error {
	approval, err := decodeApproval(msg.Data)
	if err != nil {
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "approval_invalid",
			slog.String("error", err.Error()),
		)
		return nil
	}
	approvalKey := fmt.Sprintf("approval.%s", approval.RunID)
	if entry, err := runtime.approvalsKV.Get(approvalKey); err == nil {
		_ = entry
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "approval_duplicate",
			slog.String("run_id", approval.RunID),
			slog.String("approval_key", approvalKey),
		)
		return nil
	} else if !errors.Is(err, nats.ErrKeyNotFound) {
		return err
	}
	if _, err := runtime.approvalsKV.Put(approvalKey, msg.Data); err != nil {
		return err
	}
	applied := false
	defer func() {
		if applied {
			return
		}
		_ = runtime.approvalsKV.Delete(approvalKey)
	}()
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "approval_received",
		slog.String("run_id", approval.RunID),
		slog.String("decision", approval.Decision),
		slog.String("actor", approval.Actor),
	)
	if runtime.approvalsExport != nil {
		if err := runtime.approvalsExport.Write("approval_received", map[string]any{
			"run_id":   approval.RunID,
			"decision": approval.Decision,
			"actor":    approval.Actor,
			"reason":   approval.Reason,
		}); err != nil {
			return err
		}
	}

	runKey := fmt.Sprintf("run.%s", approval.RunID)
	run, found, err := runtime.loadRun(runKey)
	if err != nil {
		return err
	}
	if !found {
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "approval_orphaned",
			slog.String("run_id", approval.RunID),
		)
		applied = true
		return nil
	}
	eligible := run.Status == "WAITING_APPROVAL" || run.Status == "APPROVED"
	if !eligible {
		if approval.Decision == "approve" && run.Status == "RUNNING" && run.ApprovalDecision == "approve" {
			eligible = true
		}
		if approval.Decision == "deny" && run.Status == "FAILED_SAFE" && run.ApprovalDecision == "deny" {
			eligible = true
		}
	}
	if !eligible {
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "approval_not_needed",
			slog.String("run_id", approval.RunID),
			slog.String("status", run.Status),
		)
		applied = true
		return nil
	}

	now := time.Now().UnixMilli()
	run.ApprovalDecision = approval.Decision
	run.ApprovalDecidedAtUnixMs = now
	run.LastUpdatedAtUnixMs = now
	run.ApprovalActor = auditActor(approval.Actor)
	if approval.Decision == "deny" {
		run.Status = "FAILED_SAFE"
		run.FailedSafeReason = "approval_denied"
		if err := runtime.persistRun(runKey, run); err != nil {
			return err
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "approval_denied",
			slog.String("run_id", approval.RunID),
			slog.String("reason", approval.Reason),
		)
		if runtime.approvalsExport != nil {
			if err := runtime.approvalsExport.Write("approval_denied", map[string]any{
				"run_id": approval.RunID,
				"reason": approval.Reason,
			}); err != nil {
				return err
			}
		}
		if err := runtime.exportRunUpdate(run); err != nil {
			return err
		}
		applied = true
		return nil
	}

	wasRunning := run.Status == "RUNNING"
	if !wasRunning {
		run.Status = "APPROVED"
		if err := runtime.persistRun(runKey, run); err != nil {
			return err
		}
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "approval_approved",
		slog.String("run_id", approval.RunID),
	)
	if runtime.approvalsExport != nil {
		if err := runtime.approvalsExport.Write("approval_approved", map[string]any{
			"run_id": approval.RunID,
		}); err != nil {
			return err
		}
	}
	steps, err := runtime.loadPlannedSteps(run.RunID)
	if err != nil {
		return err
	}
	for _, step := range steps {
		step.Actor = auditActor(run.ApprovalActor)
		subject, err := runtime.publishStep(step.Lane, step)
		if err != nil {
			return err
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_step_published",
			slog.String("run_id", run.RunID),
			slog.String("step_id", step.StepID),
			slog.Int("step_index", step.StepIndex),
			slog.String("action_type", step.ActionType),
			slog.String("step_subject", subject),
		)
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_steps_released_after_approval",
		slog.String("run_id", run.RunID),
		slog.Int("step_count", len(steps)),
	)
	run.Status = "RUNNING"
	run.LastUpdatedAtUnixMs = time.Now().UnixMilli()
	if err := runtime.persistRun(runKey, run); err != nil {
		return err
	}
	if err := runtime.exportRunUpdate(run); err != nil {
		return err
	}
	applied = true
	return nil
}
func decodeTrigger(data []byte) (responseTrigger, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return responseTrigger{}, err
	}
	if msg, ok := raw["msg"].(string); ok && msg != "response_trigger" {
		return responseTrigger{}, fmt.Errorf("unexpected msg: %s", msg)
	}
	trigger := responseTrigger{
		TriggerIdemKey: stringFieldRaw(raw, "trigger_idem_key"),
		AlertKey:       stringFieldRaw(raw, "alert_key"),
		RuleID:         stringFieldRaw(raw, "rule_id"),
		RuleKind:       stringFieldRaw(raw, "rule_kind"),
		Severity:       stringFieldRaw(raw, "severity"),
		EventType:      stringFieldRaw(raw, "event_type"),
		SourceType:     stringFieldRaw(raw, "source_type"),
		SrcIP:          stringFieldRaw(raw, "src_ip"),
		UserName:       stringFieldRaw(raw, "user"),
		Lane:           stringFieldRaw(raw, "lane"),
		GroupBy:        stringFieldRaw(raw, "group_by"),
		GroupKey:       stringFieldRaw(raw, "group_key"),
		AgentID:        stringFieldRaw(raw, "agent_id"),
		Stream:         stringFieldRaw(raw, "stream"),
		Consumer:       stringFieldRaw(raw, "consumer"),
		Subject:        stringFieldRaw(raw, "subject"),
		BatchKey:       stringFieldRaw(raw, "batch_key"),
	}
	if trigger.TriggerIdemKey == "" || trigger.AlertKey == "" || trigger.RuleID == "" || trigger.Severity == "" || trigger.Lane == "" {
		return responseTrigger{}, fmt.Errorf("missing required fields")
	}
	if ts, ok := int64Field(raw, "observed_at_unix_ms"); ok {
		trigger.ObservedAtUnixMs = ts
	}
	if ts, ok := int64Field(raw, "event_ts_unix_ms"); ok {
		trigger.EventTsUnixMs = ts
	}
	if jsSeq, ok := uint64Field(raw, "js_seq"); ok {
		trigger.JSSeq = &jsSeq
	}
	return trigger, nil
}

func decodeStepResult(data []byte) (stepResult, error) {
	var result stepResult
	if err := json.Unmarshal(data, &result); err != nil {
		return stepResult{}, err
	}
	result.RunID = strings.TrimSpace(result.RunID)
	result.StepID = strings.TrimSpace(result.StepID)
	result.ActionType = strings.TrimSpace(result.ActionType)
	result.Lane = strings.TrimSpace(result.Lane)
	result.Target = strings.TrimSpace(result.Target)
	result.Actor = strings.TrimSpace(result.Actor)
	result.Status = strings.TrimSpace(result.Status)
	if result.RunID == "" || result.StepID == "" || result.Status == "" {
		return stepResult{}, fmt.Errorf("missing required fields")
	}
	return result, nil
}

type approvalDecision struct {
	RunID    string `json:"run_id"`
	Decision string `json:"decision"`
	Actor    string `json:"actor"`
	Reason   string `json:"reason"`
	TsUnixMs int64  `json:"ts_unix_ms"`
}

func decodeApproval(data []byte) (approvalDecision, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return approvalDecision{}, err
	}
	runID, _ := raw["run_id"].(string)
	decision, _ := raw["decision"].(string)
	actor, _ := raw["actor"].(string)
	reason, _ := raw["reason"].(string)
	runID = strings.TrimSpace(runID)
	decision = strings.TrimSpace(decision)
	if runID == "" {
		return approvalDecision{}, fmt.Errorf("missing run_id")
	}
	if decision != "approve" && decision != "deny" {
		return approvalDecision{}, fmt.Errorf("invalid decision")
	}
	ts, _ := int64Field(raw, "ts_unix_ms")
	return approvalDecision{
		RunID:    runID,
		Decision: decision,
		Actor:    strings.TrimSpace(actor),
		Reason:   strings.TrimSpace(reason),
		TsUnixMs: ts,
	}, nil
}

func (r *roeRuntime) getRun(key string, result stepResult) (runRecord, error) {
	entry, err := r.runsKV.Get(key)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return runRecord{
				RunID:           result.RunID,
				Lane:            result.Lane,
				Status:          "RUNNING",
				CreatedAtUnixMs: time.Now().UnixMilli(),
				StepStatuses:    make(map[string]string),
			}, nil
		}
		return runRecord{}, err
	}
	var run runRecord
	if err := json.Unmarshal(entry.Value(), &run); err != nil {
		return runRecord{}, err
	}
	if run.StepStatuses == nil {
		run.StepStatuses = make(map[string]string)
	}
	return run, nil
}

func (r *roeRuntime) loadRun(key string) (runRecord, bool, error) {
	entry, err := r.runsKV.Get(key)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return runRecord{}, false, nil
		}
		return runRecord{}, false, err
	}
	var run runRecord
	if err := json.Unmarshal(entry.Value(), &run); err != nil {
		return runRecord{}, false, err
	}
	if run.StepStatuses == nil {
		run.StepStatuses = make(map[string]string)
	}
	return run, true, nil
}

func updateRunWithResult(run *runRecord, result stepResult) {
	now := time.Now().UnixMilli()
	if run.StepStatuses == nil {
		run.StepStatuses = make(map[string]string)
	}
	if strings.TrimSpace(run.ApprovalActor) == "" && strings.TrimSpace(result.Actor) != "" {
		run.ApprovalActor = result.Actor
	}
	if strings.TrimSpace(run.Target) == "" && strings.TrimSpace(result.Target) != "" {
		run.Target = result.Target
	}
	run.StepStatuses[result.StepID] = result.Status
	if result.Status == "FAILED_SAFE" {
		run.FailedSafeReason = classifyFailedSafeReason(result)
	}
	run.LastUpdatedAtUnixMs = now
	recomputeRunCounts(run)
}

func classifyFailedSafeReason(result stepResult) string {
	switch result.Status {
	case "FAILED_SAFE":
		if result.StepIndex > 0 {
			return "rollback_step_failed"
		}
		return "step_failed_safe"
	default:
		return ""
	}
}

func (r *roeRuntime) reconcileRunProgress(run *runRecord) error {
	if run == nil {
		return nil
	}
	steps, err := r.loadPlannedSteps(run.RunID)
	if err != nil {
		return err
	}
	if len(steps) > 0 {
		run.StepTotal = len(steps)
	}
	if run.StepStatuses == nil {
		run.StepStatuses = make(map[string]string, len(steps))
	}
	for _, step := range steps {
		if _, ok := run.StepStatuses[step.StepID]; ok {
			continue
		}
		resultKey := fmt.Sprintf("result.%s.%s", run.RunID, step.StepID)
		entry, err := r.resultsKV.Get(resultKey)
		if err != nil {
			if errors.Is(err, nats.ErrKeyNotFound) {
				continue
			}
			return err
		}
		var rec map[string]any
		if err := json.Unmarshal(entry.Value(), &rec); err != nil {
			return err
		}
		status := strings.TrimSpace(stringFieldRaw(rec, "status"))
		if status == "" {
			continue
		}
		run.StepStatuses[step.StepID] = status
	}
	recomputeRunCounts(run)
	run.LastUpdatedAtUnixMs = time.Now().UnixMilli()
	return nil
}

func recomputeRunCounts(run *runRecord) {
	succeeded := 0
	failedSafe := 0
	failedTransient := 0
	for _, status := range run.StepStatuses {
		switch status {
		case "SUCCEEDED":
			succeeded++
		case "FAILED_SAFE":
			failedSafe++
		case "FAILED_TRANSIENT":
			failedTransient++
		}
	}
	run.StepSucceededCount = succeeded
	run.StepFailedSafeCount = failedSafe
	run.StepFailedTransientCount = failedTransient
	if failedSafe > 0 {
		run.Status = "FAILED_SAFE"
		if strings.TrimSpace(run.FailedSafeReason) == "" {
			run.FailedSafeReason = "step_failed_safe"
		}
		return
	}
	run.FailedSafeReason = ""
	if run.StepTotal > 0 && succeeded >= run.StepTotal {
		run.Status = "SUCCEEDED"
		return
	}
	if failedTransient > 0 {
		run.Status = "FAILED_TRANSIENT"
		return
	}
	run.Status = "RUNNING"
}

func stringFieldRaw(raw map[string]any, key string) string {
	if raw == nil {
		return ""
	}
	val, ok := raw[key]
	if !ok {
		return ""
	}
	str, ok := val.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(str)
}

func int64Field(raw map[string]any, key string) (int64, bool) {
	val, ok := raw[key]
	if !ok {
		return 0, false
	}
	switch v := val.(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, true
		}
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	}
	return 0, false
}

func uint64Field(raw map[string]any, key string) (uint64, bool) {
	val, ok := raw[key]
	if !ok {
		return 0, false
	}
	switch v := val.(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil && i >= 0 {
			return uint64(i), true
		}
	case float64:
		if v >= 0 {
			return uint64(v), true
		}
	case int64:
		if v >= 0 {
			return uint64(v), true
		}
	case int:
		if v >= 0 {
			return uint64(v), true
		}
	}
	return 0, false
}

func selectPlaybook(playbooks []roePlaybook, ruleID string) (roePlaybook, bool) {
	trimmed := strings.TrimSpace(ruleID)
	for _, pb := range playbooks {
		if !pb.Enabled {
			continue
		}
		for _, id := range pb.Selectors.RuleIDs {
			if strings.TrimSpace(id) == trimmed {
				return pb, true
			}
		}
	}
	return roePlaybook{}, false
}

func (r *roeRuntime) persistRun(key string, run runRecord) error {
	payload, err := json.Marshal(run)
	if err != nil {
		return err
	}
	_, err = r.runsKV.Put(key, payload)
	return err
}

func (r *roeRuntime) persistIdempotency(trigger responseTrigger, runID string, playbook roePlaybook) error {
	record := map[string]any{
		"run_id":             runID,
		"created_at_unix_ms": trigger.ObservedAtUnixMs,
		"lane":               trigger.Lane,
		"playbook_id":        playbook.ID,
		"playbook_version":   playbook.Version.Value,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = r.idempKV.Put(trigger.TriggerIdemKey, payload)
	return err
}

func (r *roeRuntime) persistResultDedupe(key string, result stepResult, jsSeq uint64) error {
	record := map[string]any{
		"run_id":              result.RunID,
		"step_id":             result.StepID,
		"status":              result.Status,
		"finished_at_unix_ms": result.FinishedAtUnixMs,
		"lane":                result.Lane,
	}
	if jsSeq > 0 {
		record["js_seq"] = jsSeq
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = r.resultsKV.Put(key, payload)
	return err
}

func (r *roeRuntime) acquireResultLock(lockKey string, result stepResult) (bool, error) {
	now := time.Now().UnixMilli()
	ttl := r.cfg.Worker.LockTTLms
	if ttl <= 0 {
		ttl = defaultResultLockTTL
	}
	entry, err := r.locksKV.Get(lockKey)
	if err == nil {
		var existing map[string]any
		if err := json.Unmarshal(entry.Value(), &existing); err == nil {
			holder := stringFieldRaw(existing, "holder_id")
			acquiredAt, _ := int64Field(existing, "acquired_at_unix_ms")
			lockTTL, ok := int64Field(existing, "ttl_ms")
			if ok && lockTTL > 0 {
				ttl = lockTTL
			}
			if holder != "" && holder != r.resultLockHolderID && acquiredAt > 0 && now-acquiredAt < ttl {
				return false, nil
			}
		}
	} else if !errors.Is(err, nats.ErrKeyNotFound) {
		return false, err
	}
	record := map[string]any{
		"holder_id":           r.resultLockHolderID,
		"step_id":             result.StepID,
		"acquired_at_unix_ms": now,
		"ttl_ms":              ttl,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return false, err
	}
	if _, err := r.locksKV.Put(lockKey, payload); err != nil {
		return false, err
	}
	return true, nil
}

func (r *roeRuntime) releaseResultLock(lockKey string, result stepResult) {
	if err := r.locksKV.Delete(lockKey); err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
		r.logger.LogAttrs(context.Background(), slog.LevelError, "roe_lock_release_failed_result",
			slog.String("error", err.Error()),
			slog.String("run_id", result.RunID),
			slog.String("step_id", result.StepID),
			slog.String("lock_key", lockKey),
		)
		return
	}
	r.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_lock_released_result",
		slog.String("run_id", result.RunID),
		slog.String("step_id", result.StepID),
		slog.String("lock_key", lockKey),
	)
}

func (r *roeRuntime) tryAcquireGroupLock(trigger responseTrigger, runID string) (bool, error) {
	if trigger.GroupBy == "" || trigger.GroupKey == "" {
		return true, nil
	}
	lockKey := fmt.Sprintf("lock.group.%s.%s", trigger.RuleID, trigger.GroupKey)
	now := time.Now().UnixMilli()
	ttl := r.cfg.Locks.GroupTTLms
	if ttl <= 0 {
		ttl = defaultGroupLockTTL
	}
	entry, err := r.locksKV.Get(lockKey)
	if err == nil {
		var existing map[string]any
		if err := json.Unmarshal(entry.Value(), &existing); err == nil {
			acquiredAt, _ := int64Field(existing, "acquired_at_unix_ms")
			if acquiredAt > 0 && now-acquiredAt < ttl {
				runtimeLogSuppressed(r.logger, trigger, runID, lockKey)
				return false, nil
			}
		}
	} else if !errors.Is(err, nats.ErrKeyNotFound) {
		return false, err
	}
	record := map[string]any{
		"run_id":              runID,
		"acquired_at_unix_ms": now,
		"ttl_ms":              ttl,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return false, err
	}
	if _, err := r.locksKV.Put(lockKey, payload); err != nil {
		return false, err
	}
	return true, nil
}

func runtimeLogSuppressed(logger *slog.Logger, trigger responseTrigger, runID, lockKey string) {
	logger.LogAttrs(context.Background(), slog.LevelInfo, "response_run_suppressed_by_lock",
		slog.String("run_id", runID),
		slog.String("rule_id", trigger.RuleID),
		slog.String("group_by", trigger.GroupBy),
		slog.String("group_key", trigger.GroupKey),
		slog.String("lock_key", lockKey),
	)
}
func (r *roeRuntime) applyAllowlist(playbook roePlaybook) error {
	allowed := r.cfg.Policies.ActionAllowlist.AllowedActionTypes
	if len(allowed) == 0 {
		return nil
	}
	allowSet := make(map[string]struct{}, len(allowed))
	for _, action := range allowed {
		allowSet[action] = struct{}{}
	}
	for _, step := range playbook.Steps {
		if _, ok := allowSet[step.ActionType]; !ok {
			return fmt.Errorf("action_not_allowed")
		}
	}
	return nil
}

func (r *roeRuntime) requiresApproval(playbook roePlaybook, severity string) bool {
	switch strings.ToLower(strings.TrimSpace(playbook.PolicyRequirements.Approval)) {
	case "required":
		return true
	case "required_for_high":
		if strings.EqualFold(severity, "high") {
			return true
		}
	case "auto":
	}
	if r.cfg.Policies.SafeMode.RequireApprovalWhenDegraded && r.degraded.Load() {
		return true
	}
	return false
}

func compileSteps(runID string, trigger responseTrigger, playbook roePlaybook) ([]stepRecord, error) {
	steps := make([]stepRecord, 0, len(playbook.Steps))
	for idx, step := range playbook.Steps {
		target := ""
		switch step.TargetFrom {
		case "global":
		case "group_key":
			if trigger.GroupKey == "" {
				return nil, fmt.Errorf("missing_group_key")
			}
			target = trigger.GroupKey
		default:
			return nil, fmt.Errorf("invalid_target_from")
		}
		params := step.Params
		if params == nil {
			params = map[string]any{}
		}
		stepID := shortHash(fmt.Sprintf("%s|%d|%s|%s", runID, idx, step.ActionType, target))
		record := stepRecord{
			StepID:      stepID,
			StepIdemKey: fmt.Sprintf("step.%s", stepID),
			RunID:       runID,
			StepIndex:   idx,
			ActionType:  step.ActionType,
			Target:      target,
			Params:      params,
			Status:      "PLANNED",
			Attempt:     0,
			Lane:        trigger.Lane,
		}
		steps = append(steps, record)
	}
	return steps, nil
}

func deriveRunTarget(trigger responseTrigger) string {
	if trimmed := strings.TrimSpace(trigger.GroupKey); trimmed != "" {
		return trimmed
	}
	if trimmed := strings.TrimSpace(trigger.AgentID); trimmed != "" {
		return "agent:" + trimmed
	}
	return ""
}

func auditActor(actor string) string {
	trimmed := strings.TrimSpace(actor)
	if trimmed == "" {
		return "system:auto"
	}
	return trimmed
}

func operatorActionForRun(run runRecord) string {
	if run.Status == "FAILED_SAFE" && run.StepSucceededCount > 0 && run.StepSucceededCount < run.StepTotal {
		return "manual_restore_check_recommended"
	}
	return ""
}

func extractRunID(data []byte) string {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return ""
	}
	val, ok := raw["run_id"]
	if !ok {
		return ""
	}
	str, ok := val.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(str)
}

func (r *roeRuntime) persistStep(step stepRecord) error {
	payload, err := json.Marshal(step)
	if err != nil {
		return err
	}
	_, err = r.stepsKV.Put(step.StepIdemKey, payload)
	return err
}

func (r *roeRuntime) publishStep(lane string, step stepRecord) (string, error) {
	subject := r.subjectStepsStandard()
	if strings.EqualFold(lane, "FAST") {
		subject = r.subjectStepsFast()
	}
	if step.Params == nil {
		step.Params = map[string]any{}
	}
	payload, err := json.Marshal(step)
	if err != nil {
		return subject, err
	}
	_, err = r.js.Publish(subject, payload)
	return subject, err
}

func (r *roeRuntime) publishApprovalRequest(run runRecord) error {
	subject := r.subjectApprovalRequests()
	payload := map[string]any{
		"run_id":               run.RunID,
		"rule_id":              run.RuleID,
		"playbook_id":          run.PlaybookID,
		"playbook_version":     run.PlaybookVersion,
		"severity":             run.Severity,
		"lane":                 run.Lane,
		"group_by":             run.GroupBy,
		"group_key":            run.GroupKey,
		"timeout_ms":           run.ApprovalTimeoutMs,
		"requested_at_unix_ms": run.ApprovalRequestedAtUnixMs,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = r.js.Publish(subject, data)
	return err
}

func shortHash(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:16]
}

func newRuntimeID(prefix string) string {
	host, _ := os.Hostname()
	pid := os.Getpid()
	return fmt.Sprintf("%s-%s-%d-%d", prefix, host, pid, time.Now().UnixNano())
}

func applyROEJetstreamDefaults(cfg *roeJetstreamConfig) {
	cfg.SubjectTriggersFast = firstNonEmpty(cfg.SubjectTriggersFast, responseTriggerFast)
	cfg.SubjectTriggersStandard = firstNonEmpty(cfg.SubjectTriggersStandard, responseTriggerStd)
	cfg.SubjectStepsFast = firstNonEmpty(cfg.SubjectStepsFast, responseStepsFast)
	cfg.SubjectStepsStandard = firstNonEmpty(cfg.SubjectStepsStandard, responseStepsStd)
	cfg.SubjectResultsFast = firstNonEmpty(cfg.SubjectResultsFast, responseResultsFast)
	cfg.SubjectResultsStandard = firstNonEmpty(cfg.SubjectResultsStandard, responseResultsStd)
	cfg.SubjectApprovals = firstNonEmpty(cfg.SubjectApprovals, responseApprovals)
	cfg.SubjectApprovalRequests = firstNonEmpty(cfg.SubjectApprovalRequests, responseApprovalRequests)
}

func applyROEKVDefaults(cfg *roeKVConfig) {
	cfg.BucketIdemp = firstNonEmpty(cfg.BucketIdemp, "RSIEM_RSP_IDEMP")
	cfg.BucketRuns = firstNonEmpty(cfg.BucketRuns, "RSIEM_RSP_RUNS")
	cfg.BucketSteps = firstNonEmpty(cfg.BucketSteps, "RSIEM_RSP_STEPS")
	cfg.BucketLocks = firstNonEmpty(cfg.BucketLocks, "RSIEM_RSP_LOCKS")
	cfg.BucketApprovals = firstNonEmpty(cfg.BucketApprovals, "RSIEM_RSP_APPROVALS")
	cfg.BucketResults = firstNonEmpty(cfg.BucketResults, "RSIEM_RSP_RESULTS")
}

func firstNonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func (r *roeRuntime) subjectTriggersFast() string {
	return r.cfg.Jetstream.SubjectTriggersFast
}

func (r *roeRuntime) subjectTriggersStandard() string {
	return r.cfg.Jetstream.SubjectTriggersStandard
}

func (r *roeRuntime) subjectStepsFast() string {
	return r.cfg.Jetstream.SubjectStepsFast
}

func (r *roeRuntime) subjectStepsStandard() string {
	return r.cfg.Jetstream.SubjectStepsStandard
}

func (r *roeRuntime) subjectResultsFast() string {
	return r.cfg.Jetstream.SubjectResultsFast
}

func (r *roeRuntime) subjectResultsStandard() string {
	return r.cfg.Jetstream.SubjectResultsStandard
}

func (r *roeRuntime) subjectApprovals() string {
	return r.cfg.Jetstream.SubjectApprovals
}

func (r *roeRuntime) subjectApprovalRequests() string {
	return r.cfg.Jetstream.SubjectApprovalRequests
}

func (r *roeRuntime) loadPlannedSteps(runID string) ([]stepRecord, error) {
	keys, err := r.stepsKV.Keys()
	if err != nil {
		if errors.Is(err, nats.ErrNoKeysFound) {
			return nil, nil
		}
		return nil, err
	}
	steps := make([]stepRecord, 0)
	for _, key := range keys {
		if strings.Count(key, ".") != 1 || !strings.HasPrefix(key, "step.") {
			continue
		}
		entry, err := r.stepsKV.Get(key)
		if err != nil {
			return nil, err
		}
		var step stepRecord
		if err := json.Unmarshal(entry.Value(), &step); err != nil {
			return nil, err
		}
		if step.RunID != runID {
			continue
		}
		steps = append(steps, step)
	}
	sort.Slice(steps, func(i, j int) bool {
		return steps[i].StepIndex < steps[j].StepIndex
	})
	return steps, nil
}

func (r *roeRuntime) exportRunUpdate(run runRecord) error {
	if r.resultsExport == nil {
		return nil
	}
	obj := map[string]any{
		"msg":                         "response_run_updated",
		"run_id":                      run.RunID,
		"status":                      run.Status,
		"step_total":                  run.StepTotal,
		"step_succeeded_count":        run.StepSucceededCount,
		"step_failed_safe_count":      run.StepFailedSafeCount,
		"step_failed_transient_count": run.StepFailedTransientCount,
		"last_updated_at_unix_ms":     run.LastUpdatedAtUnixMs,
		"actor":                       auditActor(run.ApprovalActor),
	}
	if strings.TrimSpace(run.Target) != "" {
		obj["target"] = strings.TrimSpace(run.Target)
	}
	if strings.TrimSpace(run.FailedSafeReason) != "" {
		obj["failed_safe_reason"] = run.FailedSafeReason
	}
	if action := operatorActionForRun(run); action != "" {
		obj["operator_action"] = action
	}
	return r.resultsExport.WriteJSON(obj)
}

func scanForApprovalTimeouts(runtime *roeRuntime, limit int) error {
	keys, err := runtime.runsKV.Keys()
	if err != nil {
		if errors.Is(err, nats.ErrNoKeysFound) {
			return nil
		}
		return err
	}
	now := time.Now().UnixMilli()
	checked := 0
	for _, key := range keys {
		if !strings.HasPrefix(key, "run.") {
			continue
		}
		if limit > 0 && checked >= limit {
			continue
		}
		checked++
		entry, err := runtime.runsKV.Get(key)
		if err != nil {
			return err
		}
		var run runRecord
		if err := json.Unmarshal(entry.Value(), &run); err != nil {
			return err
		}
		if run.Status != "WAITING_APPROVAL" {
			continue
		}
		timeoutMs := run.ApprovalTimeoutMs
		if timeoutMs <= 0 {
			timeoutMs = runtime.cfg.Policies.Approvals.TimeoutMs
		}
		if timeoutMs <= 0 {
			timeoutMs = defaultApprovalTimeoutMs
		}
		if run.ApprovalRequestedAtUnixMs <= 0 || now <= run.ApprovalRequestedAtUnixMs+timeoutMs {
			continue
		}
		run.Status = "FAILED_SAFE"
		run.FailedSafeReason = "approval_timeout"
		run.ApprovalDecision = "timeout"
		run.ApprovalDecidedAtUnixMs = now
		run.LastUpdatedAtUnixMs = now
		if err := runtime.persistRun(key, run); err != nil {
			return err
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "approval_timed_out",
			slog.String("run_id", run.RunID),
		)
		if runtime.approvalsExport != nil {
			if err := runtime.approvalsExport.Write("approval_timed_out", map[string]any{
				"run_id": run.RunID,
			}); err != nil {
				return err
			}
		}
		if err := runtime.exportRunUpdate(run); err != nil {
			return err
		}
	}
	return nil
}

func newRoeJournal(logger *slog.Logger, cfg roeExportTarget) (*roeJournal, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	required := true
	flush := true
	if cfg.Required != nil {
		required = *cfg.Required
	}
	if cfg.Flush != nil {
		flush = *cfg.Flush
	}
	cfg.Required = &required
	cfg.Flush = &flush
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, fmt.Errorf("export path required")
	}
	dir := filepath.Dir(cfg.Path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &roeJournal{
		logger: logger,
		cfg:    cfg,
		file:   file,
	}, nil
}

func newRoeResultsExporter(logger *slog.Logger, cfg roeExportConfig) (*roeResultsExporter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	required := false
	flush := true
	if cfg.Required != nil {
		required = *cfg.Required
	}
	if cfg.Flush != nil {
		flush = *cfg.Flush
	}
	if strings.TrimSpace(cfg.RunsPath) == "" {
		cfg.RunsPath = "exports/roe_runs.jsonl"
	}
	dir := filepath.Dir(cfg.RunsPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(cfg.RunsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	cfg.Required = &required
	cfg.Flush = &flush
	return &roeResultsExporter{
		logger: logger,
		cfg:    cfg,
		file:   file,
	}, nil
}

func (j *roeJournal) Close() {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file != nil {
		_ = j.file.Close()
		j.file = nil
	}
}

func (e *roeResultsExporter) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file != nil {
		_ = e.file.Close()
		e.file = nil
	}
}

func (e *roeResultsExporter) WriteJSON(obj map[string]any) error {
	if e == nil || !e.cfg.Enabled {
		return nil
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return e.handleError(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.file.Write(append(data, '\n')); err != nil {
		return e.handleError(err)
	}
	flush := true
	if e.cfg.Flush != nil {
		flush = *e.cfg.Flush
	}
	if flush {
		if err := e.file.Sync(); err != nil {
			return e.handleError(err)
		}
	}
	return nil
}

func (e *roeResultsExporter) handleError(err error) error {
	e.logger.LogAttrs(context.Background(), slog.LevelError, "roe_export_error", slog.String("error", err.Error()))
	required := false
	if e.cfg.Required != nil {
		required = *e.cfg.Required
	}
	if required {
		return err
	}
	return nil
}

func (j *roeJournal) Write(msg string, payload any) error {
	if j == nil || !j.cfg.Enabled {
		return nil
	}
	record := map[string]any{
		"msg": msg,
	}
	if payload != nil {
		record["payload"] = payload
	}
	data, err := json.Marshal(record)
	if err != nil {
		return j.handleError(err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := j.file.Write(append(data, '\n')); err != nil {
		return j.handleError(err)
	}
	flush := true
	if j.cfg.Flush != nil {
		flush = *j.cfg.Flush
	}
	if flush {
		if err := j.file.Sync(); err != nil {
			return j.handleError(err)
		}
	}
	return nil
}

func (j *roeJournal) handleError(err error) error {
	j.logger.LogAttrs(context.Background(), slog.LevelError, "roe_export_error", slog.String("error", err.Error()))
	required := true
	if j.cfg.Required != nil {
		required = *j.cfg.Required
	}
	if required {
		return err
	}
	return nil
}

func newROEDBSink(logger *slog.Logger, cfg config.MasterDBConfig) (*roeDBSink, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	db, err := sql.Open("postgres", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	sink := &roeDBSink{
		logger: logger,
		cfg:    cfg,
		db:     db,
	}
	if err := sink.ensureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ensure db schema: %w", err)
	}
	return sink, nil
}

func (s *roeDBSink) Close() {
	if s == nil || s.db == nil {
		return
	}
	_ = s.db.Close()
}

func (s *roeDBSink) ensureSchema(ctx context.Context) error {
	schemaSQL := `
CREATE TABLE IF NOT EXISTS normalized_events (
  id BIGSERIAL PRIMARY KEY,
  ingest_ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  event_ts_unix_ms BIGINT NOT NULL,
  recv_ts_unix_ms BIGINT NOT NULL,
  node_id TEXT NOT NULL,
  source_type TEXT NOT NULL,
  event_type TEXT NOT NULL,
  src_ip INET NULL,
  user_name TEXT NULL,
  severity TEXT NULL,
  rule_id TEXT NULL,
  event_idem_key TEXT NOT NULL,
  raw_line_sha256 TEXT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS normalized_events_event_idem_key_uidx ON normalized_events(event_idem_key);
CREATE INDEX IF NOT EXISTS normalized_events_event_ts_idx ON normalized_events(event_ts_unix_ms);
CREATE INDEX IF NOT EXISTS normalized_events_node_id_idx ON normalized_events(node_id);
`
	_, err := s.db.ExecContext(ctx, schemaSQL)
	return err
}

func (s *roeDBSink) Insert(rec roeDBRecord) error {
	if s == nil || s.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const q = `
INSERT INTO normalized_events (
  event_ts_unix_ms, recv_ts_unix_ms, node_id, source_type, event_type,
  src_ip, user_name, severity, rule_id, event_idem_key, raw_line_sha256
) VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::inet,NULLIF($7,''),$8,$9,$10,$11)
ON CONFLICT (event_idem_key) DO NOTHING;
`
	_, err := s.db.ExecContext(ctx, q,
		rec.EventTsUnixMs,
		rec.RecvTsUnixMs,
		rec.NodeID,
		rec.SourceType,
		rec.EventType,
		rec.SrcIP,
		rec.UserName,
		rec.Severity,
		rec.RuleID,
		rec.EventIdemKey,
		rec.RawLineSHA256,
	)
	if err == nil {
		return nil
	}
	if s.cfg.FailClosed {
		return err
	}
	s.logger.LogAttrs(context.Background(), slog.LevelWarn, "db_insert_failed",
		slog.String("error", err.Error()),
		slog.String("event_idem_key", rec.EventIdemKey),
	)
	return nil
}

func (r *roeRuntime) persistNormalizedEvent(trigger responseTrigger, raw []byte) error {
	if r.dbSink == nil {
		return nil
	}
	rec := buildROEDBRecord(trigger, raw)
	if err := r.dbSink.Insert(rec); err != nil {
		r.logger.LogAttrs(context.Background(), slog.LevelError, "db_insert_failed",
			slog.String("error", err.Error()),
			slog.String("event_idem_key", rec.EventIdemKey),
		)
		return err
	}
	return nil
}

func buildROEDBRecord(trigger responseTrigger, raw []byte) roeDBRecord {
	nowMs := time.Now().UnixMilli()
	eventTs := trigger.EventTsUnixMs
	if eventTs <= 0 {
		eventTs = trigger.ObservedAtUnixMs
	}
	if eventTs <= 0 {
		eventTs = nowMs
	}
	recvTs := trigger.ObservedAtUnixMs
	if recvTs <= 0 {
		recvTs = nowMs
	}
	nodeID := strings.TrimSpace(trigger.AgentID)
	if nodeID == "" {
		nodeID = "unknown"
	}
	sourceType := strings.TrimSpace(trigger.SourceType)
	if sourceType == "" {
		sourceType = deriveSourceType(trigger.RuleID)
	}
	eventType := strings.TrimSpace(trigger.EventType)
	if eventType == "" {
		eventType = deriveEventType(sourceType, trigger.RuleID)
	}
	eventID := strings.TrimSpace(trigger.TriggerIdemKey)
	if eventID == "" {
		eventID = shortHash(fmt.Sprintf("%s|%s|%d", trigger.AlertKey, trigger.RuleID, recvTs))
	}
	rawHash := sha256.Sum256(raw)
	return roeDBRecord{
		EventTsUnixMs: eventTs,
		RecvTsUnixMs:  recvTs,
		NodeID:        nodeID,
		SourceType:    sourceType,
		EventType:     eventType,
		SrcIP:         strings.TrimSpace(trigger.SrcIP),
		UserName:      strings.TrimSpace(trigger.UserName),
		Severity:      strings.TrimSpace(trigger.Severity),
		RuleID:        strings.TrimSpace(trigger.RuleID),
		EventIdemKey:  eventID,
		RawLineSHA256: hex.EncodeToString(rawHash[:]),
	}
}

func deriveSourceType(ruleID string) string {
	id := strings.ToUpper(strings.TrimSpace(ruleID))
	switch {
	case strings.Contains(id, "DECEPTION"), strings.Contains(id, "HONEYPOT"):
		return "deception"
	case strings.Contains(id, "NETWORK"), strings.Contains(id, "C2"), strings.Contains(id, "EXFIL"):
		return "network"
	default:
		return "host"
	}
}

func deriveEventType(sourceType, ruleID string) string {
	st := strings.ToLower(strings.TrimSpace(sourceType))
	switch st {
	case "deception":
		return "deception_tripwire"
	case "network":
		return "network_alert"
	}
	id := strings.ToUpper(strings.TrimSpace(ruleID))
	if strings.Contains(id, "FAILED-PW") || strings.Contains(id, "INVALID-USER") || strings.Contains(id, "BRUTEFORCE") {
		return "auth_failed"
	}
	return "response_trigger"
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
	}()
	return ctx, cancel
}
