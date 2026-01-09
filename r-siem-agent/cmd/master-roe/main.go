package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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
	ActionType string `yaml:"action_type"`
	TargetFrom string `yaml:"target_from"`
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
	Runs     roeExportTarget `yaml:"runs"`
	Steps    roeExportTarget `yaml:"steps"`
	Enabled  bool            `yaml:"enabled"`
	Required *bool           `yaml:"required"`
	RunsPath string          `yaml:"runs_path"`
	Flush    *bool           `yaml:"flush"`
}

type roeConfig struct {
	Workers       roeWorkersConfig       `yaml:"workers"`
	DispatchQueue roeDispatchQueueConfig `yaml:"dispatch_queue"`
	Playbooks     []roePlaybook          `yaml:"playbooks"`
	Policies      roePolicies            `yaml:"policies"`
	Export        roeExportConfig        `yaml:"export"`
}

type roeConfigWrapper struct {
	ROE       *roeConfig    `yaml:"roe"`
	Playbooks []roePlaybook `yaml:"playbooks"`
}

type responseTrigger struct {
	TriggerIdemKey   string
	AlertKey         string
	RuleID           string
	RuleKind         string
	Severity         string
	Lane             string
	GroupBy          string
	GroupKey         string
	AgentID          string
	ObservedAtUnixMs int64
	Stream           string
	Consumer         string
	Subject          string
	JSSeq            *uint64
	BatchKey         string
}

type runRecord struct {
	RunID                    string            `json:"run_id"`
	TriggerIdemKey           string            `json:"trigger_idem_key"`
	AlertKey                 string            `json:"alert_key"`
	RuleID                   string            `json:"rule_id"`
	RuleKind                 string            `json:"rule_kind"`
	Severity                 string            `json:"severity"`
	Lane                     string            `json:"lane"`
	GroupBy                  string            `json:"group_by,omitempty"`
	GroupKey                 string            `json:"group_key,omitempty"`
	PlaybookID               string            `json:"playbook_id"`
	PlaybookVersion          string            `json:"playbook_version"`
	Status                   string            `json:"status"`
	CreatedAtUnixMs          int64             `json:"created_at_unix_ms"`
	CurrentStepIndex         int               `json:"current_step_index"`
	StepTotal                int               `json:"step_total"`
	StepSucceededCount       int               `json:"step_succeeded_count"`
	StepFailedSafeCount      int               `json:"step_failed_safe_count"`
	StepFailedTransientCount int               `json:"step_failed_transient_count"`
	LastUpdatedAtUnixMs      int64             `json:"last_updated_at_unix_ms"`
	StepStatuses             map[string]string `json:"step_statuses,omitempty"`
}

type stepRecord struct {
	StepID      string `json:"step_id"`
	StepIdemKey string `json:"step_idem_key"`
	RunID       string `json:"run_id"`
	StepIndex   int    `json:"step_index"`
	ActionType  string `json:"action_type"`
	Target      string `json:"target,omitempty"`
	Status      string `json:"status"`
	Attempt     int    `json:"attempt"`
	Lane        string `json:"lane"`
}

type stepResult struct {
	RunID            string         `json:"run_id"`
	StepID           string         `json:"step_id"`
	StepIndex        int            `json:"step_index"`
	ActionType       string         `json:"action_type"`
	Lane             string         `json:"lane"`
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
	logger          *slog.Logger
	js              nats.JetStreamContext
	cfg             roeConfig
	idempKV         nats.KeyValue
	runsKV          nats.KeyValue
	stepsKV         nats.KeyValue
	degraded        atomic.Bool
	dispatchSize    int
	dispatchHighPct int
	dispatchLowPct  int
	resultsExport   *roeResultsExporter
}

const (
	responseStream       = "RSIEM_RESPONSE"
	responseTriggerFast  = "rsiem.response.triggers.fast"
	responseTriggerStd   = "rsiem.response.triggers.standard"
	responseStepsFast    = "rsiem.response.steps.fast"
	responseStepsStd     = "rsiem.response.steps.standard"
	responseResultsFast  = "rsiem.response.results.fast"
	responseResultsStd   = "rsiem.response.results.standard"
	defaultWorkers       = 1
	defaultPullBatch     = 10
	defaultPullTimeoutMs = 500
	defaultQueueSize     = 1024
	defaultHighPct       = 80
	defaultLowPct        = 50
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

	if err := ensureResponseStream(js); err != nil {
		logger.Error("ensure_response_stream_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logStreamInfo(logger, js)

	idempKV, err := ensureKV(js, "RSIEM_RSP_IDEMP")
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_IDEMP"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	runsKV, err := ensureKV(js, "RSIEM_RSP_RUNS")
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_RUNS"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	stepsKV, err := ensureKV(js, "RSIEM_RSP_STEPS")
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_STEPS"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	_, err = ensureKV(js, "RSIEM_RSP_LOCKS")
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_LOCKS"), slog.String("error", err.Error()))
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

	runtime := &roeRuntime{
		logger:          logger,
		js:              js,
		cfg:             roeCfg,
		idempKV:         idempKV,
		runsKV:          runsKV,
		stepsKV:         stepsKV,
		dispatchSize:    roeCfg.DispatchQueue.Size,
		dispatchHighPct: roeCfg.DispatchQueue.DegradeHighWatermark,
		dispatchLowPct:  roeCfg.DispatchQueue.DegradeLowWatermark,
		resultsExport:   resultsExporter,
	}

	ctx, cancel := signalContext()
	defer cancel()

	fastQueue := make(chan *nats.Msg, roeCfg.DispatchQueue.Size)
	standardQueue := make(chan *nats.Msg, roeCfg.DispatchQueue.Size)
	resultsFastQueue := make(chan *nats.Msg, roeCfg.DispatchQueue.Size)
	resultsStandardQueue := make(chan *nats.Msg, roeCfg.DispatchQueue.Size)

	if err := ensureConsumer(js, responseStream, responseTriggerFast, "roe-trig-fast"); err != nil {
		logger.Error("ensure_consumer_failed", slog.String("lane", "FAST"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := ensureConsumer(js, responseStream, responseTriggerStd, "roe-trig-standard"); err != nil {
		logger.Error("ensure_consumer_failed", slog.String("lane", "STANDARD"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := ensureConsumer(js, responseStream, responseResultsFast, "roe-results-fast"); err != nil {
		logger.Error("ensure_consumer_failed", slog.String("lane", "FAST"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := ensureConsumer(js, responseStream, responseResultsStd, "roe-results-standard"); err != nil {
		logger.Error("ensure_consumer_failed", slog.String("lane", "STANDARD"), slog.String("error", err.Error()))
		os.Exit(1)
	}

	fastSub, err := js.PullSubscribe(responseTriggerFast, "roe-trig-fast", nats.BindStream(responseStream))
	if err != nil {
		logger.Error("subscribe_failed", slog.String("lane", "FAST"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	standardSub, err := js.PullSubscribe(responseTriggerStd, "roe-trig-standard", nats.BindStream(responseStream))
	if err != nil {
		logger.Error("subscribe_failed", slog.String("lane", "STANDARD"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	resultsFastSub, err := js.PullSubscribe(responseResultsFast, "roe-results-fast", nats.BindStream(responseStream))
	if err != nil {
		logger.Error("subscribe_failed", slog.String("lane", "FAST"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	resultsStandardSub, err := js.PullSubscribe(responseResultsStd, "roe-results-standard", nats.BindStream(responseStream))
	if err != nil {
		logger.Error("subscribe_failed", slog.String("lane", "STANDARD"), slog.String("error", err.Error()))
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
		runFetchLoop(ctx, runtime, resultsFastSub, "FAST", resultsFastQueue, nil)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		runFetchLoop(ctx, runtime, resultsStandardSub, "STANDARD", resultsStandardQueue, runtime)
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

	wg.Wait()
	logger.Info("master_roe_stopped")
}

func loadROEConfig(path string) (roeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return roeConfig{}, fmt.Errorf("read config: %w", err)
	}
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
		cfg.Policies.Approvals.TimeoutMs = 60000
	}
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

func ensureResponseStream(js nats.JetStreamContext) error {
	required := []string{
		responseTriggerFast,
		responseTriggerStd,
		responseStepsFast,
		responseStepsStd,
		responseResultsFast,
		responseResultsStd,
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
	cfg := info.Config
	cfg.Subjects = merged
	_, err = js.UpdateStream(&cfg)
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
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-queue:
			if msg == nil {
				continue
			}
			if err := processResult(runtime, msg, lane); err != nil {
				runtime.logger.Error("roe_result_process_failed", slog.String("lane", lane), slog.String("error", err.Error()))
				continue
			}
			if err := msg.Ack(); err != nil {
				runtime.logger.Error("roe_result_ack_failed", slog.String("lane", lane), slog.String("error", err.Error()))
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
		PlaybookID:      playbook.ID,
		PlaybookVersion: playbook.Version.Value,
		Status:          "CREATED",
		CreatedAtUnixMs: trigger.ObservedAtUnixMs,
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
		if err := runtime.persistRun(runKey, run); err != nil {
			return err
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelWarn, "response_run_rejected",
			slog.String("run_id", runID),
			slog.String("reason", err.Error()),
		)
		return nil
	}

	requiresApproval := runtime.requiresApproval(playbook, trigger.Severity)
	if requiresApproval {
		run.Status = "WAITING_APPROVAL"
		if err := runtime.persistRun(runKey, run); err != nil {
			return err
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "approval_requested",
			slog.String("run_id", runID),
			slog.String("rule_id", trigger.RuleID),
			slog.String("playbook_id", playbook.ID),
			slog.String("playbook_version", playbook.Version.Value),
			slog.Int64("timeout_ms", runtime.cfg.Policies.Approvals.TimeoutMs),
		)
		return nil
	}

	steps, err := compileSteps(runID, trigger, playbook)
	if err != nil {
		run.Status = "FAILED_SAFE"
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

	for _, step := range steps {
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

	runKey := fmt.Sprintf("run.%s", result.RunID)
	run, err := runtime.getRun(runKey, result)
	if err != nil {
		return err
	}
	prevStatus := run.Status
	updateRunWithResult(&run, result)
	if err := runtime.persistRun(runKey, run); err != nil {
		return err
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_run_updated",
		slog.String("run_id", run.RunID),
		slog.String("status", run.Status),
		slog.Int("step_succeeded_count", run.StepSucceededCount),
		slog.Int("step_failed_safe_count", run.StepFailedSafeCount),
		slog.Int("step_failed_transient_count", run.StepFailedTransientCount),
	)
	if run.Status == "SUCCEEDED" && prevStatus != "SUCCEEDED" {
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_run_succeeded",
			slog.String("run_id", run.RunID),
		)
	}
	if run.Status == "FAILED_SAFE" && prevStatus != "FAILED_SAFE" {
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "response_run_failed_safe",
			slog.String("run_id", run.RunID),
		)
	}
	if runtime.resultsExport != nil {
		obj := map[string]any{
			"msg":                         "response_run_updated",
			"run_id":                      run.RunID,
			"status":                      run.Status,
			"step_total":                  run.StepTotal,
			"step_succeeded_count":        run.StepSucceededCount,
			"step_failed_safe_count":      run.StepFailedSafeCount,
			"step_failed_transient_count": run.StepFailedTransientCount,
			"last_updated_at_unix_ms":     run.LastUpdatedAtUnixMs,
		}
		if err := runtime.resultsExport.WriteJSON(obj); err != nil {
			return err
		}
	}
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
	result.Status = strings.TrimSpace(result.Status)
	if result.RunID == "" || result.StepID == "" || result.Status == "" {
		return stepResult{}, fmt.Errorf("missing required fields")
	}
	return result, nil
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

func updateRunWithResult(run *runRecord, result stepResult) {
	now := time.Now().UnixMilli()
	prev, hasPrev := run.StepStatuses[result.StepID]
	if hasPrev {
		decrementCount(run, prev)
	}
	run.StepStatuses[result.StepID] = result.Status
	incrementCount(run, result.Status)
	run.LastUpdatedAtUnixMs = now
	if run.StepFailedSafeCount > 0 {
		run.Status = "FAILED_SAFE"
		return
	}
	if run.StepTotal > 0 && run.StepSucceededCount >= run.StepTotal {
		run.Status = "SUCCEEDED"
		return
	}
	if run.StepFailedTransientCount > 0 {
		run.Status = "FAILED_TRANSIENT"
		return
	}
	run.Status = "RUNNING"
}

func incrementCount(run *runRecord, status string) {
	switch status {
	case "SUCCEEDED":
		run.StepSucceededCount++
	case "FAILED_SAFE":
		run.StepFailedSafeCount++
	case "FAILED_TRANSIENT":
		run.StepFailedTransientCount++
	}
}

func decrementCount(run *runRecord, status string) {
	switch status {
	case "SUCCEEDED":
		if run.StepSucceededCount > 0 {
			run.StepSucceededCount--
		}
	case "FAILED_SAFE":
		if run.StepFailedSafeCount > 0 {
			run.StepFailedSafeCount--
		}
	case "FAILED_TRANSIENT":
		if run.StepFailedTransientCount > 0 {
			run.StepFailedTransientCount--
		}
	}
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
	if strings.EqualFold(playbook.PolicyRequirements.Approval, "required_for_high") && strings.EqualFold(severity, "high") {
		return true
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
		stepID := shortHash(fmt.Sprintf("%s|%d|%s|%s", runID, idx, step.ActionType, target))
		record := stepRecord{
			StepID:      stepID,
			StepIdemKey: fmt.Sprintf("step.%s", stepID),
			RunID:       runID,
			StepIndex:   idx,
			ActionType:  step.ActionType,
			Target:      target,
			Status:      "PLANNED",
			Attempt:     0,
			Lane:        trigger.Lane,
		}
		steps = append(steps, record)
	}
	return steps, nil
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
	subject := responseStepsStd
	if lane == "FAST" {
		subject = responseStepsFast
	}
	payload, err := json.Marshal(step)
	if err != nil {
		return subject, err
	}
	_, err = r.js.Publish(subject, payload)
	return subject, err
}

func shortHash(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:16]
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
