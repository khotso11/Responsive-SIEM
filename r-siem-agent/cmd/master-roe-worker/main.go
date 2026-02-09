package main

import (
	"bufio"
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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"gopkg.in/yaml.v3"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
	"r-siem-agent/internal/roe/connectors"
)

const (
	responseStream       = "RSIEM_RESPONSE"
	responseStepsFast    = "rsiem.response.steps.fast"
	responseStepsStd     = "rsiem.response.steps.standard"
	responseResultsFast  = "rsiem.response.results.fast"
	responseResultsStd   = "rsiem.response.results.standard"
	defaultFastWorkers   = 1
	defaultStdWorkers    = 1
	defaultPullBatch     = 10
	defaultPullTimeoutMs = 500
	defaultMaxInflight   = 100
	defaultMaxAttempts   = 3
	defaultBaseBackoffMs = 250
	defaultMaxBackoffMs  = 2000
	defaultDegradePct    = 80
	defaultLockTTLms     = int64(30000)
)

type roeWorkerConfig struct {
	FastWorkers             int                 `yaml:"fast_workers"`
	StandardWorkers         int                 `yaml:"standard_workers"`
	PullBatch               int                 `yaml:"pull_batch"`
	PullTimeoutMs           int                 `yaml:"pull_timeout_ms"`
	MaxInflight             int                 `yaml:"max_inflight"`
	MaxAttempts             int                 `yaml:"max_attempts"`
	BaseBackoffMs           int64               `yaml:"base_backoff_ms"`
	MaxBackoffMs            int64               `yaml:"max_backoff_ms"`
	DegradeHighWatermarkPct int                 `yaml:"degrade_high_watermark_pct"`
	LockTTLms               int64               `yaml:"lock_ttl_ms"`
	FailureInject           failureInjectConfig `yaml:"failure_inject"`
	Export                  workerExportConfig  `yaml:"export"`
	AllowedActionTypes      []string            `yaml:"-"`
}

type failureInjectConfig struct {
	Enabled bool `yaml:"enabled"`
	EveryN  int  `yaml:"every_n"`
}

type workerExportConfig struct {
	Enabled         bool   `yaml:"enabled"`
	Required        *bool  `yaml:"required"`
	StepsPath       string `yaml:"steps_path"`
	StepsLatestPath string `yaml:"steps_latest_path"`
	Flush           *bool  `yaml:"flush"`
}

type roeWorkerConfigWrapper struct {
	ROE struct {
		Worker   roeWorkerConfig `yaml:"worker"`
		Policies struct {
			ActionAllowlist struct {
				AllowedActionTypes []string `yaml:"allowed_action_types"`
			} `yaml:"action_allowlist"`
		} `yaml:"policies"`
	} `yaml:"roe"`
}

type stepMessage struct {
	RunID           string         `json:"run_id"`
	StepID          string         `json:"step_id"`
	StepIndex       int            `json:"step_index"`
	ActionType      string         `json:"action_type"`
	Lane            string         `json:"lane"`
	StepIdemKey     string         `json:"step_idem_key"`
	Attempt         int            `json:"attempt"`
	Target          string         `json:"target"`
	Params          map[string]any `json:"params,omitempty"`
	PlannedAtUnixMs int64          `json:"planned_at_unix_ms"`
	EmittedAtUnixMs int64          `json:"emitted_at_unix_ms"`
	Retries         *int           `json:"retries,omitempty"`
	BackoffMs       *int64         `json:"backoff_ms,omitempty"`
	BackoffMaxMs    *int64         `json:"backoff_max_ms,omitempty"`
	TimeoutMs       *int64         `json:"timeout_ms,omitempty"`
}

type stepState struct {
	Status            string         `json:"status"`
	Attempt           int            `json:"attempt"`
	LastError         string         `json:"last_error,omitempty"`
	StartedAtUnixMs   int64          `json:"started_at_unix_ms,omitempty"`
	FinishedAtUnixMs  int64          `json:"finished_at_unix_ms,omitempty"`
	NextRetryAtUnixMs int64          `json:"next_retry_at_unix_ms,omitempty"`
	Receipt           map[string]any `json:"receipt,omitempty"`
	RunID             string         `json:"run_id"`
	StepID            string         `json:"step_id"`
	StepIndex         int            `json:"step_index"`
	ActionType        string         `json:"action_type"`
	Lane              string         `json:"lane"`
}

type workerRuntime struct {
	logger     *slog.Logger
	js         nats.JetStreamContext
	kv         nats.KeyValue
	resultsKV  nats.KeyValue
	lockKV     nats.KeyValue
	cfg        roeWorkerConfig
	inflight   atomic.Int64
	degraded   atomic.Bool
	execCount  atomic.Int64
	testFailKV bool
	exporter   *workerExporter
	workerID   string
	connectors *connectors.Manager
	allowlist  map[string]struct{}
	exitFunc   func(int)
	failpoint  workerFailpoint
	failpointTriggered atomic.Bool
	publishResultPayloadOverride func([]byte) error
	executeConnectorOverride     func(context.Context, connectors.Connector, stepMessage) (map[string]any, error)
}

type workerExporter struct {
	logger *slog.Logger
	cfg    workerExportConfig
	mu     sync.Mutex
	file   *os.File
	latest map[string]latestRecord
	seq    int64
}

type latestRecord struct {
	finishedAt int64
	seq        int64
	payload    []byte
}

type workerFailpoint struct {
	enabled bool
	stage   string
	runID   string
	stepID  string
	once    bool
}
func main() {
	configPath := flag.String("config", "configs/master.yaml", "Path to master config")
	laneMode := flag.String("lane", "BOTH", "Lane mode: FAST, STANDARD, or BOTH")
	flag.Parse()

	lane := strings.ToUpper(strings.TrimSpace(*laneMode))
	if lane == "" {
		lane = "BOTH"
	}
	switch lane {
	case "FAST", "STANDARD", "BOTH":
	default:
		fmt.Fprintf(os.Stderr, "invalid -lane value: %s\n", *laneMode)
		flag.Usage()
		os.Exit(2)
	}

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

	cfg, err := loadWorkerConfig(*configPath)
	if err != nil {
		logger.Error("roe_worker_config_load_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	fastWorkers := cfg.FastWorkers
	standardWorkers := cfg.StandardWorkers
	switch lane {
	case "FAST":
		standardWorkers = 0
	case "STANDARD":
		fastWorkers = 0
	}

	logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_worker_starting",
		slog.String("lane_mode", lane),
		slog.Int("fast_workers", fastWorkers),
		slog.Int("standard_workers", standardWorkers),
		slog.Int("pull_batch", cfg.PullBatch),
		slog.Int("pull_timeout_ms", cfg.PullTimeoutMs),
		slog.Int("max_inflight", cfg.MaxInflight),
		slog.Int("max_attempts", cfg.MaxAttempts),
		slog.Int64("base_backoff_ms", cfg.BaseBackoffMs),
		slog.Int64("max_backoff_ms", cfg.MaxBackoffMs),
		slog.Int("degrade_high_watermark_pct", cfg.DegradeHighWatermarkPct),
	)

	nc, err := nats.Connect(baseCfg.JetStream.URL, nats.Name("r-siem-master-roe-worker"))
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

	kv, err := ensureKV(js, "RSIEM_RSP_STEPS")
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_STEPS"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	resultsKV, err := ensureKV(js, "RSIEM_RSP_RESULTS")
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_RESULTS"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	lockKV, err := ensureKV(js, "RSIEM_RSP_LOCKS")
	if err != nil {
		logger.Error("kv_init_failed", slog.String("bucket", "RSIEM_RSP_LOCKS"), slog.String("error", err.Error()))
		os.Exit(1)
	}

	exporter, err := newWorkerExporter(logger, cfg.Export)
	if err != nil {
		logger.Error("roe_worker_export_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if exporter != nil {
		defer exporter.Close()
	}

	runtime := &workerRuntime{
		logger:     logger,
		js:         js,
		kv:         kv,
		resultsKV:  resultsKV,
		lockKV:     lockKV,
		cfg:        cfg,
		testFailKV: isTestFailAfterKVEnabled(),
		exporter:   exporter,
		workerID:   newWorkerID(),
		exitFunc:   os.Exit,
		failpoint:  loadWorkerFailpoint(),
		connectors: connectors.NewManager(connectors.Builtins(connectors.BuiltinOptions{
			Logger: logger,
			NATS:   nc,
		})...),
		allowlist: buildAllowlist(cfg.AllowedActionTypes),
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_connector_manager_ready",
		slog.Int("connectors", runtime.connectors.Count()),
	)

	var fastSub *nats.Subscription
	var standardSub *nats.Subscription
	if lane != "STANDARD" {
		if err := ensureConsumer(js, responseStream, responseStepsFast, "roe-steps-fast"); err != nil {
			logger.Error("ensure_consumer_failed", slog.String("lane", "FAST"), slog.String("error", err.Error()))
			os.Exit(1)
		}
		fastSub, err = js.PullSubscribe(responseStepsFast, "roe-steps-fast", nats.BindStream(responseStream))
		if err != nil {
			logger.Error("subscribe_failed", slog.String("lane", "FAST"), slog.String("error", err.Error()))
			os.Exit(1)
		}
	}
	if lane != "FAST" {
		if err := ensureConsumer(js, responseStream, responseStepsStd, "roe-steps-standard"); err != nil {
			logger.Error("ensure_consumer_failed", slog.String("lane", "STANDARD"), slog.String("error", err.Error()))
			os.Exit(1)
		}
		standardSub, err = js.PullSubscribe(responseStepsStd, "roe-steps-standard", nats.BindStream(responseStream))
		if err != nil {
			logger.Error("subscribe_failed", slog.String("lane", "STANDARD"), slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	ctx, cancel := signalContext()
	defer cancel()

	var fastQueue chan *nats.Msg
	var standardQueue chan *nats.Msg
	if lane != "STANDARD" {
		fastQueue = make(chan *nats.Msg, cfg.MaxInflight)
	}
	if lane != "FAST" {
		standardQueue = make(chan *nats.Msg, cfg.MaxInflight)
	}

	var wg sync.WaitGroup
	if fastSub != nil && fastQueue != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fetchLoop(ctx, runtime, fastSub, "FAST", fastQueue, false)
		}()
	}
	if standardSub != nil && standardQueue != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fetchLoop(ctx, runtime, standardSub, "STANDARD", standardQueue, true)
		}()
	}

	if fastQueue != nil {
		for i := 0; i < fastWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				workerLoop(ctx, runtime, fastQueue)
			}()
		}
	}
	if standardQueue != nil {
		for i := 0; i < standardWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				workerLoop(ctx, runtime, standardQueue)
			}()
		}
	}

	wg.Wait()
	logger.Info("master_roe_worker_stopped")
}

func loadWorkerConfig(path string) (roeWorkerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return roeWorkerConfig{}, fmt.Errorf("read config: %w", err)
	}
	var wrapper roeWorkerConfigWrapper
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return roeWorkerConfig{}, fmt.Errorf("parse roe.worker config: %w", err)
	}
	cfg := wrapper.ROE.Worker
	cfg.AllowedActionTypes = wrapper.ROE.Policies.ActionAllowlist.AllowedActionTypes
	applyWorkerDefaults(&cfg)
	return cfg, nil
}

func applyWorkerDefaults(cfg *roeWorkerConfig) {
	if cfg.FastWorkers <= 0 {
		cfg.FastWorkers = defaultFastWorkers
	}
	if cfg.StandardWorkers <= 0 {
		cfg.StandardWorkers = defaultStdWorkers
	}
	if cfg.PullBatch <= 0 {
		cfg.PullBatch = defaultPullBatch
	}
	if cfg.PullTimeoutMs <= 0 {
		cfg.PullTimeoutMs = defaultPullTimeoutMs
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = defaultMaxInflight
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.BaseBackoffMs <= 0 {
		cfg.BaseBackoffMs = defaultBaseBackoffMs
	}
	if cfg.MaxBackoffMs <= 0 {
		cfg.MaxBackoffMs = defaultMaxBackoffMs
	}
	if cfg.DegradeHighWatermarkPct <= 0 {
		cfg.DegradeHighWatermarkPct = defaultDegradePct
	}
	if cfg.LockTTLms <= 0 {
		cfg.LockTTLms = defaultLockTTLms
	}
	if strings.TrimSpace(cfg.Export.StepsPath) == "" {
		cfg.Export.StepsPath = "exports/roe_steps.jsonl"
	}
	if strings.TrimSpace(cfg.Export.StepsLatestPath) == "" {
		cfg.Export.StepsLatestPath = filepath.Join(filepath.Dir(cfg.Export.StepsPath), "roe_steps_latest.jsonl")
	}
}

func ensureResponseStream(js nats.JetStreamContext) error {
	required := []string{
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
		logger.Error("roe_worker_stream_info_failed", slog.String("error", err.Error()))
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

func fetchLoop(ctx context.Context, runtime *workerRuntime, sub *nats.Subscription, lane string, queue chan *nats.Msg, applyDegrade bool) {
	timeout := time.Duration(runtime.cfg.PullTimeoutMs) * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if applyDegrade && runtime.shouldDegrade() {
			time.Sleep(50 * time.Millisecond)
			continue
		}

		msgs, err := sub.Fetch(runtime.cfg.PullBatch, nats.MaxWait(timeout))
		if err != nil {
			if err == nats.ErrTimeout {
				continue
			}
			runtime.logger.Error("roe_worker_fetch_failed", slog.String("lane", lane), slog.String("error", err.Error()))
			continue
		}
		for _, msg := range msgs {
			queue <- msg
		}
	}
}

func (r *workerRuntime) shouldDegrade() bool {
	max := int64(r.cfg.MaxInflight)
	if max <= 0 {
		return false
	}
	inflight := r.inflight.Load()
	threshold := max * int64(r.cfg.DegradeHighWatermarkPct) / 100
	return inflight >= threshold
}

func workerLoop(ctx context.Context, runtime *workerRuntime, queue chan *nats.Msg) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-queue:
			if msg == nil {
				continue
			}
			runtime.inflight.Add(1)
			if err := processStep(runtime, msg); err != nil {
				runtime.logger.Error("roe_step_process_failed", slog.String("error", err.Error()))
			}
			runtime.inflight.Add(-1)
		}
	}
}

func processStep(runtime *workerRuntime, msg *nats.Msg) error {
	meta, _ := msg.Metadata()
	jsSeq := uint64(0)
	if meta != nil {
		jsSeq = meta.Sequence.Stream
	}

	step, err := decodeStep(msg.Data)
	if err != nil {
		runtime.logger.Error("roe_step_decode_failed", slog.String("error", err.Error()))
		return nil
	}
	stepKey := stepKey(step)
	resultKey := resultDedupeKey(step)
	legacyKey := workerResultKey(step)
	lockKey := fmt.Sprintf("lock.run.%s", step.RunID)
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_received",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("action_type", step.ActionType),
		slog.String("lane", step.Lane),
		slog.Uint64("js_seq", jsSeq),
	)

	if handled, err := handleResultReplay(runtime, step, stepKey, resultKey, legacyKey, resultKey); err != nil {
		runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
		return err
	} else if handled {
		return msg.Ack()
	}

	var priorState *stepState
	if payload, found, err := runtime.getTerminalResultAny(resultKey, legacyKey); err != nil {
		runtime.logger.Error("roe_result_kv_error", slog.String("error", err.Error()))
		return nil
	} else if found {
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "worker_result_replay",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("result_key", resultKey),
		)
		if err := runtime.publishResultPayload(payload); err != nil {
			runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
			return nil
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_duplicate_succeeded",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
		)
		return msg.Ack()
	}

	existing, err := runtime.kv.Get(stepKey)
	if err == nil {
		state := stepState{}
		_ = json.Unmarshal(existing.Value(), &state)
		switch state.Status {
		case "SUCCEEDED":
			if err := runtime.persistTerminalResult(step, state); err != nil {
				runtime.logger.Error("roe_result_kv_error", slog.String("error", err.Error()))
				return nil
			}
			if err := runtime.publishResult(step, state); err != nil {
				runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
				return nil
			}
			runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_duplicate_succeeded",
				slog.String("run_id", step.RunID),
				slog.String("step_id", step.StepID),
			)
			return msg.Ack()
		case "RUNNING":
			runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_duplicate_running",
				slog.String("run_id", step.RunID),
				slog.String("step_id", step.StepID),
			)
			return msg.Ack()
		case "FAILED_SAFE":
			if err := runtime.persistTerminalResult(step, state); err != nil {
				runtime.logger.Error("roe_result_kv_error", slog.String("error", err.Error()))
				return nil
			}
			if err := runtime.publishResult(step, state); err != nil {
				runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
				return nil
			}
			runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_duplicate_failed_safe",
				slog.String("run_id", step.RunID),
				slog.String("step_id", step.StepID),
			)
			return msg.Ack()
		case "FAILED_TRANSIENT":
			priorState = &state
			if err := runtime.publishResult(step, state); err != nil {
				runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
				return nil
			}
			if delayMs := retryDelayMs(time.Now().UnixMilli(), &state); delayMs > 0 {
				if err := msg.NakWithDelay(time.Duration(delayMs) * time.Millisecond); err != nil {
					runtime.logger.Error("roe_step_nak_failed", slog.String("error", err.Error()))
				}
				return nil
			}
		}
	} else if !errors.Is(err, nats.ErrKeyNotFound) {
		runtime.logger.Error("roe_step_kv_error", slog.String("error", err.Error()))
		return nil
	}

	acquired, err := runtime.acquireRunLock(lockKey, step)
	if err != nil {
		runtime.logger.Error("roe_lock_error", slog.String("error", err.Error()))
		return nil
	}
	if !acquired {
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_lock_contended",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("lock_key", lockKey),
		)
		if err := msg.NakWithDelay(time.Duration(runtime.cfg.BaseBackoffMs) * time.Millisecond); err != nil {
			runtime.logger.Error("roe_step_nak_failed", slog.String("error", err.Error()))
		}
		return nil
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_lock_acquired",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("lock_key", lockKey),
	)
	defer runtime.releaseRunLock(lockKey, step)

	attempt := resolveAttempt(step, priorState)
	maxAttempts := resolveMaxAttempts(step, runtime.cfg.MaxAttempts)
	baseBackoff := resolveBackoff(step, runtime.cfg.BaseBackoffMs, defaultBaseBackoffMs)
	maxBackoff := resolveBackoffMax(step, runtime.cfg.MaxBackoffMs, defaultMaxBackoffMs)
	ctx := context.Background()
	if timeout := resolveTimeout(step); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	running := stepState{
		Status:          "RUNNING",
		Attempt:         attempt,
		StartedAtUnixMs: time.Now().UnixMilli(),
		RunID:           step.RunID,
		StepID:          step.StepID,
		StepIndex:       step.StepIndex,
		ActionType:      step.ActionType,
		Lane:            step.Lane,
	}
	if err := putState(runtime.kv, stepKey, running); err != nil {
		runtime.logger.Error("roe_step_kv_error", slog.String("error", err.Error()))
		return nil
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_state",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("status", "RUNNING"),
	)

	if !runtime.isAllowed(step.ActionType) {
		final := running
		final.Status = "FAILED_SAFE"
		final.LastError = "policy_denied"
		final.FinishedAtUnixMs = time.Now().UnixMilli()
		if err := putState(runtime.kv, stepKey, final); err != nil {
			runtime.logger.Error("roe_step_kv_error", slog.String("error", err.Error()))
			return nil
		}
		if err := runtime.persistTerminalResult(step, final); err != nil {
			runtime.logger.Error("roe_result_kv_error", slog.String("error", err.Error()))
			return nil
		}
		if os.Getenv("RSIEM_WORKER_CRASH_AFTER_PERSIST") == "1" &&
			(final.Status == "SUCCEEDED" || final.Status == "FAILED_SAFE") {

			runtime.logger.LogAttrs(context.Background(), slog.LevelError, "worker_crash_after_persist",
				slog.String("run_id", step.RunID),
				slog.String("step_id", step.StepID),
				slog.String("status", final.Status),
			)
			os.Exit(42)
		}
		if err := runtime.maybeFailpoint(step, final, "after_persist_terminal"); err != nil {
			return err
		}
		if err := runtime.maybeFailAfterKV(step, jsSeq); err != nil {
			return err
		}
		if err := runtime.publishResult(step, final); err != nil {
			runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
			return nil
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_failed_safe",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("last_error", "policy_denied"),
			slog.Int("attempt", attempt),
		)
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_connector_terminal",
			slog.String("status", final.Status),
			slog.String("err", "policy_denied"),
		)
		return msg.Ack()
	}

	connector, err := runtime.connectors.Select(step.ActionType)
	if err != nil {
		final := running
		final.Status = "FAILED_SAFE"
		final.LastError = err.Error()
		final.FinishedAtUnixMs = time.Now().UnixMilli()
		if err := putState(runtime.kv, stepKey, final); err != nil {
			runtime.logger.Error("roe_step_kv_error", slog.String("error", err.Error()))
			return nil
		}
		if err := runtime.persistTerminalResult(step, final); err != nil {
			runtime.logger.Error("roe_result_kv_error", slog.String("error", err.Error()))
			return nil
		}
		if os.Getenv("RSIEM_WORKER_CRASH_AFTER_PERSIST") == "1" &&
			(final.Status == "SUCCEEDED" || final.Status == "FAILED_SAFE") {

			runtime.logger.LogAttrs(context.Background(), slog.LevelError, "worker_crash_after_persist",
				slog.String("run_id", step.RunID),
				slog.String("step_id", step.StepID),
				slog.String("status", final.Status),
			)
			os.Exit(42)
		}
		if err := runtime.maybeFailpoint(step, final, "after_persist_terminal"); err != nil {
			return err
		}
		if err := runtime.maybeFailAfterKV(step, jsSeq); err != nil {
			return err
		}
		if err := runtime.publishResult(step, final); err != nil {
			runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
			return nil
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_failed_safe",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("last_error", err.Error()),
			slog.Int("attempt", attempt),
		)
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_connector_terminal",
			slog.String("status", final.Status),
			slog.String("err", err.Error()),
		)
		return msg.Ack()
	}

	if reason := validateStepParams(connector.RequiredParams(), connector.OptionalParams(), step.Params); reason != "" {
		final := running
		if isValidationError(reason) {
			final = validationFailureState(step, reason)
		} else {
			final.Status = "FAILED_SAFE"
			final.LastError = reason
			final.FinishedAtUnixMs = time.Now().UnixMilli()
		}
		if err := putState(runtime.kv, stepKey, final); err != nil {
			runtime.logger.Error("roe_step_kv_error", slog.String("error", err.Error()))
			return nil
		}
		if err := runtime.persistTerminalResult(step, final); err != nil {
			runtime.logger.Error("roe_result_kv_error", slog.String("error", err.Error()))
			return nil
		}
		if os.Getenv("RSIEM_WORKER_CRASH_AFTER_PERSIST") == "1" &&
			(final.Status == "SUCCEEDED" || final.Status == "FAILED_SAFE") {

			runtime.logger.LogAttrs(context.Background(), slog.LevelError, "worker_crash_after_persist",
				slog.String("run_id", step.RunID),
				slog.String("step_id", step.StepID),
				slog.String("status", final.Status),
			)
			os.Exit(42)
		}
		if err := runtime.maybeFailpoint(step, final, "after_persist_terminal"); err != nil {
			return err
		}
		if err := runtime.maybeFailAfterKV(step, jsSeq); err != nil {
			return err
		}
		if err := runtime.publishResult(step, final); err != nil {
			runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
			return nil
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_failed_safe",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("last_error", reason),
			slog.Int("attempt", final.Attempt),
		)
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_connector_terminal",
			slog.String("status", final.Status),
			slog.String("err", reason),
		)
		return msg.Ack()
	}

	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_connector_selected",
		slog.String("connector", connector.Name()),
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
	)
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_connector_attempt",
		slog.Int("attempt", attempt),
		slog.Int("max_attempts", maxAttempts),
	)
	result, err := runtime.executeConnector(ctx, connector, step)
	finished := time.Now().UnixMilli()
	if err != nil {
		if connectors.IsRetryable(err) && (attempt < maxAttempts || allowAgentNoResponderRetry(step, err, running, priorState, maxAttempts, baseBackoff, maxBackoff)) {
			backoff := computeBackoff(attempt, baseBackoff, maxBackoff)
			final := running
			final.Status = "FAILED_TRANSIENT"
			final.LastError = err.Error()
			final.FinishedAtUnixMs = finished
			final.NextRetryAtUnixMs = finished + backoff
			if err := putState(runtime.kv, stepKey, final); err != nil {
				runtime.logger.Error("roe_step_kv_error", slog.String("error", err.Error()))
				return nil
			}
			if err := runtime.publishResult(step, final); err != nil {
				runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
				return nil
			}
			runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_connector_retry",
				slog.Int("attempt", attempt),
				slog.Int64("sleep_ms", backoff),
				slog.String("err", err.Error()),
			)
			runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_failed_transient",
				slog.String("run_id", step.RunID),
				slog.String("step_id", step.StepID),
				slog.String("last_error", err.Error()),
				slog.Int("attempt", attempt),
				slog.Int64("next_retry_at_unix_ms", final.NextRetryAtUnixMs),
			)
			if err := msg.NakWithDelay(time.Duration(backoff) * time.Millisecond); err != nil {
				runtime.logger.Error("roe_step_nak_failed", slog.String("error", err.Error()))
			}
			return nil
		}
		if attempt >= maxAttempts {
			final := running
			final.Status = "FAILED_SAFE"
			final.LastError = err.Error()
			final.FinishedAtUnixMs = finished
			if err := putState(runtime.kv, stepKey, final); err != nil {
				runtime.logger.Error("roe_step_kv_error", slog.String("error", err.Error()))
				return nil
			}
			if err := runtime.persistTerminalResult(step, final); err != nil {
				runtime.logger.Error("roe_result_kv_error", slog.String("error", err.Error()))
				return nil
			}
			if os.Getenv("RSIEM_WORKER_CRASH_AFTER_PERSIST") == "1" &&
				(final.Status == "SUCCEEDED" || final.Status == "FAILED_SAFE") {

				runtime.logger.LogAttrs(context.Background(), slog.LevelError, "worker_crash_after_persist",
					slog.String("run_id", step.RunID),
					slog.String("step_id", step.StepID),
					slog.String("status", final.Status),
				)
				os.Exit(42)
			}
			if err := runtime.maybeFailpoint(step, final, "after_persist_terminal"); err != nil {
				return err
			}
			if err := runtime.maybeFailAfterKV(step, jsSeq); err != nil {
				return err
			}
			if err := runtime.publishResult(step, final); err != nil {
				runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
				return nil
			}
			runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_failed_safe",
				slog.String("run_id", step.RunID),
				slog.String("step_id", step.StepID),
				slog.String("last_error", err.Error()),
				slog.Int("attempt", attempt),
			)
			runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_connector_terminal",
				slog.String("status", final.Status),
				slog.String("err", err.Error()),
			)
			return msg.Ack()
		}
		final := running
		final.Status = "FAILED_SAFE"
		final.LastError = err.Error()
		final.FinishedAtUnixMs = finished
		if err := putState(runtime.kv, stepKey, final); err != nil {
			runtime.logger.Error("roe_step_kv_error", slog.String("error", err.Error()))
			return nil
		}
		if err := runtime.persistTerminalResult(step, final); err != nil {
			runtime.logger.Error("roe_result_kv_error", slog.String("error", err.Error()))
			return nil
		}
		if os.Getenv("RSIEM_WORKER_CRASH_AFTER_PERSIST") == "1" &&
			(final.Status == "SUCCEEDED" || final.Status == "FAILED_SAFE") {

			runtime.logger.LogAttrs(context.Background(), slog.LevelError, "worker_crash_after_persist",
				slog.String("run_id", step.RunID),
				slog.String("step_id", step.StepID),
				slog.String("status", final.Status),
			)
			os.Exit(42)
		}
		if err := runtime.maybeFailpoint(step, final, "after_persist_terminal"); err != nil {
			return err
		}
		if err := runtime.maybeFailAfterKV(step, jsSeq); err != nil {
			return err
		}
		if err := runtime.publishResult(step, final); err != nil {
			runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
			return nil
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_failed_safe",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("last_error", err.Error()),
			slog.Int("attempt", attempt),
		)
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_connector_terminal",
			slog.String("status", final.Status),
			slog.String("err", err.Error()),
		)
		return msg.Ack()
	}

	final := running
	final.Status = "SUCCEEDED"
	final.FinishedAtUnixMs = finished
	final.Receipt = result
	if err := putState(runtime.kv, stepKey, final); err != nil {
		runtime.logger.Error("roe_step_kv_error", slog.String("error", err.Error()))
		return nil
	}
	if err := runtime.persistTerminalResult(step, final); err != nil {
		runtime.logger.Error("roe_result_kv_error", slog.String("error", err.Error()))
		return nil
	}
	if os.Getenv("RSIEM_WORKER_CRASH_AFTER_PERSIST") == "1" &&
		(final.Status == "SUCCEEDED" || final.Status == "FAILED_SAFE") {

		runtime.logger.LogAttrs(context.Background(), slog.LevelError, "worker_crash_after_persist",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("status", final.Status),
		)
		os.Exit(42)
	}
	if err := runtime.maybeFailpoint(step, final, "after_persist_terminal"); err != nil {
		return err
	}
	if err := runtime.maybeFailAfterKV(step, jsSeq); err != nil {
		return err
	}
	if err := runtime.publishResult(step, final); err != nil {
		runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
		return nil
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_succeeded",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
	)
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_connector_terminal",
		slog.String("status", final.Status),
	)
	return msg.Ack()
}

func (r *workerRuntime) acquireRunLock(lockKey string, step stepMessage) (bool, error) {
	now := time.Now().UnixMilli()
	ttl := r.cfg.LockTTLms
	entry, err := r.lockKV.Get(lockKey)
	if err == nil {
		var existing map[string]any
		if err := json.Unmarshal(entry.Value(), &existing); err == nil {
			holder := stringFieldRaw(existing, "holder_id")
			acquiredAt, _ := int64Field(existing, "acquired_at_unix_ms")
			lockTTL, ok := int64Field(existing, "ttl_ms")
			if ok && lockTTL > 0 {
				ttl = lockTTL
			}
			if holder != "" && holder != r.workerID && acquiredAt > 0 && now-acquiredAt < ttl {
				return false, nil
			}
		}
	} else if !errors.Is(err, nats.ErrKeyNotFound) {
		return false, err
	}
	record := map[string]any{
		"holder_id":           r.workerID,
		"step_id":             step.StepID,
		"acquired_at_unix_ms": now,
		"ttl_ms":              ttl,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return false, err
	}
	if _, err := r.lockKV.Put(lockKey, payload); err != nil {
		return false, err
	}
	return true, nil
}

func (r *workerRuntime) releaseRunLock(lockKey string, step stepMessage) {
	if err := r.lockKV.Delete(lockKey); err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
		r.logger.LogAttrs(context.Background(), slog.LevelError, "roe_lock_release_failed",
			slog.String("error", err.Error()),
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
			slog.String("lock_key", lockKey),
		)
		return
	}
	r.logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_lock_released",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("lock_key", lockKey),
	)
}

func decodeStep(data []byte) (stepMessage, error) {
	var step stepMessage
	if err := json.Unmarshal(data, &step); err != nil {
		return stepMessage{}, err
	}
	step.RunID = strings.TrimSpace(step.RunID)
	step.StepID = strings.TrimSpace(step.StepID)
	step.ActionType = strings.TrimSpace(step.ActionType)
	step.Lane = strings.TrimSpace(step.Lane)
	step.StepIdemKey = strings.TrimSpace(step.StepIdemKey)
	if step.RunID == "" || step.ActionType == "" || step.Lane == "" {
		return stepMessage{}, fmt.Errorf("missing required fields")
	}
	if step.StepID == "" {
		step.StepID = shortHash(fmt.Sprintf("%s|%d|%s|%s", step.RunID, step.StepIndex, step.ActionType, step.Target))
	}
	if step.StepIdemKey == "" {
		step.StepIdemKey = fmt.Sprintf("step.%s", step.StepID)
	}
	return step, nil
}

func stepKey(step stepMessage) string {
	return fmt.Sprintf("step.%s.%s", step.RunID, step.StepID)
}

func workerResultKey(step stepMessage) string {
	return fmt.Sprintf("worker_result.%s.%s", step.RunID, step.StepID)
}

func resultDedupeKey(step stepMessage) string {
	return fmt.Sprintf("result.%s.%s", step.RunID, step.StepID)
}

func putState(kv nats.KeyValue, key string, state stepState) error {
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = kv.Put(key, payload)
	return err
}

func (r *workerRuntime) executeConnector(ctx context.Context, connector connectors.Connector, step stepMessage) (map[string]any, error) {
	if r.executeConnectorOverride != nil {
		return r.executeConnectorOverride(ctx, connector, step)
	}
	if r.cfg.FailureInject.Enabled && r.cfg.FailureInject.EveryN > 0 {
		count := r.execCount.Add(1)
		if int(count)%r.cfg.FailureInject.EveryN == 0 {
			return nil, connectors.Retryable(fmt.Errorf("injected_transient_failure"))
		}
	}
	return connector.Execute(ctx, connectors.Step{
		ActionType: step.ActionType,
		Target:     step.Target,
		RunID:      step.RunID,
		StepID:     step.StepID,
		Lane:       step.Lane,
		Params:     step.Params,
		TimeoutMs:  step.TimeoutMs,
	})
}

func (r *workerRuntime) publishResult(step stepMessage, final stepState) error {
	payload, err := buildResultPayload(step, final)
	if err != nil {
		return err
	}
	return r.publishResultPayload(payload)
}

func (r *workerRuntime) publishResultPayload(payload []byte) error {
	if r.publishResultPayloadOverride != nil {
		return r.publishResultPayloadOverride(payload)
	}
	record := resultRecord{}
	if err := json.Unmarshal(payload, &record); err != nil {
		return err
	}
	subject := responseResultsStd
	if strings.EqualFold(record.Lane, "FAST") {
		subject = responseResultsFast
	}
	if _, err := r.js.Publish(subject, payload); err != nil {
		return err
	}
	if r.exporter != nil {
		if err := r.exporter.WriteJSONL(payload); err != nil {
			return err
		}
	}
	return nil
}

func (r *workerRuntime) persistTerminalResult(step stepMessage, final stepState) error {
	payload, err := buildResultPayload(step, final)
	if err != nil {
		return err
	}
	if final.Status == "SUCCEEDED" || final.Status == "FAILED_SAFE" {
		if _, err := r.resultsKV.Create(resultDedupeKey(step), payload); err != nil && !errors.Is(err, nats.ErrKeyExists) {
			return err
		}
	}
	_, err = r.resultsKV.Put(workerResultKey(step), payload)
	return err
}

func (r *workerRuntime) maybeFailpoint(step stepMessage, final stepState, stage string) error {
	if !r.failpoint.enabled || r.failpoint.stage != stage {
		return nil
	}
	if final.Status != "SUCCEEDED" && final.Status != "FAILED_SAFE" {
		return nil
	}
	if r.failpoint.runID != "" && r.failpoint.runID != step.RunID {
		return nil
	}
	if r.failpoint.stepID != "" && r.failpoint.stepID != step.StepID {
		return nil
	}
	if r.failpoint.once {
		if !r.failpointTriggered.CompareAndSwap(false, true) {
			return nil
		}
	}
	r.logger.LogAttrs(context.Background(), slog.LevelError, "roe_failpoint_triggered",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("stage", stage),
	)
	if r.exitFunc != nil {
		r.exitFunc(2)
	}
	return fmt.Errorf("failpoint_triggered")
}

func (r *workerRuntime) maybeFailAfterKV(step stepMessage, jsSeq uint64) error {
	if !r.testFailKV {
		return nil
	}
	r.logger.LogAttrs(context.Background(), slog.LevelError, "roe_worker_test_fail_after_kv",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("lane", step.Lane),
		slog.Uint64("js_seq", jsSeq),
	)
	return fmt.Errorf("test_fail_after_kv")
}

func (r *workerRuntime) getTerminalResult(key string) ([]byte, bool, error) {
	entry, err := r.resultsKV.Get(key)
	if err == nil {
		return entry.Value(), true, nil
	}
	if errors.Is(err, nats.ErrKeyNotFound) {
		return nil, false, nil
	}
	return nil, false, err
}

func (r *workerRuntime) getTerminalResultAny(primary string, fallback string) ([]byte, bool, error) {
	if payload, found, err := r.getTerminalResult(primary); err != nil || found {
		return payload, found, err
	}
	if fallback == "" {
		return nil, false, nil
	}
	return r.getTerminalResult(fallback)
}

func (r *workerRuntime) hasResultDedupe(key string) (bool, error) {
	if _, err := r.resultsKV.Get(key); err == nil {
		return true, nil
	} else if errors.Is(err, nats.ErrKeyNotFound) {
		return false, nil
	} else {
		return false, err
	}
}

func (r *workerRuntime) replayFromState(step stepMessage, key string) (bool, error) {
	existing, err := r.kv.Get(key)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return false, nil
		}
		return false, err
	}
	state := stepState{}
	if err := json.Unmarshal(existing.Value(), &state); err != nil {
		return false, err
	}
	switch state.Status {
	case "SUCCEEDED", "FAILED_SAFE":
		if err := r.persistTerminalResult(step, state); err != nil {
			return false, err
		}
		if err := r.publishResult(step, state); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, nil
	}
}

func handleResultReplay(runtime *workerRuntime, step stepMessage, stepKey string, resultKey string, legacyKey string, dedupeKey string) (bool, error) {
	if exists, err := runtime.hasResultDedupe(dedupeKey); err != nil {
		return false, err
	} else if !exists {
		return false, nil
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "worker_result_replay",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("result_key", dedupeKey),
	)
	if payload, found, err := runtime.getTerminalResultAny(resultKey, legacyKey); err != nil {
		return false, err
	} else if found {
		if err := runtime.publishResultPayload(payload); err != nil {
			return false, err
		}
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_duplicate_succeeded",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
		)
		return true, nil
	}
	handled, err := runtime.replayFromState(step, stepKey)
	if err != nil {
		return false, err
	}
	if handled {
		runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_duplicate_succeeded",
			slog.String("run_id", step.RunID),
			slog.String("step_id", step.StepID),
		)
		return true, nil
	}
	runtime.logger.Error("roe_result_replay_missing",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("result_key", dedupeKey),
	)
	return false, fmt.Errorf("result_replay_missing")
}

type resultRecord struct {
	Lane string `json:"lane"`
}

func buildResultPayload(step stepMessage, final stepState) ([]byte, error) {
	result := map[string]any{
		"msg":                 "response_step_result",
		"run_id":              step.RunID,
		"step_id":             step.StepID,
		"step_index":          step.StepIndex,
		"action_type":         step.ActionType,
		"lane":                step.Lane,
		"status":              final.Status,
		"attempt":             final.Attempt,
		"finished_at_unix_ms": final.FinishedAtUnixMs,
		"step_key":            fmt.Sprintf("step.%s.%s", step.RunID, step.StepID),
	}
	if final.Receipt != nil {
		result["receipt"] = final.Receipt
	}
	if final.LastError != "" {
		result["last_error"] = final.LastError
	}
	return json.Marshal(result)
}

func buildAllowlist(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out[trimmed] = struct{}{}
	}
	return out
}

func (r *workerRuntime) isAllowed(actionType string) bool {
	if len(r.allowlist) == 0 {
		return true
	}
	_, ok := r.allowlist[actionType]
	return ok
}

func resolveMaxAttempts(step stepMessage, fallback int) int {
	if step.Retries != nil {
		if *step.Retries < 0 {
			return 1
		}
		return *step.Retries + 1
	}
	if fallback <= 0 {
		return defaultMaxAttempts
	}
	return fallback
}

func resolveAttempt(step stepMessage, state *stepState) int {
	base := step.Attempt
	if state != nil && state.Attempt > base {
		base = state.Attempt
	}
	return base + 1
}

func retryDelayMs(nowUnixMs int64, state *stepState) int64 {
	if state == nil || state.NextRetryAtUnixMs <= 0 {
		return 0
	}
	if nowUnixMs >= state.NextRetryAtUnixMs {
		return 0
	}
	delay := state.NextRetryAtUnixMs - nowUnixMs
	if delay < 1 {
		return 1
	}
	return delay
}

func isValidationError(reason string) bool {
	return strings.HasPrefix(reason, "unknown_param:") ||
		strings.HasPrefix(reason, "missing_param:") ||
		strings.HasPrefix(reason, "missing_required_param:")
}

func validationAttempt(step stepMessage) int {
	attempt := step.Attempt
	if attempt < 1 {
		return 1
	}
	return attempt
}

func validationFailureState(step stepMessage, reason string) stepState {
	return stepState{
		Status:           "FAILED_SAFE",
		Attempt:          validationAttempt(step),
		LastError:        reason,
		FinishedAtUnixMs: time.Now().UnixMilli(),
		RunID:            step.RunID,
		StepID:           step.StepID,
		StepIndex:        step.StepIndex,
		ActionType:       step.ActionType,
		Lane:             step.Lane,
	}
}

func resolveBackoff(step stepMessage, fallback int64, defaultValue int64) int64 {
	if step.BackoffMs != nil && *step.BackoffMs > 0 {
		return *step.BackoffMs
	}
	if fallback > 0 {
		return fallback
	}
	return defaultValue
}

func resolveBackoffMax(step stepMessage, fallback int64, defaultValue int64) int64 {
	if step.BackoffMaxMs != nil && *step.BackoffMaxMs > 0 {
		return *step.BackoffMaxMs
	}
	if fallback > 0 {
		return fallback
	}
	return defaultValue
}

func resolveTimeout(step stepMessage) time.Duration {
	if step.TimeoutMs == nil {
		return 0
	}
	if *step.TimeoutMs <= 0 {
		return 0
	}
	return time.Duration(*step.TimeoutMs) * time.Millisecond
}

func validateStepParams(required []string, optional []string, params map[string]any) string {
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, name := range required {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		allowed[trimmed] = struct{}{}
		if params == nil {
			return fmt.Sprintf("missing_param:%s", trimmed)
		}
		if _, ok := params[trimmed]; !ok {
			return fmt.Sprintf("missing_param:%s", trimmed)
		}
	}
	for _, name := range optional {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		allowed[trimmed] = struct{}{}
	}
	for name := range params {
		if _, ok := allowed[name]; !ok {
			return fmt.Sprintf("unknown_param:%s", name)
		}
	}
	return ""
}

func allowAgentNoResponderRetry(step stepMessage, err error, running stepState, prior *stepState, maxAttempts int, baseBackoff int64, maxBackoff int64) bool {
	if !isAgentNoResponder(step, err) {
		return false
	}
	_ = baseBackoff
	startMs := step.EmittedAtUnixMs
	if startMs <= 0 {
		startMs = step.PlannedAtUnixMs
	}
	if startMs <= 0 && prior != nil && prior.StartedAtUnixMs > 0 {
		startMs = prior.StartedAtUnixMs
	}
	if startMs <= 0 {
		startMs = running.StartedAtUnixMs
	}
	if startMs <= 0 {
		return false
	}
	windowMs := agentNoResponderRetryWindowMs(step, maxAttempts, baseBackoff, maxBackoff)
	if windowMs <= 0 {
		return false
	}
	now := time.Now().UnixMilli()
	return now-startMs <= windowMs
}

func agentNoResponderRetryWindowMs(step stepMessage, maxAttempts int, baseBackoff int64, maxBackoff int64) int64 {
	_ = baseBackoff
	timeout := resolveTimeout(step)
	if timeout > 0 {
		return int64(timeout / time.Millisecond)
	}
	if maxAttempts <= 0 {
		return 0
	}
	return int64(maxAttempts) * maxBackoff
}

func isAgentNoResponder(step stepMessage, err error) bool {
	if !strings.EqualFold(strings.TrimSpace(step.ActionType), "agent_command") {
		return false
	}
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "no responders available for request")
}

func newWorkerExporter(logger *slog.Logger, cfg workerExportConfig) (*workerExporter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	stepsDir := filepath.Dir(cfg.StepsPath)
	if stepsDir == "" {
		stepsDir = "."
	}
	if err := os.MkdirAll(stepsDir, 0o755); err != nil {
		return nil, err
	}
	latestDir := filepath.Dir(cfg.StepsLatestPath)
	if latestDir == "" {
		latestDir = "."
	}
	if err := os.MkdirAll(latestDir, 0o755); err != nil {
		return nil, err
	}
	if logger != nil {
		logger.LogAttrs(context.Background(), slog.LevelInfo, "export_steps_paths",
			slog.String("steps_path", cfg.StepsPath),
			slog.String("steps_latest_path", cfg.StepsLatestPath),
		)
	}
	file, err := os.OpenFile(cfg.StepsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	exporter := &workerExporter{
		logger: logger,
		cfg:    cfg,
		file:   file,
		latest: make(map[string]latestRecord),
	}
	if err := exporter.loadLatestFromAudit(); err != nil {
		exporter.logError(err)
		if exporter.isRequired() {
			return nil, err
		}
	}
	return exporter, nil
}

func (w *workerExporter) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
}

func (w *workerExporter) WriteJSONL(payload []byte) error {
	if w == nil || !w.cfg.Enabled {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	// roe_steps.jsonl is the append-only audit log; keep all history.
	if _, err := w.file.Write(append(payload, '\n')); err != nil {
		w.logError(err)
		if w.isRequired() {
			return err
		}
		return nil
	}
	flush := true
	if w.cfg.Flush != nil {
		flush = *w.cfg.Flush
	}
	if flush {
		if err := w.file.Sync(); err != nil {
			w.logError(err)
			if w.isRequired() {
				return err
			}
		}
	}
	// roe_steps_latest.jsonl is a case-ready snapshot of the latest state per step_key.
	if err := w.updateLatestSnapshot(payload); err != nil {
		w.logError(err)
		if w.isRequired() {
			return err
		}
	}
	return nil
}

func (w *workerExporter) updateLatestSnapshot(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	type exportRecord struct {
		StepKey          string `json:"step_key"`
		FinishedAtUnixMs int64  `json:"finished_at_unix_ms"`
	}
	var rec exportRecord
	if err := json.Unmarshal(payload, &rec); err != nil {
		return err
	}
	if strings.TrimSpace(rec.StepKey) == "" {
		return nil
	}
	w.seq++
	if !w.shouldUpdateLatest(rec.StepKey, rec.FinishedAtUnixMs, w.seq) {
		return nil
	}
	w.latest[rec.StepKey] = latestRecord{
		finishedAt: rec.FinishedAtUnixMs,
		seq:        w.seq,
		payload:    append([]byte(nil), payload...),
	}
	return w.writeLatestSnapshot()
}

func (w *workerExporter) shouldUpdateLatest(stepKey string, finishedAt int64, seq int64) bool {
	if existing, ok := w.latest[stepKey]; ok {
		if finishedAt > 0 && existing.finishedAt > 0 {
			if finishedAt < existing.finishedAt {
				return false
			}
			if finishedAt == existing.finishedAt && seq <= existing.seq {
				return false
			}
		} else if seq <= existing.seq {
			return false
		}
	}
	return true
}

func (w *workerExporter) loadLatestFromAudit() error {
	path := strings.TrimSpace(w.cfg.StepsPath)
	if path == "" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return w.writeLatestSnapshot()
		}
		return err
	}
	defer file.Close()

	type exportRecord struct {
		StepKey          string `json:"step_key"`
		FinishedAtUnixMs int64  `json:"finished_at_unix_ms"`
	}
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec exportRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			w.logError(fmt.Errorf("roe_steps_audit_parse_failed: %w", err))
			continue
		}
		stepKey := strings.TrimSpace(rec.StepKey)
		if stepKey == "" {
			continue
		}
		w.seq++
		if !w.shouldUpdateLatest(stepKey, rec.FinishedAtUnixMs, w.seq) {
			continue
		}
		w.latest[stepKey] = latestRecord{
			finishedAt: rec.FinishedAtUnixMs,
			seq:        w.seq,
			payload:    append([]byte(nil), line...),
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return w.writeLatestSnapshot()
}
func (w *workerExporter) writeLatestSnapshot() error {
	dir := filepath.Dir(w.cfg.StepsLatestPath)
	if dir == "" {
		dir = "."
	}
	tmpFile, err := os.CreateTemp(dir, ".roe_steps_latest_*.jsonl")
	if err != nil {
		return err
	}
	if err := tmpFile.Chmod(0o644); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return err
	}
	type snapshotItem struct {
		stepKey    string
		finishedAt int64
		payload    []byte
	}
	items := make([]snapshotItem, 0, len(w.latest))
	for key, entry := range w.latest {
		items = append(items, snapshotItem{
			stepKey:    key,
			finishedAt: entry.finishedAt,
			payload:    entry.payload,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].finishedAt != items[j].finishedAt {
			return items[i].finishedAt < items[j].finishedAt
		}
		return items[i].stepKey < items[j].stepKey
	})
	for _, item := range items {
		if _, err := tmpFile.Write(append(item.payload, '\n')); err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpFile.Name())
			return err
		}
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpFile.Name())
		return err
	}
	return os.Rename(tmpFile.Name(), w.cfg.StepsLatestPath)
}
func (w *workerExporter) isRequired() bool {
	if w.cfg.Required != nil {
		return *w.cfg.Required
	}
	return false
}

func (w *workerExporter) logError(err error) {
	w.logger.LogAttrs(context.Background(), slog.LevelError, "roe_worker_export_error",
		slog.String("error", err.Error()),
		slog.String("path", w.cfg.StepsPath),
	)
}

func computeBackoff(attempt int, baseMs int64, maxMs int64) int64 {
	if attempt <= 1 {
		return baseMs
	}
	backoff := baseMs * int64(1<<uint(attempt-1))
	if backoff > maxMs {
		return maxMs
	}
	return backoff
}

func shortHash(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:16]
}

func newWorkerID() string {
	host, _ := os.Hostname()
	pid := os.Getpid()
	return fmt.Sprintf("%s-%d-%d", host, pid, time.Now().UnixNano())
}

func loadWorkerFailpoint() workerFailpoint {
	stage := strings.TrimSpace(os.Getenv("RSIEM_WORKER_FAILPOINT"))
	if stage == "" {
		return workerFailpoint{}
	}
	fp := workerFailpoint{
		enabled: stage == "after_persist_terminal",
		stage:   stage,
		runID:   strings.TrimSpace(os.Getenv("RSIEM_WORKER_FAILPOINT_RUN_ID")),
		stepID:  strings.TrimSpace(os.Getenv("RSIEM_WORKER_FAILPOINT_STEP_ID")),
		once:    true,
	}
	onceEnv := strings.TrimSpace(os.Getenv("RSIEM_WORKER_FAILPOINT_ONCE"))
	if onceEnv != "" {
		lower := strings.ToLower(onceEnv)
		if lower == "false" || lower == "0" || lower == "no" {
			fp.once = false
		}
	}
	return fp
}

func isTestFailAfterKVEnabled() bool {
	return strings.TrimSpace(os.Getenv("RSIEM_TEST_FAIL_AFTER_KV")) == "1"
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
