package main

import (
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
	defaultBaseBackoffMs = 500
	defaultMaxBackoffMs  = 5000
	defaultDegradePct    = 80
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
	FailureInject           failureInjectConfig `yaml:"failure_inject"`
	Export                  workerExportConfig  `yaml:"export"`
}

type failureInjectConfig struct {
	Enabled bool `yaml:"enabled"`
	EveryN  int  `yaml:"every_n"`
}

type workerExportConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Required  *bool  `yaml:"required"`
	StepsPath string `yaml:"steps_path"`
	Flush     *bool  `yaml:"flush"`
}

type roeWorkerConfigWrapper struct {
	ROE struct {
		Worker roeWorkerConfig `yaml:"worker"`
	} `yaml:"roe"`
}

type stepMessage struct {
	RunID           string `json:"run_id"`
	StepID          string `json:"step_id"`
	StepIndex       int    `json:"step_index"`
	ActionType      string `json:"action_type"`
	Lane            string `json:"lane"`
	StepIdemKey     string `json:"step_idem_key"`
	Attempt         int    `json:"attempt"`
	Target          string `json:"target"`
	PlannedAtUnixMs int64  `json:"planned_at_unix_ms"`
	EmittedAtUnixMs int64  `json:"emitted_at_unix_ms"`
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
	logger    *slog.Logger
	js        nats.JetStreamContext
	kv        nats.KeyValue
	cfg       roeWorkerConfig
	inflight  atomic.Int64
	degraded  atomic.Bool
	execCount atomic.Int64
	exporter  *workerExporter
}

type workerExporter struct {
	logger *slog.Logger
	cfg    workerExportConfig
	mu     sync.Mutex
	file   *os.File
}

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

	cfg, err := loadWorkerConfig(*configPath)
	if err != nil {
		logger.Error("roe_worker_config_load_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.LogAttrs(context.Background(), slog.LevelInfo, "roe_worker_starting",
		slog.Int("fast_workers", cfg.FastWorkers),
		slog.Int("standard_workers", cfg.StandardWorkers),
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

	exporter, err := newWorkerExporter(logger, cfg.Export)
	if err != nil {
		logger.Error("roe_worker_export_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if exporter != nil {
		defer exporter.Close()
	}

	runtime := &workerRuntime{
		logger:   logger,
		js:       js,
		kv:       kv,
		cfg:      cfg,
		exporter: exporter,
	}

	if err := ensureConsumer(js, responseStream, responseStepsFast, "roe-steps-fast"); err != nil {
		logger.Error("ensure_consumer_failed", slog.String("lane", "FAST"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := ensureConsumer(js, responseStream, responseStepsStd, "roe-steps-standard"); err != nil {
		logger.Error("ensure_consumer_failed", slog.String("lane", "STANDARD"), slog.String("error", err.Error()))
		os.Exit(1)
	}

	fastSub, err := js.PullSubscribe(responseStepsFast, "roe-steps-fast", nats.BindStream(responseStream))
	if err != nil {
		logger.Error("subscribe_failed", slog.String("lane", "FAST"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	standardSub, err := js.PullSubscribe(responseStepsStd, "roe-steps-standard", nats.BindStream(responseStream))
	if err != nil {
		logger.Error("subscribe_failed", slog.String("lane", "STANDARD"), slog.String("error", err.Error()))
		os.Exit(1)
	}

	ctx, cancel := signalContext()
	defer cancel()

	fastQueue := make(chan *nats.Msg, cfg.MaxInflight)
	standardQueue := make(chan *nats.Msg, cfg.MaxInflight)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fetchLoop(ctx, runtime, fastSub, "FAST", fastQueue, false)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		fetchLoop(ctx, runtime, standardSub, "STANDARD", standardQueue, true)
	}()

	for i := 0; i < cfg.FastWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			workerLoop(ctx, runtime, fastQueue)
		}()
	}
	for i := 0; i < cfg.StandardWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			workerLoop(ctx, runtime, standardQueue)
		}()
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
	if strings.TrimSpace(cfg.Export.StepsPath) == "" {
		cfg.Export.StepsPath = "exports/roe_steps.jsonl"
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
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_received",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
		slog.String("action_type", step.ActionType),
		slog.String("lane", step.Lane),
		slog.Uint64("js_seq", jsSeq),
	)

	existing, err := runtime.kv.Get(stepKey)
	if err == nil {
		state := stepState{}
		_ = json.Unmarshal(existing.Value(), &state)
		switch state.Status {
		case "SUCCEEDED":
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
			if err := runtime.publishResult(step, state); err != nil {
				runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
				return nil
			}
			if state.NextRetryAtUnixMs > 0 && time.Now().UnixMilli() < state.NextRetryAtUnixMs {
				if err := msg.NakWithDelay(time.Duration(runtime.cfg.BaseBackoffMs) * time.Millisecond); err != nil {
					runtime.logger.Error("roe_step_nak_failed", slog.String("error", err.Error()))
				}
				return nil
			}
		}
	} else if !errors.Is(err, nats.ErrKeyNotFound) {
		runtime.logger.Error("roe_step_kv_error", slog.String("error", err.Error()))
		return nil
	}

	attempt := step.Attempt + 1
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

	result, err := runtime.executeStub(step.ActionType)
	finished := time.Now().UnixMilli()
	if err != nil {
		if attempt >= runtime.cfg.MaxAttempts {
			final := running
			final.Status = "FAILED_SAFE"
			final.LastError = err.Error()
			final.FinishedAtUnixMs = finished
			if err := putState(runtime.kv, stepKey, final); err != nil {
				runtime.logger.Error("roe_step_kv_error", slog.String("error", err.Error()))
				return nil
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
			return msg.Ack()
		}
		backoff := computeBackoff(attempt, runtime.cfg.BaseBackoffMs, runtime.cfg.MaxBackoffMs)
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

	final := running
	final.Status = "SUCCEEDED"
	final.FinishedAtUnixMs = finished
	final.Receipt = result
	if err := putState(runtime.kv, stepKey, final); err != nil {
		runtime.logger.Error("roe_step_kv_error", slog.String("error", err.Error()))
		return nil
	}
	if err := runtime.publishResult(step, final); err != nil {
		runtime.logger.Error("roe_step_result_publish_failed", slog.String("error", err.Error()))
		return nil
	}
	runtime.logger.LogAttrs(context.Background(), slog.LevelInfo, "step_succeeded",
		slog.String("run_id", step.RunID),
		slog.String("step_id", step.StepID),
	)
	return msg.Ack()
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

func putState(kv nats.KeyValue, key string, state stepState) error {
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = kv.Put(key, payload)
	return err
}

func executeStub(actionType string) (map[string]any, error) {
	switch actionType {
	case "notify":
		return map[string]any{"message": "notified"}, nil
	case "agent_command_stub":
		return map[string]any{"message": "command_sent_stub"}, nil
	case "network_block_stub":
		return map[string]any{"message": "blocked_stub"}, nil
	case "network_rate_limit_stub":
		return map[string]any{"message": "rate_limited_stub"}, nil
	default:
		return nil, fmt.Errorf("unknown_action_type")
	}
}

func (r *workerRuntime) executeStub(actionType string) (map[string]any, error) {
	if r.cfg.FailureInject.Enabled && r.cfg.FailureInject.EveryN > 0 {
		count := r.execCount.Add(1)
		if int(count)%r.cfg.FailureInject.EveryN == 0 {
			return nil, fmt.Errorf("injected_transient_failure")
		}
	}
	return executeStub(actionType)
}

func (r *workerRuntime) publishResult(step stepMessage, final stepState) error {
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
	subject := responseResultsStd
	if strings.ToUpper(step.Lane) == "FAST" {
		subject = responseResultsFast
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if _, err := r.js.Publish(subject, data); err != nil {
		return err
	}
	if r.exporter != nil {
		if err := r.exporter.WriteJSONL(data); err != nil {
			return err
		}
	}
	return nil
}

func newWorkerExporter(logger *slog.Logger, cfg workerExportConfig) (*workerExporter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	dir := filepath.Dir(cfg.StepsPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(cfg.StepsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &workerExporter{
		logger: logger,
		cfg:    cfg,
		file:   file,
	}, nil
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
	return nil
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
