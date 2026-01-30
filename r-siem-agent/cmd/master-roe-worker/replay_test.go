package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"log/slog"
	"r-siem-agent/internal/roe/connectors"
)

type memEntry struct {
	bucket   string
	key      string
	value    []byte
	revision uint64
	created  time.Time
}

func (e memEntry) Bucket() string      { return e.bucket }
func (e memEntry) Key() string         { return e.key }
func (e memEntry) Value() []byte       { return e.value }
func (e memEntry) Revision() uint64    { return e.revision }
func (e memEntry) Created() time.Time  { return e.created }
func (e memEntry) Delta() uint64       { return 0 }
func (e memEntry) Operation() nats.KeyValueOp { return nats.KeyValuePut }

type memKV struct {
	mu      sync.Mutex
	bucket  string
	items   map[string]memEntry
	revision uint64
}

func newMemKV(bucket string) *memKV {
	return &memKV{bucket: bucket, items: make(map[string]memEntry)}
}

func (m *memKV) Get(key string) (nats.KeyValueEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.items[key]
	if !ok {
		return nil, nats.ErrKeyNotFound
	}
	return entry, nil
}

func (m *memKV) GetRevision(key string, revision uint64) (nats.KeyValueEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.items[key]
	if !ok || entry.revision != revision {
		return nil, nats.ErrKeyNotFound
	}
	return entry, nil
}

func (m *memKV) Put(key string, value []byte) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revision++
	m.items[key] = memEntry{bucket: m.bucket, key: key, value: value, revision: m.revision, created: time.Now()}
	return m.revision, nil
}

func (m *memKV) PutString(key string, value string) (uint64, error) {
	return m.Put(key, []byte(value))
}

func (m *memKV) Create(key string, value []byte) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.items[key]; ok {
		return 0, nats.ErrKeyExists
	}
	m.revision++
	m.items[key] = memEntry{bucket: m.bucket, key: key, value: value, revision: m.revision, created: time.Now()}
	return m.revision, nil
}

func (m *memKV) Update(key string, value []byte, last uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.items[key]
	if !ok || entry.revision != last {
		return 0, nats.ErrKeyExists
	}
	m.revision++
	m.items[key] = memEntry{bucket: m.bucket, key: key, value: value, revision: m.revision, created: time.Now()}
	return m.revision, nil
}

func (m *memKV) Delete(key string, _ ...nats.DeleteOpt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
	return nil
}

func (m *memKV) Purge(key string, _ ...nats.DeleteOpt) error {
	return m.Delete(key)
}

func (m *memKV) Watch(_ string, _ ...nats.WatchOpt) (nats.KeyWatcher, error) {
	return nil, errors.New("not implemented")
}

func (m *memKV) WatchAll(_ ...nats.WatchOpt) (nats.KeyWatcher, error) {
	return nil, errors.New("not implemented")
}

func (m *memKV) Keys(_ ...nats.WatchOpt) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.items))
	for key := range m.items {
		keys = append(keys, key)
	}
	return keys, nil
}

func (m *memKV) ListKeys(_ ...nats.WatchOpt) (nats.KeyLister, error) {
	return nil, errors.New("not implemented")
}

func (m *memKV) History(_ string, _ ...nats.WatchOpt) ([]nats.KeyValueEntry, error) {
	return nil, errors.New("not implemented")
}

func (m *memKV) Bucket() string {
	return m.bucket
}

func (m *memKV) PurgeDeletes(_ ...nats.PurgeOpt) error {
	return errors.New("not implemented")
}

func (m *memKV) Status() (nats.KeyValueStatus, error) {
	return nil, errors.New("not implemented")
}

func TestHandleResultReplayFromResultsKV(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stepsKV := newMemKV("RSIEM_RSP_STEPS")
	resultsKV := newMemKV("RSIEM_RSP_RESULTS")
	locksKV := newMemKV("RSIEM_RSP_LOCKS")

	step := stepMessage{
		RunID:      "run-1",
		StepID:     "step-1",
		StepIndex:  0,
		ActionType: "agent_command",
		Lane:       "FAST",
	}
	final := stepState{
		Status:           "SUCCEEDED",
		Attempt:          1,
		FinishedAtUnixMs: time.Now().UnixMilli(),
		RunID:            step.RunID,
		StepID:           step.StepID,
		StepIndex:        step.StepIndex,
		ActionType:       step.ActionType,
		Lane:             step.Lane,
	}
	payload, err := buildResultPayload(step, final)
	if err != nil {
		t.Fatalf("buildResultPayload: %v", err)
	}
	_, _ = resultsKV.Put(resultDedupeKey(step), payload)

	var published []byte
	connectorCalled := false

	runtime := &workerRuntime{
		logger:    logger,
		kv:        stepsKV,
		resultsKV: resultsKV,
		lockKV:    locksKV,
		workerID:  "worker-1",
		publishResultPayloadOverride: func(p []byte) error {
			published = append([]byte(nil), p...)
			return nil
		},
		executeConnectorOverride: func(_ context.Context, _ connectors.Connector, _ stepMessage) (map[string]any, error) {
			connectorCalled = true
			return nil, nil
		},
	}

	handled, err := handleResultReplay(runtime, step, stepKey(step), resultDedupeKey(step), workerResultKey(step), resultDedupeKey(step))
	if err != nil {
		t.Fatalf("handleResultReplay: %v", err)
	}
	if !handled {
		t.Fatalf("expected handled=true")
	}
	if connectorCalled {
		t.Fatalf("connector should not execute on replay")
	}
	if len(published) == 0 {
		t.Fatalf("expected result to be republished")
	}
	var got map[string]any
	if err := json.Unmarshal(published, &got); err != nil {
		t.Fatalf("unmarshal published: %v", err)
	}
	if got["run_id"] != step.RunID || got["step_id"] != step.StepID {
		t.Fatalf("published payload missing run_id/step_id")
	}
}
