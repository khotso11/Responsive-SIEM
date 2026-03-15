package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"r-siem-agent/internal/collector/common"
	"r-siem-agent/internal/logging"
)

func TestMergeFileAction(t *testing.T) {
	tests := []struct {
		current string
		next    string
		want    string
	}{
		{current: "", next: "created", want: "created"},
		{current: "created", next: "attrib", want: "created"},
		{current: "created", next: "modified", want: "modified"},
		{current: "modified", next: "deleted", want: "deleted"},
		{current: "deleted", next: "modified", want: "deleted"},
		{current: "attrib", next: "moved", want: "moved"},
	}
	for _, tt := range tests {
		if got := mergeFileAction(tt.current, tt.next); got != tt.want {
			t.Fatalf("mergeFileAction(%q, %q)=%q, want %q", tt.current, tt.next, got, tt.want)
		}
	}
}

func TestPublishFileEventUsesRecentContextAttribution(t *testing.T) {
	root := t.TempDir()
	store := common.NewRecentContextStore(filepath.Join(root, "recent"))
	now := time.Now()
	targetPath := filepath.Join(root, "proof.conf")
	if err := os.WriteFile(targetPath, []byte("proof"), 0644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := store.RecordFileAccess(common.RecentFileAccessContext{
		TimestampUnixMS: now.UnixMilli(),
		NodeID:          "node-a",
		User:            "khotso",
		PID:             4242,
		Path:            targetPath,
		Access:          "open",
		ExecPath:        "/usr/bin/touch",
		Comm:            "touch",
		Cmdline:         "touch " + targetPath,
		Source:          "auditd_file_access",
	}, time.Minute); err != nil {
		t.Fatalf("record file access: %v", err)
	}

	recorder := &recordingPublisher{}
	logger, err := logging.NewLogger("INFO")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	attributed, eventID, data, metadata := buildFileEvent("inotify", "node-a", targetPath, "modified", store, time.Minute, time.Minute)
	if !attributed {
		t.Fatalf("expected attribution for %s", targetPath)
	}
	if ok := publishFileEvent(recorder, logger, eventID, data, metadata); !ok {
		t.Fatalf("publish failed")
	}

	if len(recorder.payloads) != 1 {
		t.Fatalf("payload count=%d, want 1", len(recorder.payloads))
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.payloads[0], &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["user"] != "khotso" {
		t.Fatalf("user=%v, want khotso", payload["user"])
	}
	if payload["comm"] != "touch" {
		t.Fatalf("comm=%v, want touch", payload["comm"])
	}
	if payload["attribution_source"] != "auditd_file_access" {
		t.Fatalf("attribution_source=%v, want auditd_file_access", payload["attribution_source"])
	}
}

type recordingPublisher struct {
	payloads [][]byte
}

func (r *recordingPublisher) Publish(_ context.Context, _ string, payload []byte) (bool, error) {
	r.payloads = append(r.payloads, append([]byte(nil), payload...))
	return false, nil
}
