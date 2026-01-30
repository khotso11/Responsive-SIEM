package main

import (
	"strings"
	"testing"
	"time"
)

func TestParsePendingApprovals(t *testing.T) {
	data := strings.Join([]string{
		`{"msg":"response_run_created","run_id":"run-1","rule_id":"R1","playbook_id":"PB1","lane":"FAST","created_at_unix_ms":1000,"approval_timeout_ms":60000}`,
		`{"msg":"response_run_waiting_approval","run_id":"run-1","rule_id":"R1","playbook_id":"PB1","timeout_ms":60000}`,
		`{"msg":"response_run_created","run_id":"run-2","rule_id":"R2","playbook_id":"PB2","lane":"STANDARD","created_at_unix_ms":2000}`,
		`{"msg":"response_run_updated","run_id":"run-2","status":"WAITING_APPROVAL"}`,
		`{"msg":"response_run_created","run_id":"run-3","rule_id":"R3","playbook_id":"PB3","created_at_unix_ms":1500}`,
		`{"msg":"response_run_updated","run_id":"run-3","status":"RUNNING"}`,
	}, "\n")

	entries, err := parsePendingApprovals(strings.NewReader(data))
	if err != nil {
		t.Fatalf("parsePendingApprovals: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%d, want 2", len(entries))
	}
	if entries[0].RunID != "run-1" {
		t.Fatalf("first run_id=%s, want run-1", entries[0].RunID)
	}
	if entries[1].RunID != "run-2" {
		t.Fatalf("second run_id=%s, want run-2", entries[1].RunID)
	}
	if entries[0].RuleID != "R1" || entries[0].PlaybookID != "PB1" {
		t.Fatalf("run-1 fields missing")
	}
	if entries[1].Lane != "STANDARD" {
		t.Fatalf("run-2 lane=%s, want STANDARD", entries[1].Lane)
	}
}

func TestFilterApprovalsLaneOlderThanSortLimit(t *testing.T) {
	entries := []approvalEntry{
		{
			RunID:           "run-1",
			RuleID:          "R1",
			PlaybookID:      "PB1",
			Lane:            "FAST",
			CreatedAtUnixMs: 1000,
			Status:          "WAITING_APPROVAL",
		},
		{
			RunID:           "run-2",
			RuleID:          "R2",
			PlaybookID:      "PB2",
			Lane:            "STANDARD",
			CreatedAtUnixMs: 2000,
			Status:          "WAITING_APPROVAL",
		},
		{
			RunID:           "run-3",
			RuleID:          "R3",
			PlaybookID:      "PB3",
			Lane:            "FAST",
			CreatedAtUnixMs: 3000,
			Status:          "WAITING_APPROVAL",
		},
		{
			RunID:           "run-4",
			RuleID:          "R4",
			PlaybookID:      "PB4",
			Lane:            "FAST",
			CreatedAtUnixMs: 4000,
			Status:          "RUNNING",
		},
	}
	now := time.UnixMilli(6000)

	got, err := filterApprovals(entries, now, "FAST", 0, "oldest", 0)
	if err != nil {
		t.Fatalf("filterApprovals lane: %v", err)
	}
	if len(got) != 2 || got[0].RunID != "run-1" || got[1].RunID != "run-3" {
		t.Fatalf("lane filter got=%v", got)
	}

	got, err = filterApprovals(entries, now, "ALL", 5*time.Second, "oldest", 0)
	if err != nil {
		t.Fatalf("filterApprovals older-than: %v", err)
	}
	if len(got) != 1 || got[0].RunID != "run-1" {
		t.Fatalf("older-than filter got=%v", got)
	}

	got, err = filterApprovals(entries, now, "ALL", 0, "newest", 0)
	if err != nil {
		t.Fatalf("filterApprovals sort: %v", err)
	}
	if len(got) == 0 || got[0].RunID != "run-3" {
		t.Fatalf("sort newest got=%v", got)
	}

	got, err = filterApprovals(entries, now, "ALL", 0, "oldest", 1)
	if err != nil {
		t.Fatalf("filterApprovals limit: %v", err)
	}
	if len(got) != 1 || got[0].RunID != "run-1" {
		t.Fatalf("limit got=%v", got)
	}
}
