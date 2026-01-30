package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

type approvalEntry struct {
	RunID                 string
	RuleID                string
	PlaybookID            string
	Lane                  string
	CreatedAtUnixMs       int64
	ApprovalRequestedAtMs int64
	ApprovalTimeoutMs     int64
	Status                string
}

type runEvent struct {
	Msg                      string `json:"msg"`
	RunID                    string `json:"run_id"`
	RuleID                   string `json:"rule_id"`
	PlaybookID               string `json:"playbook_id"`
	Lane                     string `json:"lane"`
	Status                   string `json:"status"`
	CreatedAtUnixMs          int64  `json:"created_at_unix_ms"`
	ApprovalRequestedAtUnixMs int64 `json:"approval_requested_at_unix_ms"`
	ApprovalTimeoutMs        int64  `json:"approval_timeout_ms"`
	TimeoutMs                int64  `json:"timeout_ms"`
}

func main() {
	path := flag.String("path", "exports/roe_runs.jsonl", "Path to roe_runs.jsonl")
	lane := flag.String("lane", "ALL", "FAST|STANDARD|ALL")
	olderThan := flag.Duration("older-than", 0, "Only include approvals older than this duration")
	limit := flag.Int("limit", 0, "Limit number of results (0 = no limit)")
	sortOrder := flag.String("sort", "oldest", "Sort order: newest|oldest")
	flag.Parse()

	file, err := os.Open(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", *path, err)
		os.Exit(1)
	}
	defer file.Close()

	entries, err := parsePendingApprovals(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse approvals: %v\n", err)
		os.Exit(1)
	}

	filtered, err := filterApprovals(entries, time.Now(), *lane, *olderThan, *sortOrder, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "filter approvals: %v\n", err)
		os.Exit(1)
	}
	for _, entry := range filtered {
		fmt.Printf("run_id=%s rule_id=%s playbook_id=%s lane=%s created_at=%s age=%s timeout_ms=%d\n",
			entry.RunID, entry.RuleID, entry.PlaybookID, entry.Lane, entry.createdAt, entry.age, entry.ApprovalTimeoutMs)
	}
}

func parsePendingApprovals(r io.Reader) ([]approvalEntry, error) {
	entries, err := parseApprovalEvents(r)
	if err != nil {
		return nil, err
	}
	pending := make([]approvalEntry, 0)
	for _, entry := range entries {
		if entry.Status == "WAITING_APPROVAL" {
			pending = append(pending, entry)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].CreatedAtUnixMs < pending[j].CreatedAtUnixMs
	})
	return pending, nil
}

type approvalView struct {
	approvalEntry
	createdAt string
	age       string
	sortMs    int64
}

func filterApprovals(entries []approvalEntry, now time.Time, lane string, olderThan time.Duration, sortOrder string, limit int) ([]approvalView, error) {
	lane = strings.ToUpper(strings.TrimSpace(lane))
	if lane == "" {
		lane = "ALL"
	}
	switch lane {
	case "FAST", "STANDARD", "ALL":
	default:
		return nil, fmt.Errorf("invalid lane: %s", lane)
	}
	sortOrder = strings.ToLower(strings.TrimSpace(sortOrder))
	if sortOrder == "" {
		sortOrder = "oldest"
	}
	if sortOrder != "oldest" && sortOrder != "newest" {
		return nil, fmt.Errorf("invalid sort: %s", sortOrder)
	}
	if limit < 0 {
		return nil, fmt.Errorf("invalid limit: %d", limit)
	}

	filtered := make([]approvalView, 0, len(entries))
	for _, entry := range entries {
		if entry.Status != "WAITING_APPROVAL" {
			continue
		}
		if lane != "ALL" && strings.ToUpper(entry.Lane) != lane {
			continue
		}
		createdAtMs := entry.CreatedAtUnixMs
		if createdAtMs <= 0 {
			createdAtMs = entry.ApprovalRequestedAtMs
		}
		if olderThan > 0 && createdAtMs > 0 {
			if now.Sub(time.UnixMilli(createdAtMs)) < olderThan {
				continue
			}
		}
		created := "unknown"
		age := "unknown"
		if createdAtMs > 0 {
			created = time.UnixMilli(createdAtMs).Format(time.RFC3339)
			age = now.Sub(time.UnixMilli(createdAtMs)).Round(time.Second).String()
		}
		laneValue := entry.Lane
		if laneValue == "" {
			laneValue = "-"
		}
		view := approvalView{
			approvalEntry: entry,
			createdAt:     created,
			age:           age,
			sortMs:        createdAtMs,
		}
		view.Lane = laneValue
		filtered = append(filtered, view)
	}

	sort.Slice(filtered, func(i, j int) bool {
		if sortOrder == "newest" {
			return filtered[i].sortMs > filtered[j].sortMs
		}
		return filtered[i].sortMs < filtered[j].sortMs
	})

	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return filtered, nil
}

func parseApprovalEvents(r io.Reader) (map[string]approvalEntry, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	out := make(map[string]approvalEntry)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var event runEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, err
		}
		if event.RunID == "" {
			continue
		}
		existing := out[event.RunID]
		existing.RunID = event.RunID
		if event.RuleID != "" {
			existing.RuleID = event.RuleID
		}
		if event.PlaybookID != "" {
			existing.PlaybookID = event.PlaybookID
		}
		if event.Lane != "" {
			existing.Lane = event.Lane
		}
		if event.CreatedAtUnixMs > 0 {
			existing.CreatedAtUnixMs = event.CreatedAtUnixMs
		}
		if event.ApprovalRequestedAtUnixMs > 0 {
			existing.ApprovalRequestedAtMs = event.ApprovalRequestedAtUnixMs
		}
		if event.ApprovalTimeoutMs > 0 {
			existing.ApprovalTimeoutMs = event.ApprovalTimeoutMs
		}
		if event.TimeoutMs > 0 {
			existing.ApprovalTimeoutMs = event.TimeoutMs
		}
		if event.Status != "" {
			existing.Status = event.Status
		}
		if event.Msg == "response_run_waiting_approval" && existing.Status == "" {
			existing.Status = "WAITING_APPROVAL"
		}
		out[event.RunID] = existing
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
