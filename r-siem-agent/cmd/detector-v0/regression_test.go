package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"r-siem-agent/internal/config"
)

type regressionFixture struct {
	Name   string                 `json:"name"`
	Events []regressionFixtureEvt `json:"events"`
}

type regressionFixtureEvt struct {
	Event  rawEvent                  `json:"event"`
	Expect regressionFixtureExpected `json:"expect"`
}

type regressionFixtureExpected struct {
	Matched    bool   `json:"matched"`
	RuleID     string `json:"rule_id"`
	Lane       string `json:"lane"`
	Severity   string `json:"severity"`
	GroupKey   string `json:"group_key"`
	User       string `json:"user"`
	ExecPath   string `json:"exec_path"`
	Comm       string `json:"comm"`
	Cmdline    string `json:"cmdline"`
	NoExecPath bool   `json:"no_exec_path"`
	NoComm     bool   `json:"no_comm"`
	NoCmdline  bool   `json:"no_cmdline"`
}

func TestDetectorRegressionFixtures(t *testing.T) {
	cfg := loadDetectorRegressionConfig(t)
	filter := strings.TrimSpace(os.Getenv("DETECTOR_FIXTURE_FILTER"))
	fixturePaths := loadDetectorRegressionFixturePaths(t)
	if len(fixturePaths) == 0 {
		t.Fatal("no detector regression fixtures found")
	}
	for _, path := range fixturePaths {
		fixture := loadDetectorRegressionFixture(t, path)
		if filter != "" && !strings.Contains(strings.ToLower(fixture.Name), strings.ToLower(filter)) && !strings.Contains(strings.ToLower(filepath.Base(path)), strings.ToLower(filter)) {
			continue
		}
		t.Run(fixture.Name, func(t *testing.T) {
			resetDetectorRegressionState(cfg)
			for idx, step := range fixture.Events {
				evt := step.Event
				if evt.ObservedAtUnixMs == 0 {
					evt.ObservedAtUnixMs = int64((idx + 1) * 1000)
				}
				msg := eventMessage(evt)
				enriched := enrichNetworkEventIdentity(evt)
				match, matched := matchRule(msg, enriched)
				if matched != step.Expect.Matched {
					t.Fatalf("event %d matched=%v want %v", idx, matched, step.Expect.Matched)
				}
				if matched {
					if match.RuleID != step.Expect.RuleID {
						t.Fatalf("event %d rule_id=%q want %q", idx, match.RuleID, step.Expect.RuleID)
					}
					if step.Expect.Lane != "" && match.Lane != step.Expect.Lane {
						t.Fatalf("event %d lane=%q want %q", idx, match.Lane, step.Expect.Lane)
					}
					if step.Expect.Severity != "" && match.Severity != step.Expect.Severity {
						t.Fatalf("event %d severity=%q want %q", idx, match.Severity, step.Expect.Severity)
					}
					if step.Expect.GroupKey != "" && match.GroupKey != step.Expect.GroupKey {
						t.Fatalf("event %d group_key=%q want %q", idx, match.GroupKey, step.Expect.GroupKey)
					}
					recordSuspiciousProcessContext(match, enriched)
				}
				if step.Expect.User != "" && enriched.User != step.Expect.User {
					t.Fatalf("event %d enriched user=%q want %q", idx, enriched.User, step.Expect.User)
				}
				if step.Expect.ExecPath != "" && enriched.ExecPath != step.Expect.ExecPath {
					t.Fatalf("event %d enriched exec_path=%q want %q", idx, enriched.ExecPath, step.Expect.ExecPath)
				}
				if step.Expect.NoExecPath && enriched.ExecPath != "" {
					t.Fatalf("event %d enriched exec_path=%q want empty", idx, enriched.ExecPath)
				}
				if step.Expect.Comm != "" && enriched.Comm != step.Expect.Comm {
					t.Fatalf("event %d enriched comm=%q want %q", idx, enriched.Comm, step.Expect.Comm)
				}
				if step.Expect.NoComm && enriched.Comm != "" {
					t.Fatalf("event %d enriched comm=%q want empty", idx, enriched.Comm)
				}
				if step.Expect.Cmdline != "" && enriched.Cmdline != step.Expect.Cmdline {
					t.Fatalf("event %d enriched cmdline=%q want %q", idx, enriched.Cmdline, step.Expect.Cmdline)
				}
				if step.Expect.NoCmdline && enriched.Cmdline != "" {
					t.Fatalf("event %d enriched cmdline=%q want empty", idx, enriched.Cmdline)
				}
			}
		})
	}
}

func loadDetectorRegressionConfig(t *testing.T) *config.DetectorConfig {
	t.Helper()
	cfg, err := config.LoadDetector(filepath.Join("..", "..", "configs", "detector.yaml"))
	if err != nil {
		t.Fatalf("load detector config: %v", err)
	}
	return cfg
}

func resetDetectorRegressionState(cfg *config.DetectorConfig) {
	fr03HostBurstTracker = newBurstTracker(fr03HostBurstWindowMs, fr03HostBurstThreshold)
	processBurstTracker = newBurstTracker(processBurstWindowMs, processCountThreshold)
	countFailedPwSrcTracker = newBurstTracker(countFailedPwWindowMs, countFailedPwThreshold)
	authFailedPwBurstUserTracker = newBurstTracker(authBurstUserWindowMs, authBurstUserThreshold)
	authFailedPwBurstSrcTracker = newBurstTracker(authBurstSrcWindowMs, authBurstSrcThreshold)
	recentAuthByNode = newLastSeenTracker(5 * time.Minute)
	recentLocalAdminByNode = newLastSeenTracker(2 * time.Minute)
	recentSuspiciousProcByNode = newLastSeenTracker(2 * time.Minute)
	recentSuspiciousProcContext = newRecentProcessContextTracker(2 * time.Minute)
	recentAuthProcByNode = newLastSeenTracker(5 * time.Minute)
	recentFileAlertByPath = newLastSeenTracker(15 * time.Second)
	recentInfrastructureTrapBySource = newLastSeenTracker(2 * time.Minute)
	initNetworkPolicy(cfg)
	initInfrastructurePolicy(cfg)
	initBaselinePolicy(cfg)
}

func loadDetectorRegressionFixturePaths(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join("testdata", "regressions", "*.json"))
	if err != nil {
		t.Fatalf("glob fixtures: %v", err)
	}
	sort.Strings(matches)
	return matches
}

func loadDetectorRegressionFixture(t *testing.T, path string) regressionFixture {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var fixture regressionFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	if strings.TrimSpace(fixture.Name) == "" {
		fixture.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if len(fixture.Events) == 0 {
		t.Fatalf("fixture %s has no events", path)
	}
	return fixture
}

func TestDetectorRegressionFixtureCatalog(t *testing.T) {
	paths := loadDetectorRegressionFixturePaths(t)
	names := make([]string, 0, len(paths))
	for _, path := range paths {
		fixture := loadDetectorRegressionFixture(t, path)
		names = append(names, fmt.Sprintf("%s:%d", fixture.Name, len(fixture.Events)))
	}
	if len(names) < 6 {
		t.Fatalf("expected at least 6 regression fixtures, got %d (%v)", len(names), names)
	}
}
