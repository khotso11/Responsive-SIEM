package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"r-siem-agent/internal/collector/common"
)

func TestBuildAuditConnectPayloadIPv4(t *testing.T) {
	item := pendingAuditEvent{
		syscallLine: `type=SYSCALL msg=audit(1773300000.123:77): arch=c000003e syscall=42 success=yes exit=0 pid=4242 ppid=1000 comm="nmap" exe="/usr/bin/nmap" uid=1000 auid=1000`,
		execveLine:  `type=EXECVE msg=audit(1773300000.123:77): argc=3 a0="nmap" a1="-sT" a2="172.30.50.11"`,
		sockaddrLines: []string{
			`type=SOCKADDR msg=audit(1773300000.123:77): saddr=02000016AC1E320B0000000000000000`,
		},
		eventTs: 1773300000123,
	}

	payload, ok := buildAuditConnectPayload(item, "node-a", "auditd_connect")
	if !ok {
		t.Fatalf("expected connect payload")
	}
	if got := payload["event_type"]; got != "network_connection" {
		t.Fatalf("event_type=%v", got)
	}
	if got := payload["source_type"]; got != "auditd_connect" {
		t.Fatalf("source_type=%v", got)
	}
	if got := payload["dst_ip"]; got != "172.30.50.11" {
		t.Fatalf("dst_ip=%v", got)
	}
	if got := payload["dst_port"]; got != 22 {
		t.Fatalf("dst_port=%v", got)
	}
	if got := payload["connect_success"]; got != true {
		t.Fatalf("connect_success=%v", got)
	}
}

func TestBuildAuditConnectPayloadFailedAttemptStillEmits(t *testing.T) {
	item := pendingAuditEvent{
		syscallLine: `type=SYSCALL msg=audit(1773300000.123:77): arch=c000003e syscall=42 success=no exit=-115 pid=4242 ppid=1000 comm="nmap" exe="/usr/bin/nmap" uid=1000 auid=1000`,
		execveLine:  `type=EXECVE msg=audit(1773300000.123:77): argc=3 a0="nmap" a1="-sT" a2="172.30.50.12"`,
		sockaddrLines: []string{
			`type=SOCKADDR msg=audit(1773300000.123:77): saddr=020001BBAC1E320C0000000000000000`,
		},
		eventTs: 1773300000123,
	}

	payload, ok := buildAuditConnectPayload(item, "node-a", "auditd_connect")
	if !ok {
		t.Fatalf("expected connect payload")
	}
	if got := payload["dst_ip"]; got != "172.30.50.12" {
		t.Fatalf("dst_ip=%v", got)
	}
	if got := payload["dst_port"]; got != 443 {
		t.Fatalf("dst_port=%v", got)
	}
	if got := payload["connect_success"]; got != false {
		t.Fatalf("connect_success=%v", got)
	}
	if got := payload["exit_code"]; got != -115 {
		t.Fatalf("exit_code=%v", got)
	}
}

func TestBuildAuditConnectPayloadDecodedSockaddr(t *testing.T) {
	item := pendingAuditEvent{
		syscallLine: `type=SYSCALL msg=audit(1773300000.123:77): arch=c000003e syscall=42 success=no exit=-115 pid=4242 ppid=1000 comm="nmap" exe="/usr/bin/nmap" uid=1000 auid=1000`,
		execveLine:  `type=EXECVE msg=audit(1773300000.123:77): argc=3 a0="nmap" a1="-sT" a2="172.30.50.14"`,
		sockaddrLines: []string{
			`type=SOCKADDR msg=audit(1773300000.123:77): SADDR={ saddr_fam=inet laddr=172.30.50.14 lport=5985 }`,
		},
		eventTs: 1773300000123,
	}

	payload, ok := buildAuditConnectPayload(item, "node-a", "auditd_connect")
	if !ok {
		t.Fatalf("expected connect payload")
	}
	if got := payload["dst_ip"]; got != "172.30.50.14" {
		t.Fatalf("dst_ip=%v", got)
	}
	if got := payload["dst_port"]; got != 5985 {
		t.Fatalf("dst_port=%v", got)
	}
}

func TestShouldRetainPendingAuditEventForIncompleteConnect(t *testing.T) {
	item := pendingAuditEvent{
		syscallLine: `type=SYSCALL msg=audit(1773300000.123:77): arch=c000003e syscall=42 success=no exit=-115 pid=4242 ppid=1000 comm="nmap" exe="/usr/bin/nmap" uid=1000 auid=1000`,
		lastSeen:    time.Now(),
	}
	if !shouldRetainPendingAuditEvent(item) {
		t.Fatal("expected incomplete connect event to be retained briefly")
	}
	item.lastSeen = time.Now().Add(-6 * time.Second)
	if shouldRetainPendingAuditEvent(item) {
		t.Fatal("expected stale incomplete connect event to be discarded")
	}
}

func TestPublishPendingAuditConnectEventDeletesCompletedConnect(t *testing.T) {
	tmpDir := t.TempDir()
	publisher, err := common.NewOfflinePublisher(common.OfflinePublisherConfig{
		Name:      "collector-auditd-test",
		URL:       "nats://127.0.0.1:1",
		Stream:    "RSIEM_EVENTS",
		Subject:   "rsiem.events.raw",
		SpoolPath: filepath.Join(tmpDir, "spool.jsonl"),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewOfflinePublisher: %v", err)
	}
	defer publisher.Close()

	pending := map[string]pendingAuditEvent{
		"1773300000.123:77": {
			syscallLine: `type=SYSCALL msg=audit(1773300000.123:77): arch=c000003e syscall=42 success=no exit=-115 pid=4242 ppid=1000 comm="nmap" exe="/usr/bin/nmap" uid=1000 auid=1000`,
			execveLine:  `type=EXECVE msg=audit(1773300000.123:77): argc=3 a0="nmap" a1="-sT" a2="172.30.50.12"`,
			sockaddrLines: []string{
				`type=SOCKADDR msg=audit(1773300000.123:77): saddr=020001BBAC1E320C0000000000000000`,
			},
			eventTs:  1773300000123,
			lastSeen: time.Now(),
		},
	}

	publishPendingAuditConnectEvent(pending, "1773300000.123:77", "node-a", "auditd_connect", publisher, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, ok := pending["1773300000.123:77"]; ok {
		t.Fatal("expected completed connect event to be removed from pending map")
	}
}

func TestPublishPendingAuditConnectEventAfterSockaddrThenSyscall(t *testing.T) {
	tmpDir := t.TempDir()
	publisher, err := common.NewOfflinePublisher(common.OfflinePublisherConfig{
		Name:      "collector-auditd-test",
		URL:       "nats://127.0.0.1:1",
		Stream:    "RSIEM_EVENTS",
		Subject:   "rsiem.events.raw",
		SpoolPath: filepath.Join(tmpDir, "spool.jsonl"),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewOfflinePublisher: %v", err)
	}
	defer publisher.Close()

	pending := map[string]pendingAuditEvent{
		"1773300000.123:77": {
			sockaddrLines: []string{
				`type=SOCKADDR msg=audit(1773300000.123:77): SADDR={ saddr_fam=inet laddr=172.30.50.14 lport=5985 }`,
			},
			eventTs:  1773300000123,
			lastSeen: time.Now(),
		},
	}

	publishPendingAuditConnectEvent(pending, "1773300000.123:77", "node-a", "auditd_connect", publisher, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, ok := pending["1773300000.123:77"]; !ok {
		t.Fatal("expected incomplete connect event to remain pending before syscall arrives")
	}

	item := pending["1773300000.123:77"]
	item.syscallLine = `type=SYSCALL msg=audit(1773300000.123:77): arch=c000003e syscall=42 success=no exit=-115 pid=4242 ppid=1000 comm="nmap" exe="/usr/bin/nmap" uid=1000 auid=1000`
	item.execveLine = `type=EXECVE msg=audit(1773300000.123:77): argc=3 a0="nmap" a1="-sT" a2="172.30.50.14"`
	pending["1773300000.123:77"] = item

	publishPendingAuditConnectEvent(pending, "1773300000.123:77", "node-a", "auditd_connect", publisher, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, ok := pending["1773300000.123:77"]; ok {
		t.Fatal("expected connect event to publish and be removed once syscall arrives")
	}
}

func TestRunPublishesConnectFromSockaddrThenSyscall(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.log")
	spoolPath := filepath.Join(tmpDir, "spool.jsonl")
	checkpointPath := filepath.Join(tmpDir, "audit.checkpoint")
	lines := strings.Join([]string{
		`type=SOCKADDR msg=audit(1773300000.123:77): saddr={ saddr_fam=inet laddr=172.30.50.14 lport=5985 }`,
		`type=SYSCALL msg=audit(1773300000.123:77): arch=c000003e syscall=42 success=no exit=-115 pid=81671 ppid=7379 comm="nmap" exe="/usr/bin/nmap" uid=1000 auid=1000 tty=pts0 ses=3`,
	}, "\n") + "\n"
	if err := os.WriteFile(auditPath, []byte(lines), 0o644); err != nil {
		t.Fatalf("WriteFile(auditPath): %v", err)
	}

	publisher, err := common.NewOfflinePublisher(common.OfflinePublisherConfig{
		Name:      "collector-auditd-test",
		URL:       "nats://127.0.0.1:1",
		Stream:    "RSIEM_EVENTS",
		Subject:   "rsiem.events.raw",
		SpoolPath: spoolPath,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewOfflinePublisher: %v", err)
	}
	defer publisher.Close()

	cfg := &configFile{}
	cfg.Collector.Path = auditPath
	cfg.Collector.CheckpointPath = checkpointPath
	cfg.Collector.PollMs = 10
	cfg.Collector.NodeID = "node-a"
	cfg.Collector.SourceType = "auditd_exec"
	cfg.Collector.ConnectSourceType = "auditd_connect"
	cfg.Collector.RecentContextRoot = filepath.Join(tmpDir, "recent-context")
	cfg.Collector.ExecContextMaxAgeMS = 120000
	cfg.Collector.FileAccessContextMaxAgeMS = 30000

	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	err = run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), publisher)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("run() error = %v", err)
	}

	spooled, err := os.ReadFile(spoolPath)
	if err != nil {
		t.Fatalf("ReadFile(spoolPath): %v", err)
	}
	type queued struct {
		Seq     uint64 `json:"seq"`
		EventID string `json:"event_id"`
		DataB64 string `json:"data_b64"`
	}
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(string(spooled)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec queued
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("json.Unmarshal(spool line): %v", err)
		}
		data, err := base64.StdEncoding.DecodeString(rec.DataB64)
		if err != nil {
			t.Fatalf("base64 decode: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatalf("json.Unmarshal(payload): %v", err)
		}
		if payload["event_type"] != "network_connection" {
			continue
		}
		found = true
		if got := payload["exec_path"]; got != "/usr/bin/nmap" {
			t.Fatalf("exec_path=%v", got)
		}
		if got := payload["dst_ip"]; got != "172.30.50.14" {
			t.Fatalf("dst_ip=%v", got)
		}
		if got := payload["dst_port"]; got != float64(5985) {
			t.Fatalf("dst_port=%v", got)
		}
	}
	if !found {
		t.Fatal("expected network_connection payload in spool")
	}
}

func TestReopenAuditFileIfRotatedResetsOffset(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	checkpointPath := filepath.Join(dir, "audit.checkpoint")
	oldContents := "old line\n"
	if err := os.WriteFile(logPath, []byte(oldContents), 0o644); err != nil {
		t.Fatalf("write old audit log: %v", err)
	}

	file, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open old audit log: %v", err)
	}
	defer file.Close()

	rotatedPath := filepath.Join(dir, "audit.log.1")
	if err := os.Rename(logPath, rotatedPath); err != nil {
		t.Fatalf("rotate audit log: %v", err)
	}
	newContents := "new line\n"
	if err := os.WriteFile(logPath, []byte(newContents), 0o644); err != nil {
		t.Fatalf("write new audit log: %v", err)
	}

	reopened, offset, err := reopenAuditFileIfRotated(file, logPath, checkpointPath, 9876, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("reopenAuditFileIfRotated error: %v", err)
	}
	defer reopened.Close()

	if offset != 0 {
		t.Fatalf("expected offset reset to 0, got %d", offset)
	}

	currentInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat new audit log: %v", err)
	}
	reopenedInfo, err := reopened.Stat()
	if err != nil {
		t.Fatalf("stat reopened file: %v", err)
	}
	if !os.SameFile(currentInfo, reopenedInfo) {
		t.Fatalf("expected reopened file to point at new audit.log")
	}

	data, err := io.ReadAll(reopened)
	if err != nil {
		t.Fatalf("read reopened file: %v", err)
	}
	if string(data) != newContents {
		t.Fatalf("unexpected reopened contents %q", string(data))
	}

	checkpointData, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	if strings.TrimSpace(string(checkpointData)) != "0" {
		t.Fatalf("expected checkpoint reset to 0, got %q", string(checkpointData))
	}
}

func TestBuildAuditFileAccessContexts(t *testing.T) {
	item := pendingAuditEvent{
		syscallLine: `type=SYSCALL msg=audit(1773300000.123:77): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55f name="/etc/sudoers.d/rsiem-proof" pid=4242 ppid=1000 comm="touch" exe="/usr/bin/touch" uid=1000 auid=1000`,
		execveLine:  `type=EXECVE msg=audit(1773300000.123:77): argc=2 a0="touch" a1="/etc/sudoers.d/rsiem-proof"`,
		pathLines: []string{
			`type=PATH msg=audit(1773300000.123:77): item=0 name="/etc/sudoers.d/rsiem-proof" inode=1 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0`,
		},
		eventTs: 1773300000123,
	}

	contexts := buildAuditFileAccessContexts(item, "node-a")
	if len(contexts) != 1 {
		t.Fatalf("len(contexts)=%d, want 1", len(contexts))
	}
	if contexts[0].Path != "/etc/sudoers.d/rsiem-proof" {
		t.Fatalf("path=%q", contexts[0].Path)
	}
	if contexts[0].Comm != "touch" {
		t.Fatalf("comm=%q", contexts[0].Comm)
	}
	if contexts[0].ExecPath != "/usr/bin/touch" {
		t.Fatalf("exec_path=%q", contexts[0].ExecPath)
	}
	if contexts[0].Cmdline != "touch /etc/sudoers.d/rsiem-proof" {
		t.Fatalf("cmdline=%q", contexts[0].Cmdline)
	}
}

func TestBuildAuditFileAccessContextsPrioritizesTargetPathAndParent(t *testing.T) {
	item := pendingAuditEvent{
		syscallLine: `type=SYSCALL msg=audit(1773300000.123:77): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55f pid=4242 ppid=1000 comm="sudo" exe="/usr/bin/sudo" uid=1000 auid=1000`,
		execveLine:  `type=EXECVE msg=audit(1773300000.123:77): argc=3 a0="sudo" a1="touch" a2="/etc/sudoers.d/rsiem-proof"`,
		pathLines: []string{
			`type=PATH msg=audit(1773300000.123:77): item=0 name="/etc/passwd"`,
			`type=PATH msg=audit(1773300000.123:77): item=1 name="/etc/sudoers.d"`,
			`type=PATH msg=audit(1773300000.123:77): item=2 name="/etc/login.defs"`,
		},
		eventTs: 1773300000123,
	}

	contexts := buildAuditFileAccessContexts(item, "node-a")
	if len(contexts) != 1 {
		t.Fatalf("len(contexts)=%d, want 1", len(contexts))
	}
	if contexts[0].Path != "/etc/sudoers.d" {
		t.Fatalf("path=%q, want /etc/sudoers.d", contexts[0].Path)
	}
}

func TestBuildAuditFileAccessContextsIgnoresNonFileAccessSyscall(t *testing.T) {
	item := pendingAuditEvent{
		syscallLine: `type=SYSCALL msg=audit(1773300000.123:77): arch=c000003e syscall=59 success=yes pid=4242 comm="touch" exe="/usr/bin/touch" uid=1000 auid=1000`,
		pathLines: []string{
			`type=PATH msg=audit(1773300000.123:77): item=0 name="/etc/sudoers.d/rsiem-proof"`,
		},
		eventTs: 1773300000123,
	}
	if contexts := buildAuditFileAccessContexts(item, "node-a"); len(contexts) != 0 {
		t.Fatalf("len(contexts)=%d, want 0", len(contexts))
	}
}
