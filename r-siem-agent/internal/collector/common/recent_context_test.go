package common

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFindFileAttributionPrefersExactFileAccess(t *testing.T) {
	root := t.TempDir()
	store := NewRecentContextStore(root)
	now := time.Now()

	if err := store.RecordExec(RecentExecContext{
		TimestampUnixMS: now.Add(-2 * time.Second).UnixMilli(),
		NodeID:          "node-a",
		User:            "shell-user",
		PID:             1001,
		ExecPath:        "/usr/bin/touch",
		Comm:            "touch",
		Cmdline:         "touch /etc/sudoers.d/proof",
		Source:          "auditd_exec",
	}, 5*time.Minute); err != nil {
		t.Fatalf("record exec: %v", err)
	}
	if err := store.RecordFileAccess(RecentFileAccessContext{
		TimestampUnixMS: now.Add(-1 * time.Second).UnixMilli(),
		NodeID:          "node-a",
		User:            "audit-user",
		PID:             1002,
		Path:            "/etc/sudoers.d/proof",
		Access:          "open",
		ExecPath:        "/usr/bin/vim",
		Comm:            "vim",
		Cmdline:         "vim /etc/sudoers.d/proof",
		Source:          "auditd_file_access",
	}, 5*time.Minute); err != nil {
		t.Fatalf("record file access: %v", err)
	}

	attr, ok := store.FindFileAttribution("node-a", "/etc/sudoers.d/proof", now, 5*time.Minute, 5*time.Minute)
	if !ok {
		t.Fatal("expected attribution")
	}
	if attr.User != "audit-user" {
		t.Fatalf("user=%q, want audit-user", attr.User)
	}
	if attr.Comm != "vim" {
		t.Fatalf("comm=%q, want vim", attr.Comm)
	}
}

func TestFindFileAttributionFallsBackToProcessHint(t *testing.T) {
	root := t.TempDir()
	store := NewRecentContextStore(root)
	now := time.Now()

	if err := store.RecordExec(RecentExecContext{
		TimestampUnixMS: now.Add(-1 * time.Second).UnixMilli(),
		NodeID:          "node-a",
		User:            "shell-user",
		PID:             1001,
		ExecPath:        "/usr/bin/touch",
		Comm:            "touch",
		Cmdline:         "touch /etc/sudoers.d/proof",
		Source:          "auditd_exec",
	}, 5*time.Minute); err != nil {
		t.Fatalf("record exec: %v", err)
	}

	attr, ok := store.FindFileAttribution("node-a", filepath.Clean("/etc/sudoers.d/proof"), now, 5*time.Minute, 5*time.Minute)
	if !ok {
		t.Fatal("expected attribution")
	}
	if attr.User != "shell-user" {
		t.Fatalf("user=%q, want shell-user", attr.User)
	}
	if attr.Comm != "touch" {
		t.Fatalf("comm=%q, want touch", attr.Comm)
	}
}

func TestFindFileAttributionFallsBackToParentDirectoryAccess(t *testing.T) {
	root := t.TempDir()
	store := NewRecentContextStore(root)
	now := time.Now()

	if err := store.RecordFileAccess(RecentFileAccessContext{
		TimestampUnixMS: now.Add(-1 * time.Second).UnixMilli(),
		NodeID:          "node-a",
		User:            "shell-user",
		PID:             1001,
		Path:            "/etc/sudoers.d",
		Access:          "open",
		ExecPath:        "/usr/bin/sudo",
		Comm:            "sudo",
		Cmdline:         "sudo touch /etc/sudoers.d/proof",
		Source:          "auditd_file_access",
	}, 5*time.Minute); err != nil {
		t.Fatalf("record file access: %v", err)
	}

	attr, ok := store.FindFileAttribution("node-a", "/etc/sudoers.d/proof", now, 5*time.Minute, 5*time.Minute)
	if !ok {
		t.Fatal("expected parent-directory attribution")
	}
	if attr.User != "shell-user" {
		t.Fatalf("user=%q, want shell-user", attr.User)
	}
	if attr.Comm != "sudo" {
		t.Fatalf("comm=%q, want sudo", attr.Comm)
	}
}

func TestFindFileAttributionNoDefensibleContext(t *testing.T) {
	root := t.TempDir()
	store := NewRecentContextStore(root)
	now := time.Now()

	if err := store.RecordExec(RecentExecContext{
		TimestampUnixMS: now.Add(-1 * time.Second).UnixMilli(),
		NodeID:          "node-a",
		User:            "shell-user",
		PID:             1001,
		ExecPath:        "/usr/bin/bash",
		Comm:            "bash",
		Cmdline:         "bash -lc echo test",
		Source:          "auditd_exec",
	}, 5*time.Minute); err != nil {
		t.Fatalf("record exec: %v", err)
	}

	if _, ok := store.FindFileAttribution("node-a", "/etc/sudoers.d/proof", now, 5*time.Minute, 5*time.Minute); ok {
		t.Fatal("expected no attribution without defensible path/process context")
	}
}
