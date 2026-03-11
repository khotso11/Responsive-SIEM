package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadTCPResolvesProcessOwnerFromSocketInode(t *testing.T) {
	procRoot := t.TempDir()
	writeProcNetTCP(t, procRoot, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 15012A0A:01BB 5D2164AC:115C 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 -1\n")

	pidDir := filepath.Join(procRoot, "4242")
	if err := os.MkdirAll(filepath.Join(pidDir, "fd"), 0o755); err != nil {
		t.Fatalf("mkdir pid dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte("Name:\tnmap\nUid:\t1000\t1000\t1000\t1000\n"), 0o644); err != nil {
		t.Fatalf("write status: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("nmap\n"), 0o644); err != nil {
		t.Fatalf("write comm: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("/usr/bin/nmap\x00--version\x00"), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	exeTarget := filepath.Join(procRoot, "bin", "nmap")
	if err := os.MkdirAll(filepath.Dir(exeTarget), 0o755); err != nil {
		t.Fatalf("mkdir exe dir: %v", err)
	}
	if err := os.WriteFile(exeTarget, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write exe target: %v", err)
	}
	if err := os.Symlink(exeTarget, filepath.Join(pidDir, "exe")); err != nil {
		t.Fatalf("symlink exe: %v", err)
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(pidDir, "fd", "7")); err != nil {
		t.Fatalf("symlink fd: %v", err)
	}

	entries, err := readTCP(procRoot, true)
	if err != nil {
		t.Fatalf("readTCP: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	got := entries[0]
	if got.PID != 4242 {
		t.Fatalf("expected pid 4242, got %d", got.PID)
	}
	if strings.TrimSpace(got.Comm) != "nmap" {
		t.Fatalf("expected comm nmap, got %q", got.Comm)
	}
	if !strings.Contains(got.Cmdline, "/usr/bin/nmap --version") {
		t.Fatalf("expected cmdline to contain nmap --version, got %q", got.Cmdline)
	}
	if got.ExecPath != exeTarget {
		t.Fatalf("expected exec path %q, got %q", exeTarget, got.ExecPath)
	}
	if got.User == "" || got.User == "unknown" {
		t.Fatalf("expected resolved user, got %q", got.User)
	}
}

func TestReadTCPFallsBackToUIDUsernameWithoutSocketOwner(t *testing.T) {
	procRoot := t.TempDir()
	writeProcNetTCP(t, procRoot, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 0100007F:1770 15012A0A:0050 01 00000000:00000000 00:00000000 00000000  0        0 67890 1 0000000000000000 20 0 0 10 -1\n")

	entries, err := readTCP(procRoot, true)
	if err != nil {
		t.Fatalf("readTCP: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].User == "" || entries[0].User == "unknown" {
		t.Fatalf("expected uid fallback to resolve user, got %q", entries[0].User)
	}
}

func writeProcNetTCP(t *testing.T, procRoot, content string) {
	t.Helper()
	path := filepath.Join(procRoot, "net")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir net dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "tcp"), []byte(content), 0o644); err != nil {
		t.Fatalf("write tcp file: %v", err)
	}
}
