package tail

import "testing"

func TestExtractAuthMetadata_DemoLine(t *testing.T) {
	line := "FAILED login user=khotso src=10.0.0.8 ts=1700000000"

	eventType, srcIP, user, tsUnix := extractAuthMetadata(line)

	if eventType != "auth_failed" {
		t.Fatalf("event_type=%q, want auth_failed", eventType)
	}
	if srcIP != "10.0.0.8" {
		t.Fatalf("src_ip=%q, want 10.0.0.8", srcIP)
	}
	if user != "khotso" {
		t.Fatalf("user=%q, want khotso", user)
	}
	if tsUnix != 1700000000 {
		t.Fatalf("ts=%d, want 1700000000", tsUnix)
	}
}

func TestExtractAuthMetadata_AuthLogLine(t *testing.T) {
	line := "Feb 19 11:26:01 host sshd[3210]: Failed password for invalid user admin from 10.0.0.22 port 51150 ssh2"

	eventType, srcIP, user, tsUnix := extractAuthMetadata(line)

	if eventType != "auth_failed" {
		t.Fatalf("event_type=%q, want auth_failed", eventType)
	}
	if srcIP != "10.0.0.22" {
		t.Fatalf("src_ip=%q, want 10.0.0.22", srcIP)
	}
	if user != "admin" {
		t.Fatalf("user=%q, want admin", user)
	}
	wantTS := deriveDeterministicTS(line)
	if tsUnix != wantTS {
		t.Fatalf("ts=%d, want deterministic %d", tsUnix, wantTS)
	}
}

func TestExtractAuthMetadata_SudoPamFailureLine(t *testing.T) {
	line := "Mar 10 11:40:10 host sudo: pam_unix(sudo:auth): authentication failure; logname=khotso uid=1000 euid=0 tty=/dev/pts/0 ruser=khotso rhost=  user=root"

	eventType, srcIP, user, tsUnix := extractAuthMetadata(line)

	if eventType != "auth_failed" {
		t.Fatalf("event_type=%q, want auth_failed", eventType)
	}
	if srcIP != "127.0.0.1" {
		t.Fatalf("src_ip=%q, want 127.0.0.1", srcIP)
	}
	if user != "khotso" {
		t.Fatalf("user=%q, want khotso", user)
	}
	wantTS := deriveDeterministicTS(line)
	if tsUnix != wantTS {
		t.Fatalf("ts=%d, want deterministic %d", tsUnix, wantTS)
	}
}

func TestExtractAuthMetadata_SudoIncorrectPasswordAttempts(t *testing.T) {
	line := "Mar 10 11:41:00 host sudo: 3 incorrect password attempts"

	eventType, srcIP, user, tsUnix := extractAuthMetadata(line)

	if eventType != "auth_failed" {
		t.Fatalf("event_type=%q, want auth_failed", eventType)
	}
	if srcIP != "127.0.0.1" {
		t.Fatalf("src_ip=%q, want 127.0.0.1", srcIP)
	}
	if user != "unknown" {
		t.Fatalf("user=%q, want unknown", user)
	}
	wantTS := deriveDeterministicTS(line)
	if tsUnix != wantTS {
		t.Fatalf("ts=%d, want deterministic %d", tsUnix, wantTS)
	}
}

func TestExtractAuthMetadata_SuFailedLine(t *testing.T) {
	line := "Mar 10 11:42:00 host su[12345]: FAILED SU (to root) khotso on pts/0"

	eventType, srcIP, user, tsUnix := extractAuthMetadata(line)

	if eventType != "auth_failed" {
		t.Fatalf("event_type=%q, want auth_failed", eventType)
	}
	if srcIP != "127.0.0.1" {
		t.Fatalf("src_ip=%q, want 127.0.0.1", srcIP)
	}
	if user != "khotso" {
		t.Fatalf("user=%q, want khotso", user)
	}
	wantTS := deriveDeterministicTS(line)
	if tsUnix != wantTS {
		t.Fatalf("ts=%d, want deterministic %d", tsUnix, wantTS)
	}
}

func TestExtractEventMetadata_ProcessExec(t *testing.T) {
	line := `PROC exec="/usr/bin/curl" user=khotso src=10.1.1.1 ts=1700000000123 node=node-03`
	meta := extractEventMetadata(line)

	if meta.EventType != "process_exec" {
		t.Fatalf("event_type=%q, want process_exec", meta.EventType)
	}
	if meta.ExecPath != "/usr/bin/curl" {
		t.Fatalf("exec_path=%q, want /usr/bin/curl", meta.ExecPath)
	}
	if meta.User != "khotso" {
		t.Fatalf("user=%q, want khotso", meta.User)
	}
	if meta.SrcIP != "10.1.1.1" {
		t.Fatalf("src_ip=%q, want 10.1.1.1", meta.SrcIP)
	}
	if meta.NodeID != "node-03" {
		t.Fatalf("node_id=%q, want node-03", meta.NodeID)
	}
	if meta.TSUnix != 1700000000 {
		t.Fatalf("ts=%d, want 1700000000", meta.TSUnix)
	}
}

func TestExtractEventMetadata_FileChange(t *testing.T) {
	line := `FILE path="/tmp/secret.txt" action=modified user=khotso src=10.1.1.2 ts=1700000000456 node=node-04`
	meta := extractEventMetadata(line)

	if meta.EventType != "file_change" {
		t.Fatalf("event_type=%q, want file_change", meta.EventType)
	}
	if meta.FilePath != "/tmp/secret.txt" {
		t.Fatalf("file_path=%q, want /tmp/secret.txt", meta.FilePath)
	}
	if meta.FileAction != "modified" {
		t.Fatalf("action=%q, want modified", meta.FileAction)
	}
	if meta.User != "khotso" {
		t.Fatalf("user=%q, want khotso", meta.User)
	}
	if meta.SrcIP != "10.1.1.2" {
		t.Fatalf("src_ip=%q, want 10.1.1.2", meta.SrcIP)
	}
	if meta.NodeID != "node-04" {
		t.Fatalf("node_id=%q, want node-04", meta.NodeID)
	}
	if meta.TSUnix != 1700000000 {
		t.Fatalf("ts=%d, want 1700000000", meta.TSUnix)
	}
}
