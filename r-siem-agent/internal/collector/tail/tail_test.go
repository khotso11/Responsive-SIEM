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
