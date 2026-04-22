package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildMessageIncludesTripwireMarker(t *testing.T) {
	msg := buildMessage(interaction{
		ServiceID:     "decoy-admin-http",
		Protocol:      protocolHTTP,
		SrcIP:         "10.10.10.5",
		DstPort:       18081,
		AttemptedUser: "admin",
		Method:        "POST",
		Path:          "/admin/login",
		Payload:       "login=admin password=secret",
		SessionKey:    "session-1",
	})

	for _, needle := range []string{
		"attack=deception_tripwire",
		"service=decoy-admin-http",
		"protocol=http",
		"src=10.10.10.5",
		"method=POST",
		"path=/admin/login",
		"password=<redacted>",
	} {
		if !strings.Contains(msg, needle) {
			t.Fatalf("expected %q in %q", needle, msg)
		}
	}
}

func TestNormalizeCandidateUser(t *testing.T) {
	if got := normalizeCandidateUser(" Admin Root "); got != "admin_root" {
		t.Fatalf("unexpected normalized user: %q", got)
	}
}

func TestRedactSecrets(t *testing.T) {
	input := "username=admin password=secret&token=123 pass=hunter2"
	output := redactSecrets(input)
	if strings.Contains(output, "secret") || strings.Contains(output, "hunter2") {
		t.Fatalf("secret leaked in output: %q", output)
	}
	for _, needle := range []string{"password=<redacted>", "pass=<redacted>"} {
		if !strings.Contains(output, needle) {
			t.Fatalf("expected %q in %q", needle, output)
		}
	}
}

func TestForwardedIP(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.test/admin", nil)
	req.Header.Set("X-RSIEM-Source-IP", "10.66.12.250")
	if got := forwardedIP(req); got != "10.66.12.250" {
		t.Fatalf("unexpected forwarded ip: %q", got)
	}
}

func TestLoadConfigResponseTargetAgentID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "honeypot.yaml")
	if err := os.WriteFile(path, []byte(`
node_id: honeypot-local
host: honeypot-local
response_target_agent_id: enforcement-host
services:
  - id: decoy-admin-http
    enabled: true
    protocol: http
    listen: 127.0.0.1:18081
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.ResponseTargetAgentID != "enforcement-host" {
		t.Fatalf("unexpected response target agent id: %q", cfg.ResponseTargetAgentID)
	}
}
