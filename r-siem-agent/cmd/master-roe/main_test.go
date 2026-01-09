package main

import "testing"

func TestParseROEConfigApprovalsTimeout(t *testing.T) {
	data := []byte("policies:\n  approvals:\n    timeout_ms: 300000\n")
	cfg, err := parseROEConfig(data)
	if err != nil {
		t.Fatalf("parseROEConfig error: %v", err)
	}
	if cfg.Policies.Approvals.TimeoutMs != 300000 {
		t.Fatalf("expected approvals timeout 300000, got %d", cfg.Policies.Approvals.TimeoutMs)
	}
}
