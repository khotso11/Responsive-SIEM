package main

import "testing"

func TestDeriveConfidenceRichProcessEvidenceScoresHigherThanBareHighSeverity(t *testing.T) {
	bare := deriveConfidence("trigger", "high", "STANDARD", 1, &NormalizedRecord{
		Fields: map[string]any{
			"source_type": "proc_net",
		},
	})
	rich := deriveConfidence("sequence", "high", "FAST", 3, &NormalizedRecord{
		Fields: map[string]any{
			"source_type": "auditd_exec",
			"user":        "alice",
			"exec_path":   "/usr/bin/nmap",
			"comm":        "nmap",
			"cmdline":     "/usr/bin/nmap --version",
			"exec_sha256": "proof-sha256",
			"signer_hint": "unsigned",
		},
	})
	if rich <= bare {
		t.Fatalf("rich confidence=%d, want greater than bare=%d", rich, bare)
	}
	if bare >= 80 {
		t.Fatalf("bare confidence=%d, want less than old hardcoded-high default", bare)
	}
}

func TestDeriveConfidenceUnknownNetworkStaysLowerThanAttributedProcess(t *testing.T) {
	networkUnknown := deriveConfidence("trigger", "high", "STANDARD", 1, &NormalizedRecord{
		Fields: map[string]any{
			"source_type": "proc_net",
			"dst_ip":      "93.184.216.13",
			"user":        "unknown",
		},
	})
	processAttributed := deriveConfidence("count", "high", "FAST", 2, &NormalizedRecord{
		Fields: map[string]any{
			"source_type": "auditd_exec",
			"user":        "alice",
			"exec_path":   "/usr/bin/python3",
			"comm":        "python3",
			"cmdline":     "python3 suspicious.py",
		},
	})
	if networkUnknown >= processAttributed {
		t.Fatalf("network unknown confidence=%d, want less than process attributed=%d", networkUnknown, processAttributed)
	}
}
