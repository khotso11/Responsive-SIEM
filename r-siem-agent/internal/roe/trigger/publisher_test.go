package trigger

import "testing"

func TestDeriveConfidenceAlertEvidenceBased(t *testing.T) {
	bare := deriveConfidence(Alert{
		Severity:   "high",
		Lane:       "STANDARD",
		SourceType: "proc_net",
		DstIP:      "93.184.216.34",
		User:       "unknown",
	})

	rich := deriveConfidence(Alert{
		Severity:   "high",
		Lane:       "FAST",
		SourceType: "auditd_exec",
		User:       "alice",
		ExecPath:   "/usr/bin/nmap",
		Comm:       "nmap",
		Cmdline:    "/usr/bin/nmap --version",
		DstIP:      "93.184.216.34",
		ExecSHA256: "proof-sha256",
		SignerHint: "unsigned",
	})

	if rich <= bare {
		t.Fatalf("rich confidence=%d, want greater than bare=%d", rich, bare)
	}
	if bare >= 80 {
		t.Fatalf("bare confidence=%d, want less than old hardcoded-high default", bare)
	}
}

func TestDeriveConfidenceAuditdConnectScoresHigherThanProcNet(t *testing.T) {
	procNet := deriveConfidence(Alert{
		Severity:   "high",
		Lane:       "FAST",
		SourceType: "proc_net",
		User:       "khotso",
		ExecPath:   "/usr/bin/nmap",
		Comm:       "nmap",
		Cmdline:    "/usr/bin/nmap -Pn -n",
		DstIP:      "172.30.50.14",
	})

	auditdConnect := deriveConfidence(Alert{
		Severity:   "high",
		Lane:       "FAST",
		SourceType: "auditd_connect",
		User:       "khotso",
		ExecPath:   "/usr/bin/nmap",
		Comm:       "nmap",
		Cmdline:    "/usr/bin/nmap -Pn -n",
		DstIP:      "172.30.50.14",
	})

	if auditdConnect <= procNet {
		t.Fatalf("auditd_connect confidence=%d, want greater than proc_net=%d", auditdConnect, procNet)
	}
}
