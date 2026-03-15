package main

import "testing"

func TestDeriveTriggerConfidenceAuditdConnectScoresHigherThanProcNet(t *testing.T) {
	procNet := deriveTriggerConfidence(responseTrigger{
		Severity:   "high",
		Lane:       "FAST",
		SourceType: "proc_net",
		UserName:   "khotso",
		ExecPath:   "/usr/bin/nmap",
		Comm:       "nmap",
		Cmdline:    "/usr/bin/nmap -Pn -n",
		DstIP:      "172.30.50.14",
	})

	auditdConnect := deriveTriggerConfidence(responseTrigger{
		Severity:   "high",
		Lane:       "FAST",
		SourceType: "auditd_connect",
		UserName:   "khotso",
		ExecPath:   "/usr/bin/nmap",
		Comm:       "nmap",
		Cmdline:    "/usr/bin/nmap -Pn -n",
		DstIP:      "172.30.50.14",
	})

	if auditdConnect <= procNet {
		t.Fatalf("auditd_connect confidence=%d, want greater than proc_net=%d", auditdConnect, procNet)
	}
}
