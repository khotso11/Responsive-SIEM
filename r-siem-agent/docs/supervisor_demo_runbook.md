# R-SIEM Supervisor Demo Runbook

## Goal
Run a concise but defensible live demo that proves:

1. the stack starts healthy
2. real endpoint telemetry triggers incidents
3. the system chooses autonomous response or approval
4. the endpoint executes containment
5. the result is visible in logs, UI, and artifacts

## Recommended Demo Sequence

## 1. Start the Stack
```bash
cd ~/projects/r-siem-agent
REAL_SYSTEM=1 UI_WEB_PORT=3100 ./scripts/demo_local_endpoint_clean_start.sh
```

Expected:

- `PASS: repo:master-roe`
- `PASS: repo:master-roe-worker`
- `PASS: repo:detector-v0`
- endpoint services `PASS`
- UI API health `PASS`

Presentation line:
"I begin by proving the control plane and endpoint plane are healthy."

## 2. Open the UI
Open:

```text
http://127.0.0.1:3100
```

Use the UI for:

- incidents list
- incident drawer
- notes / approval workflow
- evidence that runs update in near real time

## 3. Run the Real Local Endpoint Triptych
```bash
cd ~/projects/r-siem-agent
./scripts/demo_local_endpoint_triptych.sh
```

This demonstrates:

- FAST auth-style incident
- DECEPTION incident
- STANDARD path incident

Expected highlights:

- FAST path: `R-COLLECT-INVALID-USER` -> approval-gated playbook path
- DECEPTION path: `R-FR03-DECEPTION-TRIPWIRE`
- STANDARD path: `R-COUNT-PROCESS-HOST`

Presentation line:
"This shows that one running endpoint can produce multiple incident classes and that R-SIEM can separate FAST, STANDARD, and deception paths."

## 4. Run a Real Internal Scan
```bash
cd ~/projects/r-siem-agent
date '+SCAN_START %F %T %z'
nmap -Pn -n -sT -T3 --scan-delay 400ms --max-retries 1 -p 22,135,389,445,3389,5985 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14
date '+SCAN_END %F %T %z'
```

Expected:

- detector matches internal scan rules
- `PB-NET-INTERNAL-SCAN-CONTAIN` runs
- `halt_lateral_movement` executes
- run status becomes `SUCCEEDED`

Recommended evidence commands:

```bash
cd ~/projects/r-siem-agent
rg -n 'R-NET-INTERNAL-|trigger_published|cooldown_hit|auditd_connect|proc_net|172\.30\.50\.' logs/detector.log | tail -n 80
rg -n 'response_run_created|response_run_updated|SUCCEEDED|FAILED_SAFE|protocol_family|dst_port|172\.30\.50\.' logs/master-roe.log | tail -n 80
rg -n 'step_received|step_succeeded|step_failed_safe|agent_command_reply|halt_lateral_movement' logs/worker.log | tail -n 80
sudo rg -n 'halt_lateral_movement|agent_command_exec_start|agent_command_exec_done|exit_code' /var/log/rsiem/agent.log | tail -n 80
```

Presentation line:
"This is the strongest end-to-end demo because it uses real endpoint network behavior and results in actual containment."

## 5. Show Approval / Deny
Find a `WAITING_APPROVAL` run in `logs/master-roe.log` or the UI.

Approve:
```bash
nats pub rsiem.response.approvals '{"run_id":"<RUN_ID>","decision":"approve","actor":"khotso","reason":"lab approval"}'
```

Deny:
```bash
nats pub rsiem.response.approvals '{"run_id":"<RUN_ID>","decision":"deny","actor":"khotso","reason":"operator denied"}'
```

Expected:

- `approval_received`
- if approved: steps published and endpoint command runs
- if denied: no disruptive step executes

Presentation line:
"This is how human governance is enforced in the response loop."

## 6. Optional: Show Fail-Safe Timeout
Use one of:

```bash
./scripts/m57_approval_timeout_no_steps_proof.sh
./scripts/m58_approval_after_timeout_no_exec_proof.sh
./scripts/m64_timeout_respects_config_proof.sh
```

Expected:

- approval request published
- no operator action
- timeout occurs
- no late action slips through

Presentation line:
"If an operator does nothing, the system fails safe rather than silently acting later."

## 7. Optional: Show Deception + Evidence Preservation
```bash
cd ~/projects/r-siem-agent
./scripts/verify_fr04.sh
```

Expected:

- deception tripwire alert
- `capture.pcap`
- `chain_of_custody.json`
- proof artifact JSON

Presentation line:
"This shows that R-SIEM can not only detect deception events, but preserve evidence around them."

## 8. Optional: Show ATT&CK-Mapped Scenario
```bash
cd ~/projects/r-siem-agent
./scripts/adversary_emulation_harness.sh --list
./scripts/adversary_emulation_harness.sh --scenario t1110_auth_abuse_burst
```

Expected:

- ATT&CK technique mapping
- expected rule/playbook alignment
- terminal status and artifacts

Presentation line:
"This demonstrates that the system can be discussed in adversary-emulation terms, not only implementation terms."

## What to Emphasize During the Demo

### Emphasize

- the stack health check
- real endpoint telemetry
- policy-controlled autonomy
- approval governance
- safe endpoint execution
- audit trail and proof outputs

### Do not overclaim

- do not say every action is autonomous
- do not say deception is a full production honeyport platform unless you run one live
- do not say all scenarios are purely organic if a script uses canonical raw-event publishing

Preferred language:

"The core loop is complete and working. The remaining work is refinement and production hardening, not basic functionality."

## Backup Evidence if Live Demo Misbehaves

Use these scripts as fallback:

- `./scripts/verify_fr04.sh`
- `./scripts/verify_first_seen_containment.sh`
- `./scripts/adversary_emulation_harness.sh --scenario t1110_auth_abuse_burst`
- `./scripts/verify_new_playbooks.sh`

## Final Closing Line
"The system now proves that R-SIEM can ingest, detect, decide, respond, and audit across the endpoint and control plane. That is the main technical contribution of this project."
