# R-SIEM Supervisor Presentation

## 1. Title
R-SIEM: A Response-Capable SIEM for Endpoint Detection, Policy-Governed Autonomous Response, and Proof-Driven Verification

Presenter: `Khotso`  
Repository: `r-siem-agent`  
Status: End-to-end working system with live endpoint telemetry, approval-governed response orchestration, and proof scripts for defense.

## 2. Executive Summary
R-SIEM is no longer only a detector. It is a response-capable security system that:

- ingests telemetry from endpoint collectors and stream pipelines
- normalizes and correlates events into incidents
- decides whether to respond autonomously or request human approval
- executes bounded response actions on the endpoint
- records audit evidence, artifacts, and proof outputs for verification

The strongest defense claim is this:

1. the system starts cleanly
2. real endpoint telemetry can trigger incidents
3. policy decides whether action is autonomous or approval-gated
4. the endpoint executes containment safely
5. the entire chain is auditable in logs, exports, UI, and proof artifacts

## 3. Why This Project Matters
Traditional SIEMs stop at alerting. R-SIEM goes further:

- it links detection to action
- it controls action through approval policy, blast-radius limits, and guardrails
- it preserves auditability and safety instead of doing blind automation

This makes the project suitable for a defense narrative around:

- secure automation
- bounded autonomous response
- human-in-the-loop security orchestration
- trustworthy endpoint containment

## 4. System Architecture
High-level flow:

```text
endpoint collectors
  -> raw events / normalized events
  -> detector-v0
  -> alerts / incidents / response triggers
  -> ROE master
  -> approval policy decision
  -> ROE worker
  -> agent command on endpoint
  -> results / artifacts / audit trail / UI
```

Main runtime components:

- `collector-tail`
- `collector-auditd`
- `collector-inotify`
- `collector-procnet`
- `collector-dns`
- `detector-v0`
- `master-roe`
- `master-roe-worker`
- `agent`
- `ui-api`
- optional Timescale/Postgres sink for `normalized_events`

## 5. What the System Can Do
Current capabilities visible in repo configuration and runtime:

- detect auth abuse bursts
- detect invalid-user auth activity
- detect suspicious DNS queries
- detect sensitive file changes
- detect risky first-seen destinations
- detect suspicious first-seen processes
- detect internal lateral-movement style scanning
- detect process-to-network sequences
- detect deception tripwire events
- maintain incident state and UI workflow
- request approvals for high-risk actions
- autonomously execute bounded containment for approved/safe cases
- fail safe on policy rejection, timeout, or disallowed command path
- retain evidence, logs, exports, and proof artifacts

Endpoint response command families already implemented:

- `auth_contain_src_ip`
- `auth_contain_user_access`
- `auth_mark_user_verified`
- `auth_restore_src_ip`
- `auth_restore_user_access`
- `contain_destination_ip`
- `restore_destination_ip`
- `contain_process_exec`
- `restore_process_exec`
- `halt_lateral_movement`
- `contain_bruteforce_ip`
- `block_c2_beacon`
- `kill_chain_stage`
- `kill_chain_stop`
- `throttle_exfil`
- `lockdown_privesc`
- `protect_critical_service_stage`
- `protect_critical_service`
- `detector_self_protect`
- `quarantine_move`
- `quarantine_restore`
- `ping`

## 6. Startup Story for the Presentation
This is how to explain the system from zero:

### Slide message
"We start by proving that the R-SIEM control plane and endpoint plane are both healthy."

### What happens technically
`scripts/demo_local_endpoint_clean_start.sh`:

- builds and starts repo-side services
- prepares endpoint package and certs
- ensures `master-roe`, `master-roe-worker`, `detector-v0`, and `investigation-enricher` are running
- verifies endpoint services are active
- checks UI API health
- prints a health summary

### What to show
The health summary:

- repo services `PASS`
- endpoint units `PASS`
- UI API `PASS`

### Defense line
"Before demonstrating detections and response, I prove the stack is operational and observable. This removes ambiguity between a product failure and a test failure."

## 7. How Endpoint Triggering Works
There are three good categories to explain:

### 7.1 Real local collector path
Examples:

- auth failures written to `/var/log/auth.log`
- deception tripwire events written to `/var/log/auth.log`
- internal scans observed through auditd and procnet

These are the strongest demo paths because they use installed endpoint collectors, not only synthetic publishes.

### 7.2 Canonical raw-event path
Examples:

- some proof scripts publish directly to `rsiem.events.raw`

This is still valid for controlled tests, but for a supervisor demo it should be presented as:

"a deterministic verification path, not the main proof of endpoint realism."

### 7.3 Proof-driven acceptance path
Examples:

- FR-03
- FR-04
- FR-05
- first-seen containment proof
- adversary emulation harness

These are useful to show that the system was tested repeatedly, not only once in a live demo.

## 8. Playbooks and Expected Response
This section should be shown as a control matrix: rule -> playbook -> response behavior.

### 8.1 Notify-only / low-risk observation playbooks

| Playbook | Rules | Purpose | Expected Response |
|---|---|---|---|
| `PB-STAT-PROCESS-MED` | `R-STAT-PROCESS-MED` | statistical process anomaly | notify only |
| `PB-FILE-SENSITIVE-CHANGE-NOTIFY` | `R-FILE-SENSITIVE-CHANGE` | sensitive file monitoring | notify only |
| `PB-DNS-SUSPICIOUS-QUERY-NOTIFY` | `R-DNS-SUSPICIOUS-QUERY` | suspicious DNS | notify only |
| `PB-NET-OUTBOUND-OBSERVE` | `R-NET-OUTBOUND-CONNECTION` | outbound connection observation | notify only |
| `PB-NET-INTERNAL-SCAN-OBSERVE` | `R-NET-INTERNAL-APPROVED-SCAN` | approved scanning visibility | notify only |

Presentation point:
"Not every incident should trigger disruptive response. R-SIEM separates observation playbooks from containment playbooks."

### 8.2 Autonomous containment-capable playbooks

| Playbook | Rules | Approval Mode | Typical Action |
|---|---|---|---|
| `PB-NET-INTERNAL-SCAN-CONTAIN` | `R-NET-INTERNAL-*SCAN` | `auto` with bounds | `halt_lateral_movement` |
| `PB-DETECTOR-HEALTH-SELF-PROTECT` | `R-PB-DETECTOR-HEALTH-SELF-PROTECT` | `auto` | `detector_self_protect` |
| `PB-COUNT-PROCESS-HOST` | `R-COUNT-PROCESS-HOST` | `auto` | `ping` stub + notify |

Presentation point:
"Autonomy is allowed only when severity, confidence, blast radius, and playbook design stay inside policy bounds."

### 8.3 Approval-gated containment playbooks

| Playbook | Rules | Approval Mode | Why Approval Exists |
|---|---|---|---|
| `PB-AUTH-ABUSE-CONTAIN` | auth burst rules | `required_for_high` | user/src containment impacts access |
| `PB-AUTH-ACCESS-RESTORE` | restore request | `required` | re-enabling access is sensitive |
| `PB-NET-FIRST-SEEN-CONTAIN` | first-seen risky destination | `required_for_high` | new network containment |
| `PB-PROC-FIRST-SEEN-CONTAIN` | first-seen suspicious process | `required_for_high` | process execution containment |
| `PB-SEQ-PROCESS-TO-NET` | sequence rule set | `required_for_high` | chained behavior needs review |
| `PB-BRUTEFORCE-IP-CONTAIN` | brute force IP | `required_for_critical` | source IP containment can be disruptive |
| `PB-PRIVESC-LOCKDOWN` | privilege escalation rule | `required` | explicitly high impact |
| `PB-LATERAL-MOVEMENT-HALT` | lateral movement halt | `required` | disruptive network/action scope |
| `PB-C2-BEACON-BLOCK` | C2 beacon | `required_for_critical` | network blocking risk |
| `PB-RANSOMWARE-KILL-CHAIN-STOP` | ransomware kill chain | `required` | irreversible/mixed steps |
| `PB-DATA-EXFIL-THROTTLE` | exfiltration | `required_for_critical` | production traffic impact |
| `PB-CRITICAL-SERVICE-ABUSE-RESPONSE` | critical service abuse | `required` | production service sensitivity |

Presentation point:
"R-SIEM is not trying to automate everything. It automates what is safe and bounded, and requires approval for the actions that could cause business disruption."

## 9. Approval and Deny Logic
Approval modes implemented in policy:

- `auto`
- `required`
- `required_for_high`
- `required_for_critical`

### The system asks for approval when:

- playbook mode is `required`
- severity crosses the configured threshold for `required_for_high` or `required_for_critical`
- confidence is below the floor
- the endpoint/user is high impact
- the identity is privileged
- the source is local
- ROE is degraded and safe mode is active
- the playbook contains irreversible action

### The system can deny autonomy even when a playbook says `auto` if:

- confidence is below threshold
- safe mode is active
- a critical asset is involved
- a service account is involved
- a local source or privileged identity requires review

### If approval is needed:

- a run enters `WAITING_APPROVAL`
- approval request is published
- operator can `approve` or `deny`
- timeout is `300000 ms` in config
- if approval is too late, the run fails safe

### What to say in presentation
"Human approval is not a weakness in the system. It is an explicit safety boundary."

## 10. Guardrails, Allowlist, and Safety
R-SIEM has three safety layers:

### 10.1 Approval policy
Decides if action can proceed autonomously.

### 10.2 Guardrails
Examples configured:

- enforce identity context for sensitive commands
- normalize containment duration for auth and generic containment

### 10.3 Action allowlist
Ensures a playbook can only run its intended command family.

Examples:

- `PB-AUTH-ABUSE-CONTAIN` may only call `auth_contain_*`
- `PB-AUTH-ACCESS-RESTORE` may only call `auth_mark_*` and `auth_restore_*`
- `PB-NET-FIRST-SEEN-CONTAIN` may only call `contain_destination_*`
- `PB-PROC-FIRST-SEEN-CONTAIN` may only call `contain_process_*`
- `PB-LATERAL-MOVEMENT-HALT` and `PB-NET-INTERNAL-SCAN-CONTAIN` may only call `halt_lateral_movement`

Presentation point:
"R-SIEM does not just choose whether to act. It constrains what action a playbook is even allowed to attempt."

## 11. Deception / Honeyport / Tripwire Story
The current repo demonstrates deception through the rule:

- `R-FR03-DECEPTION-TRIPWIRE`

Trigger condition:

- auth/deception message contains `attack=deception_tripwire`

Configured severity:

- `critical`

### How to explain this to the supervisor
"In the current system, the deception path is implemented as a deception tripwire event. In practice, a honeyport or honeypot service can feed this exact event pattern into the detector, and R-SIEM treats it as a critical deception incident."

### Expected behavior

- deception event arrives
- detector matches `R-FR03-DECEPTION-TRIPWIRE`
- incident is created
- evidence can be captured with FR-04 proof path
- this demonstrates the system can elevate attacker interaction with deception infrastructure into a first-class incident

Important wording:

- do not claim a full production honeyport service if you are not running one
- do claim that the deception trigger path is already implemented and demonstrated end-to-end

## 12. Best Live Demo Sequence
This is the recommended presentation flow.

### Demo 1: Clean startup
Command:

```bash
cd ~/projects/r-siem-agent
REAL_SYSTEM=1 UI_WEB_PORT=3100 ./scripts/demo_local_endpoint_clean_start.sh
```

What to show:

- health summary block
- all critical services `PASS`

What to say:
"This proves the system can start in a known-good operational state before testing response."

### Demo 2: Real local endpoint triptych
Command:

```bash
cd ~/projects/r-siem-agent
./scripts/demo_local_endpoint_triptych.sh
```

What it demonstrates:

- FAST incident from auth activity
- deception tripwire incident
- STANDARD incident path

What to emphasize:

- FAST and deception both use the real local collector path
- deception is your honeyport/tripwire story

### Demo 3: Real internal scan containment
Command:

```bash
cd ~/projects/r-siem-agent
date '+SCAN_START %F %T %z'
nmap -Pn -n -sT -T3 --scan-delay 400ms --max-retries 1 -p 22,135,389,445,3389,5985 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14
date '+SCAN_END %F %T %z'
```

What it demonstrates:

- `proc_net` first trigger
- later `auditd_connect` corroboration
- `PB-NET-INTERNAL-SCAN-CONTAIN`
- autonomous `halt_lateral_movement`
- endpoint command success

Why this is one of the best defense demos:

- it is real endpoint behavior
- it shows cross-source corroboration
- it shows actual containment, not only alerting

### Demo 4: Approval-gated response
Use a playbook that waits for approval, for example an auth-abuse or first-seen containment run.

General approval command:

```bash
nats pub rsiem.response.approvals '{"run_id":"<RUN_ID>","decision":"approve","actor":"khotso","reason":"lab approval"}'
```

Deny path:

```bash
nats pub rsiem.response.approvals '{"run_id":"<RUN_ID>","decision":"deny","actor":"khotso","reason":"operator denied"}'
```

What to say:
"This shows the system is not blindly autonomous. It supports operator governance."

### Demo 5: Approval timeout / fail-safe
Use one of the approval timeout proof scripts as backup evidence:

- `scripts/m57_approval_timeout_no_steps_proof.sh`
- `scripts/m58_approval_after_timeout_no_exec_proof.sh`
- `scripts/m64_timeout_respects_config_proof.sh`

What to say:
"If the operator does nothing, the system times out safely. Late approval does not backdoor execution."

## 13. Strongest Proof-Based Demos
These are excellent if the supervisor asks for more than one live scenario.

### Option A: First-seen containment proof
Script:

```bash
./scripts/verify_first_seen_containment.sh
```

Demonstrates:

- `R-NET-FIRST-SEEN-RISKY`
- `R-PROC-FIRST-SEEN-SUSPICIOUS`
- approval-gated containment
- endpoint control artifacts

### Option B: Deception + packet capture + chain of custody
Script:

```bash
./scripts/verify_fr04.sh
```

Demonstrates:

- deception tripwire detection
- packet capture
- chain of custody
- evidence preservation

### Option C: ATT&CK-mapped adversary emulation
Script:

```bash
./scripts/adversary_emulation_harness.sh --list
./scripts/adversary_emulation_harness.sh --scenario t1110_auth_abuse_burst
```

Demonstrates:

- ATT&CK mapping
- scenario catalog
- expected rule/playbook/status verification

## 14. What the Supervisor Should Understand
This is the core message.

### R-SIEM is already capable of:

- detecting across multiple telemetry sources
- correlating events into incidents
- choosing FAST vs STANDARD response paths
- asking for operator approval when policy demands it
- autonomously containing low-blast-radius, bounded threats
- safely denying or timing out risky actions
- producing repeatable proof artifacts
- keeping an auditable record of response decisions and outcomes

### R-SIEM is not just:

- a log parser
- a dashboard
- a detector-only tool

It is a governed detection-and-response platform.

## 15. Current Project Status
Use this wording:

"R-SIEM is functionally complete in its core loop: ingest, detect, decide, respond, and audit. The project is at the stage where the remaining work is hardening, expansion, and presentation polish, not foundational invention."

Suggested honest phrasing:

- core architecture is complete
- live endpoint detection and response are working
- policy-governed autonomous response is working
- approval and fail-safe behavior are working
- proof scripts exist for repeatable validation
- remaining work is operational maturity, coverage expansion, and presentation polish

## 16. Likely Supervisor Questions and Strong Answers
### "Is it really autonomous?"
Answer:
"Yes, but only under bounded policy. R-SIEM can autonomously execute low-blast-radius, reversible or policy-approved response paths. Higher-risk actions remain approval-gated."

### "How do you avoid dangerous automation?"
Answer:
"Three layers: approval policy, guardrails, and command allowlists. A playbook cannot run arbitrary commands, and risky cases require approval or fail safe."

### "What proves this is not a one-off demo?"
Answer:
"The repository includes proof scripts and adversary emulation scenarios. The same behaviors can be reproduced repeatedly and verified through logs, exports, DB records, and artifacts."

### "Can it handle deception and honeypot signals?"
Answer:
"Yes. The deception tripwire path is implemented and demonstrated. A honeyport/honeypot signal can map directly into that tripwire event model."

### "What is still left?"
Answer:
"The remaining work is refinement: broader content coverage, more production-oriented integrations, and presentation-grade packaging. The core response platform is already operational."

## 17. Presentation Closing
Recommended closing line:

"The contribution of this work is not only detecting suspicious behavior. It is proving that a SIEM can move from evidence to controlled response on the endpoint, with explicit policy, human governance, and reproducible validation."

## 18. Suggested Slide Order
Use this exact order:

1. Problem statement: alerting is not enough
2. R-SIEM objective and contribution
3. Architecture and control flow
4. Startup proof and system health
5. Telemetry sources and detection coverage
6. Playbook inventory
7. Policy model: auto vs approval vs fail-safe
8. Live demo: endpoint auth/deception/scan
9. Live demo: approval/deny behavior
10. Proof-driven validation and FR scripts
11. Capabilities already achieved
12. Remaining work and near-term roadmap
13. Conclusion and defense message

## 19. Demo Commands Appendix
### Clean start
```bash
cd ~/projects/r-siem-agent
REAL_SYSTEM=1 UI_WEB_PORT=3100 ./scripts/demo_local_endpoint_clean_start.sh
```

### Local triptych
```bash
cd ~/projects/r-siem-agent
./scripts/demo_local_endpoint_triptych.sh
```

### Internal scan
```bash
cd ~/projects/r-siem-agent
nmap -Pn -n -sT -T3 --scan-delay 400ms --max-retries 1 -p 22,135,389,445,3389,5985 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14
```

### First-seen containment proof
```bash
cd ~/projects/r-siem-agent
./scripts/verify_first_seen_containment.sh
```

### Deception proof
```bash
cd ~/projects/r-siem-agent
./scripts/verify_fr04.sh
```

### ATT&CK adversary emulation
```bash
cd ~/projects/r-siem-agent
./scripts/adversary_emulation_harness.sh --list
./scripts/adversary_emulation_harness.sh --scenario t1110_auth_abuse_burst
```
