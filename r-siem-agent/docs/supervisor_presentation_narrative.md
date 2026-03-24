# R-SIEM Supervisor Presentation Narrative

## Purpose
This is the main speaker script for the supervisor presentation. It is written in presentation order and aligned with the current system, not the earlier project state.

Use this file to know:
- what to say
- what to run
- what the system is expected to do
- what the audience should understand from each step

Use `docs/supervisor_demo_runbook.md` as the shorter operator checklist.

## Core Message
The strongest defense claim is not that R-SIEM is finished in every possible area. The strongest claim is that the core system is now integrated and working:

1. endpoint telemetry is live
2. detections are explainable
3. playbooks define bounded response
4. policy governs autonomy vs approval
5. actions are auditable and reversible where appropriate
6. analysts and admins have distinct responsibilities
7. the UI now supports investigation, response, governance, and evidence review

Use this sentence repeatedly:

"R-SIEM is now an operational response-capable SIEM. It does not stop at detection. It ingests, detects, decides, responds, and audits."

## Recommended Presentation Order
Use this order.

1. start the stack and prove health
2. open the UI and show the operator surfaces
3. prove the endpoint is live
4. explain roles: analyst vs admin
5. run the real SSH failed-password burst
6. approve the auth-abuse run, then verify and restore
7. run the real internal `nmap` scan
8. use Advanced Search to investigate the scan evidence
9. launch a manual response action as admin and show the action lifecycle
10. open the endpoint workspace and show device event logs before and after action
11. run the real sensitive file tampering test
12. explain rules, playbooks, policies, and confidence scoring
13. show the Models workspace and explain controlled configuration governance
14. optionally run broader proof scripts
15. close with project status and production-readiness boundaries

## Opening Narrative
Say this before you run anything:

"My project is R-SIEM, a response-capable SIEM. The key contribution is not only that it raises alerts. The key contribution is that it can collect live endpoint telemetry, turn that telemetry into governed decisions, execute bounded response actions, and preserve an auditable trail of what happened and why."

Then say:

"I will present the system in the same order it works internally: startup, endpoint telemetry, detection, policy decision, response action, investigation, and audit."

## Part 1. Start the Stack
Run:

```bash
cd ~/projects/r-siem-agent
REAL_SYSTEM=1 UI_WEB_PORT=3100 ./scripts/demo_local_endpoint_clean_start.sh
```

### What to say while it runs
"I start with health because I want to remove ambiguity. If something fails during a defense, I want it to be clear whether it is a system issue or simply a stale environment. So the first proof is that the control plane and endpoint plane are healthy."

### What this script actually does
It:
- starts repo-side services such as `master-roe`, `master-roe-worker`, `detector-v0`, `ui-api`, `ui-web`, and `investigation-enricher`
- prepares the local endpoint package
- ensures endpoint-side services are active
- checks infrastructure readiness and UI health
- prints a health summary for both repo-side and endpoint-side components

### What to point at
When the health summary appears, say:

"This summary proves that the orchestration plane, the UI plane, and the endpoint plane are all active. That gives me a valid state for the live tests."

### Key point
"R-SIEM is not only code in a repository. It is running as a coordinated system."

## Part 2. Open the UI and Introduce the Main Surfaces
Open:

```text
http://127.0.0.1:3100
```

### What to say
"Now I switch to the UI because I want the audience to see the system as an operator would use it. The terminal proves technical correctness. The UI proves operational usability."

### What to point at
Show the left navigation and explain the main surfaces briefly:
- `Dashboard`: posture and incident overview
- `Incidents`: the threat tray and incident queue
- `Endpoints`: endpoint posture, event logs, and node actions
- `Actions`: fleet-wide response action ledger
- `Search`: Advanced Search over normalized events
- `Models`: controlled model editor for admins
- `Audit`: operator and governance audit trail

### Key point
"The UI is not disconnected from the backend. Every surface now maps to a real backend API and real system state."

## Part 3. Prove the Endpoint Is Live
Run:

```bash
sudo systemctl is-active ssh rsiem-agent rsiem-collector-tail rsiem-collector-auditd rsiem-collector-procnet rsiem-collector-dns
```

### What to say
"Before I trigger incidents, I want to prove that this laptop is functioning as a live endpoint, not as a dashboard host only. SSH is active, the agent is active, and the collectors are active. The next incidents therefore come through the installed endpoint services on this laptop."

### What to point at
Show that the services are `active`.

### Key point
"The endpoint plane is real and installed. The tests I run next are observed locally by the installed collectors."

## Part 4. Explain Roles: Analyst vs Admin
Say this before the first live test.

"R-SIEM now has role separation. That matters because security systems should not give every operator the same authority."

Then explain it in plain language:

### Analyst capabilities
An analyst can:
- triage incidents
- search and investigate evidence
- open incident detail, endpoint detail, and response history
- approve or reject runs where the workflow exposes that decision
- add notes and mark incidents reviewed
- assign incidents to themselves
- launch allowed response actions from incident, endpoint, or fleet action views
- use the identity workflow when a run is eligible

### Admin capabilities
An admin can do everything an analyst can do, and also:
- access the `Models` workspace
- create, validate, propose, approve, reject, and apply model changes
- restart approved repo-side services after model apply
- manage UI users
- access the full admin views and restricted audit content
- assign incidents more broadly than self-assignment

### What to say
"So the analyst handles operational triage and response. The admin handles configuration governance and user administration. That separation helps make the system usable without making it unsafe."

## Part 5. Real SSH Failed-Password Burst
Precondition:
- `openssh-server` is installed and running
- a disposable local account exists, for example `rsiemtest`
- password authentication is enabled

One-time preparation if needed:

```bash
sudo useradd -m -s /bin/bash rsiemtest
sudo passwd rsiemtest
sudo sshd -T | rg 'passwordauthentication'
```

Run the live test:

```bash
for i in $(seq 1 5); do
  echo "attempt $i"
  ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 rsiemtest@127.0.0.1
done
```

Operator note:
- type the wrong password once on each attempt
- let each login fail
- complete all five attempts

### What to say before running it
"This is the first realism proof. I am not publishing a synthetic event. I am using a real service on this endpoint, generating real failed authentication activity, and allowing the installed collectors to observe it."

### What this should trigger
Expected rule:
- `R-AUTH-FAILED-PW-BURST-USER`

Expected playbook:
- `PB-AUTH-ABUSE-CONTAIN`

Expected policy posture:
- approval-gated

### What to say when the run appears
"This proves that the endpoint is live and the auth-abuse path is real. SSH generated the log, the collector read it, the detector evaluated it, and the response engine created a governed containment run."

### Terminal proof if needed
```bash
cd ~/projects/r-siem-agent
rg -n 'R-AUTH-FAILED-PW-BURST|PB-AUTH-ABUSE-CONTAIN|rsiemtest|127\.0\.0\.1' logs/detector.log logs/master-roe.log | tail -n 50
```

### Key point
"The system is working on real endpoint behavior, not only on replayed data."

## Part 6. Approve, Verify, and Restore
Open the `PB-AUTH-ABUSE-CONTAIN` run.

### What to say before approving
"This is intentionally not fully autonomous because user access and identity containment are sensitive. Policy requires a human to approve before release of the disruptive action."

### What to do
1. if the run is `WAITING_APPROVAL`, click `Approve`
2. wait for the run to become `SUCCEEDED`
3. use `Verify User`
4. then use `Restore Access`

### What to say while doing it
"The workflow is containment first, verification second, restoration third. That matters because a response system must not only cut access. It must also support safe return to normal state under operator control."

### Key point
"R-SIEM does not end at disruption. It supports controlled recovery."

## Part 7. Real Internal Scan Test
Run:

```bash
cd ~/projects/r-siem-agent
nmap -Pn -n -sT -T3 --scan-delay 400ms --max-retries 1 -p 22,135,389,445,3389,5985 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14
```

### What to say before running it
"The second live proof is network abuse. This generates real endpoint network behavior. The collectors observe it, the detector classifies it, policy decides whether autonomy is allowed, and the agent executes bounded containment."

### What this should trigger
Examples:
- `R-NET-INTERNAL-RDP-SCAN`
- `R-NET-INTERNAL-WINRM-SCAN`

Expected playbook:
- `PB-NET-INTERNAL-SCAN-CONTAIN`

Expected action on the endpoint:
- `halt_lateral_movement`

Expected posture:
- autonomous when policy bounds are satisfied

### What to say when it succeeds
"This is the core closed loop: real endpoint behavior, live detection, policy evaluation, autonomous response, and successful endpoint execution."

### What to say if asked about `proc_net` vs `auditd_connect`
"In the current design, `proc_net` usually arrives first and wins first containment because it is faster. `auditd_connect` arrives later and acts as stronger corroborating evidence. We kept that behavior intentionally because delaying first containment to wait for later evidence would be the wrong tradeoff for internal scan response."

## Part 8. Use Advanced Search to Investigate the Scan
Go to `/search`.

### What to say
"Detection alone is not enough. Operators need a way to pivot into the actual event evidence. That is what Advanced Search does in R-SIEM. It works over normalized endpoint events, not only over the incident summary."

### How to demonstrate it
Set a short window around the `nmap` run, then use the top search bar.

Recommended sequence:

```text
comm:nmap
```

```text
comm:nmap event_type:process_exec
```

```text
dst_port:5985 protocol_family:winrm
```

```text
rule_id:R-NET-INTERNAL-WINRM-SCAN source_type:proc_net
```

```text
rule_id:R-NET-INTERNAL-WINRM-SCAN source_type:auditd_connect
```

### What to point at
Show that Advanced Search now provides:
- top query bar with parsed field filters
- time analysis for the current result set
- quick grouped analysis
- raw normalized event rows with process and network context

### Key point
"This is how an operator moves from an incident to the underlying event evidence. The incident explains that something happened. Advanced Search shows what happened, when, on which node, under which process and network context."

## Part 9. Launch a Manual Response Action as Admin
Use the incident `Actions` tab, the endpoint workspace, or the fleet `/actions` page.

Recommended example:
- `block_matching_connections`
- duration: `2 hours`
- target: a destination IP or DNS name from the incident context

### What to say before launching
"Autonomy is not the only response path. Operators also need manual bounded actions. So I can launch a response action directly, with a defined scope and a defined duration."

### What to show
Show the response action surfaces now available:
- incident-scoped actions
- endpoint-scoped actions
- fleet-wide `/actions` ledger

Explain the action lifecycle buckets:
- `Pending`
- `Active`
- `Cleared`
- `Expired`
- `Failed`

### What to say about the current action model
"The response action layer is now lifecycle-aware. Actions are not just approve or reject. They can be launched, tracked, cleared, expired, or fail safely, and the system records that history."

### Manual action examples you can mention
- `block_all_outgoing`
- `block_all_incoming`
- `block_matching_connections`
- `quarantine_device`
- `enforce_pattern_of_life`

### Key point
"The system now supports explicit response control windows, not just incident decisions."

## Part 10. Show Endpoint Event Logs Before and After the Action
Open the endpoint workspace for the affected node.

### What to say
"The next question is whether the action had observable effect. So I move to the endpoint workspace and inspect the event logs for that node before, during, and after the action."

### What to point at
Show:
- `Device Summary`
- `Device Event Logs`
- top destinations
- top domains
- top users
- top rules
- event rows with action-phase labels such as:
  - `before <action>`
  - `during <action>`
  - `after <action>`

### What to say
"This is important because response must be visible in context. If I block a destination, I need to see that the endpoint was attempting the connection before the control, and that the behavior changes after the control."

### Key point
"Response is not only issued. It is monitored."

## Part 11. Real Sensitive File Tampering Test
Run:

```bash
sudo bash -lc 'printf "# rsiem demo %s\n" "$(date +%s)" >> /etc/rsiem_demo_sensitive_test.conf'
```

Optional cleanup:

```bash
sudo rm -f /etc/rsiem_demo_sensitive_test.conf
```

### What to say before running it
"I also want to show that the system covers host integrity, not only authentication and network behavior. So here I tamper with a file in a sensitive path under `/etc`."

### What this should trigger
Expected rule:
- `R-FILE-SENSITIVE-CHANGE`

Expected playbook:
- `PB-FILE-SENSITIVE-CHANGE-NOTIFY`

Expected posture:
- observation and notification, not immediate containment

### What to say when it appears
"This demonstrates that R-SIEM does not treat every event as a reason to disrupt the endpoint. For some classes of host tampering, the right first action is to detect, preserve evidence, and notify."

## Part 12. Explain Rules, Playbooks, and Policies
Pause the live demo and explain the model in plain language.

### What to say
"In R-SIEM, a rule does not directly run a command. A rule detects. A playbook defines what response steps are allowed. Policy then decides whether those steps are autonomous, approval-gated, or blocked."

Then say:

"So there are three levels of logic. Rule: what was detected. Playbook: what actions are allowed. Policy: whether those actions may happen automatically in this context."

### Playbook categories to explain
1. observation playbooks
   - notify and preserve evidence
2. bounded autonomous playbooks
   - act automatically only within policy limits
3. approval-gated playbooks
   - require a human before disruptive or sensitive action

### Concrete examples
- `PB-AUTH-ABUSE-CONTAIN`
  - containment of abusive authentication behavior
- `PB-AUTH-ACCESS-RESTORE`
  - controlled restoration after verification
- `PB-NET-INTERNAL-SCAN-CONTAIN`
  - bounded internal scan response
- `PB-FILE-SENSITIVE-CHANGE-NOTIFY`
  - non-disruptive host integrity notification

### Approval modes to explain
In `configs/master.yaml`, approval modes include:
- `auto`
- `required`
- `required_for_high`
- `required_for_critical`

Use this explanation:

"Autonomy in R-SIEM is not a binary flag. It is policy-governed. The same response framework can allow automation for bounded low-risk cases and require human approval for higher-risk or more disruptive cases."

## Part 13. Explain Confidence Scoring and Why a Run Gets 70, 80, or 100
This section should be explicit because supervisors often ask where the number comes from.

### What to say
"Confidence is not a random display field. It is derived from available context. If a run already has an explicit confidence score, the system uses it. If it does not, the UI derives a normalized score from severity and evidence richness."

### How to explain the derivation
Use this practical summary:

1. start from a base score tied to severity
2. add confidence when higher-fidelity sources are present
3. add confidence when identity context is present
4. add confidence when process context is present
5. add confidence when destination context is present
6. normalize the result into the 0 to 100 range

### Concrete evidence factors currently used
The derived score is increased by factors such as:
- source type
  - `auditd_exec` gets more weight than `tail`
  - `inotify`, `dns_packet`, and `proc_net` also add confidence
- FAST lane handling
- known user context
- `exec_path`
- `comm`
- `cmdline`
- destination IP context
- DNS query context
- explicit policy requirement such as `approval: required`

### How to explain a specific number
Use wording like this:

"If the audience asks why this run is around 80, the answer is that the score is not only severity. It reflects the quality and richness of evidence. For example, a high-severity run observed from `auditd_exec`, with a known user, process path, command line, and destination context, will score much higher than a thin tail-only signal."

### How policy uses the score
Then say:

"Playbooks also define thresholds such as `auto_min_confidence`. That means a playbook can require, for example, 82 or 90 confidence before automatic action is allowed. So the score is operational. It helps determine whether the system may act autonomously."

## Part 14. Explain Actions, Expiry, and Clearability
Say this while the audience is looking at the action surfaces.

"A response action in R-SIEM is now a lifecycle object. It has scope, duration, status, and audit history."

Then explain:
- some actions are clearable early
- some expire automatically
- some degrade safely to marker mode when enforcement would be invalid or over-broad
- actions are context-aware, so the UI now marks them as `Eligible` or `Not Eligible` before launch

### Good example explanation
"For example, `block_matching_connections` can be launched for two hours and then cleared early. `quarantine_device` can enforce or safely degrade to marker mode depending on incident context. The important point is that response is bounded, explicit, and auditable."

## Part 15. Show the Models Workspace and Governance Story
Open `Models` as admin.

### What to say
"The system now includes a controlled model editor. I want to be precise here: this is not unsafe live rule editing. It is governed configuration management."

### What to point at
Show:
- editable rules, playbooks, and approval rules
- current values
- field-level diffs
- validation result
- proposal queue
- approval / reject / apply
- restart target status
- bounded repo-side restart options

### Governance story
Say:

"This workspace exists because production-ready response systems need change management. So model changes are validated, proposed, dual-controlled, audit logged, and only then applied. Runtime restarts are explicit and bounded."

### Key point
"This is not only a SOC tool. It is also a controlled governance surface."

## Part 16. Broader Capability Coverage
Say this after the main live proofs.

"I have shown the strongest live proofs first, but the project is broader than three incidents. The playbook model now covers multiple response classes."

### Coverage class 1. identity abuse and recovery
- `PB-AUTH-ABUSE-CONTAIN`
- `PB-AUTH-ACCESS-RESTORE`

### Coverage class 2. host integrity and local tampering
- `PB-FILE-SENSITIVE-CHANGE-NOTIFY`
- `PB-STAT-PROCESS-MED`
- `PB-COUNT-PROCESS-HOST`

### Coverage class 3. network abuse and lateral movement
- `PB-NET-OUTBOUND-OBSERVE`
- `PB-NET-INTERNAL-SCAN-CONTAIN`
- `PB-NET-INTERNAL-SCAN-OBSERVE`
- `PB-LATERAL-MOVEMENT-HALT`

### Coverage class 4. first-seen and approval-governed containment
- `PB-NET-FIRST-SEEN-CONTAIN`
- `PB-PROC-FIRST-SEEN-CONTAIN`
- `PB-BRUTEFORCE-IP-CONTAIN`
- `PB-PRIVESC-LOCKDOWN`

### Coverage class 5. higher-order response and resilience
- `PB-C2-BEACON-BLOCK`
- `PB-DATA-EXFIL-THROTTLE`
- `PB-RANSOMWARE-KILL-CHAIN-STOP`
- `PB-CRITICAL-SERVICE-ABUSE-RESPONSE`
- `PB-DETECTOR-HEALTH-SELF-PROTECT`

## Part 17. Optional Broader Proof Scripts
Only use these if time permits.

### Optional breadth proof
```bash
cd ~/projects/r-siem-agent
./scripts/verify_new_playbooks.sh
```

### Optional first-seen containment proof
```bash
cd ~/projects/r-siem-agent
./scripts/verify_first_seen_containment.sh
```

### Optional deception and evidence preservation proof
```bash
cd ~/projects/r-siem-agent
./scripts/verify_fr04.sh
```

### Optional compact breadth demo
```bash
cd ~/projects/r-siem-agent
./scripts/demo_local_endpoint_triptych.sh
```

### What to say about these
"These scripts are breadth validators. They are not my first realism proof. Their purpose is to show that the project now covers a broader playbook set beyond the three main live demonstrations."

## Part 18. Honeyport and Deception Story
Use this careful wording:

"The clearest demonstrated deception capability in this project is the deception-tripwire path. If a deceptive artifact or tripwire is touched, the detector raises a dedicated deception incident. If a full honeyport service is deployed in the environment, the same system can treat interaction with that service as a high-signal input. In this presentation, what I am proving directly is the deception-trigger path and its evidence handling."

## Part 19. Production-Readiness Position
Use this wording near the end:

"My claim is not that the system is perfect. My claim is that the core architecture is built and working end to end: telemetry, detection, policy, response, search, action lifecycle, model governance, and audit. Remaining work is refinement, hardening, and deployment maturity, not the invention of the core capability."

## Closing Line
Use this if you want a firm ending:

"R-SIEM now proves that it can ingest, detect, decide, respond, investigate, govern, and audit on a live endpoint. That is the core contribution of the project."

## Fast Reference: Commands in Order

```bash
cd ~/projects/r-siem-agent
REAL_SYSTEM=1 UI_WEB_PORT=3100 ./scripts/demo_local_endpoint_clean_start.sh
sudo systemctl is-active ssh rsiem-agent rsiem-collector-tail rsiem-collector-auditd rsiem-collector-procnet rsiem-collector-dns
for i in $(seq 1 5); do echo "attempt $i"; ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 rsiemtest@127.0.0.1; done
nmap -Pn -n -sT -T3 --scan-delay 400ms --max-retries 1 -p 22,135,389,445,3389,5985 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14
sudo bash -lc 'printf "# rsiem demo %s\n" "$(date +%s)" >> /etc/rsiem_demo_sensitive_test.conf'
./scripts/verify_new_playbooks.sh
./scripts/verify_first_seen_containment.sh
./scripts/verify_fr04.sh
./scripts/demo_local_endpoint_triptych.sh
```

## Suggested Timing
- framing and health: 3 minutes
- endpoint live proof and roles: 3 minutes
- real auth-abuse test and recovery: 5 minutes
- real network scan and autonomous containment: 4 minutes
- advanced search explanation: 3 minutes
- response action lifecycle and endpoint event logs: 4 minutes
- file tampering proof: 2 minutes
- rules, playbooks, policies, and scoring: 4 minutes
- models governance view: 3 minutes
- broader capability coverage and close: 3 minutes

This gives you a strong 20 to 25 minute defense presentation. Shorten by skipping optional proof scripts.
