# R-SIEM Supervisor Demo Runbook

## Goal
Run a concise but defensible live demo that proves:

1. the stack starts healthy
2. the endpoint is live and producing telemetry
3. real endpoint activity triggers incidents
4. policy governs autonomy vs approval
5. response actions are lifecycle-aware and bounded
6. operators can investigate evidence and govern changes through the UI

## Demo Order

## 1. Start the Stack
```bash
cd ~/projects/r-siem-agent
REAL_SYSTEM=1 UI_WEB_PORT=3100 ./scripts/demo_local_endpoint_clean_start.sh
```

Expected:
- `PASS: repo:master-roe`
- `PASS: repo:master-roe-worker`
- `PASS: repo:detector-v0`
- `PASS: repo:investigation-enricher`
- endpoint services `PASS`
- UI API health `PASS`

Presentation line:
"I begin by proving that the control plane, UI plane, and endpoint plane are healthy."

## 2. Open the UI and Introduce the Main Surfaces
Open:

```text
http://127.0.0.1:3100
```

Show briefly:
- `Incidents`
- `Endpoints`
- `Actions`
- `Search`
- `Models`
- `Audit`

Presentation line:
"The UI now mirrors the actual backend state and supports investigation, response, governance, and audit."

## 3. Prove the Endpoint Is Live
```bash
sudo systemctl is-active ssh rsiem-agent rsiem-collector-tail rsiem-collector-auditd rsiem-collector-procnet rsiem-collector-dns
```

Expected:
- `active` for `ssh`
- `active` for `rsiem-agent`
- `active` for `rsiem-collector-tail`
- `active` for `rsiem-collector-auditd`
- `active` for `rsiem-collector-procnet`
- `active` for `rsiem-collector-dns`

Presentation line:
"This laptop is acting as a live endpoint with installed services, not only as a dashboard host."

## 4. Explain Roles
Use this short explanation.

### Analyst
- triage incidents
- investigate evidence and search
- approve or reject where workflow allows it
- add notes, review, and assign to self
- launch allowed response actions
- perform verify/restore on eligible identity runs

### Admin
- everything analyst can do
- plus model editing and proposal approval
- bounded repo-side restarts after model apply
- user administration
- full admin audit visibility

Presentation line:
"The analyst handles operations. The admin handles governance and configuration control."

## 5. Run the Real SSH Failed-Password Burst
Precondition:
- `openssh-server` installed and running
- disposable user exists, for example `rsiemtest`
- SSH password auth enabled

One-time preparation if needed:

```bash
sudo useradd -m -s /bin/bash rsiemtest
sudo passwd rsiemtest
sudo sshd -T | rg 'passwordauthentication'
```

Run:

```bash
for i in $(seq 1 5); do
  echo "attempt $i"
  ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 rsiemtest@127.0.0.1
done
```

Operator action:
- type the wrong password once per attempt
- let each attempt fail
- complete all 5 attempts

Expected:
- detector match for `R-AUTH-FAILED-PW-BURST-USER`
- `PB-AUTH-ABUSE-CONTAIN` run created
- run enters `WAITING_APPROVAL`

Evidence command:

```bash
cd ~/projects/r-siem-agent
rg -n 'R-AUTH-FAILED-PW-BURST|PB-AUTH-ABUSE-CONTAIN|rsiemtest|127\.0\.0\.1' logs/detector.log logs/master-roe.log | tail -n 50
```

Presentation line:
"This is a real auth-abuse event from a real endpoint service."

## 6. Approve, Verify, and Restore
Open the `PB-AUTH-ABUSE-CONTAIN` incident.

Expected before approval:
- status `WAITING_APPROVAL`

Do:
- click `Approve`
- wait for `SUCCEEDED`
- use `Verify User`
- then use `Restore Access`

Expected:
- containment succeeds
- verification workflow becomes available
- restore succeeds after verification

Presentation line:
"This proves the identity workflow is complete: contain, verify, restore."

## 7. Run the Real Internal Scan
```bash
cd ~/projects/r-siem-agent
nmap -Pn -n -sT -T3 --scan-delay 400ms --max-retries 1 -p 22,135,389,445,3389,5985 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14
```

Expected:
- detector matches internal scan rules
- `PB-NET-INTERNAL-SCAN-CONTAIN` runs
- `halt_lateral_movement` executes
- run becomes `SUCCEEDED`

Evidence commands:

```bash
cd ~/projects/r-siem-agent
rg -n 'R-NET-INTERNAL-|trigger_published|cooldown_hit|auditd_connect|proc_net|172\.30\.50\.' logs/detector.log | tail -n 80
rg -n 'response_run_created|response_run_updated|SUCCEEDED|FAILED_SAFE|protocol_family|dst_port|172\.30\.50\.' logs/master-roe.log | tail -n 80
rg -n 'step_received|step_succeeded|step_failed_safe|agent_command_reply|halt_lateral_movement' logs/worker.log | tail -n 80
sudo rg -n 'halt_lateral_movement|agent_command_exec_start|agent_command_exec_done|exit_code' /var/log/rsiem/agent.log | tail -n 80
```

Presentation line:
"This is the strongest autonomous end-to-end proof because it uses real endpoint network behavior and results in actual containment."

## 8. Use Advanced Search
Go to `/search`.

Use a short window around the `nmap` run, then try these queries in order:

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

Expected:
- parsed field filters from the top bar
- time analysis of the result set
- grouped quick analysis
- normalized event rows with process/network context

Presentation line:
"This is how the operator pivots from an incident into the underlying event evidence."

## 9. Show a Manual Response Action as Admin
Use either:
- incident `Actions` tab
- endpoint workspace `Response Actions`
- fleet `/actions`

Recommended example:
- `block_matching_connections`
- duration `2 hours`
- use incident destination IP or DNS target

Expected:
- action launches successfully
- action appears in the lifecycle bucket views
- visible state includes `Pending`, `Active`, `Cleared`, `Expired`, or `Failed`
- action cards show `Eligible` or `Not Eligible`

Presentation line:
"R-SIEM now supports lifecycle-aware manual response actions, not only incident approval decisions."

## 10. Show Endpoint Workspace Before/During/After the Action
Open the affected node in `Endpoints`.

Show:
- `Device Summary`
- `Device Event Logs`
- top destinations
- top domains
- top users
- top rules
- event rows marked:
  - `before <action>`
  - `during <action>`
  - `after <action>`

Presentation line:
"This allows me to verify whether an action had observable effect on endpoint behavior."

## 11. Run the Real Sensitive File Tampering Test
```bash
sudo bash -lc 'printf "# rsiem demo %s\n" "$(date +%s)" >> /etc/rsiem_demo_sensitive_test.conf'
```

Optional cleanup:

```bash
sudo rm -f /etc/rsiem_demo_sensitive_test.conf
```

Expected:
- detector match for `R-FILE-SENSITIVE-CHANGE`
- `PB-FILE-SENSITIVE-CHANGE-NOTIFY` run created
- notify/observe path, not disruptive containment

Evidence command:

```bash
cd ~/projects/r-siem-agent
rg -n 'R-FILE-SENSITIVE-CHANGE|PB-FILE-SENSITIVE-CHANGE-NOTIFY|rsiem_demo_sensitive_test' logs/detector.log logs/master-roe.log | tail -n 40
```

Presentation line:
"This shows that R-SIEM also covers host integrity events, not only auth and network abuse."

## 12. Explain Rules, Playbooks, Policies, and Confidence
Use these lines during the explanation section.

### Rules
- rules describe what was detected
- examples:
  - `R-AUTH-FAILED-PW-BURST-USER`
  - `R-NET-INTERNAL-WINRM-SCAN`
  - `R-FILE-SENSITIVE-CHANGE`

### Playbooks
- playbooks describe what response actions are allowed
- examples:
  - `PB-AUTH-ABUSE-CONTAIN`
  - `PB-AUTH-ACCESS-RESTORE`
  - `PB-NET-INTERNAL-SCAN-CONTAIN`
  - `PB-FILE-SENSITIVE-CHANGE-NOTIFY`

### Policies
- policies decide whether the playbook runs automatically, waits for approval, or is blocked
- policy evaluates things like:
  - severity
  - confidence
  - blast radius
  - identity context
  - reversibility
  - whether the source is local
  - whether the action affects privileged access

Plain-language line:
"The rule explains what was detected, the playbook explains what actions are allowed, and the policy explains whether those actions are allowed automatically or only with human approval."

### Confidence explanation
Use this short version:
- start from severity
- increase confidence when higher-fidelity sources are present
- increase confidence when user/process/destination context is present
- normalize into `0-100`
- compare against playbook thresholds like `auto_min_confidence`

Plain-language line:
"A run gets to 70, 80, or 100 because the system is scoring both severity and evidence richness, not just counting alerts."

## 13. Show the Models Workspace as Admin
Open `Models`.

Show:
- editable rules, playbooks, approval rules
- current values
- field-level diffs
- validation
- proposal queue
- approve/reject/apply
- restart target status
- bounded restart targets

Explain:
- model editing is admin-only
- proposals require dual control
- changes are audit logged
- repo-side restart is explicit and bounded

Presentation line:
"This is controlled configuration governance, not unsafe live rule editing."

## 14. Optional Breadth and Proof Scripts
Use only if time permits.

### Broader playbook coverage
```bash
cd ~/projects/r-siem-agent
./scripts/verify_new_playbooks.sh
```

### First-seen containment
```bash
cd ~/projects/r-siem-agent
./scripts/verify_first_seen_containment.sh
```

### Deception and evidence preservation
```bash
cd ~/projects/r-siem-agent
./scripts/verify_fr04.sh
```

### Compact breadth demo
```bash
cd ~/projects/r-siem-agent
./scripts/demo_local_endpoint_triptych.sh
```

Presentation line:
"These are breadth validators. They are not the primary realism proof."

## What to Emphasize
- stack health
- live endpoint services
- real SSH auth-abuse proof
- approval, verification, and restore
- real internal scan containment proof
- Advanced Search as event-evidence pivot
- response action lifecycle and bounded duration
- endpoint event logs before/during/after action
- host tampering coverage
- rules, playbooks, policies, and confidence explanation
- admin-governed model editing with dual control
- auditability across the whole chain

## Do Not Overclaim
- do not say every action is autonomous
- do not say the model editor is unrestricted live editing
- do not say deception is a full honeyport platform unless one is running live
- do not use optional proof scripts as the main realism claim when the live endpoint tests are stronger

Preferred language:
"The core loop is complete and working. Remaining work is refinement and production hardening, not basic capability invention."

## Backup Evidence if a Live Step Misbehaves
Use these as fallback:
- `./scripts/verify_new_playbooks.sh`
- `./scripts/verify_first_seen_containment.sh`
- `./scripts/verify_fr04.sh`
- `./scripts/demo_local_endpoint_triptych.sh`
- `./scripts/adversary_emulation_harness.sh --scenario t1110_auth_abuse_burst`

## Final Closing Line
"R-SIEM now proves that it can ingest, detect, decide, respond, investigate, govern, and audit across the endpoint and control plane. That is the main technical contribution of this project."
