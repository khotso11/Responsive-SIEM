# R-SIEM Supervisor Presentation Narrative

## Purpose
This is the speaker script for the supervisor presentation. It is written as a real talk track, in the order you should run the demo. It tells you:

- what to say
- which script to run
- what that script actually triggers
- what the system is expected to do
- what point you should make before moving on

Use this as your primary presentation script. Use `docs/supervisor_demo_runbook.md` as the operator checklist.

## Presentation Strategy
The strongest defense is not to claim that R-SIEM can do everything. The strongest defense is to show that the main loop is complete and working:

1. the system starts cleanly
2. the endpoint produces real telemetry
3. the detector creates incidents
4. policy decides whether response is automatic or approval-gated
5. the endpoint executes safe bounded commands
6. the result is visible in the UI, logs, and artifacts

Your message throughout the presentation is:

"R-SIEM is no longer only an alerting system. It is a response-capable SIEM with policy-governed autonomy, approval boundaries, and endpoint-executed containment."

## Recommended Demo Order
Use this order:

1. `./scripts/demo_local_endpoint_clean_start.sh`
2. open the UI
3. `./scripts/demo_local_endpoint_triptych.sh`
4. approve or deny one waiting approval incident
5. real internal scan with `nmap`
6. optional `./scripts/verify_first_seen_containment.sh`
7. optional `./scripts/verify_fr04.sh`
8. close with capability summary and project status

Do not start with a complex proof script. Start by proving the stack is healthy.

## Opening Narrative
Say this before you run anything:

"My project is R-SIEM, a response-capable SIEM built to go beyond detection. The key contribution is not just that it raises alerts. The key contribution is that it can ingest endpoint telemetry, decide whether response is autonomous or approval-gated, execute bounded endpoint actions, and preserve an auditable trail of everything it did."

Then say:

"I am going to present this in the same order the system works internally: startup, telemetry ingestion, detection, policy decision, response execution, and evidence."

## Part 1. Start the Stack
Run:

```bash
cd ~/projects/r-siem-agent
REAL_SYSTEM=1 UI_WEB_PORT=3100 ./scripts/demo_local_endpoint_clean_start.sh
```

### What to say while it runs
"I start by proving that both the control plane and the endpoint plane are healthy. This matters because during a defense, I do not want any ambiguity between a demo failure and a system failure. So the first thing I show is health."

### What this script actually does
This script:

- starts repo-side services such as `master-roe`, `master-roe-worker`, `detector-v0`, and `investigation-enricher`
- prepares endpoint-side components
- ensures endpoint collectors and the agent are active
- checks UI API health
- prints a final health summary

### What to point at
When the health summary appears, say:

"This summary tells us that the orchestration plane is running, the endpoint collectors are running, the agent is running, and the UI is reachable. So now I have a valid system state for the live tests."

### Key point to make
"R-SIEM is not only code in a repository. It is running as a coordinated system."

## Part 2. Open the UI
Open:

```text
http://127.0.0.1:3100
```

### What to say
"Now I open the UI because I want the audience to see incidents and response status as a security operator would see them. The terminal gives the technical proof. The UI gives the operational view."

### What to point at
Show:

- incidents list
- incident drawer
- status updates
- approval workflow if visible

### Key point to make
"The UI is not separate from the backend logic. It reflects the same detector, policy, and response state that the backend is processing."

## Part 3. Run the Local Endpoint Triptych
Run:

```bash
cd ~/projects/r-siem-agent
./scripts/demo_local_endpoint_triptych.sh
```

### What to say before running it
"This next script is useful because it demonstrates three different response classes from one endpoint: a FAST security incident, a deception incident, and a STANDARD workflow incident. It shows that the system is not one-dimensional."

### What this script actually triggers
This script has three parts.

#### 3.1 FAST event
It appends a failed password line to `/var/log/auth.log` using a fake invalid user and source IP.

Expected trigger:

- rule: `R-COLLECT-INVALID-USER`
- expected playbook path: `PB-AUTH-ABUSE-CONTAIN`
- expected lane: `FAST`
- expected response posture: approval-gated

### What to say when this appears
"This is an authentication abuse style signal. The important thing here is that the system does not blindly contain access. It detects the event, creates the run, and because access control is sensitive, policy can require approval. That is deliberate."

#### 3.2 DECEPTION event
It appends an alert line to `/var/log/auth.log` that looks like a deception tripwire event.

Expected trigger:

- rule: `R-FR03-DECEPTION-TRIPWIRE`
- expected lane: `FAST`
- expected outcome: deception incident visible in detector and UI

### What to say when this appears
"This is the deception path. The point here is that R-SIEM can treat interaction with a tripwire or deceptive artifact as high-value security evidence. In the architecture, deception is not just another log line. It is a high-signal trigger."

Important wording:

"In this demo, I am showing the deception-tripwire detection path. I am not claiming a full production honeyport platform unless I run one live."

#### 3.3 STANDARD event
It publishes a canonical raw event for a process-count style incident.

Expected trigger:

- rule: `R-COUNT-PROCESS-HOST`
- expected lane: `STANDARD`
- expected playbook behavior: auto safe path, typically `ping` plus notification

### What to say when this appears
"This is the STANDARD path. It demonstrates that not every incident is a containment event. Some incidents are designed to notify, enrich, or perform a bounded verification step rather than disrupt the endpoint."

### What to say after the script finishes
"This one script shows three important design decisions in R-SIEM: first, incidents are classified by urgency and type; second, deception is treated as a real detection path; and third, response is not always disruptive."

## Part 4. Show Approval and Deny
At this point, find a `WAITING_APPROVAL` run in the UI or logs.

### What to say before doing it
"Now I want to show one of the most important control points in the whole system: governance. R-SIEM is designed to automate what is safe, and to ask for human approval where autonomy would be too risky."

### If you want to approve
Run:

```bash
nats pub rsiem.response.approvals '{"run_id":"<RUN_ID>","decision":"approve","actor":"khotso","reason":"lab approval"}'
```

### If you want to deny
Run:

```bash
nats pub rsiem.response.approvals '{"run_id":"<RUN_ID>","decision":"deny","actor":"khotso","reason":"operator denied"}'
```

### What to say while doing it
If approving:

"Here I am showing that the system does not need me for every step, but it can require me when the action touches access, execution, or containment in a sensitive context. Once I approve, the response loop continues and the worker can execute the allowed endpoint command."

If denying:

"Here I am proving the negative case. A response-capable system is only trustworthy if it can also decide not to act. Deny should stop the disruptive step, and that is exactly what I want to prove."

### Key point to make
"Human approval is not a missing feature. It is a safety feature."

## Part 5. Run the Real Internal Scan
Run:

```bash
cd ~/projects/r-siem-agent
date '+SCAN_START %F %T %z'
nmap -Pn -n -sT -T3 --scan-delay 400ms --max-retries 1 -p 22,135,389,445,3389,5985 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14
date '+SCAN_END %F %T %z'
```

### What to say before running it
"This is the strongest technical proof in the entire demo. Instead of injecting a synthetic event, I am going to create real endpoint network behavior. The endpoint collectors will observe it, the detector will classify it, the response engine will decide whether autonomy is allowed, and the agent will execute containment."

### What this triggers
This real scan is expected to trigger the internal scan rules, such as:

- `R-NET-INTERNAL-RDP-SCAN`
- `R-NET-INTERNAL-WINRM-SCAN`

Expected playbook:

- `PB-NET-INTERNAL-SCAN-CONTAIN`

Expected command on the agent:

- `halt_lateral_movement`

Expected posture:

- autonomous response if policy bounds are satisfied

### What to say when the incidents appear
"This is where R-SIEM shows its core value. The system is not only observing internal scan activity. It is converting that activity into a policy-governed response run and then executing a bounded containment command on the endpoint."

### What to explain about `proc_net` and `auditd_connect`
Say this if asked why one source appears first:

"In the current design, `proc_net` tends to arrive first and win first containment because it is faster. `auditd_connect` arrives later and serves as stronger corroborating evidence. We intentionally kept that behavior because delaying first containment in order to wait for a higher-fidelity source would be the wrong tradeoff for this class of event."

If you want to show the technical proof, use:

```bash
cd ~/projects/r-siem-agent
rg -n 'R-NET-INTERNAL-|trigger_published|cooldown_hit|auditd_connect|proc_net|172\.30\.50\.' logs/detector.log | tail -n 80
rg -n 'response_run_created|response_run_updated|SUCCEEDED|FAILED_SAFE|protocol_family|dst_port|172\.30\.50\.' logs/master-roe.log | tail -n 80
rg -n 'step_received|step_succeeded|step_failed_safe|agent_command_reply|halt_lateral_movement' logs/worker.log | tail -n 80
sudo rg -n 'halt_lateral_movement|agent_command_exec_start|agent_command_exec_done|exit_code' /var/log/rsiem/agent.log | tail -n 80
```

### What to say after showing success
"This proves the full closed loop: real endpoint behavior, live detection, policy evaluation, autonomous action, and successful endpoint execution. This is the part that demonstrates the project is functionally complete."

## Part 6. Explain Playbooks and Policies in Conversation Form
At this point, pause the live demo and explain the design.

### What to say
"Now that I have shown the system reacting, I want to explain why it reacted the way it did. In R-SIEM, a detection rule does not directly run a command. It maps into a playbook, and the playbook is governed by policy."

Then say:

"There are three broad categories of playbooks in this project."

### Category 1. Observation playbooks
Say:

"The first category is observation or notify-only playbooks. These are used for things like suspicious DNS, outbound observation, or sensitive file monitoring. The system creates the incident and preserves the evidence, but it does not necessarily disrupt the endpoint."

### Category 2. Autonomous but bounded playbooks
Say:

"The second category is autonomous but bounded playbooks. A good example is internal scan containment. The system can act automatically only if confidence, severity, and blast radius stay within policy bounds. This is not blind automation. It is constrained automation."

### Category 3. Approval-gated playbooks
Say:

"The third category is approval-gated playbooks. These cover actions where the system could affect user access, process execution, first-seen containment, privilege containment, or other sensitive operations. In those cases, the human is explicitly kept in the loop."

### Approval policy explanation
Say:

"The approval model is explicit. We have `auto`, `required`, `required_for_high`, and `required_for_critical`. That means the same response framework can support full autonomy for low-risk cases and strict approval for sensitive cases."

Then say:

"This is one of the core engineering decisions in the project: autonomy is not a binary setting. It is policy-governed."

## Part 7. Optional First-Seen Containment Proof
If you want a stronger approval-governed containment demo, run:

```bash
cd ~/projects/r-siem-agent
./scripts/verify_first_seen_containment.sh
```

### What to say before running it
"This script proves a different response class: first-seen risky network destinations and first-seen suspicious processes. These are intentionally approval-oriented containment cases because they can affect execution or connectivity in a more disruptive way."

### What this script actually triggers
This script drives two containment paths:

#### 7.1 Network first-seen
Expected trigger:

- rule: `R-NET-FIRST-SEEN-RISKY`
- expected behavior: waiting approval, then `contain_destination_ip` after approval

#### 7.2 Process first-seen
Expected trigger:

- rule: `R-PROC-FIRST-SEEN-SUSPICIOUS`
- expected behavior: waiting approval, then `contain_process_exec` after approval

### What to say after it succeeds
"This proves that R-SIEM can do more than one kind of containment. It can contain network destinations and process execution, but only after policy and approval allow it."

## Part 8. Optional FR04 Deception and Evidence Preservation
If you want to demonstrate evidence handling, run:

```bash
cd ~/projects/r-siem-agent
./scripts/verify_fr04.sh
```

### What to say before running it
"This final proof is about evidence, not only response. Detection is useful, containment is useful, but forensics and auditability are also part of a serious security system."

### What this script actually does
It:

- starts a local packet capture
- produces local network activity
- injects a deception tripwire style event
- waits for `R-FR03-DECEPTION-TRIPWIRE`
- writes proof artifacts such as:
  - `capture.pcap`
  - `chain_of_custody.json`
  - `fr04_proof.json`

### What to say after it completes
"This demonstrates that the system can pair detection with retained evidence. In other words, the incident is not only visible, it is also defensible."

## Part 9. Explain When the System Responds Autonomously
Use this wording:

"The system responds autonomously when the playbook allows auto mode and the policy checks are satisfied. In practical terms, that means severity, confidence, blast radius, and identity context stay inside acceptable bounds."

Then say:

"A good example from this demo is internal scan containment. Because the response is bounded and the policy thresholds are satisfied, the system can run `halt_lateral_movement` automatically."

## Part 10. Explain When the System Asks Me to Approve or Deny
Use this wording:

"The system asks me to approve or deny when the action could be more disruptive or sensitive. That includes access containment, first-seen containment, privilege-linked actions, and cases where the policy says a human must remain in the loop."

Then say:

"So the question is not whether the system can automate. The question is whether it should automate this specific action in this specific context."

## Part 11. Explain the Honeyport / Deception Story Carefully
Use this wording:

"In this project, the clearest demonstrated deception capability is the deception-tripwire path. When a deceptive artifact or tripwire event is touched, the detector raises a dedicated deception incident."

Then say:

"If I run a full honeyport or deception service in the environment, the system can treat interaction with that service as a high-signal input. In this presentation, what I am proving directly is the deception-trigger path and the way the system handles that signal."

This keeps the claim accurate.

## Part 12. Close the Presentation
Say this near the end:

"At this point, I have shown the project in the same sequence a real deployment would experience it. I started the stack, produced endpoint telemetry, triggered detections, showed policy-governed response, demonstrated autonomous containment, demonstrated approval-gated control, and showed that the whole chain is auditable."

Then say:

"So my defense claim is not that the system is perfect or fully production-hardened. My defense claim is that the core system is built, integrated, and working end to end. The remaining work is refinement and hardening, not the invention of the core capability."

## Short Closing Line
Use this exact line if you want a firm ending:

"R-SIEM now proves that it can ingest, detect, decide, respond, and audit on a live endpoint. That is the core contribution of the project."

## Fast Reference: Commands in Order

```bash
cd ~/projects/r-siem-agent
REAL_SYSTEM=1 UI_WEB_PORT=3100 ./scripts/demo_local_endpoint_clean_start.sh
./scripts/demo_local_endpoint_triptych.sh
nmap -Pn -n -sT -T3 --scan-delay 400ms --max-retries 1 -p 22,135,389,445,3389,5985 172.30.50.11 172.30.50.12 172.30.50.13 172.30.50.14
./scripts/verify_first_seen_containment.sh
./scripts/verify_fr04.sh
```

## Recommended Timing

- startup and framing: 3 minutes
- triptych demo: 4 minutes
- approval/deny explanation: 3 minutes
- internal scan live proof: 5 minutes
- optional first-seen proof: 3 minutes
- optional FR04 evidence proof: 3 minutes
- closing argument: 2 minutes

This gives you a strong 15 to 20 minute defense presentation.
