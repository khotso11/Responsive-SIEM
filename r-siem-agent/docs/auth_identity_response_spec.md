# Auth Identity Response Spec

## Goal

Add a first-class identity containment and recovery workflow to R-SIEM for repeated authentication abuse.

This feature extends the existing R-SIEM response model with:

- dedicated auth-abuse detection rules
- dedicated auth containment playbook
- dedicated auth restore playbook
- explicit operator verification workflow
- auditable restore path
- panel-ready demo flow

This spec is written against the current repo structure and current control plane:

- rules and playbooks in `configs/master.yaml`
- ROE playbook execution in `cmd/master-roe`
- endpoint action execution in `cmd/agent`
- incident/audit workflow in `cmd/ui-api`
- SOC operator workflow in `ui/`

It is intentionally incremental. It does not require a new response engine.

## Non-goals

This spec does not start with:

- direct `/etc/shadow` mutation
- PAM file edits
- irreversible account disablement
- hidden endpoint-side state outside R-SIEM-managed storage

The first implementation must be:

- reversible
- deterministic
- auditable
- safe for demos and lab testing

## Desired lifecycle

1. repeated auth failures are detected
2. auth abuse is correlated by user, source IP, and node
3. policy evaluates severity, confidence, blast radius, and reversibility
4. containment is auto-executed or approval-gated
5. operator verifies user identity
6. operator restores access through a dedicated recovery action
7. incident report includes containment, verification, restore, and lessons learned

## Rule additions for `configs/master.yaml`

Add these rules under `rce.rules`.

These are concrete rule IDs to introduce:

```yaml
    - id: R-AUTH-FAILED-PW-BURST-USER
      enabled: true
      kind: count
      severity: high
      group_by: user
      window_ms: 300000
      threshold: 5
      when:
        type: auth
        fields:
          message_contains: "Failed password"

    - id: R-AUTH-FAILED-PW-BURST-SRCIP
      enabled: true
      kind: count
      severity: high
      group_by: src_ip
      window_ms: 300000
      threshold: 8
      when:
        type: auth
        fields:
          message_contains: "Failed password"

    - id: R-AUTH-USER-SRCIP-BURST
      enabled: true
      kind: count
      severity: critical
      group_by: user
      window_ms: 300000
      threshold: 10
      when:
        type: auth
        fields:
          message_contains: "Failed password"

    - id: R-AUTH-ACCESS-RESTORE-REQUEST
      enabled: true
      kind: trigger
      severity: medium
      group_by: user
      when:
        type: auth
        fields:
          message_contains: "auth_restore_requested"
```

### Rule intent

- `R-AUTH-FAILED-PW-BURST-USER`
  - repeated failed passwords against a user
- `R-AUTH-FAILED-PW-BURST-SRCIP`
  - repeated failed passwords from a source
- `R-AUTH-USER-SRCIP-BURST`
  - higher-confidence auth abuse escalation path
- `R-AUTH-ACCESS-RESTORE-REQUEST`
  - optional workflow/event hook if restore actions are also represented as events

### Detection notes

Use the existing detector event model first. Do not add a new event transport.

For implementation, enrich auth events with:

- `user_name`
- `src_ip`
- `node_id`
- `auth_service`
- `auth_result`

Current auth collector already gives enough to start with `message_contains`.

## Playbook additions for `configs/master.yaml`

Add these playbooks under `playbooks`.

### 1. Containment playbook

```yaml
  - id: "PB-AUTH-ABUSE-CONTAIN"
    version: 1
    enabled: true
    selectors:
      rule_ids:
        - "R-AUTH-FAILED-PW-BURST-USER"
        - "R-AUTH-FAILED-PW-BURST-SRCIP"
        - "R-AUTH-USER-SRCIP-BURST"
    policy_requirements:
      approval: "required_for_high"
      max_blast_radius: 1
      auto_max_severity: "high"
      auto_max_blast_radius: 1
      auto_min_confidence: 88
    steps:
      - name: "auth_contain_src_ip"
        action_type: "agent_command"
        reversibility: "reversible"
        timeout_ms: 4000
        retries: 1
        backoff_ms: 500
        target_from: "global"
        params:
          command: "auth_contain_src_ip"
          duration_ms: 900000
          state_file: "auth_access_state.json"

      - name: "auth_contain_user_access"
        action_type: "agent_command"
        reversibility: "reversible"
        timeout_ms: 4000
        retries: 1
        backoff_ms: 500
        target_from: "global"
        params:
          command: "auth_contain_user_access"
          duration_ms: 900000
          state_file: "auth_access_state.json"

      - name: "notify_auth_containment"
        action_type: "notify"
        reversibility: "reversible"
        timeout_ms: 2000
        retries: 0
        backoff_ms: 0
        target_from: "group_key"
```

### 2. Restore playbook

```yaml
  - id: "PB-AUTH-ACCESS-RESTORE"
    version: 1
    enabled: true
    selectors:
      rule_ids:
        - "R-AUTH-ACCESS-RESTORE-REQUEST"
    policy_requirements:
      approval: "required"
      max_blast_radius: 1
      auto_min_confidence: 100
    steps:
      - name: "auth_mark_user_verified"
        action_type: "agent_command"
        reversibility: "reversible"
        timeout_ms: 3000
        retries: 0
        backoff_ms: 0
        target_from: "global"
        params:
          command: "auth_mark_user_verified"
          state_file: "auth_access_state.json"

      - name: "auth_restore_src_ip"
        action_type: "agent_command"
        reversibility: "reversible"
        timeout_ms: 4000
        retries: 1
        backoff_ms: 500
        target_from: "global"
        params:
          command: "auth_restore_src_ip"
          state_file: "auth_access_state.json"

      - name: "auth_restore_user_access"
        action_type: "agent_command"
        reversibility: "reversible"
        timeout_ms: 4000
        retries: 1
        backoff_ms: 500
        target_from: "global"
        params:
          command: "auth_restore_user_access"
          state_file: "auth_access_state.json"

      - name: "notify_auth_restore"
        action_type: "notify"
        reversibility: "reversible"
        timeout_ms: 2000
        retries: 0
        backoff_ms: 0
        target_from: "group_key"
```

## Policy intent

Containment and restore should not share the same approval posture.

### Containment

Auto or approval-gated based on:

- severity
- confidence
- blast radius
- reversibility

Recommended effective policy:

- auto-run if:
  - severity <= high
  - confidence >= 88
  - max blast radius <= 1
  - all steps reversible
- require approval if:
  - account is privileged
  - target node is production-critical
  - scope expands beyond single user or single source IP
  - blast radius > 1

### Restore

Restore should always be explicit and operator-driven.

Recommended policy:

- restore requires:
  - verified user
  - actor
  - restore reason
  - incident in containment or manual-review/resolved state
- restore may require second approval later for privileged identities, but not in v1

## Exact agent command contract

Implement these new `agent_command` IDs in `cmd/agent/command.go`.

Add them to the existing command allowlist next to current marker-style commands.

### 1. `auth_contain_src_ip`

Purpose:
- write reversible endpoint-side state indicating source IP is temporarily blocked

Required params:

- `src_ip`
- `run_id`
- `duration_ms`
- `state_file`

Optional params:

- `reason`
- `user_name`
- `node_id`

Expected execution:

- validate `run_id`
- validate `src_ip`
- write/update R-SIEM-managed state under:
  - `/var/lib/rsiem/auth_controls/<run_id>.json`
  - or a single indexed state file such as:
    - `/var/lib/rsiem/auth_controls/auth_access_state.json`
- store:
  - `run_id`
  - `src_ip`
  - `user_name`
  - `contained_at_unix_ms`
  - `expires_at_unix_ms`
  - `actor`
  - `reason`
  - `scope = src_ip`

Expected reply:

- `status=ok`
- `exit_code=0`
- stdout contains the state path

### 2. `auth_contain_user_access`

Purpose:
- write reversible state indicating user access is temporarily contained

Required params:

- `user_name`
- `run_id`
- `duration_ms`
- `state_file`

Optional params:

- `src_ip`
- `reason`
- `auth_service`

State content:

- `scope = user`
- `user_name`
- `src_ip`
- `contained_at_unix_ms`
- `expires_at_unix_ms`
- `restore_required = true`

### 3. `auth_mark_user_verified`

Purpose:
- record that a human verified the identity before restore

Required params:

- `user_name`
- `run_id`
- `verification_method`
- `verification_reference`
- `state_file`

Optional params:

- `verified_by`
- `notes`

Expected behavior:

- append or update verification details in the same R-SIEM-managed state record
- do not restore anything yet

### 4. `auth_restore_src_ip`

Purpose:
- reverse the temporary source-IP containment state

Required params:

- `src_ip`
- `run_id`
- `state_file`

Expected behavior:

- confirm matching containment state exists
- mark restored, record `restored_at_unix_ms`
- return `safe_denied` if no matching state is present or state mismatches

### 5. `auth_restore_user_access`

Purpose:
- reverse the temporary user containment state

Required params:

- `user_name`
- `run_id`
- `state_file`

Optional params:

- `restore_reason`
- `verified_by`

Expected behavior:

- confirm containment state exists
- confirm verification is present
- mark restored
- if verification missing:
  - return `safe_denied:verification_required`

## Endpoint-side storage

Do not use hidden state.

Store auth containment state under:

- `/var/lib/rsiem/auth_controls/`

Recommended file layout:

- per-run state:
  - `/var/lib/rsiem/auth_controls/<run_id>.json`
- optional index:
  - `/var/lib/rsiem/auth_controls/index.json`

Minimum state object:

```json
{
  "run_id": "abc123",
  "scope": "user",
  "user_name": "alice",
  "src_ip": "10.0.0.8",
  "node_id": "endpoint-01",
  "status": "contained",
  "contained_at_unix_ms": 1770000000000,
  "expires_at_unix_ms": 1770000900000,
  "verified": false,
  "verified_by": "",
  "verification_method": "",
  "verification_reference": "",
  "restored": false,
  "restored_at_unix_ms": 0
}
```

This keeps restore deterministic and auditable.

## UI actions

Add identity-specific actions to the incident workspace for auth-abuse incidents.

### Incident drawer / detail page

Show these actions when:

- `rule_id` is one of the auth-abuse rule IDs
- or `playbook_id` is `PB-AUTH-ABUSE-CONTAIN`
- or incident metadata declares `response_family = auth_identity`

### New operator actions

1. `Verify User`
2. `Contain Access`
3. `Restore Access`
4. `Mark Restored`

### Verification form fields

- `actor`
- `verification_method`
  - `phone`
  - `helpdesk`
  - `manager_confirmation`
  - `mfa_challenge`
  - `other`
- `verification_reference`
- `notes`

### Restore form fields

- `actor`
- `restore_reason`
- `verified_by`
- `change_reference` or `ticket_id`

### UI flow

For `WAITING_APPROVAL` containment:

- show:
  - user
  - source IP
  - node
  - confidence
  - reversibility
  - blast radius class
- actions:
  - Approve
  - Reject

For contained incidents:

- show:
  - containment active
  - scope
  - expiry
  - verification state
- actions:
  - Verify User
  - Restore Access

For restore-eligible incidents:

- require verification fields before restore submit

## UI API endpoints

Add these endpoints in `cmd/ui-api/main.go`.

### Verification

- `POST /api/incidents/{run_id}/verify-user`

Body:

```json
{
  "actor": "admin",
  "verification_method": "phone",
  "verification_reference": "HD-4832",
  "notes": "User confirmed failed VPN login attempts were their own"
}
```

### Restore

- `POST /api/incidents/{run_id}/restore-access`

Body:

```json
{
  "actor": "admin",
  "restore_reason": "identity verified and service access restored",
  "verified_by": "admin",
  "change_reference": "CHG-8842"
}
```

### Access-state query

- `GET /api/incidents/{run_id}/access-state`

Response should include:

- containment active
- scope
- verification state
- restore state
- expiry

## Audit events

Add these audit events and include them in `/api/audit`.

- `identity_verification_started`
- `identity_verification_completed`
- `auth_access_contained`
- `auth_access_contain_denied`
- `auth_access_restore_requested`
- `auth_access_restored`
- `auth_access_restore_denied`
- `auth_restore_failed_safe`

Each event should include:

- `run_id`
- `actor`
- `user_name`
- `src_ip`
- `node_id`
- `verification_method`
- `verification_reference`
- `restore_reason`
- `scope`
- `status`
- `ts`

### Human-friendly labels

Add UI labels in `ui/app/audit/page.tsx`:

- `identity_verification_started` -> `Identity Verification Started`
- `identity_verification_completed` -> `Identity Verification Completed`
- `auth_access_contained` -> `Access Contained`
- `auth_access_restore_requested` -> `Access Restore Requested`
- `auth_access_restored` -> `Access Restored`
- `auth_access_restore_denied` -> `Access Restore Denied`
- `auth_restore_failed_safe` -> `Access Restore Failed Safe`

## Reporting impact

Incident reports for auth-identity incidents should add:

- affected user
- affected source IP
- containment scope
- verification method/reference
- restore actor and restore reason
- containment duration
- lessons learned

SOC operations report should count:

- auth containment actions
- restore actions
- restore success rate
- mean time to restore

## Demo sequence for panel

This is the exact panel sequence the product should support when implemented.

### Step 1: trigger the incident

- operator intentionally generates repeated failed passwords
- endpoint collector ships auth telemetry
- detector matches auth-abuse rule
- incident is created

### Step 2: show governed containment

- open incident in UI
- show:
  - user
  - source IP
  - policy reason
  - confidence
  - reversibility
- operator approves containment if required

### Step 3: show access has been contained

- incident shows:
  - containment active
  - scope
  - duration
- audit shows:
  - `Access Contained`

### Step 4: verify the user

- operator contacts the user
- operator fills `Verify User`
- audit shows:
  - `Identity Verification Completed`

### Step 5: restore access

- operator clicks `Restore Access`
- enters restore reason
- system executes restore playbook
- audit shows:
  - `Access Restore Requested`
  - `Access Restored`

### Step 6: close with reporting

- incident report PDF/HTML includes:
  - detection summary
  - containment
  - verification
  - restore
  - lessons learned

## Acceptance criteria

This feature is ready when all of the following are true:

1. repeated failed-auth rules produce dedicated auth-abuse incidents
2. containment can be auto or approval-gated based on existing policy model
3. containment writes reversible R-SIEM-managed auth-control state on the endpoint
4. verification is an explicit UI action with audit
5. restore is an explicit UI action with audit
6. restore requires prior verification
7. reports include containment and restore details
8. no irreversible host-account mutation is required for v1

## Recommended implementation order

1. add rules in `configs/master.yaml`
2. add playbooks in `configs/master.yaml`
3. extend `cmd/agent/command.go` with auth contain/restore handlers
4. add UI API verification/restore endpoints
5. add UI actions in incident workspace
6. add audit labels and report fields
7. add deterministic verifier script for the full auth containment/restore story
