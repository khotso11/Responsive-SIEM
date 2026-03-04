# Cert and Allowlist Onboarding (FR-02 Aligned)

This repo already includes PKI lifecycle scripts for issuance, allowlisting, and revocation.

## Identity Model

Recommended identity rule:
- `agent.instance_id` == cert CN == allowlist subject identity.

Per endpoint, use a unique ID, for example:
- `linux-endpoint-01`
- `win-endpoint-02`

## 1) Issue Master Certificate (if needed)

```bash
cd /path/to/r-siem-agent
./scripts/pki_issue_master_cert.sh
```

## 2) Issue Endpoint Agent Certificate

```bash
AGENT_ID="linux-endpoint-01"
./scripts/pki_issue_agent_cert.sh "$AGENT_ID"
```

Output includes:
- `AGENT_CERT_PATH=...`
- `AGENT_FP_SHA256=...`

## 3) Add Endpoint Fingerprint to Allowlist

```bash
FP="<agent_fp_sha256_from_issue_step>"
./scripts/pki_allowlist_add_fingerprint.sh "$FP"
```

Allowlist file (default):
- `pki/allowlist_fingerprints.txt`

## 4) Distribute Cert Material to Endpoint

Linux target paths:
- `/etc/rsiem/pki/ca.pem`
- `/etc/rsiem/pki/agent.pem`
- `/etc/rsiem/pki/agent-key.pem`

Windows target paths:
- `C:\ProgramData\rsiem\pki\ca.pem`
- `C:\ProgramData\rsiem\pki\agent.pem`
- `C:\ProgramData\rsiem\pki\agent-key.pem`

## 5) Revocation / Compromise Response

Immediate revocation flow:

```bash
FP="<compromised_agent_fp>"
./scripts/pki_revoke_fingerprint.sh "$FP"
```

or remove directly:

```bash
./scripts/pki_allowlist_remove_fingerprint.sh "$FP"
```

Then restart affected services:
- master side (`master-roe` if allowlist is read at startup in your deployment mode)
- endpoint side (`rsiem-agent`)

## Verification Evidence

Expected rejection evidence for revoked fingerprint:

```bash
rg 'fingerprint_not_allowlisted' logs/master-roe.log
```

Expected accepted mTLS evidence (when allowlisted):

```bash
rg 'ALLOWLIST_ALLOW=PASS|grpc_mtls_server_started' demo_artifacts -n
```
