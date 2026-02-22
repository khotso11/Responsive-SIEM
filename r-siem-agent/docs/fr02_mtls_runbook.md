# FR-02 mTLS Operator Runbook

This runbook covers FR-02 operational lifecycle commands for local mTLS cert issuance and rotation rehearsal.

## 1) Baseline verifier

```bash
cd ~/projects/r-siem-agent
./scripts/verify_fr02_mtls.sh
```

Expected end lines include:
- `PASS: FR-02 mTLS`
- `fr02_status=PASS`
- `agent_id_source=cert_cn`
- `NEG:no_client_cert=PASS`
- `NEG:unknown_ca=PASS`
- `NEG:identity_mismatch=PASS`
- `ALLOWLIST_REJECT=PASS reason=fingerprint_not_allowlisted`
- `FR02_PROOF_JSON=demo_artifacts/<timestamp>/fr02_mtls_proof.json`

## 2) PKI initialization and issuance

```bash
./scripts/pki_init_ca.sh
./scripts/pki_issue_master_cert.sh
./scripts/pki_issue_agent_cert.sh agent.local
```

Optional next-slot issuance for planned rotation:

```bash
TARGET=next ./scripts/pki_issue_master_cert.sh
TARGET=next ./scripts/pki_issue_agent_cert.sh agent.local
```

The scripts emit cert paths and SHA256 fingerprints for audit capture.

## 3) Rotation rehearsal proof

```bash
./scripts/verify_fr02_rotation.sh
```

Expected end lines:
- `PASS: FR-02 ROTATION REHEARSAL completed`
- `FR02_ROTATION_PROOF_JSON=demo_artifacts/<timestamp>/fr02_rotation_proof.json`

The JSON artifact records before/after master and agent fingerprints and verifier pass state before and after rotation.

## 4) Revocation automation (allowlist deny)

Allowlist source of truth:
- `pki/allowlist_fingerprints.txt`

Add or remove fingerprints:

```bash
./scripts/pki_allowlist_add_fingerprint.sh <FP_SHA256>
./scripts/pki_allowlist_remove_fingerprint.sh <FP_SHA256>
```

Deterministic end-to-end revocation proof:

```bash
./scripts/verify_fr02_revocation.sh
```

Expected end lines:
- `PASS: FR-02 REVOCATION WORKFLOW completed`
- `FR02_REVOCATION_PROOF_JSON=demo_artifacts/<timestamp>/fr02_revocation_proof.json`

The proof JSON captures revoked fingerprint, `fingerprint_not_allowlisted` reject evidence, and reallow verification PASS.
