# FR-02 mTLS Certificate Lifecycle (Judge Notes)

FR-02 uses mutual TLS between agent and master, so both sides present certificates signed by the trusted CA.
Master enforces `tls.RequireAndVerifyClientCert`, validates chain/time, and applies identity + optional fingerprint allowlist checks.
Agent verifies the master certificate using CA trust plus configured server name.

Certificate issuance model:
- The CA signs `master.pem` and `agent.pem` leaf certificates.
- Agent identity is derived from certificate SAN/CN (`client_identity_source` policy controls fallback behavior).
- Optional fingerprint allowlist can restrict access to a known set of leaf certs.

Rotation plan (no downtime):
- Issue a new leaf certificate before expiry.
- Keep CA trust stable during leaf rotation.
- Roll master/agent one side at a time using overlapping validity windows.
- If pinning/allowlists are used, add new fingerprint first, then remove old fingerprint after cutover.

Compromise response:
- If an agent key/cert is compromised, remove its fingerprint from allowlist immediately.
- Reissue a new agent cert and update allowlist with new fingerprint.
- If master cert is compromised, rotate master cert and update client pinning if enabled.
- If CA is compromised, rotate CA, reissue all leaf certs, and redeploy trust roots.

Slide-ready bullets:
- mTLS everywhere: both sides authenticate with CA-signed certs.
- Identity from cert SAN/CN; metadata fallback is policy-controlled.
- Optional fingerprint allowlist = immediate deny switch.
- Safe rotation: overlap certs, then remove old fingerprints.
- Compromise playbook: deny -> reissue -> rotate trust if CA impacted.
