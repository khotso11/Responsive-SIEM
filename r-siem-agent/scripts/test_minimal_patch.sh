#!/usr/bin/env bash
set -euo pipefail

command -v rg >/dev/null 2>&1 || { echo "FAIL: rg missing"; exit 1; }

./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/demo_up.sh >/dev/null

echo "=== TEST 1: Reliability Suite ==="
./scripts/demo_reliability_suite.sh | tee /tmp/reliability_suite.out
rg '^PASS: demo reliability suite completed$' /tmp/reliability_suite.out >/dev/null

echo "=== TEST 2: FR-02 Verifier ==="
./scripts/verify_fr02_mtls.sh | tee /tmp/verify_fr02.out
rg '^fr02_status=PASS$' /tmp/verify_fr02.out >/dev/null

echo "=== TEST 3: FR-01 Verifier ==="
./scripts/verify_fr01.sh | tee /tmp/verify_fr01.out
rg '^PASS: FR-01 local verification completed$' /tmp/verify_fr01.out >/dev/null

echo "PASS: minimal patch validation complete"
