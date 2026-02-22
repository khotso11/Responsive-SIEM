#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

./scripts/verify_fr02_mtls.sh
./scripts/verify_fr02_rotation.sh
./scripts/verify_fr02_revocation.sh

echo "PASS: FR-02 full suite completed"
