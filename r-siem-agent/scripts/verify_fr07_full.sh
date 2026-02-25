#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

./scripts/verify_fr07_signing.sh
./scripts/verify_fr07_rotation.sh

echo "PASS: FR-07 full suite completed"
