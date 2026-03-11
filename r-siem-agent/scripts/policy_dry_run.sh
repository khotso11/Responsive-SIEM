#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${CONFIG_PATH:-$ROOT/configs/master.yaml}"
GOCACHE_DIR="${GOCACHE:-$ROOT/.cache/go-build}"

usage() {
  cat <<'EOF'
Usage:
  scripts/policy_dry_run.sh --playbook-id <id> [options]
  scripts/policy_dry_run.sh --rule-id <id> [options]

Examples:
  scripts/policy_dry_run.sh \
    --playbook-id PB-AUTH-ABUSE-CONTAIN \
    --rule-id R-COLLECT-INVALID-USER \
    --severity high \
    --confidence 85 \
    --lane FAST \
    --node-id demo-node \
    --src-ip 10.99.1.21 \
    --user alice

Environment:
  CONFIG_PATH=/path/to/master.yaml
  GOCACHE=/custom/go-build-cache

Notes:
  - This wrapper prints JSON only.
  - Extra flags are passed directly to cmd/master-roe.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

mkdir -p "$GOCACHE_DIR"

exec env GOCACHE="$GOCACHE_DIR" \
  go run -mod=vendor ./cmd/master-roe \
    --config "$CONFIG_PATH" \
    --policy-dry-run \
    --json-only \
    "$@"
