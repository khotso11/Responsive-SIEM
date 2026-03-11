#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_A="configs/master.yaml"
CONFIG_B="configs/master.yaml"
LEFT_ARGS=()
RIGHT_ARGS=()
SIDE="left"

usage() {
  cat <<'EOF'
Usage:
  policy_diff.sh [--config-a PATH] [--config-b PATH] [left dry-run args ...] [--vs right dry-run args ...]

Examples:
  ./scripts/policy_diff.sh \
    --config-a configs/master.yaml \
    --config-b tmp/alt-master.yaml \
    --playbook-id PB-AUTH-ABUSE-CONTAIN --rule-id R-COLLECT-INVALID-USER --severity high --confidence 85 --lane FAST --node-id demo-node --src-ip 10.99.1.21 --user alice

  ./scripts/policy_diff.sh \
    --playbook-id PB-AUTH-ABUSE-CONTAIN --rule-id R-COLLECT-INVALID-USER --severity medium --confidence 60 --lane FAST --node-id demo-node --src-ip 10.99.1.21 --user alice \
    --vs \
    --playbook-id PB-AUTH-ABUSE-CONTAIN --rule-id R-COLLECT-INVALID-USER --severity high --confidence 85 --lane FAST --node-id demo-node --src-ip 10.99.1.21 --user alice
EOF
}

while (($# > 0)); do
  case "$1" in
    --config-a)
      CONFIG_A="${2:?missing value for --config-a}"
      shift 2
      ;;
    --config-b)
      CONFIG_B="${2:?missing value for --config-b}"
      shift 2
      ;;
    --vs)
      SIDE="right"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      if [[ "$SIDE" == "left" ]]; then
        LEFT_ARGS+=("$1")
      else
        RIGHT_ARGS+=("$1")
      fi
      shift
      ;;
  esac
done

if ((${#LEFT_ARGS[@]} == 0)); then
  usage >&2
  exit 1
fi

if ((${#RIGHT_ARGS[@]} == 0)); then
  RIGHT_ARGS=("${LEFT_ARGS[@]}")
fi

TMP_A="$(mktemp)"
TMP_B="$(mktemp)"
trap 'rm -f "$TMP_A" "$TMP_B"' EXIT

(
  cd "$ROOT"
  CONFIG_PATH="$CONFIG_A" ./scripts/policy_dry_run.sh "${LEFT_ARGS[@]}"
) >"$TMP_A"

(
  cd "$ROOT"
  CONFIG_PATH="$CONFIG_B" ./scripts/policy_dry_run.sh "${RIGHT_ARGS[@]}"
) >"$TMP_B"

python3 - "$TMP_A" "$TMP_B" "$CONFIG_A" "$CONFIG_B" <<'PY'
import difflib
import json
import sys

left_path, right_path, config_a, config_b = sys.argv[1:5]
with open(left_path, "r", encoding="utf-8") as fh:
    left = json.load(fh)
with open(right_path, "r", encoding="utf-8") as fh:
    right = json.load(fh)

summary_keys = [
    "playbook_id",
    "rule_id",
    "severity",
    "confidence_score",
    "approval_required",
    "approval_policy_mode",
    "approval_policy_rule_id",
    "approval_policy_reason",
    "playbook_reversibility",
    "allowlist_ok",
    "allowlist_error",
    "compile_ok",
    "compile_error",
]

def summarize(doc):
    out = {k: doc.get(k) for k in summary_keys if k in doc}
    out["step_count"] = len(doc.get("steps", []))
    out["steps"] = [
        {
            "step_index": step.get("step_index"),
            "action_type": step.get("action_type"),
            "allowlist_rule_id": step.get("allowlist_rule_id"),
            "guardrail_rule_ids": step.get("guardrail_rule_ids", []),
        }
        for step in doc.get("steps", [])
    ]
    return out

left_summary = summarize(left)
right_summary = summarize(right)

print(f"LEFT_CONFIG={config_a}")
print(json.dumps(left_summary, indent=2, sort_keys=True))
print()
print(f"RIGHT_CONFIG={config_b}")
print(json.dumps(right_summary, indent=2, sort_keys=True))
print()
print("DIFF")
left_text = json.dumps(left_summary, indent=2, sort_keys=True).splitlines()
right_text = json.dumps(right_summary, indent=2, sort_keys=True).splitlines()
for line in difflib.unified_diff(left_text, right_text, fromfile="left", tofile="right", lineterm=""):
    print(line)
PY
