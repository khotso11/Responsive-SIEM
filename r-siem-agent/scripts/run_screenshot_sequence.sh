#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PANEL_SCRIPT="./scripts/prepare_screenshot_proofs.sh"
if [[ ! -x "$PANEL_SCRIPT" ]]; then
  echo "FAIL: missing executable $PANEL_SCRIPT" >&2
  exit 1
fi

echo "=== Generating screenshot panels ==="
"$PANEL_SCRIPT"

OUT_DIR="$(find demo_artifacts -maxdepth 2 -type d -name screenshot_panels | sort | tail -n 1)"
if [[ -z "$OUT_DIR" || ! -d "$OUT_DIR" ]]; then
  echo "FAIL: screenshot panel directory not found" >&2
  exit 1
fi

echo
echo "Panels directory: $OUT_DIR"
echo

order=(
  "01_FR01_verify_summary.png|01_FR01_verify_summary.txt"
  "02_FR01_checkpoint_authlog.png|02_FR01_checkpoint_authlog.txt"
  "03_FR08_demo_summary_json.png|03_FR08_demo_summary_json.txt"
  "04_FR02_mtls_summary.png|04_FR02_mtls_summary.txt"
  "05_FR02_mtls_negative_tests.png|05_FR02_mtls_negative_tests.txt"
  "06_FR02_allowlist_reject.png|06_FR02_allowlist_reject.txt"
  "07_FR05_rollback_success.png|07_FR05_rollback_success.txt"
  "08_FR05_partial_failure_safe.png|08_FR05_partial_failure_safe.txt"
)

for entry in "${order[@]}"; do
  png_name="${entry%%|*}"
  txt_name="${entry##*|}"
  txt_path="$OUT_DIR/$txt_name"

  echo "============================================================"
  echo "NEXT SCREENSHOT: $png_name"
  echo "SOURCE PANEL:    $txt_path"
  echo "============================================================"

  if [[ ! -f "$txt_path" ]]; then
    echo "MISSING PANEL: $txt_name"
  else
    cat "$txt_path"
  fi

  echo
  read -r -p "Take screenshot as '$png_name', then press Enter to continue..."
  echo
done

echo "PASS: screenshot walkthrough complete"
echo "Panel source directory: $OUT_DIR"
