#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "FAIL: missing command: $1" >&2; exit 1; }
}

need_cmd curl
need_cmd jq

UI_API_URL="${UI_API_URL:-http://127.0.0.1:8090}"
UI_REPORT_USERNAME="${UI_REPORT_USERNAME:-admin}"
UI_REPORT_PASSWORD="${UI_REPORT_PASSWORD:-admin123}"
REPORT_WINDOW="${REPORT_WINDOW:-24h}"
REPORT_FORMATS="${REPORT_FORMATS:-pdf json html}"
REPORT_TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
REPORT_DIR="${REPORT_DIR:-retained/reports/soc_operations/${REPORT_TIMESTAMP}}"

mkdir -p "$REPORT_DIR"

LOGIN_JSON="$(curl -fsS -H 'Content-Type: application/json' \
  -X POST "${UI_API_URL}/api/auth/login" \
  -d "{\"username\":\"${UI_REPORT_USERNAME}\",\"password\":\"${UI_REPORT_PASSWORD}\"}")"

TOKEN="$(printf '%s\n' "$LOGIN_JSON" | jq -r '.token // empty')"
if [[ -z "$TOKEN" ]]; then
  echo "FAIL: login token missing" >&2
  exit 1
fi

REPORT_META="${REPORT_DIR}/soc_operations_report.meta.json"
jq -n \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg ui_api_url "$UI_API_URL" \
  --arg report_window "$REPORT_WINDOW" \
  --arg report_dir "$REPORT_DIR" \
  '{
    generated_at: $generated_at,
    ui_api_url: $ui_api_url,
    report_window: $report_window,
    report_dir: $report_dir
  }' > "$REPORT_META"

for format in $REPORT_FORMATS; do
  case "$format" in
    pdf|json|html) ;;
    *)
      echo "FAIL: unsupported format in REPORT_FORMATS: $format" >&2
      exit 1
      ;;
  esac
  out="${REPORT_DIR}/soc_operations_report.${format}"
  curl -fsS \
    -H "Authorization: Bearer ${TOKEN}" \
    "${UI_API_URL}/api/reports/soc/operations?window=${REPORT_WINDOW}&format=${format}" \
    -o "$out"
  echo "WROTE=$out"
done

echo "PASS: SOC operational report generated"
echo "SOC_REPORT_DIR=${REPORT_DIR}"
