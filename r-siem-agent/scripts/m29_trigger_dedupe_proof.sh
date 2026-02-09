#!/usr/bin/env bash
set -euo pipefail

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.24.11}"

LOG_MASTER="logs/master-roe.log"

if [[ ! -f "$LOG_MASTER" ]]; then
  echo "Missing $LOG_MASTER. Start Terminal E (master-roe) first." >&2
  exit 1
fi

last_line_num() {
  local pattern="$1"
  local file="$2"
  local last
  last="$(rg -n "$pattern" "$file" | tail -n 1 || true)"
  if [[ -z "$last" ]]; then
    echo 0
    return
  fi
  echo "${last%%:*}"
}

wait_new_line() {
  local pattern="$1"
  local file="$2"
  local baseline="$3"
  local last line
  while true; do
    last="$(rg -n "$pattern" "$file" | tail -n 1 || true)"
    if [[ -n "$last" ]]; then
      line="${last%%:*}"
      if [[ "$line" =~ ^[0-9]+$ ]] && (( line > baseline )); then
        echo "$last"
        return
      fi
    fi
    sleep 1
  done
}

extract_json_field() {
  # naive but works for our logs: extracts "field":"value"
  local field="$1"
  sed -n "s/.*\"$field\":\"\([^\"]*\)\".*/\1/p"
}

echo "=== M29: ROE trigger dedupe (same trigger_idem_key) ==="

TS="$(date +%s)"
EVENT_IDEM_KEY="evt.m29.$TS"
ALERT_KEY="A-COLLECT-INVALID-USER-$EVENT_IDEM_KEY"
TRIG_IDEM_KEY="trig.alert.$ALERT_KEY"

echo "EVENT_IDEM_KEY=$EVENT_IDEM_KEY"
echo "ALERT_KEY=$ALERT_KEY"
echo "TRIG_IDEM_KEY=$TRIG_IDEM_KEY"

BASE_TRIG="$(last_line_num '"msg":"response_trigger_received"' "$LOG_MASTER")"
BASE_WAIT="$(last_line_num '"msg":"response_run_waiting_approval"' "$LOG_MASTER")"
BASE_DUP="$(last_line_num '"msg":"response_trigger_duplicate"' "$LOG_MASTER")"

echo "Baselines: trigger_received=$BASE_TRIG waiting_approval=$BASE_WAIT trigger_duplicate=$BASE_DUP"
echo

echo "Publish #1 (expect: trigger_received + waiting_approval)"
go run -mod=vendor ./cmd/master-roe-pubtrigger \
  -config configs/master.yaml \
  -lane FAST \
  -rule-id R-COLLECT-INVALID-USER \
  -severity high \
  -alert-key "$ALERT_KEY" \
  -group-key "10.0.0.77" >/dev/null

# Wait for first run to reach waiting approval
WAIT_LINE_1="$(wait_new_line '"msg":"response_run_waiting_approval"' "$LOG_MASTER" "$BASE_WAIT")"
RUN_ID="$(echo "$WAIT_LINE_1" | extract_json_field run_id)"

if [[ -z "$RUN_ID" ]]; then
  echo "ERROR: failed to extract run_id from waiting_approval line:" >&2
  echo "$WAIT_LINE_1" >&2
  exit 1
fi

echo "waiting_approval (first): $WAIT_LINE_1"
echo "RUN_ID=$RUN_ID"
echo

echo "Assert: exactly 1 waiting_approval exists for RUN_ID (should be 1)"
COUNT_WAIT="$(rg -n "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"$RUN_ID\"" "$LOG_MASTER" | wc -l | tr -d ' ')"
echo "count=$COUNT_WAIT"
if [[ "$COUNT_WAIT" != "1" ]]; then
  echo "ERROR: expected 1 waiting_approval for run_id=$RUN_ID, got $COUNT_WAIT" >&2
  rg -n "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"$RUN_ID\"" "$LOG_MASTER" | tail -n 50 >&2
  exit 1
fi
echo

echo "Publish #2 (IDENTICAL) (expect: response_trigger_duplicate, and STILL only 1 waiting_approval for RUN_ID)"
go run -mod=vendor ./cmd/master-roe-pubtrigger \
  -config configs/master.yaml \
  -lane FAST \
  -rule-id R-COLLECT-INVALID-USER \
  -severity high \
  -alert-key "$ALERT_KEY" \
  -group-key "10.0.0.77" >/dev/null

# Wait for duplicate line (must be new after baseline_dup)
DUP_LINE="$(wait_new_line "\"msg\":\"response_trigger_duplicate\".*\"trigger_idem_key\":\"$TRIG_IDEM_KEY\"" "$LOG_MASTER" "$BASE_DUP")"
echo "duplicate: $DUP_LINE"

DUP_RUN_ID="$(echo "$DUP_LINE" | extract_json_field run_id)"
if [[ "$DUP_RUN_ID" != "$RUN_ID" ]]; then
  echo "ERROR: duplicate run_id mismatch. expected $RUN_ID got $DUP_RUN_ID" >&2
  exit 1
fi
echo "OK: response_trigger_duplicate points to same RUN_ID=$RUN_ID"
echo

echo "Re-check waiting_approval count (should still be 1)"
COUNT_WAIT_2="$(rg -n "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"$RUN_ID\"" "$LOG_MASTER" | wc -l | tr -d ' ')"
echo "count=$COUNT_WAIT_2"
if [[ "$COUNT_WAIT_2" != "1" ]]; then
  echo "ERROR: expected waiting_approval count to remain 1 for run_id=$RUN_ID, got $COUNT_WAIT_2" >&2
  rg -n "\"msg\":\"response_run_waiting_approval\".*\"run_id\":\"$RUN_ID\"" "$LOG_MASTER" | tail -n 50 >&2
  exit 1
fi

echo
echo "PASS: M29 dedupe proven (1 waiting_approval for run + response_trigger_duplicate for same trigger_idem_key)"
