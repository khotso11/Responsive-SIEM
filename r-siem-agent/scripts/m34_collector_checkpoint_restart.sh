#!/usr/bin/env bash
set -euo pipefail

LOG_COLLECTOR="logs/collector-tail.log"
DEMO_LOG="tmp/demo.log"

if [[ ! -f "$LOG_COLLECTOR" ]]; then
  echo "Missing $LOG_COLLECTOR. Start Terminal H (collector-tail) first." >&2
  exit 1
fi

mkdir -p tmp

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

last_line() {
  local pattern="$1"
  local file="$2"
  rg -n "$pattern" "$file" | tail -n 1 || true
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

parse_event_id() {
  printf "%s\n" "$1" | sed -n 's/.*"event_idem_key":"\([^"]*\)".*/\1/p'
}

parse_offset() {
  printf "%s\n" "$1" | sed -n 's/.*"offset":\([0-9]*\).*/\1/p'
}

echo "=== M34 collector checkpoint restart safety ==="

pre_line="$(last_line '"msg":"event_published"' "$LOG_COLLECTOR")"
pre_line_num="${pre_line%%:*}"
if [[ -z "${pre_line}" ]]; then
  pre_line_num=0
fi
pre_event_id="$(parse_event_id "$pre_line")"
pre_offset="$(parse_offset "$pre_line")"


echo "M34 collector checkpoint pre: line=${pre_line_num} event_idem_key=${pre_event_id} offset=${pre_offset}"

echo "M34 collector line 1 ts=$(date +%s)" >> "$DEMO_LOG"

first_pub="$(wait_new_line '"msg":"event_published"' "$LOG_COLLECTOR" "$pre_line_num")"
first_event_id="$(parse_event_id "$first_pub")"
first_offset="$(parse_offset "$first_pub")"

echo "$first_pub"

read -r -p "Restart collector (Terminal H) now (Ctrl+C then re-run), press Enter" _

restart_baseline="$(last_line_num '"msg":"event_published"' "$LOG_COLLECTOR")"


echo "M34 collector line 2 ts=$(date +%s)" >> "$DEMO_LOG"

second_pub="$(wait_new_line '"msg":"event_published"' "$LOG_COLLECTOR" "$restart_baseline")"
second_event_id="$(parse_event_id "$second_pub")"
second_offset="$(parse_offset "$second_pub")"

echo "$second_pub"

if [[ -n "${first_offset}" && -n "${second_offset}" ]]; then
  if (( second_offset <= first_offset )); then
    echo "ERROR: post-restart offset did not advance (pre=${first_offset}, post=${second_offset})" >&2
    exit 1
  fi
fi

if [[ -n "${first_event_id}" ]]; then
  last_pre_occurrence="$(rg -n "\"event_idem_key\":\"${first_event_id}\"" "$LOG_COLLECTOR" | tail -n 1 | cut -d: -f1 || true)"
  if [[ -n "${last_pre_occurrence}" && "$last_pre_occurrence" =~ ^[0-9]+$ ]]; then
    if (( last_pre_occurrence > restart_baseline )); then
      echo "ERROR: pre-restart event_idem_key reappeared after restart baseline" >&2
      exit 1
    fi
  fi
fi

echo "PASS: collector resumed from checkpoint without duplicate publish"
