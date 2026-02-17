#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: ./scripts/trigger_demo_events.sh [m41|m42|both]" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

mode="$1"
case "$mode" in
  m41|m42|both) ;;
  *)
    usage
    exit 1
    ;;
esac

mkdir -p tmp

NOW="$(date +%s)"
octet=$(( (NOW % 200) + 20 ))
m41_line="M41 invalid user from 10.0.0.${octet} ts=${NOW}"
m42_line="M42 process count host=m42-${NOW} ts=${NOW}"

written=()
if [[ "$mode" == "m41" || "$mode" == "both" ]]; then
  echo "$m41_line" >> tmp/demo.log
  written+=("$m41_line")
fi
if [[ "$mode" == "m42" || "$mode" == "both" ]]; then
  echo "$m42_line" >> tmp/demo.log
  written+=("$m42_line")
fi

echo "Triggered at ts=${NOW}"
for line in "${written[@]}"; do
  echo "$line"
done
tail -n 5 tmp/demo.log
