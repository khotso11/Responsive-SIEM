#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

fail_with_context() {
  local msg="$1"
  echo "FAIL: ${msg}" >&2
  echo "Context: detector (last 150)" >&2
  tail -n 150 logs/detector.log >&2 || true
  exit 1
}

need_cmd rg
need_cmd python3
need_cmd date

echo "=== FR-01 source types verification ==="

./scripts/demo_down.sh >/dev/null 2>&1 || true
pkill -f 'cmd/collector-tail|/collector-tail' >/dev/null 2>&1 || true
pkill -f 'cmd/detector-v0|/detector-v0' >/dev/null 2>&1 || true
pkill -f 'cmd/master-roe-worker|/master-roe-worker' >/dev/null 2>&1 || true
pkill -f 'cmd/agent|/agent' >/dev/null 2>&1 || true
pkill -f 'cmd/master-roe([^[:alnum:]_-]|$)|/master-roe([^[:alnum:]_-]|$)' >/dev/null 2>&1 || true
sleep 1
mkdir -p tmp logs demo_artifacts
: > tmp/demo.log
rm -f tmp/tail.checkpoint.json
./scripts/demo_up.sh >/dev/null

detector_log="logs/detector.log"
[[ -f "$detector_log" ]] || fail_with_context "missing ${detector_log}"

base_detector_lines="$(wc -l < "$detector_log" | tr -d '[:space:]')"

run_tag="fr01src$(date +%s)"
base_ms="$(date +%s%3N)"
host_src_ip="10.78.$(( (base_ms / 1000) % 200 + 20 )).10"
net_src_ip="10.79.$(( (base_ms / 1000) % 200 + 20 )).20"
dec_src_ip="10.80.$(( (base_ms / 1000) % 200 + 20 )).30"

# host source-type: needs burst threshold=3 on same source
for burst in 0 1 2; do
  printf 'ALERT invalid user=%s_host src=%s attack=host_bruteforce ts=%s\n' \
    "$run_tag" "$host_src_ip" "$((base_ms + burst))" >> tmp/demo.log
done

# network source-type
printf 'ALERT invalid user=%s_net src=%s attack=network_scan ts=%s\n' \
  "$run_tag" "$net_src_ip" "$((base_ms + 20))" >> tmp/demo.log

# deception source-type
printf 'ALERT invalid user=%s_dec src=%s attack=deception_tripwire ts=%s\n' \
  "$run_tag" "$dec_src_ip" "$((base_ms + 30))" >> tmp/demo.log

for _ in $(seq 1 120); do
  new_lines="$(tail -n "+$((base_detector_lines + 1))" "$detector_log" 2>/dev/null || true)"
  host_hits="$(printf '%s\n' "$new_lines" | rg -c "\"msg\":\"detector_rule_matched\".*\"rule_id\":\"R-FR03-HOST-BRUTEFORCE-BURST\".*\"user\":\"${run_tag}_host\"" || true)"
  net_hits="$(printf '%s\n' "$new_lines" | rg -c "\"msg\":\"detector_rule_matched\".*\"rule_id\":\"R-FR03-NETWORK-C2-BEACON\".*\"user\":\"${run_tag}_net\"" || true)"
  dec_hits="$(printf '%s\n' "$new_lines" | rg -c "\"msg\":\"detector_rule_matched\".*\"rule_id\":\"R-FR03-DECEPTION-TRIPWIRE\".*\"user\":\"${run_tag}_dec\"" || true)"
  host_hits="${host_hits:-0}"
  net_hits="${net_hits:-0}"
  dec_hits="${dec_hits:-0}"
  if (( host_hits >= 1 && net_hits >= 1 && dec_hits >= 1 )); then
    break
  fi
  sleep 0.25
done

artifact_ts="$(date +%Y%m%d_%H%M%S)"
artifact_dir="demo_artifacts/${artifact_ts}"
mkdir -p "$artifact_dir"
proof_json="${artifact_dir}/fr01_source_types_proof.json"

python3 - "$detector_log" "$base_detector_lines" "$run_tag" "$proof_json" <<'PY'
import json
import sys
from pathlib import Path

detector_log = Path(sys.argv[1])
base_detector = int(sys.argv[2])
run_tag = sys.argv[3]
proof_path = Path(sys.argv[4])

types_expected = ["host", "network", "deception"]
rules = {
    "host": "R-FR03-HOST-BRUTEFORCE-BURST",
    "network": "R-FR03-NETWORK-C2-BEACON",
    "deception": "R-FR03-DECEPTION-TRIPWIRE",
}
users = {
    "host": f"{run_tag}_host",
    "network": f"{run_tag}_net",
    "deception": f"{run_tag}_dec",
}

examples = {}
for source_type, rule_id in rules.items():
    wanted_user = users[source_type]
    with detector_log.open("r", encoding="utf-8") as f:
        for idx, raw in enumerate(f, start=1):
            if idx <= base_detector:
                continue
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if rec.get("msg") != "detector_rule_matched":
                continue
            if str(rec.get("rule_id", "")) != rule_id:
                continue
            if str(rec.get("user", "")) != wanted_user:
                continue
            examples[source_type] = {
                "rule_id": rule_id,
                "severity": str(rec.get("severity", "")),
                "event_type": str(rec.get("event_type", "")),
                "src_ip": str(rec.get("src_ip", "")),
                "user": str(rec.get("user", "")),
                "event_ts_unix_ms": int(rec.get("event_ts_unix_ms", 0) or 0),
                "alert_ts_unix_ms": int(rec.get("alert_ts_unix_ms", 0) or 0),
            }
            break

missing = [t for t in types_expected if t not in examples]
if missing:
    raise SystemExit(f"missing source type evidence: {','.join(missing)}")

decoded_fields_present = True
for t in types_expected:
    ex = examples[t]
    if not ex["event_type"] or not ex["src_ip"] or not ex["user"]:
        decoded_fields_present = False
    if ex["event_ts_unix_ms"] <= 0 or ex["alert_ts_unix_ms"] <= 0:
        decoded_fields_present = False

if not decoded_fields_present:
    raise SystemExit("decoded fields not fully present for source type examples")

proof = {
    "timestamp": __import__("datetime").datetime.now(__import__("datetime").UTC).replace(tzinfo=None, microsecond=0).isoformat() + "Z",
    "types_expected": types_expected,
    "types_observed": types_expected,
    "decoded_fields_present": True,
    "examples": examples,
    "pass": True,
}
proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
PY

echo "PASS: FR-01 source types completed"
echo "FR01_SOURCE_TYPES_PROOF_JSON=${proof_json}"
