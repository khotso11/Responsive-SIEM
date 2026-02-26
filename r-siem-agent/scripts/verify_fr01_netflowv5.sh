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

need_cmd go
need_cmd rg

TS="$(date -u +%Y%m%d_%H%M%S)"
ART_DIR="demo_artifacts/${TS}"
mkdir -p "$ART_DIR" logs .pids .cache/go-build tmp
PROOF_JSON="${ART_DIR}/fr01_netflowv5_proof.json"
LOG_FILE="logs/collector-netflowv5.log"

collector_pid=""
cleanup() {
  if [[ -n "${collector_pid}" ]] && kill -0 "${collector_pid}" 2>/dev/null; then
    kill "${collector_pid}" >/dev/null 2>&1 || true
    wait "${collector_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

./scripts/demo_down.sh >/dev/null 2>&1 || true
./scripts/demo_up.sh >/dev/null

: > "$LOG_FILE"
GOCACHE="$ROOT_DIR/.cache/go-build" go run -mod=vendor ./cmd/collector-netflowv5 --config configs/collector-netflowv5.yaml >> "$LOG_FILE" 2>&1 &
collector_pid=$!
sleep 1
if ! kill -0 "$collector_pid" 2>/dev/null; then
  echo "FAIL: collector-netflowv5 failed to start" >&2
  tail -n 80 "$LOG_FILE" >&2 || true
  exit 1
fi

published_before="$(rg -c '"msg":"collector_event_published".*"collector":"netflow_v5"' "$LOG_FILE" || true)"
published_before="${published_before:-0}"
detector_before="$(rg -c '"msg":"event_received".*"event_idem_key":"evt.netflowv5\.' logs/detector.log || true)"
detector_before="${detector_before:-0}"

gen_file="$(mktemp -t netflowv5gen.XXXX.go)"
cat > "$gen_file" <<'GO'
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	headerLen = 24
	recordLen = 48
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s <addr> <packets> <records>\n", os.Args[0])
		os.Exit(2)
	}
	addr := os.Args[1]
	packets, _ := strconv.Atoi(os.Args[2])
	records, _ := strconv.Atoi(os.Args[3])
	conn, err := net.Dial("udp", addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	baseSec := uint32(time.Now().Unix())
	for p := 0; p < packets; p++ {
		buf := make([]byte, headerLen+records*recordLen)
		sysUptime := uint32(600000 + p*100)
		binary.BigEndian.PutUint16(buf[0:2], 5)
		binary.BigEndian.PutUint16(buf[2:4], uint16(records))
		binary.BigEndian.PutUint32(buf[4:8], sysUptime)
		binary.BigEndian.PutUint32(buf[8:12], baseSec+uint32(p))
		binary.BigEndian.PutUint32(buf[12:16], 1000000)
		binary.BigEndian.PutUint32(buf[16:20], uint32(p*records))

		off := headerLen
		for r := 0; r < records; r++ {
			src := net.IPv4(10, 44, byte(p+1), byte(r+10)).To4()
			dst := net.IPv4(172, 20, 0, byte(r+1)).To4()
			copy(buf[off:off+4], src)
			copy(buf[off+4:off+8], dst)
			binary.BigEndian.PutUint32(buf[off+16:off+20], uint32(100+r))
			binary.BigEndian.PutUint32(buf[off+20:off+24], uint32(2048+r*64))
			binary.BigEndian.PutUint32(buf[off+24:off+28], sysUptime-1000)
			binary.BigEndian.PutUint32(buf[off+28:off+32], sysUptime-100)
			binary.BigEndian.PutUint16(buf[off+32:off+34], uint16(10000+r))
			binary.BigEndian.PutUint16(buf[off+34:off+36], uint16(443))
			buf[off+38] = 6
			off += recordLen
		}
		if _, err := conn.Write(buf); err != nil {
			panic(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
GO

packets_sent=10
records_per_packet=3
records_total=$((packets_sent * records_per_packet))
GOCACHE="$ROOT_DIR/.cache/go-build" go run "$gen_file" 127.0.0.1:2055 "$packets_sent" "$records_per_packet"
rm -f "$gen_file"

published_after="$published_before"
for _ in $(seq 1 40); do
  published_after="$(rg -c '"msg":"collector_event_published".*"collector":"netflow_v5"' "$LOG_FILE" || true)"
  published_after="${published_after:-0}"
  if (( published_after - published_before >= records_total )); then
    break
  fi
  sleep 0.5
done

published_delta=$(( published_after - published_before ))
if (( published_delta < records_total )); then
  echo "FAIL: netflow collector published ${published_delta}, expected >= ${records_total}" >&2
  tail -n 120 "$LOG_FILE" >&2 || true
  exit 1
fi

detector_after="$(rg -c '"msg":"event_received".*"event_idem_key":"evt.netflowv5\.' logs/detector.log || true)"
detector_after="${detector_after:-0}"
detector_delta=$(( detector_after - detector_before ))
if (( detector_delta < records_total )); then
  echo "FAIL: detector did not receive expected netflow events (delta=${detector_delta}, expected>=${records_total})" >&2
  rg '"msg":"event_received"' logs/detector.log | tail -n 80 >&2 || true
  exit 1
fi

cat > "$PROOF_JSON" <<JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "bind": "127.0.0.1:2055",
  "packets_sent": ${packets_sent},
  "records_sent": ${records_total},
  "events_published": ${published_delta},
  "pass": true
}
JSON

echo "PASS: FR-01 netflowv5 streaming completed"
echo "FR01_NETFLOWV5_PROOF_JSON=${PROOF_JSON}"
