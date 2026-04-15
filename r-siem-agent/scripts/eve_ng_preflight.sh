#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

need_cmd awk
need_cmd df
need_cmd free
need_cmd nproc
need_cmd uname

ART_DIR="demo_artifacts/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$ART_DIR"
PROOF_JSON="${ART_DIR}/eve_ng_preflight.json"

CORES="$(nproc)"
MEM_GIB="$(free -g | awk '/^Mem:/{print $2}')"
AVAIL_GIB="$(df -BG / | awk 'NR==2{gsub(/G/,"",$4); print $4}')"
HOSTNAME_NOW="$(hostname)"
KERNEL="$(uname -srmo)"

RECOMMENDATION="separate_eve_host"
RATIONALE="This laptop already runs the R-SIEM stack locally. A dedicated EVE-NG VM or second host will be more stable for the defense."
if [[ "${CORES}" -ge 8 && "${MEM_GIB}" -ge 24 && "${AVAIL_GIB}" -ge 100 ]]; then
  RECOMMENDATION="local_compact_eve_vm"
  RATIONALE="The host has enough CPU, RAM, and disk headroom for a compact EVE-NG VM alongside R-SIEM, if the lab stays small."
fi

cat > "$PROOF_JSON" <<EOF
{
  "hostname": "${HOSTNAME_NOW}",
  "kernel": "${KERNEL}",
  "cores": ${CORES},
  "memory_gib": ${MEM_GIB},
  "root_available_gib": ${AVAIL_GIB},
  "recommendation": "${RECOMMENDATION}",
  "rationale": "${RATIONALE}"
}
EOF

cat <<EOF
EVE-NG Preflight
host: ${HOSTNAME_NOW}
kernel: ${KERNEL}
cores: ${CORES}
memory_gib: ${MEM_GIB}
root_available_gib: ${AVAIL_GIB}
recommended_path: ${RECOMMENDATION}
rationale: ${RATIONALE}
proof_json: ${PROOF_JSON}
EOF
