#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="scripts/deploy/master/master_env"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

need_cmd docker
need_cmd nats
need_cmd rg
need_cmd go

NATS_CONTAINER_NAME="${NATS_CONTAINER_NAME:-rsiem-nats-lan}"
NATS_IMAGE="${NATS_IMAGE:-nats:2}"
NATS_PORT="${NATS_PORT:-4222}"
NATS_MON_PORT="${NATS_MON_PORT:-8222}"
NATS_URL="${NATS_URL:-nats://127.0.0.1:${NATS_PORT}}"

nats_reachable() {
  nats --server "$NATS_URL" pub rsiem.deploy.precheck "{\"ts\":$(date +%s)}" >/dev/null 2>&1
}

ensure_nats() {
  if nats_reachable; then
    echo "NATS already reachable at ${NATS_URL}"
    return 0
  fi

  if docker ps -a --format '{{.Names}}' | rg -qx "$NATS_CONTAINER_NAME"; then
    if ! docker ps --format '{{.Names}}' | rg -qx "$NATS_CONTAINER_NAME"; then
      echo "Starting existing NATS container: ${NATS_CONTAINER_NAME}"
      docker start "$NATS_CONTAINER_NAME" >/dev/null
    fi
  else
    echo "Starting NATS container: ${NATS_CONTAINER_NAME}"
    docker run -d \
      --name "$NATS_CONTAINER_NAME" \
      -p "${NATS_PORT}:4222" \
      -p "${NATS_MON_PORT}:8222" \
      "$NATS_IMAGE" \
      -js -m 8222 >/dev/null
  fi

  local ready=0
  for _ in $(seq 1 40); do
    if nats_reachable; then
      ready=1
      break
    fi
    sleep 1
  done

  if [[ "$ready" -ne 1 ]]; then
    echo "FAIL: NATS not reachable after container start (${NATS_URL})" >&2
    exit 1
  fi
}

detect_master_ip() {
  if [[ -n "${MASTER_IP:-}" ]]; then
    echo "$MASTER_IP"
    return 0
  fi
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [[ -n "$ip" ]]; then
    echo "$ip"
    return 0
  fi
  ip="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')"
  if [[ -n "$ip" ]]; then
    echo "$ip"
    return 0
  fi
  echo "127.0.0.1"
}

echo "[1/3] Ensuring NATS JetStream is up"
ensure_nats
NATS_LOCAL_CHECK="PASS"

echo "[2/3] Ensuring TimescaleDB is up"
./scripts/db_up.sh >/tmp/master_up_lan_db.out

echo "[3/3] Starting ROE stack (master/worker/agent/detector/collector-tail)"
./scripts/demo_up.sh >/tmp/master_up_lan_demo.out

MASTER_IP_VALUE="$(detect_master_ip)"
MASTER_GRPC_PORT="$(sed -n 's/^listen_addr:[[:space:]]*.*:\([0-9][0-9]*\)$/\1/p' configs/master.yaml | head -n1)"
MASTER_GRPC_PORT="${MASTER_GRPC_PORT:-7777}"
ENDPOINT_NATS_URL="nats://${MASTER_IP_VALUE}:${NATS_PORT}"
NATS_LAN_CHECK="PASS"

if ! nats --server "$ENDPOINT_NATS_URL" pub rsiem.deploy.lan_check "{\"ts\":$(date +%s)}" >/dev/null 2>&1; then
  NATS_LAN_CHECK="WARN"
  echo "WARN: endpoint LAN NATS check failed; endpoints may not reach ${ENDPOINT_NATS_URL} (verify firewall/bind settings)." >&2
fi

cat <<SUMMARY
PASS: master LAN stack started
MASTER_IP=${MASTER_IP_VALUE}
NATS_FOR_ENDPOINTS=${ENDPOINT_NATS_URL}
MASTER_GRPC_MTLS=${MASTER_IP_VALUE}:${MASTER_GRPC_PORT}
TIMESCALE_CONTAINER=${DB_CONTAINER_NAME:-rsiem-timescale}
NATS_LOCAL_CHECK=${NATS_LOCAL_CHECK}
NATS_LAN_CHECK=${NATS_LAN_CHECK}

Next steps:
1) Onboard endpoint cert + allowlist fingerprint (see docs/deploy/certs_allowlist_onboarding.md).
2) Install endpoint package (Linux: scripts/deploy/linux/install_endpoint.sh, Windows: scripts/deploy/windows/install_endpoint.ps1).
3) Run docs/deploy/two_host_pilot.md checks.
SUMMARY
