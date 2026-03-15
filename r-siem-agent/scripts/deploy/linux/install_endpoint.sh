#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: sudo $0 \
  --master-ip <MASTER_IP> \
  --agent-id <AGENT_ID> \
  --nats-url <NATS_URL> \
  --config-dir <PACKAGE_DIR> \
  [--grpc-port 7777] \
  [--install-dir /opt/rsiem] \
  [--etc-dir /etc/rsiem] \
  [--data-dir /var/lib/rsiem] \
  [--log-dir /var/log/rsiem] \
  [--service-user rsiem]
USAGE
}

MASTER_IP=""
AGENT_ID=""
NATS_URL=""
CONFIG_DIR=""
GRPC_PORT="7777"
INSTALL_DIR="/opt/rsiem"
ETC_DIR="/etc/rsiem"
DATA_DIR="/var/lib/rsiem"
LOG_DIR="/var/log/rsiem"
SERVICE_USER="rsiem"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --master-ip) MASTER_IP="$2"; shift 2 ;;
    --agent-id) AGENT_ID="$2"; shift 2 ;;
    --nats-url) NATS_URL="$2"; shift 2 ;;
    --config-dir) CONFIG_DIR="$2"; shift 2 ;;
    --grpc-port) GRPC_PORT="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --etc-dir) ETC_DIR="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    --log-dir) LOG_DIR="$2"; shift 2 ;;
    --service-user) SERVICE_USER="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

[[ -n "$MASTER_IP" && -n "$AGENT_ID" && -n "$NATS_URL" && -n "$CONFIG_DIR" ]] || {
  usage
  exit 1
}

if [[ "$EUID" -ne 0 ]]; then
  echo "FAIL: run as root (use sudo)." >&2
  exit 1
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL: missing command: $1" >&2
    exit 1
  }
}

need_cmd install
need_cmd systemctl
need_cmd sed

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

if getent group adm >/dev/null 2>&1; then
  usermod -a -G adm "$SERVICE_USER" || true
fi
if getent group audit >/dev/null 2>&1; then
  usermod -a -G audit "$SERVICE_USER" || true
fi

SERVICE_GROUP="$(id -gn "$SERVICE_USER")"

mkdir -p "$INSTALL_DIR/bin" "$ETC_DIR/configs" "$ETC_DIR/pki" "$DATA_DIR" "$LOG_DIR"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR" "$LOG_DIR" "$ETC_DIR"

copy_first() {
  local dest="$1"
  shift
  local src
  for src in "$@"; do
    if [[ -f "$src" ]]; then
      install -m 0755 "$src" "$dest"
      return 0
    fi
  done
  return 1
}

if ! copy_first "$INSTALL_DIR/bin/agent" \
  "$CONFIG_DIR/bin/agent" \
  "$CONFIG_DIR/agent" \
  "$CONFIG_DIR/agent-linux-amd64"; then
  echo "FAIL: could not find agent binary in $CONFIG_DIR" >&2
  exit 1
fi

if ! copy_first "$INSTALL_DIR/bin/collector-tail" \
  "$CONFIG_DIR/bin/collector-tail" \
  "$CONFIG_DIR/collector-tail" \
  "$CONFIG_DIR/collector-tail-linux-amd64"; then
  echo "FAIL: could not find collector-tail binary in $CONFIG_DIR" >&2
  exit 1
fi

HAS_COLLECTOR_AUDITD=0
if copy_first "$INSTALL_DIR/bin/collector-auditd" \
  "$CONFIG_DIR/bin/collector-auditd" \
  "$CONFIG_DIR/collector-auditd"; then
  HAS_COLLECTOR_AUDITD=1
  echo "Installed optional collector-auditd binary"
fi

HAS_COLLECTOR_INOTIFY=0
if copy_first "$INSTALL_DIR/bin/collector-inotify" \
  "$CONFIG_DIR/bin/collector-inotify" \
  "$CONFIG_DIR/collector-inotify"; then
  HAS_COLLECTOR_INOTIFY=1
  echo "Installed optional collector-inotify binary"
fi

HAS_COLLECTOR_PROCNET=0
if copy_first "$INSTALL_DIR/bin/collector-procnet" \
  "$CONFIG_DIR/bin/collector-procnet" \
  "$CONFIG_DIR/collector-procnet"; then
  HAS_COLLECTOR_PROCNET=1
  echo "Installed optional collector-procnet binary"
fi

HAS_COLLECTOR_DNS=0
if copy_first "$INSTALL_DIR/bin/collector-dns" \
  "$CONFIG_DIR/bin/collector-dns" \
  "$CONFIG_DIR/collector-dns"; then
  HAS_COLLECTOR_DNS=1
  echo "Installed optional collector-dns binary"
fi

if copy_first "$INSTALL_DIR/bin/collector-syslog" \
  "$CONFIG_DIR/bin/collector-syslog" \
  "$CONFIG_DIR/collector-syslog"; then
  echo "Installed optional collector-syslog binary"
fi

# Copy PKI material if provided.
for f in ca.pem agent.pem agent-key.pem; do
  if [[ -f "$CONFIG_DIR/pki/$f" ]]; then
    install -m 0644 "$CONFIG_DIR/pki/$f" "$ETC_DIR/pki/$f"
  elif [[ -f "$CONFIG_DIR/certs/$f" ]]; then
    install -m 0644 "$CONFIG_DIR/certs/$f" "$ETC_DIR/pki/$f"
  fi
  if [[ "$f" == "agent-key.pem" && -f "$ETC_DIR/pki/$f" ]]; then
    chmod 0600 "$ETC_DIR/pki/$f"
  fi
done

if [[ -z "$GRPC_PORT" ]]; then
  GRPC_PORT="7777"
fi
MASTER_ADDR="${MASTER_IP}:${GRPC_PORT}"

cat > "$ETC_DIR/configs/agent.yaml" <<CFG
log:
  level: INFO
heartbeat:
  interval_seconds: 60
mock:
  interval_seconds: 1
agent:
  name: r-siem-agent
  instance_id: ${AGENT_ID}
  quarantine_root: ${DATA_DIR}/quarantine
  quarantine_allowed_source_roots:
    - /tmp
lanes:
  fast_buffer: 1000
  standard_buffer: 5000
wal:
  path: ${DATA_DIR}/agent.wal
  fsync: true
batch:
  fast:
    max_size: 50
    max_latency_ms: 200
  standard:
    max_size: 200
    max_latency_ms: 500
transport:
  mode: grpc_mtls
  addr: ${MASTER_ADDR}
  ack_delay_ms: 150
  ack_drop_rate: 0.0
  tls:
    ca: ${ETC_DIR}/pki/ca.pem
    cert: ${ETC_DIR}/pki/agent.pem
    key: ${ETC_DIR}/pki/agent-key.pem
    server_name: master.local
CFG

cat > "$ETC_DIR/configs/collector.yaml" <<CFG
# This is the collector-tail config used by rsiem-collector-tail.service
log_level: INFO

jetstream:
  url: ${NATS_URL}
  stream: RSIEM_EVENTS
  subject: rsiem.events.raw

tail:
  path: /var/log/auth.log
  checkpoint_path: ${DATA_DIR}/tail.checkpoint.json
  poll_ms: 200
CFG

copy_config_if_present() {
  local name="$1"
  if [[ -f "$CONFIG_DIR/configs/$name" ]]; then
    cp "$CONFIG_DIR/configs/$name" "$ETC_DIR/configs/$name"
  elif [[ -f "$ROOT_DIR/configs/$name" ]]; then
    cp "$ROOT_DIR/configs/$name" "$ETC_DIR/configs/$name"
  fi
}

copy_config_if_present "collector-auditd.yaml"
copy_config_if_present "collector-inotify.yaml"
copy_config_if_present "collector-procnet.yaml"
copy_config_if_present "collector-dns.yaml"
if [[ -f "$ROOT_DIR/scripts/deploy/linux/rsiem-audit-execve.rules" ]]; then
  cp "$ROOT_DIR/scripts/deploy/linux/rsiem-audit-execve.rules" "$ETC_DIR/configs/rsiem-audit-execve.rules"
fi
if [[ -f "$CONFIG_DIR/configs/collector-syslog.yaml" ]]; then
  cp "$CONFIG_DIR/configs/collector-syslog.yaml" "$ETC_DIR/configs/collector-syslog.yaml"
elif [[ -f "$ROOT_DIR/configs/collector-syslog.yaml" ]]; then
  cp "$ROOT_DIR/configs/collector-syslog.yaml" "$ETC_DIR/configs/collector-syslog.yaml"
fi

# Render systemd units from templates.
render_unit() {
  local src="$1"
  local dst="$2"
  sed \
    -e "s|__SERVICE_USER__|${SERVICE_USER}|g" \
    -e "s|__SERVICE_GROUP__|${SERVICE_GROUP}|g" \
    -e "s|__INSTALL_DIR__|${INSTALL_DIR}|g" \
    -e "s|__ETC_DIR__|${ETC_DIR}|g" \
    -e "s|__DATA_DIR__|${DATA_DIR}|g" \
    -e "s|__LOG_DIR__|${LOG_DIR}|g" \
    "$src" > "$dst"
}

render_unit "$ROOT_DIR/scripts/deploy/linux/rsiem-agent.service" /etc/systemd/system/rsiem-agent.service
render_unit "$ROOT_DIR/scripts/deploy/linux/rsiem-collector-tail.service" /etc/systemd/system/rsiem-collector-tail.service
if [[ "$HAS_COLLECTOR_AUDITD" == "1" ]]; then
  render_unit "$ROOT_DIR/scripts/deploy/linux/rsiem-collector-auditd.service" /etc/systemd/system/rsiem-collector-auditd.service
fi
if [[ "$HAS_COLLECTOR_INOTIFY" == "1" ]]; then
  render_unit "$ROOT_DIR/scripts/deploy/linux/rsiem-collector-inotify.service" /etc/systemd/system/rsiem-collector-inotify.service
fi
if [[ "$HAS_COLLECTOR_PROCNET" == "1" ]]; then
  render_unit "$ROOT_DIR/scripts/deploy/linux/rsiem-collector-procnet.service" /etc/systemd/system/rsiem-collector-procnet.service
fi
if [[ "$HAS_COLLECTOR_DNS" == "1" ]]; then
  render_unit "$ROOT_DIR/scripts/deploy/linux/rsiem-collector-dns.service" /etc/systemd/system/rsiem-collector-dns.service
fi

systemctl daemon-reload
systemctl enable --now rsiem-agent.service
systemctl enable --now rsiem-collector-tail.service

AUDIT_RULES_STATUS="not loaded (auditd tooling not detected)"
if [[ -f "$ETC_DIR/configs/rsiem-audit-execve.rules" ]]; then
  if command -v augenrules >/dev/null 2>&1 && [[ -d /etc/audit/rules.d ]]; then
    install -d -m 0755 /etc/audit/rules.d
    cp "$ETC_DIR/configs/rsiem-audit-execve.rules" /etc/audit/rules.d/rsiem-execve.rules
    if augenrules --load; then
      AUDIT_RULES_STATUS="loaded (/etc/audit/rules.d/rsiem-execve.rules)"
    else
      AUDIT_RULES_STATUS="copy succeeded, but augenrules --load failed"
    fi
  else
    AUDIT_RULES_STATUS="not loaded (missing /etc/audit/rules.d or augenrules)"
  fi
else
  AUDIT_RULES_STATUS="not loaded (missing ${ETC_DIR}/configs/rsiem-audit-execve.rules)"
fi

cat <<OUT
PASS: linux endpoint install completed
AGENT_ID=${AGENT_ID}
MASTER_ADDR=${MASTER_ADDR}
NATS_URL=${NATS_URL}
OPTIONAL collectors:
  systemctl enable --now rsiem-collector-auditd.service
  systemctl enable --now rsiem-collector-inotify.service
  systemctl enable --now rsiem-collector-procnet.service
  systemctl enable --now rsiem-collector-dns.service
  systemctl enable --now rsiem-collector-syslog.service (if present)
AUDIT_RULES=${AUDIT_RULES_STATUS}

Health checks:
  systemctl status rsiem-agent --no-pager
  systemctl status rsiem-collector-tail --no-pager
  journalctl -u rsiem-agent -n 50 --no-pager
  journalctl -u rsiem-collector-tail -n 50 --no-pager
OUT
