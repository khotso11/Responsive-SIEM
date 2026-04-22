#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

APPLY=0
KEEP_LATEST_ARTIFACTS="${KEEP_LATEST_ARTIFACTS:-5}"

usage() {
  cat <<'EOF'
Usage: scripts/cleanup_local_workspace.sh [--apply] [--keep-latest-artifacts N]

Conservative local cleanup for generated workspace data.

Default behavior:
  - dry-run only
  - keeps the newest 5 demo_artifacts runs
  - removes only rebuildable caches and old proof artifacts

Targets:
  - .cache/
  - .pids/
  - logs/
  - ui/.next
  - ui/.next-dev
  - ui/tsconfig.tsbuildinfo
  - demo_artifacts/* except the newest N timestamped runs
  - repo-root generated binaries only if they are NOT tracked by git

It does NOT touch:
  - pki/
  - exports/
  - retained/
  - tmp/
  - tracked repo files
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      APPLY=1
      shift
      ;;
    --keep-latest-artifacts)
      KEEP_LATEST_ARTIFACTS="${2:?missing value for --keep-latest-artifacts}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! [[ "$KEEP_LATEST_ARTIFACTS" =~ ^[0-9]+$ ]]; then
  echo "KEEP_LATEST_ARTIFACTS must be an integer" >&2
  exit 1
fi

declare -a REMOVE_PATHS=()

add_if_exists() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  REMOVE_PATHS+=("$path")
}

add_if_untracked() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  if git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
    return 0
  fi
  REMOVE_PATHS+=("$path")
}

add_if_exists ".cache"
add_if_exists ".pids"
add_if_exists "logs"
add_if_exists "ui/.next"
add_if_exists "ui/.next-dev"
add_if_exists "ui/tsconfig.tsbuildinfo"

for bin in \
  agent \
  collector-auditd \
  collector-dns \
  collector-inotify \
  collector-procnet \
  collector-tail \
  detector-v0 \
  investigation-enricher \
  master-consume \
  master-roe \
  master-roe-worker \
  ui-api
do
  add_if_untracked "$bin"
done

if [[ -d demo_artifacts ]]; then
  mapfile -t artifact_dirs < <(find demo_artifacts -mindepth 1 -maxdepth 1 -type d -printf '%P\n' | sort -r)
  if (( ${#artifact_dirs[@]} > KEEP_LATEST_ARTIFACTS )); then
    for dir in "${artifact_dirs[@]:KEEP_LATEST_ARTIFACTS}"; do
      REMOVE_PATHS+=("demo_artifacts/$dir")
    done
  fi
fi

if (( ${#REMOVE_PATHS[@]} == 0 )); then
  echo "Nothing to clean."
  exit 0
fi

echo "Cleanup candidates:"
du -sh "${REMOVE_PATHS[@]}" 2>/dev/null | sort -hr || true

if (( APPLY == 0 )); then
  echo
  echo "Dry run only. Re-run with --apply to remove these paths."
  exit 0
fi

for path in "${REMOVE_PATHS[@]}"; do
  rm -rf -- "$path"
done

echo
echo "Cleanup completed."
