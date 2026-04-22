#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRY_RUN=0
WITH_DB=0

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --with-db) WITH_DB=1 ;;
    *)
      echo "usage: $0 [--dry-run] [--with-db]" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT_DIR"

files=(
  "exports/alerts.jsonl"
  "exports/incidents.jsonl"
  "exports/notify.jsonl"
  "exports/roe_runs.jsonl"
  "exports/roe_steps.jsonl"
  "exports/roe_steps_latest.jsonl"
  "retained/ui_state/assignments.jsonl"
  "retained/ui_state/notes.jsonl"
  "retained/ui_state/purged_incidents.jsonl"
  "retained/ui_state/response_actions.jsonl"
  "logs/master-roe.log"
  "logs/worker.log"
  "logs/detector.log"
  "logs/ui-api.log"
)

echo "Resetting volatile presentation state under $ROOT_DIR"
for path in "${files[@]}"; do
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "would truncate $path"
    continue
  fi
  mkdir -p "$(dirname "$path")"
  : > "$path"
  echo "truncated $path"
done

if [[ $WITH_DB -eq 1 ]]; then
  : "${DB_DSN:=postgres://rsiem:rsiem@127.0.0.1:5432/rsiem?sslmode=disable}"
  SQL="TRUNCATE TABLE observable_enrichments, enrichment_jobs, incident_observables, normalized_events;"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "would run DB reset against $DB_DSN"
    echo "$SQL"
  else
    psql "$DB_DSN" -v ON_ERROR_STOP=1 -c "$SQL"
    echo "database event/enrichment tables truncated"
  fi
fi

echo "presentation demo state reset complete"
