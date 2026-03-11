#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

FILTER="${DETECTOR_FIXTURE_FILTER:-}"
TEST_REGEX='TestDetectorRegression(Fixtures|FixtureCatalog)$'

echo "=== Detector Regression Verification ==="
if [[ -n "$FILTER" ]]; then
  echo "FILTER=$FILTER"
fi

DETECTOR_FIXTURE_FILTER="$FILTER" \
GOCACHE="$ROOT_DIR/.cache/go-build" \
go test -mod=vendor -run "$TEST_REGEX" -v ./cmd/detector-v0

echo "PASS: detector regression framework verified"
