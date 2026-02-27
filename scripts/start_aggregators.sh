#!/usr/bin/env bash
# start_aggregators.sh — Start all three persistent aggregators with metrics enabled.
#
# Sources .runtime.env so this can be run from any shell without prior `source`.
# Aggregators run as background jobs in the current shell.
#
# Usage:
#   bash scripts/start_aggregators.sh
#
# Stop with: kill $(cat .runtime/agg.pids)
set -euo pipefail

if [ ! -f .runtime.env ]; then
  echo "ERROR: .runtime.env not found — run scripts/01_ttp_setup.sh first" >&2
  exit 1
fi
source .runtime.env

mkdir -p metrics/results .runtime

echo "[agg] starting request_aggregator..."
METRICS=1 METRICS_FILE=metrics/results/request_aggregator.ndjson \
  RUST_LOG=info \
  cargo run --features mpc --bin request_aggregator &
PID_REQ=$!

echo "[agg] starting presentation_aggregator..."
METRICS=1 METRICS_FILE=metrics/results/presentation_aggregator.ndjson \
  RUST_LOG=info \
  cargo run --features mpc --bin presentation_aggregator &
PID_PRES=$!

echo "[agg] starting service_provider..."
METRICS=1 METRICS_FILE=metrics/results/service_provider.ndjson \
  cargo run --bin service_provider &
PID_SP=$!

echo "$PID_REQ $PID_PRES $PID_SP" > .runtime/agg.pids
echo "[agg] PIDs saved to .runtime/agg.pids"
echo "[agg] To stop: kill \$(cat .runtime/agg.pids)"
