#!/usr/bin/env bash
# bench_request.sh — Batched credential-request gas benchmark.
#
# Runs BENCH_SIZES batch sizes in sequence:
#   1. Updates on-chain batch sizes via update_batch_sizes.ts  (no aggregator restart)
#   2. Clears local user state so clients can re-request
#   3. Fires N clients in parallel, each exporting a proof to batch_request.json
#   4. Waits for request_aggregator to emit a NDJSON success record
#   5. Archives the NDJSON file as request_aggregator_nN.ndjson
#
# Prerequisites (run once before this script):
#   anvil --hardfork pragueEOF --gas-limit 300000000 -p 8545
#   BATCH_SIZE_REQ=1 BATCH_SIZE_PRES=1 bash scripts/01_ttp_setup.sh
#   source .runtime.env
#   RUST_LOG=info METRICS=1 cargo run --features mpc --bin request_aggregator &
#   BATCH_SIZE=1 BATCH_TIMEOUT_MS=30000 bash scripts/02_start_issuers.sh
#
# Usage:
#   BENCH_SIZES="1 2 4 8 16" bash scripts/bench_request.sh
set -euo pipefail

if [ ! -f .runtime.env ]; then
  echo "ERROR: .runtime.env not found — run scripts/01_ttp_setup.sh first" >&2
  exit 1
fi
source .runtime.env

# Preflight: verify the request_aggregator is running with METRICS=1
# (it must be started separately via scripts/start_aggregators.sh)
if ! pgrep -f 'target/debug/request_aggregator' > /dev/null 2>&1; then
  echo "ERROR: request_aggregator is not running." >&2
  echo "       Start it first: bash scripts/start_aggregators.sh" >&2
  exit 1
fi

BENCH_SIZES="${BENCH_SIZES:-1 2 4 8 16}"
MNEMONIC="${MNEMONIC:-test test test test test test test test test test test junk}"
BATCH_TIMEOUT_SECS="${BATCH_TIMEOUT_SECS:-120}"
NDJSON_FILE="metrics/results/request_aggregator.ndjson"

echo "=== bench_request.sh ==="
echo "Sizes: $BENCH_SIZES"
echo ""

# Pre-build client binary once so parallel invocations don't fight over the cargo lock
echo "[bench] pre-building client binary..."
cargo build --features mpc --bin client 2>&1 | grep -v '^$'
echo ""

for N in $BENCH_SIZES; do
  echo "────────────────────────────────────────"
  echo "Bench: batch size N=$N"
  echo "────────────────────────────────────────"

  # 1. Update on-chain batch sizes (aggregators pick this up next poll, no restart needed)
  BATCH_SIZE_REQ="$N" BATCH_SIZE_PRES="$N" \
    npx hardhat run scripts/update_batch_sizes.ts --network localhost

  # 2. Clear local user credential state so clients can re-request
  rm -rf .runtime/users
  rm -f batch_request.json batch_presentation.json

  # 3. Remove stale NDJSON from previous run so we can detect new entry below
  rm -f "$NDJSON_FILE"

  # 4. Launch N clients in parallel; each writes one proof to batch_request.json
  PIDS=()
  for IDX in $(seq 1 "$N"); do
    (
      MNEMONIC_INDEX="$IDX" \
      BATCH_REQUEST_EXPORT=1 \
      BATCH_REQUEST_FILE=batch_request.json \
        bash scripts/run_client.sh request
    ) &
    PIDS+=($!)
  done

  echo "[bench] waiting for $N clients to write proofs..."
  for pid in "${PIDS[@]}"; do
    wait "$pid" || echo "[bench] client pid $pid exited non-zero"
  done
  echo "[bench] all $N clients done."

  # 5. Wait for request_aggregator to emit a success NDJSON record
  echo "[bench] waiting for batch tx confirmation (timeout=${BATCH_TIMEOUT_SECS}s)..."
  ELAPSED=0
  until grep -q '"scenario":"batchBroadcastSigReqBBSPlusVerified"' "$NDJSON_FILE" 2>/dev/null; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [ "$ELAPSED" -ge "$BATCH_TIMEOUT_SECS" ]; then
      echo "[bench] ERROR: timed out waiting for batch tx confirmation at size N=$N"
      exit 1
    fi
  done
  echo "[bench] batch tx confirmed for N=$N."

  # 6. Archive NDJSON so next iteration starts fresh
  mkdir -p metrics/results
  cp "$NDJSON_FILE" "metrics/results/request_aggregator_n${N}.ndjson"
  rm -f "$NDJSON_FILE"

  echo "[bench] archived → metrics/results/request_aggregator_n${N}.ndjson"
  echo ""
done

echo "=== Benchmark complete ==="
echo "Run 'cargo run --bin bench_summary' to produce the gas summary table."
