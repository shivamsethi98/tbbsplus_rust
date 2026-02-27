#!/usr/bin/env bash
# bench_presentation_e2e.sh — Presentation gas + timing benchmark.
#
# Assumes credentials have ALREADY been issued for all users up to max(BENCH_SIZES).
# (Run bench_issuance_e2e.sh first with a large enough N, or issue separately.)
#
# For each batch size N:
#   1. Updates on-chain batch sizes
#   2. Clears batch_presentation.json and NDJSON files
#   3. Launches N clients in Mode::Verify with AUTO_WITNESS_SYNC + BATCH_PRESENTATION_EXPORT
#   4. Waits for N presentation_build records in client NDJSON
#   5. Waits for verifyPresentationBatch in presentation_aggregator NDJSON
#   6. Archives NDJSON files
#
# Prerequisites (start once before running this script):
#   anvil running, .runtime.env present
#   Start issuers             — bash scripts/02_start_issuers.sh  (they poll batch_size from chain)
#   Start aggregators/SP      — see E2E_TEST.md T5a/T5b/T5c (each in its own terminal)
#   Credentials already issued for MNEMONIC_INDEX 1..max(BENCH_SIZES)
#
# Usage:
#   BENCH_SIZES="1 2 4 8 16 32 64 128" bash scripts/bench_presentation_e2e.sh
set -euo pipefail

if [ ! -f .runtime.env ]; then
  echo "ERROR: .runtime.env not found" >&2; exit 1
fi
source .runtime.env

# Preflight: verify required processes are running
if ! pgrep -f 'target/debug/presentation_aggregator' > /dev/null 2>&1; then
  echo "ERROR: presentation_aggregator is not running." >&2
  echo "       Start it first (see E2E_TEST.md T5b)." >&2; exit 1
fi
if ! pgrep -f 'target/debug/service_provider' > /dev/null 2>&1; then
  echo "ERROR: service_provider is not running." >&2
  echo "       Start it first (see E2E_TEST.md T5c)." >&2; exit 1
fi

BENCH_SIZES="${BENCH_SIZES:-1 2 4 8 16}"
MNEMONIC="${MNEMONIC:-test test test test test test test test test test test junk}"
BATCH_TIMEOUT_SECS="${BATCH_TIMEOUT_SECS:-180}"
PRES_NDJSON="metrics/results/presentation_aggregator.ndjson"
SP_NDJSON="metrics/results/service_provider.ndjson"
CLIENT_NDJSON="metrics/results/client.ndjson"

echo "=== bench_presentation_e2e.sh ==="
echo "Sizes: $BENCH_SIZES"
echo ""

# Pre-build client with interactive feature for witness sync + presentation export
echo "[bench] pre-building client binary..."
cargo build --features mpc,interactive --bin client 2>&1 | tail -1
echo ""

# Non-overlapping wallet indices — must match bench_issuance_e2e.sh offset scheme
OFFSET=0
for N in $BENCH_SIZES; do
  echo "════════════════════════════════════════"
  echo "Bench: presentation batch size N=$N"
  echo "════════════════════════════════════════"

  # 1. Update on-chain batch sizes
  BATCH_SIZE_REQ="$N" BATCH_SIZE_PRES="$N" \
    npx hardhat run scripts/update_batch_sizes.ts --network localhost

  # 1b. Give aggregator 2× AGG_POLL_SECS to pick up the new threshold
  sleep 4

  # 2. Clear presentation JSON + NDJSON (keep user credential state!)
  rm -f batch_presentation.json
  rm -f "$PRES_NDJSON" "$SP_NDJSON" "$CLIENT_NDJSON"

  # 3. Launch N clients in verify mode (fetches sig from registry, runs witness sync, exports presentation)
  PIDS=()
  for IDX in $(seq 1 "$N"); do
    (
      MNEMONIC_INDEX=$((OFFSET + IDX)) \
      FEATURES=mpc,interactive \
      AUTO_WITNESS_SYNC=1 \
      BATCH_PRESENTATION_EXPORT=1 \
      BATCH_PRESENTATION_FILE=batch_presentation.json \
      AUTO_REVEALED_IDX=0 \
      METRICS=1 \
      METRICS_FILE="$CLIENT_NDJSON" \
        bash scripts/run_client.sh verify
    ) &
    PIDS+=($!)
  done

  echo "[bench] waiting for $N clients to build presentations..."
  for pid in "${PIDS[@]}"; do
    wait "$pid" || echo "[bench] client pid $pid exited non-zero"
  done
  echo "[bench] all $N clients done."

  # 4. Wait for N presentation_build records in client NDJSON
  echo "[bench] waiting for $N presentation_build records..."
  ELAPSED=0
  while true; do
    COUNT=$(grep -c '"scenario":"presentation_build"' "$CLIENT_NDJSON" 2>/dev/null) || true
    COUNT=${COUNT:-0}
    if [ "$COUNT" -ge "$N" ]; then break; fi
    sleep 2; ELAPSED=$((ELAPSED + 2))
    if [ "$ELAPSED" -ge "$BATCH_TIMEOUT_SECS" ]; then
      echo "[bench] ERROR: only $COUNT/$N presentation_build records at N=$N"; exit 1
    fi
  done
  echo "[bench] all $N presentations built."

  # 5. Wait for verifyPresentationBatch in presentation_aggregator NDJSON
  echo "[bench] waiting for batch verification tx (timeout=${BATCH_TIMEOUT_SECS}s)..."
  ELAPSED=0
  until grep -q '"scenario":"verifyPresentationBatch"' "$PRES_NDJSON" 2>/dev/null; do
    sleep 2; ELAPSED=$((ELAPSED + 2))
    if [ "$ELAPSED" -ge "$BATCH_TIMEOUT_SECS" ]; then
      echo "[bench] ERROR: timed out waiting for verifyPresentationBatch at N=$N"; exit 1
    fi
  done
  echo "[bench] batch presentation verified."

  # 6. Archive NDJSON files
  mkdir -p metrics/results
  cp "$PRES_NDJSON" "metrics/results/presentation_aggregator_n${N}.ndjson" 2>/dev/null || true
  cp "$SP_NDJSON"   "metrics/results/service_provider_n${N}.ndjson" 2>/dev/null || true
  cp "$CLIENT_NDJSON" "metrics/results/client_pres_n${N}.ndjson" 2>/dev/null || true

  rm -f "$PRES_NDJSON" "$SP_NDJSON" "$CLIENT_NDJSON"

  OFFSET=$((OFFSET + N))
  echo "[bench] archived N=$N"
  echo ""
done

echo "=== Presentation benchmark complete ==="
echo "Run bench_summary to produce tables."
