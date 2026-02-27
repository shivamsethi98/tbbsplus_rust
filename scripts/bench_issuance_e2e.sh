#!/usr/bin/env bash
# bench_issuance_e2e.sh — Full issuance gas + timing benchmark.
#
# For each batch size N:
#   1. Updates on-chain batch sizes (aggregators + issuers poll from chain)
#   2. Clears user state + NDJSON files
#   3. Launches N clients with METRICS, BATCH_REQUEST_EXPORT, AUTO_WITNESS_SYNC, --wait
#   4. Waits for batchBroadcastSigReqBBSPlusVerified in request_aggregator NDJSON
#   5. Waits for all N issuance_e2e_confirmed records in client NDJSON
#   6. Archives all NDJSON files as *_nN.ndjson
#
# Prerequisites (start once before running this script):
#   anvil --hardfork pragueEOF --gas-limit 300000000 -p 8545
#   BATCH_SIZE_REQ=1 BATCH_SIZE_PRES=1 bash scripts/01_ttp_setup.sh
#   source .runtime.env
#   Start issuers        — bash scripts/02_start_issuers.sh  (they poll batch_size from chain)
#   Start aggregators/SP — see E2E_TEST.md T5a/T5b/T5c (each in its own terminal)
#
# Usage:
#   BENCH_SIZES="1 2 4 8 16 32 64 128" bash scripts/bench_issuance_e2e.sh
set -euo pipefail

if [ ! -f .runtime.env ]; then
  echo "ERROR: .runtime.env not found — run scripts/01_ttp_setup.sh first" >&2; exit 1
fi
source .runtime.env

# Preflight: verify required processes are running
if ! pgrep -f 'target/debug/request_aggregator' > /dev/null 2>&1; then
  echo "ERROR: request_aggregator is not running." >&2
  echo "       Start it first (see E2E_TEST.md T5a)." >&2; exit 1
fi
if ! pgrep -f 'target/debug/issuer_onchain' > /dev/null 2>&1; then
  echo "ERROR: issuer_onchain is not running." >&2
  echo "       Start issuers first: bash scripts/02_start_issuers.sh" >&2; exit 1
fi

BENCH_SIZES="${BENCH_SIZES:-1 2 4 8 16}"
MNEMONIC="${MNEMONIC:-test test test test test test test test test test test junk}"
BATCH_TIMEOUT_SECS="${BATCH_TIMEOUT_SECS:-300}"
REQ_NDJSON="metrics/results/request_aggregator.ndjson"
CLIENT_NDJSON="metrics/results/client.ndjson"
ISSUER_NDJSON_PREFIX="metrics/results/issuer"

echo "=== bench_issuance_e2e.sh ==="
echo "Sizes: $BENCH_SIZES"
echo ""

# Pre-build client binary once so parallel invocations don't fight over the cargo lock
echo "[bench] pre-building client binary..."
cargo build --features mpc,interactive --bin client 2>&1 | tail -1
echo ""

OFFSET=0   # cumulative offset so each iteration uses unique wallet indices
for N in $BENCH_SIZES; do
  echo "════════════════════════════════════════"
  echo "Bench: batch size N=$N"
  echo "════════════════════════════════════════"

  # 1. Update on-chain batch sizes (aggregators + issuers poll from chain, no restart needed)
  BATCH_SIZE_REQ="$N" BATCH_SIZE_PRES="$N" \
    npx hardhat run scripts/update_batch_sizes.ts --network localhost

  # 1b. Give aggregator 2× AGG_POLL_SECS to pick up the new threshold
  sleep 4

  # 2. Clear local state + NDJSON
  rm -rf .runtime/users
  rm -f batch_request.json batch_presentation.json
  rm -f "$REQ_NDJSON" "$CLIENT_NDJSON"
  for f in ${ISSUER_NDJSON_PREFIX}_*.ndjson; do rm -f "$f" 2>/dev/null; done

  # 3. Launch N clients in parallel (they export proof, then wait for Confirmed event)
  PIDS=()
  for IDX in $(seq 1 "$N"); do
    (
      MNEMONIC_INDEX=$((OFFSET + IDX)) \
      FEATURES=mpc,interactive \
      BATCH_REQUEST_EXPORT=1 \
      BATCH_REQUEST_FILE=batch_request.json \
      AUTO_WITNESS_SYNC=1 \
      METRICS=1 \
      METRICS_FILE="$CLIENT_NDJSON" \
        bash scripts/run_client.sh request --wait
    ) &
    PIDS+=($!)
  done

  # 4. Wait for batch tx in request_aggregator NDJSON
  echo "[bench] waiting for batch tx confirmation (timeout=${BATCH_TIMEOUT_SECS}s)..."
  ELAPSED=0
  until grep -q '"scenario":"batchBroadcastSigReqBBSPlusVerified"' "$REQ_NDJSON" 2>/dev/null; do
    sleep 2; ELAPSED=$((ELAPSED + 2))
    if [ "$ELAPSED" -ge "$BATCH_TIMEOUT_SECS" ]; then
      echo "[bench] ERROR: timed out waiting for batch tx at N=$N"; exit 1
    fi
  done
  echo "[bench] batch tx confirmed."

  # 5. Wait for N issuance_e2e_confirmed records in client NDJSON
  echo "[bench] waiting for $N issuance_e2e_confirmed records..."
  ELAPSED=0
  while true; do
    COUNT=$(grep -c '"scenario":"issuance_e2e_confirmed"' "$CLIENT_NDJSON" 2>/dev/null) || true
    COUNT=${COUNT:-0}
    if [ "$COUNT" -ge "$N" ]; then break; fi
    sleep 2; ELAPSED=$((ELAPSED + 2))
    if [ "$ELAPSED" -ge "$BATCH_TIMEOUT_SECS" ]; then
      echo "[bench] ERROR: only $COUNT/$N issuance_e2e_confirmed records at N=$N"; exit 1
    fi
  done
  echo "[bench] all $N issuance confirmed."

  # 6. Wait for all client processes (they should have exited after Confirmed)
  echo "[bench] waiting for $N clients to exit..."
  for pid in "${PIDS[@]}"; do
    wait "$pid" || echo "[bench] client pid $pid exited non-zero"
  done
  echo "[bench] all $N clients done."

  # 7. Archive NDJSON files
  mkdir -p metrics/results
  cp "$REQ_NDJSON" "metrics/results/request_aggregator_n${N}.ndjson" 2>/dev/null || true
  cp "$CLIENT_NDJSON" "metrics/results/client_n${N}.ndjson" 2>/dev/null || true
  for f in ${ISSUER_NDJSON_PREFIX}_*.ndjson; do
    base=$(basename "$f" .ndjson)
    cp "$f" "metrics/results/${base}_n${N}.ndjson" 2>/dev/null || true
  done
  # Archive opener aggregator NDJSON if present
  if [ -f metrics/results/aggregator.ndjson ]; then
    cp metrics/results/aggregator.ndjson "metrics/results/aggregator_n${N}.ndjson" 2>/dev/null || true
    > metrics/results/aggregator.ndjson  # truncate for next iteration
  fi

  rm -f "$REQ_NDJSON" "$CLIENT_NDJSON"
  for f in ${ISSUER_NDJSON_PREFIX}_*.ndjson; do rm -f "$f" 2>/dev/null; done

  OFFSET=$((OFFSET + N))
  echo "[bench] archived N=$N"
  echo ""
done

echo "=== Issuance benchmark complete ==="
echo "Run bench_summary to produce tables."
