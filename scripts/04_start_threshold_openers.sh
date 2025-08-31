#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$ROOT_DIR"

# Use a separate base port for openers to avoid clashing with issuers (issuers use 9900 by default)
OPENERS_BASE_PORT=${OPENERS_BASE_PORT:-10900}
# Number of opener participants to start; default to THRESHOLD_OPENER
OPENERS_COUNT=${OPENERS_COUNT:-${THRESHOLD_OPENER:-${THRESHOLD:-5}}}

# Load env produced by 01_ttp_setup.sh if present
if [[ -f .runtime.env ]]; then
  set -a
  source .runtime.env
  set +a
fi

# Validate required env
required=(ETH_WS CHAIN_ID PARAMS_CONTRACT ACC_CONTRACT CRED_NAME THRESHOLD_OPENER TOTAL)
for v in "${required[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    echo "Missing required env: $v (run scripts/01_ttp_setup.sh first)" >&2
    exit 1
  fi
done

if [[ ! -f .runtime.openers.json ]]; then
  echo "[openers] WARNING: .runtime.openers.json not found; opener shares may be missing. Run scripts/01_ttp_setup.sh" >&2
fi

echo "[openers] starting $OPENERS_COUNT openers from BASE_PORT=$OPENERS_BASE_PORT"
for i in $(seq 1 "$OPENERS_COUNT"); do
  (
    PID=$i \
    BASE_PORT=$OPENERS_BASE_PORT \
    ETH_WS=$ETH_WS \
    CHAIN_ID=$CHAIN_ID \
    PARAMS_CONTRACT=$PARAMS_CONTRACT \
    ACC_CONTRACT=$ACC_CONTRACT \
    CRED_NAME=$CRED_NAME \
    THRESHOLD=${OPENER_COUNT:-${THRESHOLD_OPENER:-${THRESHOLD:-3}}} \
    TOTAL=${OPENER_COUNT:-${TOTAL:-3}} \
    AGG_PID=${AGG_PID:-99} \
    AGGREGATOR=0 \
    cargo run --features mpc --bin opener_threshold | sed -u "s/^/[opener-$i] /"
  ) &
  sleep 0.2
done

echo "[openers] all started. Waiting for any to exit..."
wait -n || true

