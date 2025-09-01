#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$ROOT_DIR"

# Use a separate base port for openers to avoid clashing with issuers (02_start_issuers.sh uses BASE_PORT=9900)
OPENERS_BASE_PORT=${OPENERS_BASE_PORT:-10900}
# Aggregator logical index (distinct from opener indices 1..THRESHOLD). You can override via first arg or AGG_PID env.
AGG_PID=${1:-${AGG_PID:-99}}

# Load env produced by 01_ttp_setup.sh if present
if [[ -f .runtime.env ]]; then
  set -a
  source .runtime.env
  set +a
fi

# Validate required env
required=(ETH_WS CHAIN_ID PARAMS_CONTRACT ACC_CONTRACT REGISTRY_CONTRACT CRED_NAME THRESHOLD_OPENER TOTAL)
for v in "${required[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    echo "Missing required env: $v (run scripts/01_ttp_setup.sh first)" >&2
    exit 1
  fi
done

# Note: We intentionally do not print any private keys
listen_port=$((OPENERS_BASE_PORT + AGG_PID - 1))
echo "[opener-agg] starting aggregator PID=$AGG_PID BASE_PORT=$OPENERS_BASE_PORT (listens on tcp/$listen_port)"

PID=$AGG_PID \
BASE_PORT=$OPENERS_BASE_PORT \
ETH_WS=$ETH_WS \
CHAIN_ID=$CHAIN_ID \
PARAMS_CONTRACT=$PARAMS_CONTRACT \
ACC_CONTRACT=$ACC_CONTRACT \
REGISTRY_CONTRACT=$REGISTRY_CONTRACT \
CRED_NAME=$CRED_NAME \
THRESHOLD=${THRESHOLD_OPENER:-${THRESHOLD:-3}} \
TOTAL=$TOTAL \
cargo run --features mpc --bin opener_aggregator | sed -u "s/^/[opener-agg] /"

