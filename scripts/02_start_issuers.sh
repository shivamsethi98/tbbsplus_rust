#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$ROOT_DIR"

BASE_PORT=${BASE_PORT:-9900}
THRESHOLD=${THRESHOLD:-3}

# Load env produced by stage 1 if present
if [[ -f .runtime.env ]]; then
	set -a
	source .runtime.env
	set +a
fi

if [[ -z "${ETH_WS:-}" || -z "${CHAIN_ID:-}" || -z "${REQ_CONTRACT:-}" || -z "${REGISTRY_CONTRACT:-}" || -z "${PARAMS_CONTRACT:-}" || -z "${CRED_NAME:-}" || -z "${MESSAGE_COUNT:-}" || -z "${TOTAL:-}" ]]; then
	echo "Missing required env (ETH_WS, CHAIN_ID, REQ_CONTRACT, REGISTRY_CONTRACT, PARAMS_CONTRACT, CRED_NAME, MESSAGE_COUNT, TOTAL). Ensure 01_ttp_setup.sh was run in same shell." >&2
	
	exit 1
fi

echo "[issuers] starting $THRESHOLD issuers from BASE_PORT=$BASE_PORT"
for i in $(seq 1 $THRESHOLD); do
	(
		PID=$i \
		BASE_PORT=$BASE_PORT \
		ETH_WS=$ETH_WS \
		CHAIN_ID=$CHAIN_ID \
		REQ_CONTRACT=$REQ_CONTRACT \
		REGISTRY_CONTRACT=$REGISTRY_CONTRACT \
		PARAMS_CONTRACT=$PARAMS_CONTRACT \
		CRED_NAME=$CRED_NAME \
		THRESHOLD=$THRESHOLD \
		TOTAL=$TOTAL \
		MESSAGE_COUNT=$MESSAGE_COUNT \
	SHARES_FILE=${SHARES_FILE:-.runtime.shares.json} \
		cargo run --features mpc --bin issuer_onchain | sed -u "s/^/[issuer-$i] /"
	) &

done

wait -n || true
