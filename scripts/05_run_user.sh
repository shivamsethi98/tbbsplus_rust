#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$ROOT_DIR"

# Load env produced by stage 1 if present
if [[ -f .runtime.env ]]; then
	set -a
	source .runtime.env
	set +a
fi

if [[ -z "${ETH_WS:-}" || -z "${CHAIN_ID:-}" || -z "${REQ_CONTRACT:-}" || -z "${REGISTRY_CONTRACT:-}" || -z "${PARAMS_CONTRACT:-}" || -z "${CRED_NAME:-}" || -z "${MESSAGE_COUNT:-}" ]]; then
	echo "Missing required env (ETH_WS, CHAIN_ID, REQ_CONTRACT, REGISTRY_CONTRACT, PARAMS_CONTRACT, CRED_NAME, MESSAGE_COUNT). Ensure 01_ttp_setup.sh was run in same shell." >&2
	exit 1
fi

echo "[user] sending request and verifying"
ETH_WS=$ETH_WS \
CHAIN_ID=$CHAIN_ID \
REQ_CONTRACT=$REQ_CONTRACT \
REGISTRY_CONTRACT=$REGISTRY_CONTRACT \
PARAMS_CONTRACT=$PARAMS_CONTRACT \
CRED_NAME=$CRED_NAME \
MESSAGE_COUNT=$MESSAGE_COUNT \
METRICS=1 cargo run --bin client --features mpc,interactive
