#!/usr/bin/env bash
# run_client.sh — Derive CLIENT_PK from MNEMONIC_INDEX and run the client binary.
#
# Usage:
#   MNEMONIC_INDEX=1 bash scripts/run_client.sh request
#   MNEMONIC_INDEX=2 FEATURES=mpc,interactive bash scripts/run_client.sh request --wait
#
# Environment variables:
#   MNEMONIC_INDEX  — Anvil account index (default: 1)
#   MNEMONIC        — BIP-39 mnemonic (default: Hardhat/Anvil test mnemonic)
#   FEATURES        — Cargo features (default: mpc)
#   All other vars are passed through to the client binary (BATCH_REQUEST_EXPORT, etc.)
set -euo pipefail

MNEMONIC="${MNEMONIC:-test test test test test test test test test test test junk}"
MNEMONIC_INDEX="${MNEMONIC_INDEX:-1}"
FEATURES="${FEATURES:-mpc}"

export CLIENT_PK
CLIENT_PK="$(cast wallet private-key --mnemonic "$MNEMONIC" --mnemonic-index "$MNEMONIC_INDEX")"

# Use pre-built binary if present (avoids cargo file-lock contention when N clients run in parallel)
if [ -x "target/debug/client" ]; then
  exec target/debug/client "$@"
else
  exec cargo run --features "$FEATURES" --bin client -- "$@"
fi
