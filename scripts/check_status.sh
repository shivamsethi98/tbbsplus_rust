#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$ROOT_DIR"

# Load env from previous stages if present
if [[ -f .runtime.env ]]; then
  set -a
  source .runtime.env
  set +a
fi

if [[ -z "${ETH_WS:-}" || -z "${REGISTRY_CONTRACT:-}" || -z "${CRED_NAME:-}" ]]; then
  echo "Require ETH_WS, REGISTRY_CONTRACT, CRED_NAME in env" >&2
  exit 1
fi

SID="${1:-${SID:-}}"
if [[ -z "${SID}" ]]; then
  echo "Usage: $0 <sid>  (or set SID env)" >&2
  exit 1
fi

WATCH="${WATCH:-1}"
EXIT_ON_VERIFIED="${EXIT_ON_VERIFIED:-1}"
POLL_MS="${POLL_MS:-2000}"

ETH_WS="$ETH_WS" \
REGISTRY_CONTRACT="$REGISTRY_CONTRACT" \
CRED_NAME="$CRED_NAME" \
WATCH="$WATCH" \
EXIT_ON_VERIFIED="$EXIT_ON_VERIFIED" \
POLL_MS="$POLL_MS" \
cargo run --bin cred_status --features mpc -- --sid "$SID" ${WATCH:+--watch}
