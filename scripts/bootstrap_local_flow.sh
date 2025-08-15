#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$ROOT_DIR"

ANVIL_PORT=${ANVIL_PORT:-8545}
BASE_PORT=${BASE_PORT:-9900}
THRESHOLD=${THRESHOLD:-3}
TOTAL=${TOTAL:-4}
MESSAGE_COUNT=${MESSAGE_COUNT:-5}
CRED_NAME=${CRED_NAME:-IITH_UG_AC}

echo "[1/4] Stage 1: TTP setup (start anvil, compile/deploy, allowlist, run ttp)"
# Source so that env vars persist and anvil trap is registered in this shell
source ./scripts/01_ttp_setup.sh

echo "[2/4] Stage 2: Start issuers"
./scripts/02_start_issuers.sh &
ISSUERS_PID=$!
sleep 2

echo "[3/4] Stage 3: Run user (send + verify)"
./scripts/03_run_user.sh

echo "[4/4] Done"
# Cleanup issuer processes
kill $ISSUERS_PID 2>/dev/null || true
pkill -f issuer_onchain 2>/dev/null || true
