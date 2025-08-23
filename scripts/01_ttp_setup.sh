#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$ROOT_DIR"

ANVIL_PORT=${ANVIL_PORT:-8545}
BASE_PORT=${BASE_PORT:-9900}
THRESHOLD=${THRESHOLD:-4}
TOTAL=${TOTAL:-5}
MESSAGE_COUNT=${MESSAGE_COUNT:-5}
CRED_NAME=${CRED_NAME:-ANON_CRED}
SHARES_FILE=${SHARES_FILE:-.runtime.shares.json}

echo "[00] Clean runtime caches"
rm -rf .runtime/sids .runtime/users .runtime.g2_base.hex .runtime.pk_g2.hex .runtime/pok.json || true
rm -f "$SHARES_FILE" || true

echo "[01] Start anvil"
anvil --port "$ANVIL_PORT" --hardfork prague > anvil.log 2>&1 &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null || true' EXIT
sleep 1

echo "[02] Compile"
npx hardhat clean >/dev/null 2>&1 || true
npx hardhat compile --force

echo "[03] Deploy core"
DEP_ENV=$(CRED_NAME="$CRED_NAME" MESSAGE_COUNT="$MESSAGE_COUNT" THRESHOLD="$THRESHOLD" TOTAL="$TOTAL" npx hardhat run --network localhost scripts/deploy_local.ts | sed -n 's/^export /export /p')
eval "$DEP_ENV"
export ETH_WS=ws://127.0.0.1:${ANVIL_PORT}
export CHAIN_ID=31337
# Write/refresh .runtime.env (verify vars will be added after step 04)
cat > .runtime.env <<EOF
ETH_WS=$ETH_WS
CHAIN_ID=$CHAIN_ID
REQ_CONTRACT=$REQ_CONTRACT
RELAY_CONTRACT=$RELAY_CONTRACT
REGISTRY_CONTRACT=${REGISTRY_CONTRACT}
PARAMS_CONTRACT=$PARAMS_CONTRACT
ACC_CONTRACT=$ACC_CONTRACT
CRED_NAME=$CRED_NAME
MESSAGE_COUNT=$MESSAGE_COUNT
THRESHOLD=$THRESHOLD
TOTAL=$TOTAL
BASE_PORT=$BASE_PORT
SHARES_FILE=$SHARES_FILE
EOF
set -a; source .runtime.env; set +a

echo "[04] Deploy PoK/Verify helpers"
VERIFY_ENV=$(npx hardhat run --network localhost scripts/deploy_pok_verifiers.ts | sed -n 's/^export /export /p')
eval "$VERIFY_ENV"
# Append verify vars
{
  echo "VERIFY_CONTRACT=${VERIFY_CONTRACT}"
  echo "POK_VERIFY_WRAPPER=${POK_VERIFY_WRAPPER}"
  echo "POK_TRANSCRIPT_WRAPPER=${POK_TRANSCRIPT_WRAPPER}"
} >> .runtime.env

echo "[05] Allowlist issuers & set multiaddrs in Params"
PARAMS_CONTRACT="$PARAMS_CONTRACT" THRESHOLD="$THRESHOLD" BASE_PORT="$BASE_PORT" npx hardhat run --network localhost scripts/allowlist_and_set_multiaddrs.ts

echo "[06] Run TTP (sets g1/h0/H, g2base, pkG2, and writes shares)"
# Use Anvil's first default private key (0xf39f...)
export OWNER_PK=${OWNER_PK:-0xac0974bec36b3...} # placeholder, will set exact next line
export OWNER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
eval "$(SHARES_FILE=$SHARES_FILE cargo run --features mpc --bin ttp | sed -n 's/^export /export /p')"



echo "[07] Done"
