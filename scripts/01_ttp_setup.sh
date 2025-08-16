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

echo "[02] Compile & deploy"
npx hardhat clean >/dev/null 2>&1 || true
npx hardhat compile --force
DEP_ENV=$(CRED_NAME="$CRED_NAME" MESSAGE_COUNT="$MESSAGE_COUNT" THRESHOLD="$THRESHOLD" TOTAL="$TOTAL" npx hardhat run --network localhost scripts/deploy_local.ts)
eval "$DEP_ENV"
export ETH_WS=ws://127.0.0.1:${ANVIL_PORT}
export CHAIN_ID=31337

echo "[03] Deploy PoK/Verify helpers"
VERIFY_ENV=$(npx hardhat run --network localhost scripts/deploy_pok_verifiers.ts)
eval "$VERIFY_ENV"

# Write runtime env after both deployments so Verify addresses are included
cat > .runtime.env <<EOF
ETH_WS=$ETH_WS
CHAIN_ID=$CHAIN_ID
REQ_CONTRACT=$REQ_CONTRACT
RELAY_CONTRACT=$RELAY_CONTRACT
PARAMS_CONTRACT=$PARAMS_CONTRACT
VERIFY_CONTRACT=${VERIFY_CONTRACT}
POK_VERIFY_WRAPPER=${POK_VERIFY_WRAPPER}
POK_TRANSCRIPT_WRAPPER=${POK_TRANSCRIPT_WRAPPER}
CRED_NAME=$CRED_NAME
MESSAGE_COUNT=$MESSAGE_COUNT
THRESHOLD=$THRESHOLD
TOTAL=$TOTAL
BASE_PORT=$BASE_PORT
SHARES_FILE=$SHARES_FILE
G2_GEN_256=${G2_GEN_256:-}
EOF
echo "[env] Wrote .runtime.env with Verify addresses"

echo "[04] Allowlist issuers & set multiaddrs in Params"
PARAMS_CONTRACT="$PARAMS_CONTRACT" THRESHOLD="$THRESHOLD" BASE_PORT="$BASE_PORT" npx hardhat run --network localhost scripts/allowlist_and_set_multiaddrs.ts

echo "[05] Run TTP"
export OWNER_PK=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
# Capture TTP exports (PK_G2_HEX) into env
eval "$(SHARES_FILE=$SHARES_FILE cargo run --features mpc --bin ttp | sed -n 's/^export /export /p')"

# If pk hex was emitted, set it on-chain via hardhat
if [ -n "${PK_G2_HEX:-}" ]; then
	echo "[06] Set pkG2 in Params"
	PARAMS_CONTRACT="$PARAMS_CONTRACT" CRED_NAME="$CRED_NAME" PK_G2_HEX="$PK_G2_HEX" npx hardhat run --network localhost scripts/set_params_pkg2.ts
fi

# Update .runtime.env with values exported by TTP
{
	echo "PK_G2_HEX=${PK_G2_HEX:-}"
	echo "G2_GEN_256=${G2_GEN_256:-}"
} >> .runtime.env
echo "[env] Updated .runtime.env with PK_G2_HEX and G2_GEN_256"
