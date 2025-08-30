#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$ROOT_DIR"

ANVIL_PORT=${ANVIL_PORT:-8545}
BASE_PORT=${BASE_PORT:-9900}

THRESHOLD_ISSUER=${THRESHOLD_ISSUER:-${ISSUER_THRESHOLD:-4}}
THRESHOLD_OPENER=${THRESHOLD_OPENER:-${OPENER_THRESHOLD:-4}}
TOTAL=${TOTAL:-5}
MESSAGE_COUNT=${MESSAGE_COUNT:-5}
CRED_NAME=${CRED_NAME:-ANON_CRED}
SHARES_FILE=${SHARES_FILE:-.runtime.shares.json}


echo "[00] Check whether anvil is running with hardfork=prague on port ${ANVIL_PORT:-8545}"

get_listener_pid() {
  local port=$1
  local pid=""
  if command -v lsof >/dev/null 2>&1; then
    pid=$(lsof -n -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)
  fi
  if [ -z "$pid" ] && command -v ss >/dev/null 2>&1; then
    pid=$(ss -ltnp "( sport = :$port )" 2>/dev/null | awk -F',' '/LISTEN/ { for(i=1;i<=NF;i++) if ($i ~ /pid=/) { sub("pid=","",$i); split($i,a," "); print a[1]; exit } }')
  fi
  if [ -z "$pid" ] && command -v netstat >/dev/null 2>&1; then
    pid=$(netstat -ltnp 2>/dev/null | awk -v p=":$port" '$4 ~ p { match($0, /pid=[0-9]+/); if (RSTART) { pidstr=substr($0,RSTART,RLENGTH); sub("pid=","",pidstr); print pidstr; exit } }')
  fi
  echo "$pid"
}

ANVIL_PID=$(get_listener_pid "$ANVIL_PORT")

if [ -z "$ANVIL_PID" ]; then
  echo "ERROR: No process is listening on port $ANVIL_PORT. Anvil is not running on that port."
  echo "Please start anvil with: anvil --hardfork=prague -p $ANVIL_PORT"
  exit 1
fi

ANVIL_CMD=$(ps -o args= -p "$ANVIL_PID" 2>/dev/null || true)

if printf '%s\n' "$ANVIL_CMD" | grep -iq 'anvil' && printf '%s\n' "$ANVIL_CMD" | grep -iq 'prague'; then
  echo "Found anvil (pid=$ANVIL_PID) running with hardfork prague."
  export ANVIL_PID
else
  echo "ERROR: Port $ANVIL_PORT is in use by pid $ANVIL_PID: $ANVIL_CMD"
  echo "But it is not an anvil process launched with '--hardfork prague'."
  echo "Please start/replace the process with: anvil --hardfork=prague -p $ANVIL_PORT"
  exit 1
fi



echo "[01] Clean runtime caches"
rm -rf .runtime/sids .runtime/users .runtime.g2_base.hex .runtime.pk_g2.hex .runtime/pok.json || true
rm -f "$SHARES_FILE" || true



echo "[02] Compile"
npx hardhat clean >/dev/null 2>&1 || true
npx hardhat compile --force

echo "[03] Deploy core"
DEPLOY_METRICS_FILE=${DEPLOY_METRICS_FILE:-metrics/results/deploy.ndjson}
DEP_ENV=$(DEPLOY_METRICS_FILE="$DEPLOY_METRICS_FILE" CRED_NAME="$CRED_NAME" MESSAGE_COUNT="$MESSAGE_COUNT" THRESHOLD="$THRESHOLD_ISSUER" TOTAL="$TOTAL" npx hardhat run --network localhost scripts/deploy_local.ts | sed -n 's/^export /export /p')
eval "$DEP_ENV"
export ETH_WS=ws://127.0.0.1:${ANVIL_PORT}
export CHAIN_ID=31337
# Write/refresh .runtime.env (verify vars will be added after step 04)
cat > .runtime.env <<EOF
ETH_WS=$ETH_WS
CHAIN_ID=$CHAIN_ID
REQ_CONTRACT=$REQ_CONTRACT
REGISTRY_CONTRACT=${REGISTRY_CONTRACT}
PARAMS_CONTRACT=$PARAMS_CONTRACT
ACC_CONTRACT=$ACC_CONTRACT
CRED_NAME=$CRED_NAME
MESSAGE_COUNT=$MESSAGE_COUNT
THRESHOLD_ISSUER=$THRESHOLD_ISSUER
THRESHOLD_OPENER=$THRESHOLD_OPENER
TOTAL=$TOTAL
BASE_PORT=$BASE_PORT
SHARES_FILE=$SHARES_FILE
EOF
set -a; source .runtime.env; set +a

echo "[04] Deploy Verify contract"
VERIFY_ENV=$(DEPLOY_METRICS_FILE="$DEPLOY_METRICS_FILE" npx hardhat run --network localhost scripts/deploy_pok_verifiers.ts | sed -n 's/^export /export /p')
eval "$VERIFY_ENV"
# Append verify var
{
  echo "VERIFY_CONTRACT=${VERIFY_CONTRACT}"
} >> .runtime.env

echo "[05] Allowlist issuers & set multiaddrs in Params"
PARAMS_CONTRACT="$PARAMS_CONTRACT" THRESHOLD_ISSUER="$THRESHOLD_ISSUER" THRESHOLD_OPENER="$THRESHOLD_OPENER" BASE_PORT="$BASE_PORT" npx hardhat run --network localhost scripts/allowlist_and_set_multiaddrs.ts

echo "[06] Run TTP (sets g1/h0/H, g2base, pkG2, and writes shares)"
# Use Anvil's first default private key (0xf39f...)
export OWNER_PK=${OWNER_PK:-0xac0974bec36b3...} # placeholder, will set exact next line
export OWNER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
eval "$(SHARES_FILE=$SHARES_FILE cargo run --features mpc --bin ttp | sed -n 's/^export /export /p')"



echo "[07] Done"
