#!/usr/bin/env bash
set -euo pipefail

# Starts local chain, deploys contracts, allowlists issuers in Params, and prints env exports.

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$ROOT_DIR"

if ! command -v anvil >/dev/null 2>&1; then
  echo "anvil not found. Install foundry (https://book.getfoundry.sh/)." >&2
  exit 1
fi

ANVIL_PORT=${ANVIL_PORT:-8545}
ANVIL_LOG="anvil.log"

echo "Starting anvil on :$ANVIL_PORT..."
anvil --port "$ANVIL_PORT" --silent >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null || true' EXIT
sleep 1

echo "Installing deps and compiling contracts..."
npm ci >/dev/null 2>&1 || npm install
npx hardhat clean >/dev/null 2>&1 || true
npx hardhat compile --force

echo "Deploying contracts..."
DEPLOY_OUT=$(CRED_NAME=${CRED_NAME:-ANON_CRED} MESSAGE_COUNT=${MESSAGE_COUNT:-5} THRESHOLD=${THRESHOLD:-3} TOTAL=${TOTAL:-4} npx hardhat run --network localhost scripts/deploy_local.ts)
echo "$DEPLOY_OUT"
eval "$DEPLOY_OUT"

echo "Allowlisting 3 issuers (accounts[1..3]) in Params..."
cat > scripts/allowlist_issuers.ts <<'TS'
import { ethers } from "hardhat";
async function main() {
  const signers = await ethers.getSigners();
  const owner = signers[0];
  const paramsAddr = process.env.PARAMS_CONTRACT!;
  const Params = await ethers.getContractFactory("Params");
  const params = Params.attach(paramsAddr).connect(owner) as any;
  for (let i = 1; i <= 3; i++) {
    const issuer = signers[i].address;
    await (await params.setIssuer(issuer, i, true)).wait();
    console.log(`Issuer ${i}: ${issuer}`);
  }
}
main().then(()=>process.exit(0)).catch((e)=>{console.error(e);process.exit(1)});
TS

PARAMS_CONTRACT="$PARAMS_CONTRACT" npx hardhat run --network localhost scripts/allowlist_issuers.ts

echo "Writing .env.local ..."
cat > .env.local <<ENV
ETH_WS=ws://127.0.0.1:${ANVIL_PORT}
CHAIN_ID=31337
REQ_CONTRACT=${REQ_CONTRACT}
RELAY_CONTRACT=${RELAY_CONTRACT}
PARAMS_CONTRACT=${PARAMS_CONTRACT}
CRED_NAME=${CRED_NAME:-ANON_CRED}
MESSAGE_COUNT=${MESSAGE_COUNT:-5}
THRESHOLD=${THRESHOLD:-3}
TOTAL=${TOTAL:-4}
BASE_PORT=${BASE_PORT:-9900}
ENV

echo "Done. Source .env.local and run issuer nodes."
echo "Example:"
echo "  export ISSUER_PK=<hex_privkey_of_account_1> PID=1; cargo run --features mpc --bin issuer_onchain"
echo "  export ISSUER_PK=<hex_privkey_of_account_2> PID=2; cargo run --features mpc --bin issuer_onchain"
echo "  export ISSUER_PK=<hex_privkey_of_account_3> PID=3; cargo run --features mpc --bin issuer_onchain"
