## tbbsplus_rust — Build, Run, and Test

End-to-end demo of threshold BBS+ credential issuance and presentation with opener/accumulator services and metrics.

### Prerequisites

- Rust stable (cargo) --link provide
- Node.js v22 -- ensure that terminal defaults to this version on a new instance.
- Hardhat CLI (`npx hardhat` installed via devDependencies)
- Anvil (from Foundry) for a local Prague hardfork EVM
- https://getfoundry.sh/introduction/installation/

### Install dependencies

```bash
npm ci
```

### Start local chain (Anvil, Prague)

```bash
anvil --hardfork prague -p 8545
```

### Build Rust

```bash
cargo build -q --bins --features mpc
```

### Solidity/Hardhat configuration

- Compiler version: 0.8.27
- EVM version: prague
- viaIR: true
  Defined in `hardhat.config.ts`.

### One-time setup and deploy

The setup script compiles and deploys contracts, wires addresses, and writes a runtime file used by all binaries and scripts.
Also use chmod +x to make the scripts executable.


```bash
# From repo root
bash scripts/01_ttp_setup.sh THRESHOLD=3 TOTAL=3 CRED_NAME=ANON_CRED MESSAGE_COUNT=5

# Load exported environment for the current shell
set -a; source .runtime.env; set +a
```

This creates/refreshes:

- `.runtime.env` with `ETH_WS`, `CHAIN_ID`, and contract addresses like `REQ_CONTRACT`, `REGISTRY_CONTRACT`, `PARAMS_CONTRACT`, `ACC_CONTRACT`, `VERIFY_CONTRACT`.
- `.runtime.shares.json` and other runtime artifacts.

Note: `.runtime*` and `metrics/results/*` are git-ignored; they will not be committed.

### Run services (manual windows)

Open separate shells:

```bash
# 1) Issuers (t distinct processes)
bash scripts/02_start_issuers.sh

# 2) Opener aggregator
bash scripts/03_start_opener_aggregator.sh

# 3) Threshold openers (t processes)
bash scripts/04_start_threshold_openers.sh

# 4) Service provider (auto open/revoke defaults to true)
SP_AUTO_OPEN=true SP_AUTO_REVOKE=true bash scripts/06_run_service_provider.sh

# 5) Client (user) — sends request, waits confirm, records metrics
bash scripts/05_run_user.sh
```

Before running any Rust binary directly in your own shells, ensure the runtime is loaded:

```bash
set -a; source .runtime.env; set +a
# Optional: enable metrics logging across all processes
# export METRICS=1
```

### Orchestrated multi-window run

To launch issuers, aggregator, openers, client, and service provider in one go, the helper script requires `gnome-terminal` and opens one window per component. If `gnome-terminal` is not installed, the script exits without running.

```bash
# Optional: enable metrics for all launched processes
# export METRICS=1
bash scripts/07_run_all.sh
```

-- Wait for a minute before launching any CredRequest from client if you ran the ./07_run_all.sh script.

### Metrics

When `METRICS=1` is set (exported in your shell), components write NDJSON to `metrics/results/`. These files are ignored by git.

Rust binaries to summarize metrics (examples):

```bash
# Issuance: average gas (request + issuers) and E2E confirm time
cargo run -q --bin issuance_metrics -- \
  --issuer metrics/results/issuer_*.ndjson \
  --client metrics/results/client.ndjson

# Presentation: averages from client.ndjson
cargo run -q --bin presentation_metrics --

# Accumulator register info (aggregator .ndjson)
cargo run -q --bin acc_register_info_metrics --

# Opening/revocation averages (SP + aggregator)
cargo run -q --bin sp_agg_open_revoke --

# Deployment gas averages (from deploy.ndjson and JSON summaries if present)
cargo run -q --bin deploy_gas_metrics --
```

### Hardhat quick checks

```bash
# Compile contracts (evm=prague, viaIR enabled)
npx hardhat compile



```

### Common environment variables

- `THRESHOLD_ISSUER`, `THRESHOLD_OPENER`, `TOTAL` — committee sizes
- `CRED_NAME`, `MESSAGE_COUNT` — credential configuration
- `BASE_PORT`, `OPENERS_BASE_PORT` — service base TCP ports
- `SP_AUTO_OPEN`, `SP_AUTO_REVOKE` — default `true` in service provider

### Troubleshooting

- Ensure Anvil is running with `--hardfork prague` on the expected port before `01_ttp_setup.sh`.
- If a script reports missing `.runtime.env`, re-run setup and re-source the file in the same shell: `set -a; source .runtime.env; set +a`.
- `scripts/07_run_all.sh` does not override env; it relies on `.runtime.env` and your shell.
- Ensure `gnome-terminal` is installed and on PATH; otherwise, use the manual run section.

### Repo hygiene (.gitignore highlights)

- Runtime/state artifacts `.runtime*` are ignored.
- Contract build products `artifacts/`, `typechain-types/` are ignored.
- Metrics outputs under `metrics/results/` and `metrics/**/*.ndjson` are ignored.

### What this demo covers

- Threshold credential issuance on-chain (client request with PoK → issuer shares → on-chain aggregation → client confirm).
- Opener aggregator and threshold openers services (for accumulator and presentation flows).
- Summarizable metrics for deployment, issuance, opening/revocation, and presentation.
