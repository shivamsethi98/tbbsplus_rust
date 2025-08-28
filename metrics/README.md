# Metrics Suite

What/why: Collect wall-time and gas metrics for credential lifecycle flows on local Anvil and Sepolia.

Setup
- Export RPC and contracts in `.runtime.env` and source it.
- Optional: `ETHERSCAN_API_KEY=...` to record oracle gas on Sepolia/Mainnet.

Utilities
- `utils/env.ts`: loads provider/signers from env, reads `.runtime.env`.
- `utils/measure.ts`: wraps tx sending; records wallMs, gasUsed, effectiveGasPrice, costWei; optionally queries Etherscan gas oracle.
- `utils/events.ts`: small event waiters with timeout.

Scenarios
- `scenarios/deploy_gas.ts`: per-contract deploy gas/time.
- `scenarios/verify_cred.ts`: confirmCredential gas/time (local only; reverts on Sepolia).
- `scenarios/register_info.ts`: setDelta/publishWitness gas/time.
- `scenarios/registration_full.ts`: combines verifyCred+setDelta+publishWitness; sums wallMs.
- `scenarios/observe_*.ts`: NDJSON observers for issuance/opening/presentation/revocation.
- `scenarios/present_cred.ts`: sends VerifyWrapper presentation using prebuilt calldata.
- `scenarios/sweep_openers.ts`: registration timing across k=t=n; emits JSON and CSV.
- `scenarios/sweep_param_runner.ts`: orchestrates per-k end-to-end runs with observers and client.
- `scenarios/summarize.ts`: aggregates NDJSON/JSON into CSV summaries.
- `scenarios/set_service_provider.ts`, `trigger_opening.ts`, `trigger_revocation.ts`: helpers for opening/revocation coverage.

Off-chain hooks
- Client logs commitment PoK and issuance E2E times when `METRICS=1`.
- `opener_threshold` logs compute_decrypt_share and reconstruct timings.
- `opener_aggregator` logs open_reconstruct, acc_add and acc_delete timings.

Outputs
- JSON under `metrics/results/<name>.<chainId>.<ts>.json`.
- NDJSON for observers.

Config example
See `metrics/config.example.json` for `name`, `t`, `n`, `messageCount`, `repetitions`.

Sepolia notes
- Pairing/MSM precompiles may not be available for all ops; presentation/confirm may revert. In that case, use observers and off-chain metrics; on-chain gas available for non-precompile calls.

Quick start (local Anvil)
1) Start Anvil (Prague):
```bash
anvil --hardfork prague
```
2) Build Rust:
```bash
cargo build -q --bins --features mpc
```
3) Deploy and setup:
```bash
scripts/01_ttp_setup.sh THRESHOLD=3 TOTAL=3 CRED_NAME=ANON_CRED MESSAGE_COUNT=5
set -a; source .runtime.env; set +a
npx hardhat run metrics/scenarios/set_service_provider.ts
```
4) Start observers (in background terminals):
```bash
npx hardhat run metrics/scenarios/observe_issuance.ts &
npx hardhat run metrics/scenarios/observe_opening.ts &
npx hardhat run metrics/scenarios/observe_revocation.ts &
npx hardhat run metrics/scenarios/observe_presentation.ts &
```
5) Start issuers, then send a client request (captures NDJSON):
```bash
scripts/02_start_issuers.sh &
METRICS=1 METRICS_FILE=metrics/results/client.ndjson scripts/05_run_user.sh

```
7) Per-tx gas/time (optional):
```bash
npx hardhat run metrics/scenarios/verify_cred.ts
npx hardhat run metrics/scenarios/register_info.ts
npx hardhat run metrics/scenarios/registration_full.ts
```
8) Summarize outputs:
```bash
npx hardhat run metrics/scenarios/summarize.ts -- metrics/results
```

Sweep runs
- Full sweep with observers and client per k:
```bash
npx hardhat run metrics/scenarios/sweep_param_runner.ts -- --sweep=2..5 --name=ANON_CRED
```
- Registration-only sweep (no orchestration):
```bash
npx hardhat run metrics/scenarios/sweep_openers.ts -- --sweep=2..5 --name=ANON_CRED --rpc=$ETH_WS
```

Sepolia
```bash
export SEPOLIA_URL=... CHAIN_ID=11155111 ETHERSCAN_API_KEY=...
set -a; source .runtime.env; set +a
# use observers + register_info; confirm/presentation may revert
npx hardhat run metrics/scenarios/observe_issuance.ts
```


