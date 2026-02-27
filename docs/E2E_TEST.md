# E2E Batched Flow Test & Benchmarking Guide

This document covers the full credential lifecycle (request → issuance → presentation → opening) with **persistent aggregators** and configurable batch sizes, plus instructions for running automated gas + timing benchmarks.

---

## Architecture Overview

The credential request batch flow consists of 4 sequential on-chain transactions:

| # | Transaction | Binary | What It Does |
|---|-------------|--------|--------------|
| 1 | `batchBroadcastSigReqBBSPlusVerified` | request_aggregator | Batched Schnorr PoK verification of N user commitment proofs |
| 2 | `submitShareBatch` × T issuers | issuer_onchain | Each issuer submits N partial BBS+ shares; last issuer triggers aggregation |
| 3 | `confirmBatchRandomized` | issuer_onchain (leader) | Batched pairing verification of N aggregated credentials + publishes to accumulator mapping |
| 4 | `addMembers` | opener_aggregator | Accumulator delta update — single tx for the whole batch |

The presentation flow then adds:

| # | Transaction | Binary | What It Does |
|---|-------------|--------|--------------|
| 5 | `verifyPresentationBatch` | presentation_aggregator | Batched BBS+ PoK + accumulator membership verification |
| 6 | `requestOpen` × N | service_provider | Requests decryption opening for each user |

Every transaction is instrumented with `gasUsed`, `perUserGas`, and `ms` timing in NDJSON format.

---

## Prerequisites

- `anvil` (foundry) and `cast` installed
- `cargo build --features mpc,interactive` succeeds
- `npx hardhat compile` succeeds
- Node.js 18+ (`npx hardhat`)

---

## Part 1: Manual E2E Test (batch size = 2)

### T1 — Anvil

```bash
anvil --hardfork pragueEOF --gas-limit 300000000 -p 8545
```

### T2 — Deploy contracts & generate keys

```bash
cd /home/quanta/fast_ssd/codebases/tbbsplus_rust
BATCH_SIZE_REQ=2 BATCH_SIZE_PRES=2 bash scripts/01_ttp_setup.sh
source .runtime.env
```

### T3 — Start issuers

```bash
source .runtime.env
BATCH_SIZE=2 BATCH_TIMEOUT_MS=30000 bash scripts/02_start_issuers.sh
```

### T4 — Start opener aggregator + threshold openers

```bash
source .runtime.env
bash scripts/03_start_opener_aggregator.sh
source .runtime.env
bash scripts/04_start_threshold_openers.sh
```

### T5a — Start request aggregator

```bash
source .runtime.env
mkdir -p metrics/results
METRICS=1 METRICS_FILE=metrics/results/request_aggregator.ndjson \
  RUST_LOG=info \
  cargo run --features mpc --bin request_aggregator
```

### T5b — Start presentation aggregator

```bash
source .runtime.env
METRICS=1 METRICS_FILE=metrics/results/presentation_aggregator.ndjson \
  RUST_LOG=info \
  cargo run --features mpc --bin presentation_aggregator
```

### T5c — Start service provider

```bash
source .runtime.env
METRICS=1 METRICS_FILE=metrics/results/service_provider.ndjson \
  cargo run --bin service_provider
```

All three poll every 2s. Metrics are written to `metrics/results/`.

### T6 — User 1: credential request (exports proof to batch JSON)

```bash
source .runtime.env
BATCH_REQUEST_EXPORT=1 BATCH_REQUEST_FILE=batch_request.json \
  MNEMONIC_INDEX=1 bash scripts/run_client.sh request
```

Writes 1 entry to `batch_request.json`. Aggregator sees 1 < 2, waits.

### T7 — User 2: credential request

```bash
source .runtime.env
BATCH_REQUEST_EXPORT=1 BATCH_REQUEST_FILE=batch_request.json \
  MNEMONIC_INDEX=2 bash scripts/run_client.sh request
```

Writes 2nd entry. **request_aggregator** auto-submits the batch tx within 2s.
Issuers see `SigReqBBSPlusVerified` events and begin threshold MPC signing.

### T8 — User 1: fetch credential + witness sync + export presentation

After issuers finish (watch T3 for `confirmBatchRandomized ok` and T4 for `addition verified`):

```bash
source .runtime.env
AUTO_WITNESS_SYNC=1 BATCH_PRESENTATION_EXPORT=1 AUTO_REVEALED_IDX=0 \
  BATCH_PRESENTATION_FILE=batch_presentation.json \
  MNEMONIC_INDEX=1 FEATURES=mpc,interactive bash scripts/run_client.sh request --wait
```

### T9 — User 2: fetch credential + witness sync + export presentation

```bash
source .runtime.env
AUTO_WITNESS_SYNC=1 BATCH_PRESENTATION_EXPORT=1 AUTO_REVEALED_IDX=0 \
  BATCH_PRESENTATION_FILE=batch_presentation.json \
  MNEMONIC_INDEX=2 FEATURES=mpc,interactive bash scripts/run_client.sh request --wait
```

Once both presentations land in `batch_presentation.json`, **presentation_aggregator** auto-submits.

### Expected log sequences

| Step | Terminal | Expected |
|------|----------|----------|
| Request batch fires | T5a | `batch ready - packing and submitting... batch request verified (2 users)` |
| Issuers process | T3 | `SigReqBBSPlusVerified` per user → `submitShareBatch ok` → `confirmBatchRandomized ok` |
| Accumulator update | T4 | `addition verified for sid=...` → `acc_addMembers_batch done: 2 member(s) added` |
| Users get credential | T8/T9 | `[auto] credential confirmed` → `[auto-witness] membership OK` → `[auto-batch] presentation exported` |
| Presentation batch fires | T5b | `batch ready... batch presentation verified (2 users)` |
| Opening | T5c | `requestOpen tx status=OK` per user |

### Verification checklist

- [ ] `batch_request.json` had 2 entries, was consumed by request_aggregator
- [ ] Both users received `Confirmed` event and fetched aggregated signatures
- [ ] Witness sync reports `membership OK` for both users
- [ ] `batch_presentation.json` had 2 entries, was consumed by presentation_aggregator
- [ ] Service provider emitted `requestOpen` txs
- [ ] No errors in any terminal

---

## Part 2: Automated Benchmarking

### Benchmark scripts

Three scripts automate gas + timing measurements across batch sizes:

| Script | What it measures |
|--------|-----------------|
| `scripts/bench_issuance_e2e.sh` | Full issuance flow: PoK verification → share submission → batch credential verification → accumulator update |
| `scripts/bench_presentation_e2e.sh` | Presentation flow: witness sync → proof build → batch verification → opening |
| `scripts/bench_full.sh` | Runs both above back-to-back, then produces summary tables |

### Quick start (issuance benchmark only)

```bash
# T1: Anvil
anvil --hardfork pragueEOF --gas-limit 300000000 -p 8545

# T2: Deploy + start issuers
BATCH_SIZE_REQ=1 BATCH_SIZE_PRES=1 bash scripts/01_ttp_setup.sh
source .runtime.env
bash scripts/02_start_issuers.sh    # start once — issuers poll batch_size from chain

# T3: Start opener aggregator + threshold openers
bash scripts/03_start_opener_aggregator.sh
source .runtime.env
bash scripts/04_start_threshold_openers.sh

# T5a: request_aggregator  (own terminal)
source .runtime.env
RUST_LOG=info METRICS=1 cargo run --features mpc --bin request_aggregator

# T5b: presentation_aggregator  (own terminal — needed for bench_full / bench_presentation)
source .runtime.env
RUST_LOG=info METRICS=1 cargo run --features mpc --bin presentation_aggregator

# T5c: service_provider  (own terminal — needed for bench_full / bench_presentation)
source .runtime.env
RUST_LOG=info METRICS=1 cargo run --features mpc --bin service_provider

# T6: Run issuance benchmark
BENCH_SIZES="1 2 4 8 16 32 64 128" bash scripts/bench_issuance_e2e.sh
```

### Full benchmark (issuance + presentation)

```bash
# Same setup as above (T1–T5c), then:
BENCH_SIZES="1 2 4 8 16 32 64 128" bash scripts/bench_full.sh
```

### Summary tables

After benchmarks complete, produce Markdown tables:

```bash
cargo run --bin bench_summary -- \
  --req    metrics/results/request_aggregator_n*.ndjson \
  --issuer metrics/results/issuer_*_n*.ndjson \
  --opener metrics/results/aggregator_n*.ndjson \
  --sp     metrics/results/service_provider_n*.ndjson \
  --pres   metrics/results/presentation_aggregator_n*.ndjson \
  --client metrics/results/client_n*.ndjson metrics/results/client_pres_n*.ndjson
```

This produces 4 tables:

1. **Per-User Gas Cost** — amortised gas for each tx step + `issuanceSum` and `presSum` totals
2. **On-Chain Tx Timing (ms)** — wall-clock per tx step + issuance/presentation totals
3. **Issuance E2E Summary** — per-user amortised: total gas, server-side ms sum, client-perceived `issuance_e2e_confirmed` ms
4. **Client-Side Timing** — per-user avg: `issuance_e2e`, `witness_sync`, `pres_build` ms

### NDJSON metrics reference

All metrics are appended as one JSON object per line to the `METRICS_FILE` path.

| Binary | Scenario | Key fields |
|--------|----------|------------|
| request_aggregator | `batchBroadcastSigReqBBSPlusVerified` | batch_size, gasUsed, perUserGas, ms |
| issuer_onchain | `submitShareBatch` | batch_size, idx, gasUsed, perUserGas, ms |
| issuer_onchain | `confirmBatchRandomized` | batch_size, idx, gasUsed, perUserGas, ms |
| opener_aggregator | `acc_add_verify_sum` | sid, threshold, ms (off-chain pairing verification) |
| opener_aggregator | `acc_addMembers_batch` | batch_size, gasUsedTotal, perUserGas, ms |
| presentation_aggregator | `verifyPresentationBatch` | batch_size, gasUsed, perUserGas, ms |
| service_provider | `requestOpen` | user_idx, gasUsed, ms |
| client | `issuance_e2e_confirmed` | userId, ms (PoK build → Confirmed event) |
| client | `witness_sync` | userId, ms, events_replayed |
| client | `presentation_build` | userId, ms |

---

## Notes

- `scripts/run_client.sh` derives `CLIENT_PK` from `MNEMONIC_INDEX` via `cast wallet private-key`; indices 1..N correspond to Anvil accounts #1..#N (account #0 is the deployer/owner)
- `FEATURES=mpc,interactive` is needed for witness sync + presentation export; plain `request` mode only needs `mpc`
- `AGG_POLL_SECS` (default 2) controls how often aggregators check batch files
- `AGG_GAS_LIMIT` (default 200000000) can be raised for very large batches
- Batch sizes are stored on-chain in `Params.sol`; update post-deploy via `scripts/update_batch_sizes.ts` without restarting any processes
- Issuers poll `getBatchSizesByName` from on-chain `Params` each event-loop iteration (when idle), so they pick up new batch sizes automatically — no restart needed
- The `confirmBatchRandomized` tx performs a batched random-linear-combination pairing check (single 2-pair check for all N credentials), making it significantly cheaper per user as N grows
- The accumulator delta update (`addMembers`) is a single tx regardless of batch size — the opener_aggregator buffers additions and flushes when `BATCH_ADD_SIZE` is reached or `BATCH_ADD_TIMEOUT_MS` expires
