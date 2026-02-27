# Handoff — TBBS+ Rust Project State

**Date**: 2026-02-26
**Branch**: `master`
**Latest commit**: `358d36a` Remove synthetic benchmark_batching binary
**Uncommitted**: NDJSON metrics added to `request_aggregator.rs` and `presentation_aggregator.rs` (53 lines, builds clean)

---

## What Was Completed (Recent Sessions)

### 1. V-chain Serialized Addition (commit 17d8391)
- `opener_aggregator.rs`: Added `add_queue: VecDeque<(u64, U256)>` + `add_in_progress: bool` to serialize `addMember`/`addMembers` calls so each waits for the previous to confirm before sending next
- Prevents nonce collisions when multiple open-result batches trigger membership additions in quick succession
- Also includes batch verification fixes and opener refactors in same commit

### 2. Batch Commitment PoK Verification
- `contracts/BatchCommitmentPokVerify.sol`: Library using random linear combination (RLC) to collapse N Schnorr PoK verifications into a single batched check via EIP-2537 BLS12-381 precompiles
- `contracts/RequestCredential.sol`: `batchBroadcastSigReqBBSPlusVerified()` at line 99 — batch entry point using the library
- `src/orchestration/batching.rs`: `pack_batch_request_input()` packs N `RequestData` into the 13-tuple expected by the contract

### 3. Gas Metrics Instrumentation (current uncommitted work)
- **Already had metrics**: `issuer_onchain.rs`, `opener_aggregator.rs` (full NDJSON)
- **Just added metrics to**: `request_aggregator.rs`, `presentation_aggregator.rs`
- Pattern: `METRICS=1` env var enables it, `METRICS_FILE` overrides output path
- Default output: `metrics/results/<binary>.ndjson`
- Each line is a JSON object with: scenario, batch_size, gasUsed, perUserGas, effectiveGasPrice, costWei, hash

### 4. Removed benchmark_batching.rs (commit 358d36a)
- User explicitly rejected the synthetic benchmark approach — doesn't test real flows
- Deleted `src/bin/benchmark_batching.rs` and its `Cargo.toml` entry

---

## Metrics Instrumentation Status

| Binary | Transactions Instrumented | NDJSON Output |
|--------|--------------------------|---------------|
| `issuer_onchain.rs` | submitShare, submitShareBatch, confirmBatchRandomized | YES |
| `opener_aggregator.rs` | publishOpenResult, deleteMember, addMember, addMembers | YES |
| `request_aggregator.rs` | batchBroadcastSigReqBBSPlusVerified | YES (just added) |
| `presentation_aggregator.rs` | verifyPresentationBatch | YES (just added) |

**Usage**: Set `METRICS=1` before running any binary. All results go to `metrics/results/`.

---

## Key Architecture

### Binaries (src/bin/)
| Binary | Feature Flag | Purpose |
|--------|-------------|---------|
| `client` | `mpc` | End-user CLI: request credential, present, etc. |
| `issuer_onchain.rs` | `mpc` | Threshold issuer node (DKG + credential signing shares) |
| `opener_threshold.rs` | `mpc` | Threshold opener node (decryption share contribution) |
| `opener_aggregator.rs` | `mpc` | Opener aggregator: collects shares, publishes results, manages accumulator |
| `request_aggregator.rs` | — | Batches credential requests, submits batch PoK verification tx |
| `presentation_aggregator.rs` | — | Batches presentations, submits batch verification tx |
| `ttp.rs` | — | Trusted third party (key generation, setup) |
| `service_provider.rs` | — | Service provider: listens for presentations |
| `cred_status.rs` | — | Credential status checker |
| `export_pok_json.rs` | — | Export PoK data as JSON |

### Smart Contracts (contracts/)
| Contract | Purpose |
|----------|---------|
| `RequestCredential.sol` | Single + batch credential request with PoK verification |
| `BatchCommitmentPokVerify.sol` | Batched Schnorr PoK via RLC + EIP-2537 precompiles |
| `CommitmentPokVerify.sol` | Single commitment PoK verification |
| `BatchVerifyWrapper.sol` | Batch presentation verification |
| `CredentialRegistry.sol` | Registry linking requests to credentials |
| `Params.sol` | On-chain parameters (batch sizes, credential configs) |
| `Accumulator.sol` | Dynamic universal accumulator for revocation |

### Library Modules (src/orchestration/)
| Module | Purpose |
|--------|---------|
| `batching.rs` | `RequestData`, `PresentationData`, `consume_batch_if_ready`, `pack_batch_input`, `pack_batch_request_input` |
| `chain/clients.rs` | `ParamsClient`, `BatchVerifyClient`, contract wrappers |
| `crypto/pok.rs` | `build_commitment_pok()`, `decode_commitment_pok_for_onchain()` |
| `crypto/threshold.rs` | Threshold BBS+ signing, DKG integration |

### Local Crypto Crates (crypto/)
`bbs_plus`, `schnorr_pok`, `dock_crypto_utils`, `secret_sharing_and_dkg`, `proof_system`, `legogroth16`, `oblivious_transfer`, `vb_accumulator`, `short_group_sig`, `test_utils`

---

## Next Tasks / Open Items

1. **Commit the metrics changes** — `request_aggregator.rs` and `presentation_aggregator.rs` have uncommitted NDJSON metrics additions (build-verified)

2. **Multi-user integration testbench** — Run the full flow (request → issue → present → open → revoke) with multiple concurrent users to generate real gas metrics under realistic conditions

3. **Presentation batch gas benchmarking** — With `METRICS=1`, run `presentation_aggregator` against varying batch sizes to measure per-user gas scaling for `verifyPresentationBatch`

4. **Request batch gas benchmarking** — Same for `request_aggregator` with `batchBroadcastSigReqBBSPlusVerified`

5. **Metrics analysis tooling** — Consider a script to aggregate the NDJSON files into summary tables (min/max/avg gas per scenario per batch size)

6. **Service provider instrumentation** — `service_provider.rs` may also benefit from metrics if it performs on-chain operations (needs investigation)

---

## Environment Notes
- Default chain: Hardhat local (`127.0.0.1:8545`, chain ID 31337)
- Default deployer PK: `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` (Hardhat account #0)
- Build with `--features mpc` for binaries that need libp2p networking
- `.env` file loaded via `dotenvy::dotenv()` in all binaries
