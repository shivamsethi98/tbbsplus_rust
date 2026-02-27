# RTBBS+ Project Handoff Document

> **Date:** 23 February 2026  
> **Build status:** ✅ Rust compiles (`cargo check --features mpc`), ✅ Solidity compiles (`npx hardhat compile`)  
> **Workspace root:** `/home/quanta/fast_ssd/codebases/tbbsplus_rust`

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Tech Stack & Toolchain](#2-tech-stack--toolchain)
3. [Repository Layout](#3-repository-layout)
4. [Architecture Overview](#4-architecture-overview)
5. [Solidity Contracts (Detailed)](#5-solidity-contracts-detailed)
6. [Rust Codebase (Detailed)](#6-rust-codebase-detailed)
7. [Batching Implementation (Phases A–F)](#7-batching-implementation-phases-af)
8. [Environment Variables Reference](#8-environment-variables-reference)
9. [Build & Run Instructions](#9-build--run-instructions)
10. [Scripts Reference](#10-scripts-reference)
11. [Documentation Artifacts](#11-documentation-artifacts)
12. [Known State & Open Items](#12-known-state--open-items)
13. [Key Design Decisions](#13-key-design-decisions)

---

## 1. Project Overview

RTBBS+ is a **threshold BBS+ anonymous credential system** deployed on Ethereum (Prague hardfork, BLS12-381 precompiles via EIP-2537). It implements the full lifecycle:

1. **Credential Request** — User commits to attributes, proves knowledge (Schnorr PoK), broadcasts on-chain
2. **Threshold Issuance** — `t`-of-`n` issuers run MPC (Oblivious Transfer-based) to produce partial BBS+ signatures, submitted on-chain, aggregated by smart contract
3. **Credential Presentation** — User randomizes credential, encrypts identity point for threshold opening, proves membership in accumulator, proves knowledge of signature — all verified on-chain
4. **Threshold Opening** — Openers decrypt ElGamal ciphertext to recover user identity if needed
5. **Accumulator Management** — Dynamic threshold accumulator (DTA) for revocation

The **primary body of work done in this session** was implementing **six batching phases (A–F)** that reduce on-chain gas costs by orders of magnitude when processing multiple users simultaneously. These changes span both the Solidity contracts and the Rust orchestration layer.

### What the paper is

The paper is "RTBBS+: Real-Time Threshold BBS+ for Privacy-Preserving Credential Systems" — a threshold anonymous credential scheme with on-chain verification, using BLS12-381 pairings. The batching optimizations use random linear combination (Schwartz-Zippel soundness) to collapse N verification equations into single MSM + pairing calls.

---

## 2. Tech Stack & Toolchain

| Component | Version / Config |
|-----------|-----------------|
| **Rust** | Stable edition 2021, Cargo workspace |
| **Solidity** | 0.8.27 (Hardhat), 0.8.24 (Foundry) |
| **EVM** | Prague hardfork (EIP-2537 BLS precompiles) |
| **Hardhat** | viaIR=true, optimizer runs=200, evmVersion=prague |
| **Local chain** | Anvil: `anvil --hardfork pragueEOF --gas-limit 300000000 -p 8545` |
| **ethers-rs** | v2 with `abigen`, `ws`, `rustls` features |
| **libp2p** | v0.54 (gossipsub, mdns, kad, request-response) — behind `mpc` feature flag |
| **Crypto lib** | Local fork of Dock crypto (`crypto/` directory) — BBS+, accumulators, Schnorr, OT, DKG, etc. |
| **Node.js** | 22+ with npm |
| **Chain ID** | 31337 (localhost Anvil) |

### Feature flags

```toml
[features]
mpc = ["libp2p"]      # Required for all networked binaries (issuers, client, openers)
interactive = []       # Unused currently
```

Most binaries require `--features mpc`. The `ttp` and utility binaries don't.

---

## 3. Repository Layout

```
tbbsplus_rust/
├── Cargo.toml                    # Workspace root — all [[bin]] targets defined here
├── hardhat.config.ts             # Solidity compiler config (0.8.27, viaIR, prague)
├── foundry.toml                  # Foundry config (0.8.24, parallel build)
├── package.json                  # Node deps (hardhat, ethers, typechain)
├── plan.md                       # Implementation plan — all 6 phases marked DONE
├── README.md                     # Build/run instructions
│
├── contracts/                    # Solidity source (2,519 lines total)
│   ├── BatchVerify.sol           # [NEW] Batched presentation verification (480 lines)
│   ├── BatchCommitmentPokVerify.sol  # [NEW] Batched commitment PoK library (83 lines)
│   ├── CredentialRegistry.sol    # [MODIFIED] +submitShareBatch, +confirmBatchRandomized (515 lines)
│   ├── RequestCredential.sol     # [MODIFIED] +batchBroadcastSigReqBBSPlusVerified (155 lines)
│   ├── Accumulator.sol           # [MODIFIED] +addMembers (209 lines)
│   ├── Verify.sol                # [MODIFIED] +verifyBbsPairingBatch, +verifyAccPairingBatch (302 lines)
│   ├── BbsPlusPokVerify.sol      # BBS+ PoK verification library (160 lines)
│   ├── CommitmentPokVerify.sol   # Single commitment PoK verification (58 lines)
│   ├── VBAccPokVerify.sol        # Accumulator membership PoK (77 lines)
│   ├── Params.sol                # Credential parameter storage (282 lines)
│   └── lib/
│       ├── Fr.sol                # BLS12-381 scalar field arithmetic (43 lines)
│       └── Bls12381.sol          # Curve operations, precompile wrappers (155 lines)
│
├── src/
│   ├── lib.rs                    # `pub mod orchestration;`
│   ├── main.rs                   # Stub (3 lines)
│   ├── orchestration/
│   │   ├── mod.rs                # Module declarations (10 lines)
│   │   ├── batching.rs           # [NEW] PresentationData, RequestData, pack functions (457 lines)
│   │   ├── chain/
│   │   │   ├── clients.rs        # [MODIFIED] +BatchVerifyClient, +batch methods (226 lines)
│   │   │   ├── abi.rs            # ABI loading utilities
│   │   │   └── mod.rs
│   │   ├── crypto/
│   │   │   ├── pok.rs            # Commitment PoK construction (315 lines)
│   │   │   ├── commitment_pok.rs # Commitment PoK types
│   │   │   ├── encoding.rs       # Point encoding utilities
│   │   │   ├── seeds.rs          # Fiat-Shamir seed construction
│   │   │   ├── shares.rs         # Share handling
│   │   │   └── tests.rs
│   │   ├── mesh.rs               # libp2p mesh networking
│   │   ├── threshold_phases.rs   # MPC phase 1/2/3 orchestration
│   │   ├── onchain.rs            # On-chain transaction helpers
│   │   ├── persistence.rs        # File I/O for runtime state
│   │   ├── io/                   # I/O utilities
│   │   └── tests/
│   └── bin/
│       ├── presentation_aggregator.rs  # [NEW] Batched presentation submission (163 lines)
│       ├── request_aggregator.rs       # [NEW] Batched credential request submission (195 lines)
│       ├── benchmark_batching.rs       # [NEW] Gas benchmarking harness (928 lines)
│       ├── issuer_onchain.rs           # [MODIFIED] +batch manifest, +submitShareBatch (775 lines)
│       ├── opener_aggregator.rs        # [MODIFIED] +batch accumulator additions (644 lines)
│       ├── service_provider.rs         # [MODIFIED] +BatchPresentationVerified handler (454 lines)
│       ├── client/
│       │   ├── main.rs                 # [MODIFIED] +BATCH_REQUEST_EXPORT path (395 lines)
│       │   ├── ui.rs                   # [MODIFIED] +BATCH_PRESENTATION_EXPORT path (562 lines)
│       │   ├── session.rs              # Session management (103 lines)
│       │   ├── args.rs                 # CLI arg parsing (39 lines)
│       │   └── cli.rs                  # CLI helpers (25 lines)
│       ├── ttp.rs                      # Trusted third party setup (312 lines)
│       ├── opener_threshold.rs         # Threshold opener process (621 lines)
│       ├── cred_status.rs              # Credential status checker
│       └── export_pok_json.rs          # Export PoK as JSON
│
├── scripts/                      # Bash/TS deployment scripts
│   ├── 01_ttp_setup.sh           # Full setup: compile, deploy, configure
│   ├── 02_start_issuers.sh       # Launch t issuer processes
│   ├── 03_start_opener_aggregator.sh
│   ├── 04_start_threshold_openers.sh
│   ├── 05_run_user.sh / 05_run_users.sh
│   ├── 06_run_service_provider.sh
│   ├── 07_run_all.sh             # Orchestrated multi-window launch
│   ├── deploy_local.ts           # Contract deployment (Hardhat)
│   ├── deploy_pok_verifiers.ts   # PoK verifier deployment
│   └── allowlist_and_set_multiaddrs.ts
│
├── metrics/                      # Benchmarking infrastructure
│   ├── config.example.json
│   ├── results/                  # NDJSON output (git-ignored)
│   ├── scenarios/                # Metric aggregation binaries
│   └── utils/
│
├── artifacts/                    # Hardhat compiled output (ABI JSON)
├── cache_hardhat/
├── typechain-types/              # TypeScript contract bindings
├── crypto/                       # Local Dock crypto library fork (NOT modified)
└── target/                       # Rust build output
```

---

## 4. Architecture Overview

### Actors

| Actor | Binary | Network | Purpose |
|-------|--------|---------|---------|
| **User (Client)** | `client` | libp2p + chain | Requests credentials, presents them |
| **Issuer** (×n) | `issuer_onchain` | libp2p + chain | Runs MPC, submits partial signatures |
| **Opener Aggregator** | `opener_aggregator` | libp2p + chain | Coordinates threshold opening, manages accumulator |
| **Threshold Opener** (×n) | `opener_threshold` | libp2p | Partial ElGamal decryption |
| **Service Provider** | `service_provider` | chain | Verifies presentations, requests openings |
| **Presentation Aggregator** | `presentation_aggregator` | chain (HTTP) | Submits batch presentations |
| **Request Aggregator** | `request_aggregator` | chain (HTTP) | Submits batch credential requests |
| **TTP** | `ttp` | none | One-time setup: key generation, contract deployment |

### Communication

- **libp2p gossipsub** — MPC protocol messages between issuers; opener coordination
- **Ethereum chain** — All verification, credential storage, accumulator state
- **JSON files** — Batch export from clients → aggregator binaries (`batch_presentation.json`, `batch_request.json`)

### Lifecycle Flow

```
User → RequestCredential.broadcastSigReqBBSPlusVerified() → SigReqBBSPlusVerified event
                                                              ↓
Issuers (MPC Phase 1→2→3) → CredentialRegistry.submitShare() → aggregates → confirms
                                                              ↓
User → Accumulator.addMember() (via opener) → MemberAdded event
                                                              ↓
User → Verify.verifyPresentation() → PresentationVerified event → SP sees it
                                                              ↓
SP → Opener Aggregator → threshold_openers (partial decrypt) → recovered A → lookup userId
```

### Batched Flow (new)

```
N Users → export batch_presentation.json
                  ↓
presentation_aggregator → BatchVerify.verifyPresentationBatch() → BatchPresentationVerified event
                                                              ↓
SP handles event → requests open for each user in batch

N Users → export batch_request.json
                  ↓
request_aggregator → RequestCredential.batchBroadcastSigReqBBSPlusVerified()
                                                              ↓
N × SigReqBBSPlusVerified events → issuers pick up → batched MPC → submitShareBatch
                                                              ↓
batch leader → confirmBatchRandomized() → all N credentials verified in 1 pairing
                                                              ↓
opener_aggregator buffers → addMembers() → 1 SSTORE for N accumulator additions
```

---

## 5. Solidity Contracts (Detailed)

### 5.1 `contracts/lib/Fr.sol` (43 lines)

Library for BLS12-381 scalar field arithmetic.

```
FR_MOD = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

Functions: `add(a,b)`, `sub(a,b)`, `mul(a,b)`, `inv(a)` (via MODEXP precompile at 0x05).

### 5.2 `contracts/lib/Bls12381.sol` (155 lines)

Library wrapping EIP-2537 precompiles.

| Precompile | Address | Function |
|------------|---------|----------|
| G1ADD | 0x0b | `g1add(a, b) → bytes memory` |
| G1MSM | 0x0c | `g1msm(data) → bytes memory` (points+scalars concatenated) |
| G2ADD | 0x0d | `g2add(a, b)` |
| G2MSM | 0x0e | `g2msm(data)` |
| PAIRING | 0x0f | `pairing(data) → bool` (pairs of G1+G2, checks product=1) |

Also: `concatMSM(points[], scalars[])` helper, `negG1(p)` (negates y-coordinate over Fq).

### 5.3 `contracts/Params.sol` (282 lines)

Stores per-credential-name parameters:
- `g1`, `g2`, `h0` (generator/blinding bases)
- `H[]` (message bases, one per attribute slot)
- `X` (issuer public key in G2)
- `pkAcc` (accumulator public key in G2)
- `openerPk` (ElGamal public key in G1)
- `threshold`, `messageCount`
- `allowedIssuers[]` with index mapping

Key functions: `setParams()`, `getG1H0G2()`, `getH()`, `getThreshold()`, `allowIssuer()`, `setMultiaddr()`.

### 5.4 `contracts/CredentialRegistry.sol` (515 lines)

Core credential lifecycle management. Per-user storage: `shares[name][userId]` tracking `sum_R` (G1), `sum_u` (Fr), accumulated `e` and `s`, count, status (None/Pending/Unverified/Confirmed).

**Original functions:**
- `submitShare(name, userId, idx, R128, u, e, s)` — accumulate one issuer's partial credential
- `confirmCredential(name, userId)` — verify single credential via 2-pair pairing

**Batch additions (Phase B + C):**
- `submitShareBatch(name, userIds[], idx, R128concat, us[], es[], ss[])` — submit N shares in one tx. Internally loops `_accumulateShare` per user. Emits `BatchSharesAccepted`.
- `confirmBatchRandomized(name, userIds[])` — verify N credentials with one 2-pair pairing. Derives weights `δ_j = keccak256(seed || j) mod r` where `seed = keccak256(A_1 || ... || A_N || prevrandao)`. Builds `L = MSM({A_j}, {δ_j})`, `M = MSM({A_j}, {δ_j·e_j})`, `R = MSM({B_j}, {δ_j})`, checks `e(L, X) · e(M-R, g2) = 1`. Emits `BatchConfirmed`.

**Events added:** `BatchSharesAccepted(address indexed issuer, string indexed name, uint16 idx, uint256 count)`, `BatchConfirmed(string indexed name, uint256 count)`.

### 5.5 `contracts/RequestCredential.sol` (155 lines)

Handles credential request broadcasting.

**Original function:**
- `broadcastSigReqBBSPlusVerified(name, commitmentU, commitmentB, ...)` — verifies single commitment PoK, emits `SigReqBBSPlusVerified`.

**Batch addition (Phase D):**
- `batchBroadcastSigReqBBSPlusVerified(name, userAddrs[], commitmentUs[], commitmentBs[], h0, H[], hiddenIdx[], Ts[], challenges[], flatResponses[], allRevealedIdx[][], allRevealedVals[][], contexts[])` — calls `BatchCommitmentPokVerify.batchVerify()` once for all N users' commitment PoKs, then loops to record each user and emit individual `SigReqBBSPlusVerified` events (so issuers don't need to change their event listener).

**Key detail:** `userId = uint160(userAddrs[j])` since the aggregator calls on behalf of users.

### 5.6 `contracts/BatchCommitmentPokVerify.sol` (83 lines) — NEW

Library for batched Schnorr PoK verification.

**Single function:** `batchVerify(h0, H, hiddenIdx, commitments, Ts, challenges, flatResponses) → bool`

**Algorithm:**
1. Derive weights: `ρ_j = keccak256(j || T_j || C_j) mod r` (set to 1 if 0)
2. Aggregate responses: `aggResp[i] = Σ_j ρ_j · z_{i,j}` per base index
3. LHS: `MSM(bases, aggResp)` — one MSM of size `|bases|`
4. RHS_T: `MSM({T_j}, {ρ_j})` — one MSM of size N
5. RHS_C: `MSM({C_j}, {ρ_j · c_j})` — one MSM of size N
6. Check: `LHS == G1ADD(RHS_T, RHS_C)`

**Note:** Originally had custom errors (`BadPointLen`, etc.) but these were removed to avoid ABI duplicate conflicts with `CommitmentPokVerify.sol` when both are linked into `RequestCredential`. Uses `require` with string messages instead.

### 5.7 `contracts/BatchVerify.sol` (480 lines) — NEW

Full batched presentation verification. This is the largest and most complex contract addition.

**Struct** `BatchPresInput`:
```solidity
struct BatchPresInput {
    bytes   sigPts;     // B × 384 B (A', Ā, d per user)
    bytes   bbsT;       // B × 256 B (T1_bbs, T2_bbs per user)
    uint256[] bbsC;     // B challenges
    uint256[] bbsResp;  // B × R responses (R = 4 + numHidden)
    bytes   encPts;     // B × 384 B (T1_enc, T2_enc, T_enc per user)
    uint256[] encResp;  // B × 2 (resp_a3, resp_k)
    bytes   accPts;     // B × 384 B (A'_acc, Ā_acc, t_acc per user)
    uint256[] accC;     // B accumulator challenges
    uint256[] accResp;  // B × 2 (resp_r, resp_e)
    uint32[]  revIdx;   // shared revealed indices
    uint256[] revVals;  // shared revealed values
}
```

**Main function:** `verifyPresentationBatch(name, paramsAddr, accumulatorAddr, inp) → bool`

**Verification steps (all using random weights ρ_j derived from proof transcript):**
1. **BBS+ Schnorr Relation 1** — MSM of size `1 + 4B` (shared base h0, per-user A', Ā, d, T1_bbs)
2. **BBS+ Schnorr Relation 2** — MSM of size `U + 2 + 2B` (shared bases h_l, h0, c_m; per-user d, T2_bbs)
3. **Encryption Relation** — MSM of size `1 + 3B` (shared base ȳ; per-user A', T_enc, T2_enc)
4. **Accumulator Schnorr** — MSM of size `1 + 3B` (shared base Δ; per-user A'_acc, Ā_acc, t_acc)
5. **Combined 4-pair pairing** — aggregates BBS+ pairing (A*, Ā*) and accumulator pairing (L_acc, R_acc) into one `e(A*, X) · e(-Ā*, g2) · e(L_acc, pkAcc) · e(-R_acc, g2) = 1`

**Event:** `BatchPresentationVerified(string indexed name, uint256 batchSize, bytes T1s, bytes T2s)` — includes ElGamal ciphertext components for downstream opening.

### 5.8 `contracts/Verify.sol` (302 lines) — MODIFIED

**Original:** Single presentation verification (`verifyPresentation`).

**Added (Phase E):**
- `verifyBbsPairingBatch(A'[], Ā[], X)` — standalone batched BBS+ pairing verification
- `verifyAccPairingBatch(A'_acc[], Ā_acc[], pkAcc)` — standalone batched accumulator pairing verification

Both use `seed = keccak256(points || prevrandao)` for weight derivation.

### 5.9 `contracts/Accumulator.sol` (209 lines) — MODIFIED

**Original:** `addMember(name, e, newDelta128)`, `deleteMember(name, e, newDelta128)`.

**Added (Phase F):**
- `addMembers(name, es[], newDelta128)` — adds N members in one tx. Emits individual `MemberAdded(name, es[j])` events for each member (so witness update listeners work unchanged), but only one SSTORE for the delta update. Requires `onlyOpener` modifier.

### 5.10 Other unchanged contracts

- **`BbsPlusPokVerify.sol`** (160 lines) — Library verifying BBS+ PoK Relations 1 and 2 for single presentations
- **`CommitmentPokVerify.sol`** (58 lines) — Library verifying single commitment PoK (MSM(bases, responses) == T + c·C)
- **`VBAccPokVerify.sol`** (77 lines) — Library verifying single accumulator membership PoK (Schnorr + pairing)

---

## 6. Rust Codebase (Detailed)

### 6.1 `src/orchestration/batching.rs` (457 lines) — NEW

Core data structures and ABI packing for batch operations.

**`PresentationData` struct** — serializable representation of one user's credential presentation proof:
- 11 G1 points (128 bytes each): `a_prime`, `a_bar`, `d`, `t1_bbs`, `t2_bbs`, `t1_enc`, `t2_enc`, `t_enc`, `a_prime_acc`, `a_bar_acc`, `t_acc`
- 6 scalar responses: `resp_a`, `resp_h0`, `resp_r3`, `resp_sprime`, `resp_a3`, `resp_k`
- 2 challenges: `bbs_challenge`, `acc_challenge`
- Variable-length: `resp_msgs: Vec<U256>`, `resp_r_acc`, `resp_e_acc`
- Revealed: `revealed_idx: Vec<u32>`, `revealed_vals: Vec<U256>`
- Methods: `validate()` (checks point lengths), `from_tuples()` (constructs from proof components)

**`pack_batch_input(presentations: &[PresentationData]) → Token`** — packs N presentations into one `ethers::abi::Token::Tuple` matching the Solidity `BatchPresInput` struct. Concatenates per-user G1 points into flat `bytes`, flattens responses into arrays. This is what `presentation_aggregator` calls.

**`RequestData` struct** — serializable representation of one user's credential request:
- `user_addr: String`, `commitment_u/b: Vec<u8>` (128B), `h0/h: Vec<u8>`, `hidden_idx`, `t` (Schnorr commitment), `challenge`, `responses`, `context`, `cred_name`

**`pack_batch_request_input(requests: &[RequestData]) → (name, addrs, commitments, h0, H, hiddenIdx, Ts, challenges, flatResponses, revIdx, revVals, contexts)`** — unpacks N requests into flat arrays matching the Solidity function signature. This is what `request_aggregator` calls.

### 6.2 `src/orchestration/chain/clients.rs` (226 lines) — MODIFIED

Contract client wrappers using dynamic `ethers::Contract` with loaded ABIs.

**Clients defined:**
| Client | ABI Source | Purpose |
|--------|-----------|---------|
| `RegistryClient<M>` | `CredentialRegistry.json` | Share submission, credential confirmation |
| `VerifyClient<M>` | `VerifyWrapper` ABI (Verify.sol) | Single presentation verification |
| `AccumulatorClient<M>` | `Accumulator.json` | Accumulator operations |
| `ParamsClient<M>` | `Params.json` | Parameter queries (with in-memory caching) |
| `BatchVerifyClient<M>` | `BatchVerifyWrapper` ABI | **[NEW]** Batched presentation verification |

**Batch methods added to `RegistryClient`:**
- `submit_share_batch_call(name, user_ids, idx, r_concat, us, es, ss)` — builds `submitShareBatch` contract call
- `confirm_batch_randomized_call(name, user_ids)` — builds `confirmBatchRandomized` contract call

**`ParamsClient` caching:** Uses `OnceCell<RwLock<HashMap>>` for `threshold_cache`, `h_cache`, `g1h0g2_cache`, `mcount_cache`. Methods: `get_threshold_cached`, `get_h_cached`, `get_g1h0g2_cached`, `get_message_count_cached`, `invalidate_all`, `invalidate_cred`.

### 6.3 `src/bin/issuer_onchain.rs` (775 lines) — MODIFIED

The issuer is the most complex binary. It connects via libp2p to other issuers, listens for `SigReqBBSPlusVerified` events, and runs 3-phase MPC.

**Batch additions:**

1. **Batch configuration** (env vars at startup):
   - `BATCH_SIZE` (default "1") — how many requests to buffer before triggering MPC
   - `BATCH_TIMEOUT_MS` (default "5000") — max wait time for batch to fill
   - `is_batch_leader = participant_id == 1` — only PID 1 coordinates

2. **Batch manifest** (leader broadcasts via gossipsub topic `"batch-manifest"`):
   - When PID 1's buffer reaches `BATCH_SIZE` or timeout expires, it broadcasts `{from, batch_sid, user_ids: [u1..uN]}`
   - Non-leaders receive manifest, reorder their pending queue to match, then all proceed with same-ordered batch

3. **MPC with batch_size > 1:**
   - `Phase1::init_for_bbs_plus(rng, batch_size, ...)` — library handles vector sizing
   - Phase 2 automatically scales (2 × batch_size OT messages)
   - Phase 3 loops `sig_index = 0..batch_size-1`, each with its own user's commitment + messages

4. **`submitShareBatch` call** (after MPC):
   - Builds `r_concat` (N × 128 bytes), `us`, `es`, `ss` arrays
   - Single contract call: `registry.submit_share_batch_call(...)`

5. **`confirmBatchRandomized` call** (batch leader only):
   - Waits 8 seconds after submitShareBatch (to ensure all issuers have submitted)
   - Calls `registry.confirm_batch_randomized_call(name, user_ids)`

### 6.4 `src/bin/client/main.rs` (395 lines) — MODIFIED

**Batch request export path:**
- If env `BATCH_REQUEST_EXPORT` is set (any value), after constructing the `RequestSession` (which builds the commitment PoK), the client serializes a `RequestData` struct and writes it to `BATCH_REQUEST_FILE` (default "batch_request.json") in append mode (JSON array), then exits early without broadcasting on-chain.
- This allows running N client instances sequentially with `BATCH_REQUEST_EXPORT=1`, collecting all requests in one file, then running `request_aggregator` to submit them as a batch.

### 6.5 `src/bin/client/ui.rs` (562 lines) — MODIFIED

**Batch presentation export path:**
- In the interactive UI menu, the user can choose "export batch presentation"
- Constructs `PresentationData` from the proof tuples
- Prompts for output file (default "batch_presentation.json")
- Appends to JSON array file
- This feeds into `presentation_aggregator`

### 6.6 `src/bin/presentation_aggregator.rs` (163 lines) — NEW

Standalone binary that reads a JSON file of `PresentationData[]` and submits a single batched verification transaction.

**CLI args** (clap):
```
--input FILE          # Path to batch_presentation.json
--batch-verify ADDR   # Override BATCH_VERIFY_CONTRACT
--params ADDR         # Override PARAMS_CONTRACT  
--accumulator ADDR    # Override ACC_CONTRACT
--cred-name NAME      # Override CRED_NAME
--rpc-url URL         # Override ETH_RPC
--gas-limit NUM       # Default 200000000
```

**Flow:**
1. Load & validate `Vec<PresentationData>` from JSON
2. Connect to chain (HTTP provider + wallet signer from `AGG_PK` or `DEPLOYER_PK`)
3. Create `BatchVerifyClient`
4. `pack_batch_input(&presentations)` → ABI token
5. Call `verifyPresentationBatch(name, params_addr, acc_addr, batch_token)` with configurable gas limit
6. Parse `BatchPresentationVerified` event from receipt logs

### 6.7 `src/bin/request_aggregator.rs` (195 lines) — NEW

Standalone binary that reads `RequestData[]` and submits a batched credential request.

**Uses `abigen!`:**
```rust
abigen!(RequestCredential, "artifacts/contracts/RequestCredential.sol/RequestCredential.json");
```

**CLI args** (clap):
```
--input FILE              # Path to batch_request.json
--request-contract ADDR   # Override REQUEST_CONTRACT
--rpc-url URL             # Override ETH_RPC
--gas-limit NUM           # Default 200000000
```

**Flow:**
1. Load & validate `Vec<RequestData>` from JSON
2. Connect to chain
3. `pack_batch_request_input(&requests)` → 13-element tuple
4. Call `batch_broadcast_sig_req_bbs_plus_verified(...)` (abigen-generated method)
5. Count `SigReqBBSPlusVerified` events

### 6.8 `src/bin/opener_aggregator.rs` (644 lines) — MODIFIED

The opener aggregator coordinates threshold ElGamal opening and manages the accumulator.

**Batch accumulator additions (Phase F):**

1. **Configuration:**
   - `BATCH_ADD_SIZE` (default "1") — buffer size before flushing
   - `BATCH_ADD_TIMEOUT_MS` (default "5000") — max wait before flushing

2. **Local V tracking:**
   ```rust
   let mut local_v: Option<Vec<u8>> = None;        // locally-tracked accumulator delta
   let mut pending_adds: Vec<U256> = Vec::new();     // buffered member elements
   let mut pending_v_new: Option<Bytes> = None;      // final delta for batch
   let mut batch_add_first: Option<Instant> = None;  // first arrival timestamp
   ```

3. **On each credential confirmation:**
   - Compute new accumulator: `v_new = local_v ^ (e + sk_acc)` 
   - Update `local_v = Some(v_new_bytes)` — this prevents stale chain reads
   - Push `e` to `pending_adds`, set `pending_v_new = Some(v_new_bytes)`

4. **Flush trigger** (when `pending_adds.len() >= batch_add_size` OR timeout):
   - If 1 element: `addMember(name, e, final_v)`
   - If >1 elements: `addMembers(name, es, final_v)`
   - Reset: `local_v = None; pending_adds.clear(); batch_add_first = None;`

### 6.9 `src/bin/service_provider.rs` (454 lines) — MODIFIED

**Batch presentation handling:**
- If `BATCH_VERIFY_CONTRACT` env var is set, subscribes to `BatchPresentationVerified(string indexed name, uint256 batchSize, bytes T1s, bytes T2s)` events
- On receiving event: ABI-decodes `batchSize`, extracts `T1s` and `T2s` (concatenated G1 points, 128B each)
- Iterates over `batch_size` users, calls `requestOpen(name, t1, t2)` for each user individually (opening is still per-user)

### 6.10 `src/bin/benchmark_batching.rs` (928 lines) — NEW

Comprehensive gas benchmarking harness that deploys fresh contracts, generates synthetic credentials, and measures gas for both individual and batched operations across configurable batch sizes.

### 6.11 Other binaries (unchanged)

- **`ttp.rs`** (312 lines) — One-time setup: generates keys, deploys contracts, writes `.runtime.env`
- **`opener_threshold.rs`** (621 lines) — Runs partial ElGamal decryption when requested
- **`cred_status.rs`** — Query credential status from chain
- **`export_pok_json.rs`** — Export PoK data as JSON for testing

---

## 7. Batching Implementation (Phases A–F)

All six phases are marked **DONE** in `plan.md`.

### Phase A: Batched Presentation Verification ✅

**What:** N users' credential presentations verified in one transaction instead of N.

**Files created:**
- `contracts/BatchVerify.sol` — 480 lines, full batched verifier
- `src/bin/presentation_aggregator.rs` — 163 lines, aggregator binary
- `src/orchestration/batching.rs` — `PresentationData`, `pack_batch_input()`

**Files modified:**
- `src/bin/client/ui.rs` — batch export path
- `src/bin/service_provider.rs` — `BatchPresentationVerified` event handler
- `src/orchestration/chain/clients.rs` — `BatchVerifyClient`
- `Cargo.toml` — `[[bin]] name="presentation_aggregator"` entry

**Gas savings:** 4 MSMs + 1 pairing (4-pair) instead of N × (4 MSMs + 2 pairings).

### Phase B: Batched Credential Issuance ✅

**What:** Each issuer submits N partial credentials in one transaction; MPC runs for batch_size > 1.

**Files modified:**
- `contracts/CredentialRegistry.sol` — `submitShareBatch()` function
- `src/bin/issuer_onchain.rs` — batch manifest coordination, batch MPC, `submitShareBatch` call

**Key mechanism:** Batch leader (PID 1) broadcasts manifest via gossipsub. All issuers wait for consensus on batch order before starting MPC.

### Phase C: Batched Credential Verification ✅

**What:** After issuers submit shares and contract aggregates N credentials, verify all N with one pairing instead of N pairings.

**Files modified:**
- `contracts/CredentialRegistry.sol` — `confirmBatchRandomized()` function
- `src/orchestration/chain/clients.rs` — `confirm_batch_randomized_call()` method
- `src/bin/issuer_onchain.rs` — batch leader calls `confirmBatchRandomized` after 8s delay

**Math:** Random δ_j weights, `e(Σδ_j·A_j, X) · e(Σδ_j·e_j·A_j - Σδ_j·B_j, g2) = 1`.

### Phase D: Batched Credential Request Verification ✅

**What:** N users' commitment PoKs verified in one transaction using batched Schnorr.

**Files created:**
- `contracts/BatchCommitmentPokVerify.sol` — 83 lines, batched Schnorr library
- `src/bin/request_aggregator.rs` — 195 lines, aggregator binary

**Files modified:**
- `contracts/RequestCredential.sol` — `batchBroadcastSigReqBBSPlusVerified()` function
- `src/orchestration/batching.rs` — `RequestData`, `pack_batch_request_input()`
- `src/bin/client/main.rs` — `BATCH_REQUEST_EXPORT` early-exit path
- `Cargo.toml` — `[[bin]] name="request_aggregator"` entry

**Design choice:** Batched Schnorr with random linear combination (Option B) was chosen over compressed Σ-protocol (Option A). Rationale: no client changes needed, simpler Solidity, same soundness guarantees, 3 MSMs total regardless of N.

**ABI fix:** `BatchCommitmentPokVerify.sol` originally had custom errors (`error BadPointLen()`) that conflicted with the same names in `CommitmentPokVerify.sol` when both were linked into `RequestCredential.sol`. The ethers `abigen!` macro generated duplicate Rust types. Fixed by removing custom errors from `BatchCommitmentPokVerify` and using `require()` with string messages.

### Phase E: Standalone Batched Pairing Verifiers ✅

**What:** Standalone batch-verification functions for BBS+ and accumulator pairings.

**Files modified:**
- `contracts/Verify.sol` — `verifyBbsPairingBatch()`, `verifyAccPairingBatch()`

### Phase F: Batched Accumulator Operations ✅

**What:** Buffer N accumulator additions and submit as one transaction.

**Files modified:**
- `contracts/Accumulator.sol` — `addMembers()` function
- `src/bin/opener_aggregator.rs` — batch buffering with `local_v` tracking

**Key design:** Local accumulator delta tracking prevents stale chain reads when multiple batches are in flight. The opener aggregator maintains `local_v` in memory, updates it after each MPC round, and only reads from chain after a flush.

---

## 8. Environment Variables Reference

### Shared (set by `01_ttp_setup.sh` in `.runtime.env`)

| Variable | Example | Used By |
|----------|---------|---------|
| `ETH_WS` | `ws://127.0.0.1:8545` | All WebSocket binaries |
| `ETH_HTTP` | `http://127.0.0.1:8545` | Aggregator binaries |
| `ETH_RPC` | same as ETH_HTTP | Aggregator binaries |
| `CHAIN_ID` | `31337` | All |
| `REQ_CONTRACT` | `0x...` | client, request_aggregator |
| `REGISTRY_CONTRACT` | `0x...` | issuer, opener_aggregator |
| `PARAMS_CONTRACT` | `0x...` | All verification |
| `ACC_CONTRACT` | `0x...` | opener_aggregator, service_provider |
| `VERIFY_CONTRACT` | `0x...` | service_provider |
| `CRED_NAME` | `ANON_CRED` | All |
| `DEPLOYER_PK` | hex private key | Fallback signer |
| `AGG_PK` | hex private key | Aggregator signer |

### Issuer-specific

| Variable | Default | Purpose |
|----------|---------|---------|
| `BATCH_SIZE` | `"1"` | Number of requests to buffer before MPC |
| `BATCH_TIMEOUT_MS` | `"5000"` | Max wait for batch to fill (ms) |
| `PARTICIPANT_ID` | required | Issuer index (1-based) |
| `ISSUER_SK` | required | Issuer's secret share |

### Opener-specific

| Variable | Default | Purpose |
|----------|---------|---------|
| `BATCH_ADD_SIZE` | `"1"` | Members to buffer before addMembers |
| `BATCH_ADD_TIMEOUT_MS` | `"5000"` | Max wait before flush |

### Client batch export

| Variable | Default | Purpose |
|----------|---------|---------|
| `BATCH_REQUEST_EXPORT` | unset | If set, export request JSON instead of broadcasting |
| `BATCH_REQUEST_FILE` | `"batch_request.json"` | Output file path |
| `BATCH_PRESENTATION_EXPORT` | via UI | Manually triggered in presentation UI |

### Service provider

| Variable | Default | Purpose |
|----------|---------|---------|
| `BATCH_VERIFY_CONTRACT` | unset | If set, subscribe to batch presentation events |
| `SP_AUTO_OPEN` | `"false"` | Automatically request opening |
| `SP_AUTO_REVOKE` | `"false"` | Automatically request revocation |

---

## 9. Build & Run Instructions

### Prerequisites

```bash
# Rust stable
rustup update stable

# Node 22+ and npm
node --version  # should be v22+

# Foundry (for Anvil)
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Install & Compile

```bash
# Install Node dependencies
npm ci

# Compile Solidity (generates artifacts/ and typechain-types/)
npx hardhat compile

# Build all Rust binaries
cargo build --features mpc
# or for release:
cargo build --release --features mpc
```

### Start Local Chain

```bash
anvil --hardfork pragueEOF --gas-limit 300000000 -p 8545
```

### One-Time Setup

```bash
bash scripts/01_ttp_setup.sh THRESHOLD=3 TOTAL=3 CRED_NAME=ANON_CRED MESSAGE_COUNT=5
set -a; source .runtime.env; set +a
```

### Run Services

```bash
# Terminal 1: Issuers (3 processes)
bash scripts/02_start_issuers.sh

# Terminal 2: Opener aggregator
bash scripts/03_start_opener_aggregator.sh

# Terminal 3: Threshold openers (3 processes)
bash scripts/04_start_threshold_openers.sh

# Terminal 4: Service provider
SP_AUTO_OPEN=true SP_AUTO_REVOKE=true bash scripts/06_run_service_provider.sh

# Terminal 5: Client
bash scripts/05_run_user.sh
```

### Run Batched Operations

```bash
# 1. Export N credential requests to JSON
for i in $(seq 1 $N); do
    BATCH_REQUEST_EXPORT=1 BATCH_REQUEST_FILE=batch_request.json \
        cargo run --release --features mpc --bin client
done

# 2. Submit batch request
cargo run --release --bin request_aggregator -- --input batch_request.json

# 3. Issuers will process the N SigReqBBSPlusVerified events as a batch
#    (if BATCH_SIZE=N is set for issuers)

# 4. After credentials are issued, export presentations:
#    (done via interactive client UI, choosing "export batch presentation")

# 5. Submit batch presentation verification
cargo run --release --bin presentation_aggregator -- --input batch_presentation.json
```

---

## 10. Scripts Reference

| Script | Purpose |
|--------|---------|
| `scripts/01_ttp_setup.sh` | Full setup: TTP key generation → Hardhat compile → deploy contracts → write `.runtime.env` |
| `scripts/02_start_issuers.sh` | Launches `TOTAL` issuer processes with correct `PARTICIPANT_ID` and `ISSUER_SK` |
| `scripts/03_start_opener_aggregator.sh` | Launches opener aggregator with accumulator key |
| `scripts/04_start_threshold_openers.sh` | Launches threshold opener processes |
| `scripts/05_run_user.sh` | Launches single client |
| `scripts/05_run_users.sh` | Launches multiple clients sequentially |
| `scripts/06_run_service_provider.sh` | Launches service provider |
| `scripts/07_run_all.sh` | Orchestrated multi-terminal launch (requires gnome-terminal) |
| `scripts/deploy_local.ts` | Hardhat deployment script for all contracts |
| `scripts/deploy_pok_verifiers.ts` | PoK verifier library deployment |
| `scripts/allowlist_and_set_multiaddrs.ts` | Register issuers and their libp2p multiaddrs |

---

## 11. Documentation Artifacts

Two LaTeX documents were generated covering the mathematics of the batching implementation:

1. **`batched_verification_math.tex`** (25 pages when compiled)
   - Prelims: BLS12-381, EIP-2537 precompiles, field arithmetic, Schwartz-Zippel, Lagrange interpolation
   - BBS+ signatures: sign, verify, threshold variant
   - Commitment PoK: Schnorr protocol, Fiat-Shamir
   - Presentation protocol: credential randomization, Relations 1 & 2, encryption, accumulator PoK
   - All batching equations: batched credential verification, batched presentation, batched commitment PoK
   - Security: UC model, hybrid proof, advantage bound
   - Design decisions and gas analysis

2. **`batched_verification_problems.tex`** (11 pages, 300 marks)
   - 28 pen-and-paper problems across field arithmetic, Schnorr protocol, BBS+ signatures, batching derivations, soundness proofs

> **Note:** These may need to be regenerated — they were created during a previous session and may have been cleaned. The content is fully specified above and can be recreated from the conversation history.

The academic paper the implementation is based on is **RTBBS__PETS_new.txt** (4982 lines of LaTeX source). Key equations referenced: Eq 27 (batched credential verification), Eqs 28-29 (batched presentation), Eqs 7-9 (compressed sigma protocol — not used, batched Schnorr chosen instead).

---

## 12. Known State & Open Items

### Current Build Status

- ✅ `cargo check --features mpc` — compiles clean
- ✅ `npx hardhat compile` — compiles clean (all type bindings generated)
- ✅ All 6 batching phases implemented and compiling
- ✅ `plan.md` updated with all phases marked DONE

### What Has NOT Been Tested End-to-End

- The full batched flow (N users → request aggregator → batched issuance → confirm batch → presentation aggregator → batch verify) has not been run as an integrated test on a live Anvil chain
- `benchmark_batching.rs` exists (928 lines) for gas measurement but its results were not captured in this session
- Batch sizes > 30 were not tested against the crypto library (the library tests up to batch_size=30)

### Potential Issues

1. **8-second delay for `confirmBatchRandomized`** — The batch leader waits a hardcoded 8 seconds after `submitShareBatch` to ensure all issuers have submitted. This is fragile; a proper approach would be to listen for `BatchSharesAccepted` events from all issuers.

2. **request_aggregator.rs location** — The `Cargo.toml` declares `path = "src/bin/request_aggregator.rs"` but the file lives at `src/bin/request_aggregator.rs` (confirmed present). It uses `abigen!` which requires the Hardhat ABI artifact to exist at compile time.

3. **Gas limits** — Both aggregator binaries default to `gas_limit = 200_000_000`. The Anvil chain is started with `--gas-limit 300000000`. For large batches (>64 users), the gas limit may need to be increased.

4. **`BatchCommitmentPokVerify` error handling** — Custom errors were removed (replaced with `require` strings) to work around ABI duplicate conflicts. This means error messages are less gas-efficient (strings vs error selectors).

5. **Foundry vs Hardhat solc versions** — `foundry.toml` uses 0.8.24, `hardhat.config.ts` uses 0.8.27. The Hardhat config is authoritative for deployment. Make sure to use `npx hardhat compile` not `forge build` for the artifacts that Rust binaries consume.

### Missing Infrastructure

- No automated integration tests (the existing `tests/` dir under `src/orchestration/tests/` has unit tests)
- No CI/CD pipeline
- Metrics results from benchmarks not captured
- No formal gas comparison table between batched and non-batched (the benchmark binary exists but hasn't been run with results collected)

---

## 13. Key Design Decisions

### 1. Batched Schnorr over Compressed Σ-Protocol (Phase D)

The paper describes a compressed sigma protocol with O(log n) proof size via recursive vector folding. Instead, we chose batched Schnorr with random linear combination because:
- **No client changes** — users generate standard Schnorr proofs
- **No witness access** — aggregator only collects public proofs
- **Simpler Solidity** — 3 MSMs total vs N × log(|bases|) MSMs for compressed
- **Same soundness** — Schwartz-Zippel gives the same security bound

### 2. Local Δ Tracking (Phase F)

When buffering accumulator additions, subsequent MPC rounds would read stale Δ from chain. Solution: maintain `local_v` in memory in the opener aggregator, update after each computation, clear after flush.

### 3. Batch Manifest via Gossipsub (Phase B)

Rather than expecting all issuers to independently agree on batch composition through deterministic ordering (risky due to clock drift), the batch leader (PID 1) broadcasts an explicit manifest. Other issuers wait for and follow this manifest.

### 4. Individual Events from Batch Operations (Phase D)

`batchBroadcastSigReqBBSPlusVerified` emits individual `SigReqBBSPlusVerified` events per user rather than a single batch event. This means existing issuer code that listens for individual events works unchanged — they don't need to know the request was batched.

### 5. ABI Conflict Resolution (Phase D)

When `BatchCommitmentPokVerify.sol` and `CommitmentPokVerify.sol` both defined `error BadPointLen()`, ethers `abigen!` generated conflicting Rust types. Fixed by removing custom errors from the batch library and using `require(condition, "message")` instead. Trade-off: slightly higher gas for error cases, but avoids architectural complexity.

### 6. 4-Pair Combined Pairing (Phase A)

The batched presentation verifier combines BBS+ and accumulator pairing checks into a single 4-pair precompile call. This saves ~32K gas per additional pairing pair avoided (compared to two separate 2-pair calls).

---

*End of handoff document.*
