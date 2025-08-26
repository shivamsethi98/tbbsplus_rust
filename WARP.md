# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

Project type: Rust workspace focused on BBS+/threshold credentials with on-chain (EVM) interactions and local MPC over libp2p.

Commands you’ll use often
- Build everything
  ```bash path=null start=null
  cargo build --workspace --all-features
  ```
- Lint (deny warnings) and format
  ```bash path=null start=null
  cargo fmt --all
  cargo clippy --workspace --all-features -D warnings
  ```
- Run tests for the whole workspace
  ```bash path=null start=null
  cargo test --workspace --all-features
  ```
- Run a single crate’s tests or a single test
  ```bash path=null start=null
  # by crate
  cargo test -p proof_system --all-features
  # single test by name pattern
  cargo test -p proof_system --all-features -- testVerifyFromRustJson
  ```
- Binaries (examples below expect a local Anvil/Hardhat node and deployed contracts)
  ```bash path=null start=null
  # Interactive client (enable interactive UI if desired)
  ETH_WS=ws://127.0.0.1:8545 \
  CHAIN_ID=31337 \
  REQ_CONTRACT={{REQ_CONTRACT}} \
  PARAMS_CONTRACT={{PARAMS_CONTRACT}} \
  REGISTRY_CONTRACT={{REGISTRY_CONTRACT}} \
  ACC_CONTRACT={{ACC_CONTRACT}} \
  CRED_NAME=ANON_CRED \
  MESSAGE_COUNT=5 \
  cargo run --features "mpc interactive" --bin client -- --help

  # Request a credential for sid=1 and wait for aggregation
  ETH_WS=ws://127.0.0.1:8545 CHAIN_ID=31337 REQ_CONTRACT={{REQ_CONTRACT}} PARAMS_CONTRACT={{PARAMS_CONTRACT}} REGISTRY_CONTRACT={{REGISTRY_CONTRACT}} CRED_NAME=ANON_CRED MESSAGE_COUNT=5 \
  cargo run --features mpc --bin client -- request 1 --wait

  # Verify (fetch aggregated signature and persist artifacts), then enter actions (if interactive)
  ETH_WS=ws://127.0.0.1:8545 CHAIN_ID=31337 PARAMS_CONTRACT={{PARAMS_CONTRACT}} REGISTRY_CONTRACT={{REGISTRY_CONTRACT}} CRED_NAME=ANON_CRED MESSAGE_COUNT=5 \
  cargo run --features "mpc interactive" --bin client -- verify 1

  # Issuer node (participant id PID=1); listens for verified requests and submits a share
  ETH_WS=ws://127.0.0.1:8545 CHAIN_ID=31337 \
  REQ_CONTRACT={{REQ_CONTRACT}} REGISTRY_CONTRACT={{REGISTRY_CONTRACT}} PARAMS_CONTRACT={{PARAMS_CONTRACT}} \
  PID=1 THRESHOLD=3 TOTAL=4 MESSAGE_COUNT=5 \
  cargo run --features mpc --bin issuer_onchain

  # TTP setup (deals secret shares); consult scripts below for full flow
  cargo run --bin ttp
  ```
- End-to-end local flow (if provided scripts are present in this repo)
  ```bash path=null start=null
  # One-shot helper (if available)
  bash scripts/run_local_e2e.sh

  # Or step-by-step
  bash scripts/01_ttp_setup.sh
  bash scripts/02_start_issuers.sh
  bash scripts/03_run_user.sh
  ```

Runtime environment (commonly used)
- ETH_WS: ws:// endpoint (e.g., ws://127.0.0.1:8545)
- CHAIN_ID: numeric chain id (e.g., 31337)
- REQ_CONTRACT, PARAMS_CONTRACT, REGISTRY_CONTRACT, ACC_CONTRACT: deployed contract addresses (0x...)
- CRED_NAME: credential suite name used to look up on-chain params (default ANON_CRED)
- MESSAGE_COUNT: number of messages expected by params (e.g., 5)
- Issuer-only: PID (1..TOTAL), THRESHOLD, TOTAL, BASE_PORT (libp2p listen base, default 9900), SHARES_FILE (path to TTP output)

Where artifacts are persisted
- Under .runtime/users/{user_id}/{cred_name}/sid_{sid}/ you’ll find: messages.json, agg_signature.json, revealed.json, blinding.hex, request_meta.json. These are managed via src/orchestration/persistence.rs.

High-level architecture and how pieces fit
- Workspace layout and dependency model
  - This top-level crate (package name: tbbsplus_rust) depends on a set of local cryptography crates under crypto/ (e.g., bbs_plus, schnorr_pok, proof_system, legogroth16, oblivious_transfer, vb_accumulator, etc.) via path dependencies declared in Cargo.toml. Those crates provide primitives and protocols; this crate orchestrates flows, networking, and on-chain I/O.

- Binaries and roles (src/bin)
  - client: End-user CLI that creates a selective-disclosure commitment PoK, sends a verified signing request to RequestCredential, optionally waits for aggregation events from a registry, persists artifacts, and can present on-chain via a VerifyWrapper. The client can run in an interactive mode behind the "interactive" feature (UI prompts/action loop in src/bin/client/ui.rs).
  - issuer_onchain: Issuer daemon that listens for SigReqBBSPlusVerified events, runs threshold MPC (Phase 1 commitments broadcast and Phase 2 direct exchanges over a local libp2p mesh), and submits a signature share to an on-chain aggregator. Uses deterministic seeds for Base OT and per-session randomness so different issuer instances stay consistent. Networking helpers live under src/orchestration/mesh.rs and types in src/orchestration/types/.
  - ttp: Trusted setup helper to deal Shamir shares (used by issuers). Outputs are consumed by issuer_onchain via SHARES_FILE.
  - Additional utilities: export_pok_json, cred_status, opener, service_provider support specific flows like exporting proof inputs or opening commitments.

- Orchestration layer (src/orchestration)
  - onchain.rs: Typed ParamsContract (abigen) and fetch_params_bundle which reconstructs BBS+ SignatureParamsG1 by reading G1/H/G2 byte arrays from chain (EIP-2537 uncompressed 128B for G1 and 256B for G2 encoding expected). This is the bridge from on-chain parameter storage to off-chain cryptography.
  - crypto/encoding.rs: Canonical conversions for BLS12-381 points/scalars to and from the EIP-2537 ABI shapes used on-chain. Includes fr<->U256 and keccak→Fr helpers. These are used throughout (client, issuer, verify flows) to shape calldata and parse logs.
  - crypto/pok.rs: Core proof building blocks for the client presentation/commitment PoKs. Provides: 
    - build_commitment_pok to produce a compact, serialized Schnorr proof over commitment bases [h0, H_hidden...] with a domain-separated transcript that binds sid, mcount, cred_name, revealed pairs, hidden indices, commitment, Schnorr t, and an optional context.
    - decode_commitment_pok_for_onchain to unpack the serialized bytes into ABI-friendly tuples for the verified request.
    - build_pok_and_proof and build_presentation_tuples to produce the on-chain VerifyWrapper call inputs for selective disclosure presentations (including encryption-binding to the opener’s Ybar and extra relations for T1_enc/T2_enc).
    - verify_commitment_pok_from_fields for issuers to double-check the verified request off-chain using the same challenge transcript.
  - chain/clients.rs: Thin, typed wrappers around on-chain contracts (Registry, Verify, Accumulator, Params) with small caches and prebuilt event filters to simplify subscription and calls. This hides ABI lookup (embedded or from artifacts/contracts/*.json) and lets binaries focus on flow.
  - persistence.rs: Filesystem facade for saving and loading request artifacts and resulting credentials under .runtime/..., with both legacy and typed JSON shapes supported.
  - config.rs: Reads required runtime configuration from environment (ETH_WS, contract addresses, etc.).

- Data and flow invariants to keep in mind (from both code and repo Copilot rules)
  - EIP-2537 encodings: G1 points are 128 bytes (x||y, big-endian limbs, left-padded to 64B each). Scalars are 32-byte big-endian mod Fr. Any mismatch breaks verification or precompile calls.
  - Transcript binding: Challenges for commitment and presentation proofs are derived deterministically (Blake2b/Keccak as wired) and bind sid, credential parameters, revealed set, and ordering. Changing ordering or serialization produces challenge mismatches.
  - Revealed set rules: indices must be sorted/unique/in-bounds. Client helpers serialize revealed pairs deterministically before computing the challenge.
  - Artifacts pathing: All per-session, per-user artifacts are stored in .runtime/users/{user}/{cred}/sid_{sid}/. Flows expect these to exist between request, verify, and present steps; the client creates them as it runs.

Important notes from .github/copilot-instructions.md (applies to this repo)
- Cross-stack flow: Rust exporters and client build PoK inputs matching Solidity ABI artifacts under artifacts/contracts/*.json and tests may read Rust-exported JSON. If you modify encodings, keep Rust and Solidity in lockstep.
- Data shapes for EIP-2537: 128-byte uncompressed G1 points and 32-byte big-endian scalars; MSM tuples are concatenations of (point||scalar). Use the encoding helpers as the single source of truth.
- Challenge derivation: The on-chain verifier reduces keccak256 bytes mod Fr; Rust side must match transcript byte construction exactly (see crypto/pok.rs and bbs_plus proof code). Any divergence leads to invalid proofs.
- Test environments: Some networks/tools don’t support EIP-2537 precompiles without a mainnet fork. Ensure your local chain exposes the necessary precompiles when running on-chain verifiers.

When something breaks
- Encoding/ABI issues: Check src/orchestration/crypto/encoding.rs and ensure artifacts/contracts/*.json align with the expected ABI/function names. Many helpers accept and return ethers::types::Bytes and U256 so mismatches are visible as length checks.
- Not seeing Aggregated events or signatures: Ensure REGISTRY_CONTRACT is set and the issuer_onchain daemons are running with consistent PID/THRESHOLD/TOTAL and can connect over libp2p (BASE_PORT and multiaddrs via Params).
- Present flow reverting: Verify that VERIFY_CONTRACT and ACC_CONTRACT are deployed and that witness data exists on-chain for the signature’s e value.

Notes specific to this repo
- Feature flags
  - mpc: required for networked flows (client, issuer_onchain) using libp2p and related orchestration.
  - interactive: optional; enables the client’s interactive action loop (present/witness/verify prompts). Use --features "mpc interactive" when you want the interactive loop.
- Contract artifacts: Binaries expect compiled artifacts under artifacts/contracts/.../*.json. Generate these with your Solidity toolchain before running the Rust clients/issuers that reference them.

