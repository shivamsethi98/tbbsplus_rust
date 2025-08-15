# Copilot Instructions for this repo

This workspace blends Rust cryptography (arkworks, Dock’s crypto libs) with Solidity contracts and TypeScript/Foundry tests. Use these rules and workflows to be effective here.

## Architecture snapshot
- Rust crypto crates under `crypto/` (workspace): primitives and protocols used off-chain.
  - `crypto/bbs_plus`: BBS+ signatures and PoK protocols. Key files: `src/proof.rs` (challenge bytes, Schnorr relations, response ordering), `src/signature.rs`.
  - `crypto/bbs_pok_circuits`: SNARK circuits and small examples; `examples/` contains scripts to generate PoK JSON used by on-chain tests.
  - Other supporting crates: `schnorr_pok`, `utils`, `proof_system`, etc.
- Solidity contracts under `contracts/`:
  - `lib/Bls12381.sol`: EIP-2537 precompile helpers for G1 MSM/add (expects 128-byte uncompressed points, 32-byte BE scalars).
  - `BbsPlusPokTranscript.sol`: Fiat–Shamir transcript (keccak256→Fr) used to bind proofs.
  - `BbsPlusPokVerify.sol`: Verifies BBS+ PoK Schnorr relations on-chain without pairings via MSM.
  - `contracts/test/*Wrapper.sol`: thin wrappers exposing internal libraries/functions for tests.
- Tests and scripts:
  - Hardhat: `test/*.spec.ts`, configure fork in `hardhat.config.ts` (set `FORK=1` to enable mainnet fork for precompiles).
  - Foundry: `foundry.toml` (src=contracts, test=test, libs=lib). Custom Foundry test at `test/BbsPlusPokFromRust.t.sol` reads a Rust-exported PoK JSON and calls the wrapper.
  - Rust example exporters: `crypto/bbs_pok_circuits/examples/export_pok_json.rs` outputs inputs in the exact Solidity ABI shape.

## Critical workflows
- Rust (workspace root)
  - Build examples: `cargo run --example export_pok_json --release -p bbs_pok_circuits` (writes `pok.json`).
- Hardhat
  - Compile/tests: `npx hardhat compile` and `FORK=1 npx hardhat test`.
  - Run only the PoK JSON test: `FORK=1 RUST_POK_JSON=./crypto/bbs_pok_circuits/pok.json npx hardhat test test/bbsplus.pok.verify.from_rust.spec.ts`.
  - hardhat.config.ts enables mainnet fork when `FORK=1`; INFURA key via `INFURA_KEY`.
- Foundry (Anvil)
  - Start anvil with a mainnet fork URL that supports EIP-2537.
  - Run PoK test: `RUST_POK_JSON=./crypto/bbs_pok_circuits/pok.json forge test -vv --match-test testVerifyFromRustJson`.
  - Foundry test will skip if precompiles are missing or env is unset.

## Data shapes and conventions
- BLS12-381 G1 points on-chain are 128-byte uncompressed (x||y), big-endian limbs, no flags or compression.
- Scalars are 32-byte big-endian mod Fr. FR_MODULUS is hard-coded in `BbsPlusPokVerify.sol`.
- MSM input layout: concatenated pairs of (128B point || 32B scalar). See `Bls12381.concatMSM`.
- PoK response ordering on-chain matches `bbs_plus::proof::PoKOfSignatureG1Protocol`:
  - Proof1 (T1): responses for A′ (-e) then h0 (r2).
  - Proof2 (T2): responses for undisclosed H (in param index order), then d (r3), then h0 (s').
- Transcript challenge binding: keccak256 over serialized transcript (T1, T2, params, revealed values) then reduced mod Fr. See `BbsPlusPokTranscript.sol` and `crypto/bbs_plus/src/proof.rs::compute_challenge_contribution`.

## Tips when editing/adding code
- Solidity viaIR is enabled; avoid inline assembly for precompiles—use high-level `staticcall` like in `Bls12381.sol`.
- Always validate 128-byte point lengths and array sizes before MSM. Follow checks in `BbsPlusPokVerify.verify`.
- Keep revealed indices sorted/unique/in-bounds; Foundry/TS tests may rely on strict checks.
- When wiring Rust→Solidity, ensure consistent endian and lengths. Use the Rust exporter as the ground truth for formatting.

## Key files to read first
- `contracts/BbsPlusPokVerify.sol` for the on-chain equations and MSM wiring.
- `contracts/lib/Bls12381.sol` for precompile calling conventions and packing.
- `crypto/bbs_plus/src/proof.rs` for off-chain PoK structure and transcript computation.
- `test/bbsplus.pok.verify.from_rust.spec.ts` and `test/BbsPlusPokFromRust.t.sol` for end-to-end shapes.

## Common pitfalls
- Running MSM on a local non-forked Hardhat/Anvil node that doesn’t support EIP-2537 will fail; use mainnet fork or a client with those precompiles.
- 128B point mismatches (compressed vs uncompressed) and 32B scalar endianness errors will silently invalidate proofs; use the exporter outputs.
- Challenge mismatch if transcript bytes differ (ordering, revealed set, or serialization). Match `compute_challenge_contribution` exactly.
