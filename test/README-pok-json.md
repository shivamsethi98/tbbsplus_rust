# From-Rust PoK JSON test

- Build the Rust exporter example:
  - workspace: `crypto/bbs_pok_circuits`
  - example: `export_pok_json.rs`
- Run to produce a JSON file (defaults to pok.json):
  - cargo run --example export_pok_json --release
- Then run the Hardhat test pointing to the JSON and enabling mainnet fork:
  - FORK=1 RUST_POK_JSON=./crypto/bbs_pok_circuits/pok.json npx hardhat test test/bbsplus.pok.verify.from_rust.spec.ts

Foundry (anvil) option
- Start anvil (ensure it supports BLS12-381 precompiles):
  - anvil --fork-url $FORK_URL
- Run the Foundry test from repo root:
  - RUST_POK_JSON=./crypto/bbs_pok_circuits/pok.json forge test -vv --match-test testVerifyFromRustJson

Notes
- Hardhat PoK tests now auto-skip when EIP-2537 precompiles are unavailable.
- Precompiles require fork mode (FORK=1) with a mainnet RPC or a local client that implements EIP-2537.
- JSON fields are 128-byte uncompressed G1 points and 32-byte big-endian Fr scalars.
