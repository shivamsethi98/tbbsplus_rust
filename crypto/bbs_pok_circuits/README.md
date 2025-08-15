BBS+ PoK Groth16 Circuits (BLS12-381)

This crate provides a Groth16-ready circuit skeleton to prove the correctness of a BBS+ proof-of-knowledge of signature and selective disclosure without pairings in-circuit.

Scope (v0):
- Circuit API and data structures for public inputs: params_hash, pk_hash, message_count, revealed indices/values, context hash, and optional sid.
- Minimal constraint gadgets wiring for placeholders; no pairing checks in-circuit.
- Prover and verifier helpers over ark-groth16 for BLS12-381.

Next:
- Implement full algebraic constraints for the BBS+ PoK verification equations.
- Export verifying key constants for Solidity verifier using EIP-2537.
