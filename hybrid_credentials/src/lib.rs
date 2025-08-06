//! Hybrid BBS+ Credential System with zk-SNARK On-chain Verification
//! 
//! Architecture:
//! 1. Off-chain: BBS+ CDL proof generation using selective disclosure
//! 2. Circuit: Convert BBS+ proof to R1CS constraints for LegoGroth16
//! 3. On-chain: Solidity verifier for zk-SNARK proofs
//! 4. Commitment: Pedersen commitments to ensure witness consistency

pub mod common;
pub mod circuits;
pub mod proofs;

// Re-export main types
pub use common::*;
pub use circuits::*;
pub use proofs::*;
