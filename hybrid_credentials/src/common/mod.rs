//! Common types and utilities for hybrid BBS+ credential system

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use bbs_plus::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Type aliases
pub type Scalar = Fr;
pub type G1Point = G1Affine;  
pub type G2Point = G2Affine;
pub type Curve = Bls12_381;

// System configuration
pub const MESSAGE_COUNT: u32 = 10;
pub const SIG_BATCH_SIZE: u32 = 1;

// Network ports
pub const ISSUER_PORT: u16 = 8001;
pub const VERIFIER_PORT: u16 = 8002;

// ID types
pub type RequestId = Uuid;
pub type AttributeId = u32;

/// System parameters shared by all participants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemParams {
    pub bbs_params: SignatureParams23G1<Curve>,
    pub message_count: u32,
    pub sig_batch_size: u32,
}

/// Credential request from user with blinded commitments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    pub request_id: RequestId,
    pub user_id: String,
    
    // Blinded commitments to private attributes
    pub blinded_commitments: Vec<G1Point>,
    
    // Public attributes (revealed)
    pub public_attributes: Vec<(AttributeId, Scalar)>,
    
    // Count of private attributes
    pub private_attribute_count: u32,
    
    // Pedersen commitment to all attributes for witness consistency
    pub attribute_commitment: G1Point,
    pub commitment_randomness: Scalar,
}

/// BBS+ CDL proof with commitment binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BBSPlusCDLProof {
    pub request_id: RequestId,
    
    // CDL proof components (from proof_23_cdl.rs)
    pub cdl_proof_bytes: Vec<u8>,
    
    // Selective disclosure info
    pub revealed_attributes: Vec<(AttributeId, Scalar)>,
    pub hidden_attribute_count: u32,
    
    // Pedersen commitment linking BBS+ proof to SNARK circuit
    pub witness_commitment: G1Point,
    pub commitment_proof: Vec<u8>, // Schnorr PoK of commitment opening
}

/// zk-SNARK proof for on-chain verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SNARKProof {
    pub request_id: RequestId,
    
    // LegoGroth16 proof
    pub groth16_proof: Vec<u8>,
    
    // Public inputs for the circuit
    pub public_inputs: Vec<Scalar>,
    
    // Merkle root or commitment hash for verification
    pub verification_hash: [u8; 32],
}

/// On-chain verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub request_id: RequestId,
    pub is_valid: bool,
    pub verified_attributes: Vec<(AttributeId, Scalar)>,
    pub verification_timestamp: u64,
    pub transaction_hash: Option<String>,
}

/// Circuit public inputs structure
#[derive(Debug, Clone)]
pub struct CircuitPublicInputs {
    /// Hash of the issuer's public key
    pub issuer_pubkey_hash: Fr,
    
    /// Hash of revealed attributes
    pub revealed_attrs_hash: Fr,
    
    /// Pedersen commitment to witness (for consistency)
    pub witness_commitment_x: Fr,
    pub witness_commitment_y: Fr,
    
    /// Challenge hash from Fiat-Shamir
    pub challenge_hash: Fr,
}

/// Circuit private inputs (witness)
#[derive(Debug, Clone)]
pub struct CircuitPrivateInputs {
    /// BBS+ signature components
    pub signature_a: Fr,
    pub signature_e: Fr,
    pub signature_s: Fr,
    
    /// Private attributes
    pub private_attributes: Vec<Fr>,
    
    /// Randomness values from CDL proof
    pub r1: Fr,
    pub r2: Fr,
    pub r3: Fr,
    
    /// Commitment randomness
    pub commitment_randomness: Fr,
}

/// Error types
#[derive(Debug, thiserror::Error)]
pub enum HybridCredentialError {
    #[error("BBS+ error: {0}")]
    BBSPlus(#[from] bbs_plus::error::BBSPlusError),
    
    #[error("SNARK error: {0}")]
    SNARK(String),
    
    #[error("Circuit synthesis error: {0}")]
    Synthesis(#[from] ark_relations::r1cs::SynthesisError),
    
    #[error("Circuit error: {0}")]
    Circuit(String),
    
    #[error("Commitment error: {0}")]
    Commitment(String),
    
    #[error("Verification error: {0}")]
    Verification(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, HybridCredentialError>;
