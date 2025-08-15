use ark_bls12_381::Bls12_381;
use ark_groth16::{Proof as Groth16InnerProof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

use crate::{
    encode_public_inputs, expected_public_inputs_len, prove as circuit_prove, Fr, PublicInputs,
};

/// Encapsulates a Groth16 proof and its public inputs for verification.
#[derive(Clone, Debug)]
pub struct SnarkProof {
    pub proof: Groth16InnerProof<Bls12_381>,
    pub public_inputs: Vec<Fr>,
}

impl SnarkProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.proof.serialize_compressed(&mut out).unwrap();
        // Append public inputs as canonical bytes
        for pi in &self.public_inputs {
            pi.serialize_compressed(&mut out).unwrap();
        }
        out
    }

    pub fn from_bytes(bytes: &[u8], public_inputs_len: usize) -> Result<Self, ark_serialize::SerializationError> {
        use ark_serialize::Read;
        let mut cursor = std::io::Cursor::new(bytes);
        let proof = Groth16InnerProof::<Bls12_381>::deserialize_compressed(&mut cursor)?;
        let mut public_inputs = Vec::with_capacity(public_inputs_len);
        for _ in 0..public_inputs_len {
            public_inputs.push(Fr::deserialize_compressed(&mut cursor)?);
        }
        Ok(SnarkProof { proof, public_inputs })
    }
}

/// Create a SNARK proof for the given public inputs and message witnesses.
pub fn create_proof(
    pk: &ProvingKey<Bls12_381>,
    pi: &PublicInputs,
    messages: &[Fr],
    max_messages: u32,
    max_revealed: u32,
) -> Result<SnarkProof, SynthesisError> {
    let (proof, publics) = circuit_prove(pk, pi, messages, max_messages, max_revealed)?;
    Ok(SnarkProof { proof, public_inputs: publics })
}

/// Verify a SNARK proof with the given verifying key.
pub fn verify_proof(
    vk: &VerifyingKey<Bls12_381>,
    snark: &SnarkProof,
) -> Result<bool, SynthesisError> {
    crate::verify(vk, &snark.proof, &snark.public_inputs)
}

/// Helper to encode public inputs externally (must match max_revealed used for setup).
pub fn encode_pi(pi: &PublicInputs, max_revealed: u32) -> Vec<Fr> { encode_public_inputs(pi, max_revealed) }

/// Helper to compute expected PI length externally.
pub fn pi_len(max_revealed: u32) -> usize { expected_public_inputs_len(max_revealed) }

/// Serialize/deserialize verifying key.
pub fn vk_to_bytes(vk: &VerifyingKey<Bls12_381>) -> Vec<u8> {
    let mut out = Vec::new();
    vk.serialize_compressed(&mut out).unwrap();
    out
}

pub fn vk_from_bytes(bytes: &[u8]) -> Result<VerifyingKey<Bls12_381>, ark_serialize::SerializationError> {
    let mut cursor = std::io::Cursor::new(bytes);
    VerifyingKey::<Bls12_381>::deserialize_compressed(&mut cursor)
}

/// Serialize/deserialize proving key (large; keep compressed).
pub fn pk_to_bytes(pk: &ProvingKey<Bls12_381>) -> Vec<u8> {
    let mut out = Vec::new();
    pk.serialize_compressed(&mut out).unwrap();
    out
}

pub fn pk_from_bytes(bytes: &[u8]) -> Result<ProvingKey<Bls12_381>, ark_serialize::SerializationError> {
    let mut cursor = std::io::Cursor::new(bytes);
    ProvingKey::<Bls12_381>::deserialize_compressed(&mut cursor)
}
