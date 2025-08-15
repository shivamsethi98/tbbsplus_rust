//! Groth16 circuits for BBS+ PoK over BLS12-381 (no pairings in-circuit).

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_snark::{SNARK, CircuitSpecificSetupSNARK};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::eq::EqGadget;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{vec::Vec, One, rand::{rngs::StdRng, SeedableRng}};
use blake2::Blake2b512;
use digest::Digest;

/// Public inputs carried on-chain.
#[derive(Clone, Debug, Default)]
pub struct PublicInputs {
    pub params_hash: [u8; 32],
    pub pk_hash: [u8; 32],
    pub message_count: u32,
    pub revealed_idx: Vec<u32>,
    pub revealed_vals: Vec<<Bls12_381 as Pairing>::ScalarField>,
    pub context_hash: [u8; 32],
    pub sid_opt: Option<u32>,
}

/// Circuit: placeholder wiring for now.
pub struct BbsPokCircuit {
    pub pi: PublicInputs,
    pub max_revealed: u32,
    pub max_messages: u32,
    pub messages: Vec<Fr>,
}

impl ConstraintSynthesizer<<Bls12_381 as Pairing>::ScalarField> for BbsPokCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<<Bls12_381 as Pairing>::ScalarField>) -> Result<(), SynthesisError> {
        // Placeholder constraints will be replaced. For now, enforce revealed values equal selected messages by index.
        let one = <Bls12_381 as Pairing>::ScalarField::one();
        // All public inputs as field elements in the following order:
        // params_hash, pk_hash, context_hash, sid, message_count, revealed_idx[0..max], revealed_vals[0..max]
        let _params_hash = ark_r1cs_std::fields::fp::FpVar::<
            <Bls12_381 as Pairing>::ScalarField,
        >::new_input(cs.clone(), || Ok(<Bls12_381 as Pairing>::ScalarField::from(0u64)))?;
        let _pk_hash = ark_r1cs_std::fields::fp::FpVar::<
            <Bls12_381 as Pairing>::ScalarField,
        >::new_input(cs.clone(), || Ok(<Bls12_381 as Pairing>::ScalarField::from(0u64)))?;
        let _context_hash = ark_r1cs_std::fields::fp::FpVar::<
            <Bls12_381 as Pairing>::ScalarField,
        >::new_input(cs.clone(), || Ok(<Bls12_381 as Pairing>::ScalarField::from(0u64)))?;
        let _sid = ark_r1cs_std::fields::fp::FpVar::<
            <Bls12_381 as Pairing>::ScalarField,
        >::new_input(cs.clone(), || Ok(<Bls12_381 as Pairing>::ScalarField::from(self.pi.sid_opt.unwrap_or(0) as u64)))?;
        let _msg_cnt_fp = ark_r1cs_std::fields::fp::FpVar::<
            <Bls12_381 as Pairing>::ScalarField,
        >::new_input(cs.clone(), || Ok(<Bls12_381 as Pairing>::ScalarField::from(self.pi.message_count as u64)))?;
        // revealed_idx padded to max_revealed
        let mut idx_vars = Vec::with_capacity(self.max_revealed as usize);
        for i in 0..self.max_revealed as usize {
            let idx = if i < self.pi.revealed_idx.len() { self.pi.revealed_idx[i] as u64 } else { 0u64 };
            let v = ark_r1cs_std::fields::fp::FpVar::<
                <Bls12_381 as Pairing>::ScalarField,
            >::new_input(cs.clone(), || Ok(<Bls12_381 as Pairing>::ScalarField::from(idx)))?;
            idx_vars.push(v);
        }
        // Allocate exactly max_revealed public inputs for revealed values
        let mut rev_val_vars = Vec::with_capacity(self.max_revealed as usize);
        for i in 0..self.max_revealed as usize {
            let val = if i < self.pi.revealed_vals.len() { self.pi.revealed_vals[i] } else { <Bls12_381 as Pairing>::ScalarField::from(0u64) };
            let v = ark_r1cs_std::fields::fp::FpVar::new_input(cs.clone(), || Ok(val))?;
            rev_val_vars.push(v);
        }

        // Witness allocate the messages vector, padded to max_messages with zeros.
        let mut msg_vars = Vec::with_capacity(self.max_messages as usize);
        for j in 0..(self.max_messages as usize) {
            let m = if j < self.messages.len() { self.messages[j] } else { <Bls12_381 as Pairing>::ScalarField::from(0u64) };
            let v = ark_r1cs_std::fields::fp::FpVar::new_witness(cs.clone(), || Ok(m))?;
            msg_vars.push(v);
        }

        // For each revealed index/value, enforce selected message equals revealed value using one-hot selectors.
        for k in 0..(self.max_revealed as usize) {
            // Build one-hot selector b_{k,j} = (idx_k == j)
            let mut selectors = Vec::with_capacity(self.max_messages as usize);
            for j in 0..(self.max_messages as usize) {
                let j_const = ark_r1cs_std::fields::fp::FpVar::new_constant(
                    cs.clone(), <Bls12_381 as Pairing>::ScalarField::from(j as u64)
                )?;
                let b = idx_vars[k].is_eq(&j_const)?; // Boolean
                selectors.push(b);
            }
            // sum b_j == 1 (enforces idx in-range)
            let mut sum_b = ark_r1cs_std::fields::fp::FpVar::new_constant(cs.clone(), <Bls12_381 as Pairing>::ScalarField::from(0u64))?;
            for b in selectors.iter() {
                let b_fp: ark_r1cs_std::fields::fp::FpVar<<Bls12_381 as Pairing>::ScalarField> = b.clone().into();
                sum_b = sum_b + b_fp.clone();
            }
            sum_b.enforce_equal(&ark_r1cs_std::fields::fp::FpVar::new_constant(cs.clone(), one)?)?;

            // sum b_j * j == idx_k
            let mut lin_idx = ark_r1cs_std::fields::fp::FpVar::new_constant(cs.clone(), <Bls12_381 as Pairing>::ScalarField::from(0u64))?;
            for (j, b) in selectors.iter().enumerate() {
                let b_fp: ark_r1cs_std::fields::fp::FpVar<<Bls12_381 as Pairing>::ScalarField> = b.clone().into();
                let j_const = ark_r1cs_std::fields::fp::FpVar::new_constant(
                    cs.clone(), <Bls12_381 as Pairing>::ScalarField::from(j as u64)
                )?;
                lin_idx = lin_idx + (b_fp * j_const);
            }
            lin_idx.enforce_equal(&idx_vars[k])?;

            // selected message value equals sum b_j * m_j
            let mut selected = ark_r1cs_std::fields::fp::FpVar::new_constant(cs.clone(), <Bls12_381 as Pairing>::ScalarField::from(0u64))?;
            for (b, mvar) in selectors.iter().zip(msg_vars.iter()) {
                let b_fp: ark_r1cs_std::fields::fp::FpVar<<Bls12_381 as Pairing>::ScalarField> = b.clone().into();
                selected = selected + (b_fp * mvar);
            }
            selected.enforce_equal(&rev_val_vars[k])?;
        }
        Ok(())
    }
}

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

/// Blake2b-512 over input bytes; returns 64-byte array
pub fn blake2b512(input: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(input);
    let out = hasher.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

/// First 32 bytes of Blake2b-512 hash (little-endian slice, no further processing).
pub fn blake2b512_first32(input: &[u8]) -> [u8; 32] {
    let full = blake2b512(input);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&full[..32]);
    arr
}

/// Map bytes to field element via little-endian reduction modulo Fr.
pub fn bytes_to_fr_le(bytes: &[u8]) -> Fr { <Fr as PrimeField>::from_le_bytes_mod_order(bytes) }

/// Blake2b-512 hash mapped into Fr via from_le_bytes_mod_order.
pub fn blake2b512_to_fr(input: &[u8]) -> Fr {
    let full = blake2b512(input);
    bytes_to_fr_le(&full)
}

/// Convenience: map a 32-byte hash (e.g., truncated B2b-512) to Fr.
pub fn hash32_to_fr(h: &[u8; 32]) -> Fr { bytes_to_fr_le(h) }

/// Return the expected number of public inputs for a circuit configured with `max_revealed`.
/// Layout: params_hash, pk_hash, context_hash, sid, message_count, revealed_idx[max], revealed_vals[max]
pub fn expected_public_inputs_len(max_revealed: u32) -> usize {
    // 3 hashes + sid + message_count + max_revealed indices + max_revealed values
    5usize + (2 * (max_revealed as usize))
}

/// Encode PublicInputs into field elements in the canonical order used by the circuit.
pub fn encode_public_inputs(pi: &PublicInputs, max_revealed: u32) -> Vec<Fr> {
    let to_fr = |b: &[u8; 32]| -> Fr { <Fr as PrimeField>::from_le_bytes_mod_order(b) };
    let mut out = Vec::<Fr>::with_capacity(expected_public_inputs_len(max_revealed));
    out.push(to_fr(&pi.params_hash));
    out.push(to_fr(&pi.pk_hash));
    out.push(to_fr(&pi.context_hash));
    out.push(Fr::from(pi.sid_opt.unwrap_or(0) as u64));
    out.push(Fr::from(pi.message_count as u64));
    for i in 0..(max_revealed as usize) {
        if i < pi.revealed_idx.len() { out.push(Fr::from(pi.revealed_idx[i] as u64)); }
        else { out.push(Fr::from(0u64)); }
    }
    for i in 0..(max_revealed as usize) {
        if i < pi.revealed_vals.len() { out.push(pi.revealed_vals[i]); }
        else { out.push(Fr::from(0u64)); }
    }
    out
}

pub fn setup(max_messages: u32, max_revealed: u32) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>), SynthesisError> {
    // A dummy circuit to derive keys; fixes the public input shape via max_revealed.
    let circ = BbsPokCircuit { pi: PublicInputs { message_count: max_messages, ..Default::default() }, max_revealed, max_messages, messages: vec![<Bls12_381 as Pairing>::ScalarField::from(0u64); max_messages as usize] };
    let mut rng = StdRng::seed_from_u64(1);
    Groth16::<Bls12_381>::setup(circ, &mut rng)
}

pub fn prove(pk: &ProvingKey<Bls12_381>, pi: &PublicInputs, messages: &[Fr], max_messages: u32, max_revealed: u32) -> Result<(Proof<Bls12_381>, Vec<Fr>), SynthesisError> {
    let circ = BbsPokCircuit { pi: pi.clone(), max_revealed, max_messages, messages: messages.to_vec() };
    let mut rng = StdRng::seed_from_u64(2);
    let proof = Groth16::<Bls12_381>::prove(pk, circ, &mut rng)?;
    let publics = encode_public_inputs(pi, max_revealed);
    Ok((proof, publics))
}

pub fn verify(vk: &VerifyingKey<Bls12_381>, proof: &Proof<Bls12_381>, public_inputs: &[Fr]) -> Result<bool, SynthesisError> {
    let pvk = prepare_verifying_key(vk);
    Groth16::<Bls12_381>::verify_proof(&pvk, proof, public_inputs)
}

pub fn prepare_vk(vk: &VerifyingKey<Bls12_381>) -> PreparedVerifyingKey<Bls12_381> {
    prepare_verifying_key(vk)
}

pub mod proof;
