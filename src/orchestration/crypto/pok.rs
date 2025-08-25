
use ark_bls12_381::{Bls12_381, Fr, Fq};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::{rngs::StdRng, SeedableRng}, UniformRand};
use bbs_plus::prelude::*;
use blake2::Blake2b512;
use ark_ff::PrimeField;
use schnorr_pok::{SchnorrChallengeContributor, pok_generalized_pedersen::{SchnorrCommitment, compute_random_oracle_challenge}};
use ethers::types::Bytes as EthBytes;
use ethers::types::TxHash;
use ethers::types::U256;

pub use bbs_plus::proof::PoKOfSignatureG1Proof as PokProof;


use crate::orchestration::crypto::encoding::{fr_to_u256, g1_to_eip2537_bytes, keccak_to_fr, eip2537_g1_to_affine};

pub struct EncExtras {
    pub t1_b: EthBytes,
    pub t2enc_b: EthBytes,
    pub t_enc_b: EthBytes,
    pub resp_a3_u: U256,
    pub resp_k_u: U256,
}

pub fn build_pok_and_proof(
    params_bbs: &SignatureParamsG1<Bls12_381>,
    sig_struct: &bbs_plus::signature::SignatureG1<Bls12_381>,
    messages: &Vec<Fr>,
    ybar_aff: &<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine,
    revealed_idx: &Vec<u32>,
) -> anyhow::Result<(PokProof<Bls12_381>, Fr, Vec<u32>)> {
    use ark_std::{rand::{rngs::StdRng, SeedableRng}, UniformRand};
    use dock_crypto_utils::signature::MessageOrBlinding;
    let mut revealed_msgs = std::collections::BTreeMap::<usize, Fr>::new();
    for &ix in revealed_idx.iter() { let i = ix as usize; if i < messages.len() { revealed_msgs.insert(i, messages[i]); } }
    let mut rng = StdRng::seed_from_u64(99);
    let message_iter = messages.iter().enumerate().map(|(i, m)| {
        if revealed_msgs.contains_key(&i) { MessageOrBlinding::RevealMessage(m) } else { MessageOrBlinding::BlindMessageRandomly(m) }
    });
    let pok = bbs_plus::proof::PoKOfSignatureG1Protocol::<Bls12_381>::init_with_encryption(&mut rng, sig_struct, params_bbs, message_iter, ybar_aff)
        .map_err(|e| anyhow::anyhow!("pok init_with_encryption failed: {:?}", e))?;
    let mut transcript = Vec::new();
    pok.challenge_contribution(&revealed_msgs, params_bbs, &mut transcript)
        .map_err(|e| anyhow::anyhow!("challenge contrib failed: {:?}", e))?;
    let c_fr = keccak_to_fr(&transcript);
    let proof = pok.gen_proof(&c_fr).map_err(|e| anyhow::anyhow!("gen_proof failed: {:?}", e))?;
    Ok((proof, c_fr, revealed_idx.clone()))
}

pub fn build_presentation_tuples(
    params_bbs: &SignatureParamsG1<Bls12_381>,
    proof: &PokProof<Bls12_381>,
    revealed_idx: &Vec<u32>,
    messages: &Vec<Fr>,
    onchain_mcount: u32,
    c_fr: &Fr,
) -> anyhow::Result<
    (
        (EthBytes, EthBytes, EthBytes),
        (u32, EthBytes, EthBytes, Vec<EthBytes>),
        (Vec<u32>, Vec<U256>),
        U256,
        (EthBytes, U256, U256),
        (EthBytes, Vec<U256>, U256, U256),
        EncExtras,
    ),
> {
    use crate::orchestration::crypto::encoding::{g1_to_eip2537_bytes, fr_to_u256};
    fn check_len(label: &str, b: &EthBytes, exp: usize) -> anyhow::Result<()> { if b.len() != exp { anyhow::bail!("{}: expected {} bytes, got {}", label, exp, b.len()); } Ok(()) }
    let ctx_g1 = EthBytes::from(g1_to_eip2537_bytes(&params_bbs.g1).to_vec());
    let ctx_h0 = EthBytes::from(g1_to_eip2537_bytes(&params_bbs.h_0).to_vec());
    let ctx_h: Vec<EthBytes> = params_bbs.h.iter().map(|h| EthBytes::from(g1_to_eip2537_bytes(h).to_vec())).collect();
    check_len("ctx.g1", &ctx_g1, 128)?; check_len("ctx.h0", &ctx_h0, 128)?; for (i, hh) in ctx_h.iter().enumerate() { check_len(&format!("ctx.H[{}]", i), hh, 128)?; }
    let ctx_t = (onchain_mcount, ctx_g1, ctx_h0, ctx_h);
    let sig_ap = EthBytes::from(g1_to_eip2537_bytes(&proof.A_prime).to_vec());
    let sig_ab = EthBytes::from(g1_to_eip2537_bytes(&proof.A_bar).to_vec());
    let sig_d  = EthBytes::from(g1_to_eip2537_bytes(&proof.d).to_vec());
    check_len("sig.APrime", &sig_ap, 128)?; check_len("sig.ABar", &sig_ab, 128)?; check_len("sig.d", &sig_d, 128)?;
    let sig_t = (sig_ap.clone(), sig_ab.clone(), sig_d);
    let revealed_vals_u256: Vec<U256> = revealed_idx.iter().map(|ix| fr_to_u256(&messages[*ix as usize])).collect();
    let revealed_t = (revealed_idx.clone(), revealed_vals_u256);
    let challenge_u256 = fr_to_u256(c_fr);
    let p1_t_t1 = EthBytes::from(g1_to_eip2537_bytes(&proof.sc_resp_1.t).to_vec());
    check_len("p1.T1", &p1_t_t1, 128)?;
    let p1_t = (p1_t_t1, fr_to_u256(&proof.sc_resp_1.response1), fr_to_u256(&proof.sc_resp_1.response2));
    let sc2 = proof.sc_resp_2.as_ref().ok_or_else(|| anyhow::anyhow!("missing sc_resp_2"))?;
    let undis_count = (onchain_mcount as usize) - revealed_idx.len();
    let resp_msgs: Vec<U256> = sc2.0.iter().take(undis_count).map(fr_to_u256).collect();
    if resp_msgs.len() != undis_count { anyhow::bail!("respMsgs length {} != undisclosed count {}", resp_msgs.len(), undis_count); }
    let resp_r3 = fr_to_u256(&sc2.0[undis_count]);
    let resp_sprime = fr_to_u256(&sc2.0[undis_count + 1]);
    let p2_t_t2 = EthBytes::from(g1_to_eip2537_bytes(&proof.T2).to_vec());
    check_len("p2.T2", &p2_t_t2, 128)?;
    let p2_t = (p2_t_t2, resp_msgs, resp_r3, resp_sprime);
    let t1_b    = EthBytes::from(g1_to_eip2537_bytes(proof.T1_enc.as_ref().ok_or_else(|| anyhow::anyhow!("missing T1_enc"))?).to_vec());
    let t2enc_b = EthBytes::from(g1_to_eip2537_bytes(proof.T2_enc.as_ref().ok_or_else(|| anyhow::anyhow!("missing T2_enc"))?).to_vec());
    let t_enc_b = EthBytes::from(g1_to_eip2537_bytes(&proof.sc_resp_enc.as_ref().ok_or_else(|| anyhow::anyhow!("missing sc_resp_enc"))?.t).to_vec());
    let resp_a3_u = fr_to_u256(&proof.sc_resp_enc.as_ref().unwrap().response1);
    let resp_k_u = fr_to_u256(&proof.sc_resp_enc.as_ref().unwrap().response2);
    let enc_extras = EncExtras { t1_b, t2enc_b, t_enc_b, resp_a3_u, resp_k_u };
    Ok((sig_t, ctx_t, revealed_t, challenge_u256, p1_t, p2_t, enc_extras))
}


pub fn decode_commitment_pok_for_onchain(
    proof_bytes: &[u8]
) -> anyhow::Result<(Vec<u32>, EthBytes, U256, Vec<U256>)> {
    use ark_serialize::CanonicalDeserialize;
    use std::io::Read;
    // hidden_len || hidden_indices || T || c || rlen || responses
    let mut rdr = std::io::Cursor::new(proof_bytes);
    let mut u32buf = [0u8; 4];
    rdr.read_exact(&mut u32buf)?;
    let hidden_len = u32::from_be_bytes(u32buf) as usize;
    let mut hidden_idx = Vec::with_capacity(hidden_len);
    for _ in 0..hidden_len { rdr.read_exact(&mut u32buf)?; hidden_idx.push(u32::from_be_bytes(u32buf)); }
    let t_aff: <Bls12_381 as ark_ec::pairing::Pairing>::G1Affine = CanonicalDeserialize::deserialize_compressed(&mut rdr)?;
    let mut tb = [0u8; 128]; tb.copy_from_slice(&g1_to_eip2537_bytes(&t_aff));
    let c_fr: Fr = CanonicalDeserialize::deserialize_compressed(&mut rdr)?;
    let c_u256 = fr_to_u256(&c_fr);
    rdr.read_exact(&mut u32buf)?;
    let rlen = u32::from_be_bytes(u32buf) as usize;
    let mut responses_u256 = Vec::with_capacity(rlen);
    for _ in 0..rlen {
        let rj: Fr = CanonicalDeserialize::deserialize_compressed(&mut rdr)?;
        responses_u256.push(fr_to_u256(&rj));
    }
    Ok((hidden_idx, EthBytes::from(tb.to_vec()), c_u256, responses_u256))
}

pub fn build_commitment_pok(
    params: &SignatureParamsG1<Bls12_381>,
    commitment: &<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine,
    hidden_msgs: &std::collections::BTreeMap<usize, Fr>,
    blinding: &Fr,
    mcount: u32,
    sid: u64,
    cred_name: &str,
    revealed_idx: &Vec<u32>,
    revealed_vals: &Vec<U256>,
    context: &Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    
    

    // Bases for Schnorr: [h_0] for blinding, and [h_i] for each hidden i
    let mut bases = Vec::with_capacity(1 + hidden_msgs.len());
    bases.push(params.h_0);
    let mut witnesses = Vec::with_capacity(1 + hidden_msgs.len());
    witnesses.push(*blinding);
    let mut hidden_indices_sorted: Vec<usize> = hidden_msgs.keys().copied().collect();
    hidden_indices_sorted.sort_unstable();
    for i in hidden_indices_sorted.iter() {
        bases.push(params.h[*i]);
        witnesses.push(*hidden_msgs.get(i).unwrap());
    }
    // y is the commitment; not used directly here as we serialize t and verify at issuers
    // Random blindings for Schnorr
    let mut rng = StdRng::seed_from_u64(rand::random::<u64>());
    let blindings = (0..witnesses.len()).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let comm = SchnorrCommitment::new(&bases, blindings);

    // Transcript for challenge: domain separator + sid + name + mcount + revealed pairs sorted + hidden idx set + commitment + t + context
    let mut chal_bytes = Vec::new();
    chal_bytes.extend_from_slice(b"TBBS+_Blind_PoK_v1");
    chal_bytes.extend_from_slice(&sid.to_be_bytes());
    chal_bytes.extend_from_slice(&(mcount as u64).to_be_bytes());
    chal_bytes.extend_from_slice(cred_name.as_bytes());
    // revealed pairs sorted by idx
    let mut pairs: Vec<(u32, &U256)> = revealed_idx.iter().cloned().zip(revealed_vals.iter()).collect();
    pairs.sort_by_key(|(i, _)| *i);
    for (i, v) in pairs.into_iter() {
        chal_bytes.extend_from_slice(&i.to_be_bytes());
        let mut be = [0u8; 32];
        v.to_big_endian(&mut be);
        chal_bytes.extend_from_slice(&be);
    }
    // hidden indices
    for i in hidden_indices_sorted.iter() {
        let i_u32 = *i as u32;
        chal_bytes.extend_from_slice(&i_u32.to_be_bytes());
    }
    // commitment and Schnorr t contribution
    commitment.serialize_compressed(&mut chal_bytes)?;
    SchnorrChallengeContributor::challenge_contribution(&comm, &mut chal_bytes)
        .map_err(|e| anyhow::anyhow!("challenge_contribution failed: {:?}", e))?;
    // context
    chal_bytes.extend_from_slice(context);

    // Compute challenge using Blake2b512
    let c: Fr = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
    let resp = comm.response(&witnesses, &c)
        .map_err(|e| anyhow::anyhow!("Schnorr response failed: {:?}", e))?;

    // Serialize proof bytes: hidden_len || hidden_indices || t || c || rlen || responses
    let mut out = Vec::new();
    // encode hidden count and indices
    let hidden_len = hidden_indices_sorted.len() as u32;
    out.extend_from_slice(&hidden_len.to_be_bytes());
    for i in hidden_indices_sorted.iter() {
        let i_u32 = *i as u32;
        out.extend_from_slice(&i_u32.to_be_bytes());
    }
    // encode t (commitment to randomness)
    comm.t.serialize_compressed(&mut out)?;
    // encode challenge c
    c.serialize_compressed(&mut out)?;
    // encode responses count and values
    let rlen = resp.len() as u32;
    out.extend_from_slice(&rlen.to_be_bytes());
    for j in 0..resp.len() {
        let rj = resp.get_response(j)
            .map_err(|e| anyhow::anyhow!("get_response failed: {:?}", e))?;
        rj.serialize_compressed(&mut out)?;
    }
    Ok(out)
}

// Verify commitment PoK from on-chain fields (moved from helpers; canonical version here)
pub fn verify_commitment_pok_from_fields(
    params: &SignatureParamsG1<Bls12_381>,
    commitment: &<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine,
    sid: u64,
    cred_name: &str,
    revealed_idx: &Vec<u32>,
    revealed_vals: &Vec<U256>,
    context: &[u8],
    hidden_idx: Vec<u32>,
    t_eip: &[u8],
    c: &Fr,
    responses: &Vec<Fr>,
) -> anyhow::Result<()> {
    use blake2::Blake2b512;
    use schnorr_pok::pok_generalized_pedersen::{SchnorrResponse, compute_random_oracle_challenge};

    let t = eip2537_g1_to_affine(t_eip)?;
    // Bases and y
    let mut bases = Vec::with_capacity(1 + hidden_idx.len());
    bases.push(params.h_0);
    for i in hidden_idx.iter() { bases.push(params.h[*i as usize]); }
    let y = *commitment;
    let resp = SchnorrResponse::<ark_bls12_381::G1Affine>(responses.clone());
    // Recompute challenge transcript
    let mut chal_bytes = Vec::new();
    chal_bytes.extend_from_slice(b"TBBS+_Blind_PoK_v1");
    chal_bytes.extend_from_slice(&sid.to_be_bytes());
    chal_bytes.extend_from_slice(&(params.h.len() as u64).to_be_bytes());
    chal_bytes.extend_from_slice(cred_name.as_bytes());
    let mut pairs: Vec<(u32, &U256)> = revealed_idx.iter().cloned().zip(revealed_vals.iter()).collect();
    pairs.sort_by_key(|(i, _)| *i);
    for (i, v) in pairs.into_iter() { chal_bytes.extend_from_slice(&i.to_be_bytes()); let mut be=[0u8;32]; v.to_big_endian(&mut be); chal_bytes.extend_from_slice(&be); }
    for i in hidden_idx.iter() { chal_bytes.extend_from_slice(&i.to_be_bytes()); }
    commitment.serialize_compressed(&mut chal_bytes)?;
    let mut t_ser = Vec::new();
    t.serialize_compressed(&mut t_ser)?;
    chal_bytes.extend_from_slice(&t_ser);
    chal_bytes.extend_from_slice(context);
    let c_check: Fr = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
    if *c != c_check { anyhow::bail!("commitment PoK challenge mismatch"); }
    // Verify Schnorr relation
    resp.is_valid(&bases, &y, &t, c).map_err(|e| anyhow::anyhow!("invalid PoK: {:?}", e))
}
