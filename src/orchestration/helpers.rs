
use ark_bls12_381::{Bls12_381, Fr, Fq};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::{rngs::StdRng, SeedableRng}, UniformRand};
use bbs_plus::prelude::*;
use blake2::Blake2b512;
use ark_ff::PrimeField;
use schnorr_pok::{SchnorrChallengeContributor, pok_generalized_pedersen::{SchnorrCommitment, compute_random_oracle_challenge}};
use ethers::types::Bytes as EthBytes;
use ethers::types::TxHash;
use ethers::types::U256;



pub fn fq2_pair_to_be(x_c0: &Fq, x_c1: &Fq) -> [u8; 128] {
    let c0 = fq_to_be64(x_c0);
    let c1 = fq_to_be64(x_c1);
    let mut out = [0u8; 128];
    out[..64].copy_from_slice(&c0);
    out[64..].copy_from_slice(&c1);
    out
}


// Decode the locally-built commitment PoK into fields needed for on-chain verification
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

// --- Persistence helpers for per-sid artifacts ---
pub fn persist_share(user_id: &str, cred_name: &str, sid: u64, idx: u16, payload: &[u8]) -> anyhow::Result<()> {
    use std::fs;
    use std::path::PathBuf;
    let dir: PathBuf = [".runtime", "users", user_id, cred_name, &format!("sid_{}", sid), "shares"].iter().collect();
    fs::create_dir_all(&dir)?;
    let fp = dir.join(format!("{}.bin", idx));
    fs::write(fp, payload)?;
    Ok(())
}

pub fn load_persisted_shares(user_id: &str, cred_name: &str, sid: u64) -> anyhow::Result<Vec<Vec<u8>>> {
    use std::fs;
    use std::path::PathBuf;
    let dir: PathBuf = [".runtime", "users", user_id, cred_name, &format!("sid_{}", sid), "shares"].iter().collect();
    if !dir.exists() { return Ok(Vec::new()); }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let e = entry?;
        if e.file_type()?.is_file() {
            out.push(fs::read(e.path())?);
        }
    }
    Ok(out)
}

pub fn persist_request_meta(user_id: &str, cred_name: &str, sid: u64, tx_hash: TxHash, block_number: u64) -> anyhow::Result<()> {
    use std::fs;
    use std::path::PathBuf;
    let dir: PathBuf = [".runtime", "users", user_id, cred_name, &format!("sid_{}", sid)].iter().collect();
    fs::create_dir_all(&dir)?;
    let meta = serde_json::json!({
        "tx": format!("0x{:x}", tx_hash),
        "block": block_number,
    });
    fs::write(dir.join("request_meta.json"), serde_json::to_vec_pretty(&meta)?)?;
    Ok(())
}


pub fn u256_to_fr<F: PrimeField>(v: &U256) -> F {
    let mut be = [0u8; 32];
    v.to_big_endian(&mut be);
    F::from_be_bytes_mod_order(&be)
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
    use ark_ec::AffineRepr;
    use std::collections::BTreeMap;

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

pub fn fr_to_u256(fr: &Fr) -> U256 {
    let bi = fr.into_bigint();
    let limbs: [u64; 4] = bi.0;
    let mut le32 = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        le32[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    let mut be32 = [0u8; 32];
    for i in 0..32 { be32[i] = le32[31 - i]; }
    U256::from_big_endian(&be32)
}

pub fn keccak_to_fr(bytes: &[u8]) -> Fr {
    use sha3::Digest;
    let mut h = sha3::Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    Fr::from_be_bytes_mod_order(&out)
}


pub fn fq_to_be64(x: &Fq) -> [u8; 64] {
    let bi = x.into_bigint();
    let limbs: [u64; 6] = bi.0;
    let mut le48 = [0u8; 48];
    for (i, limb) in limbs.iter().enumerate() {
        le48[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    let mut be48 = [0u8; 48];
    for i in 0..48 { be48[i] = le48[47 - i]; }
    let mut out = [0u8; 64];
    out[16..].copy_from_slice(&be48);
    out
}

pub fn g1_to_eip2537_bytes(p: &<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine) -> [u8; 128] {
    let (x, y) = (p.x, p.y);
    let xb = fq_to_be64(&x);
    let yb = fq_to_be64(&y);
    let mut out = [0u8; 128];
    out[..64].copy_from_slice(&xb);
    out[64..].copy_from_slice(&yb);
    out
}

pub fn fq2_to_be64_pair(x_c0: &Fq, x_c1: &Fq) -> [u8; 128] {
    let x0 = fq_to_be64(x_c0);
    let x1 = fq_to_be64(x_c1);
    let mut out = [0u8; 128];
    out[..64].copy_from_slice(&x0);
    out[64..].copy_from_slice(&x1);
    out
}

pub fn g2_to_eip2537_bytes(p: &<Bls12_381 as ark_ec::pairing::Pairing>::G2Affine) -> [u8; 256] {
    use ark_bls12_381::Fq2;
    let (x, y) = (p.x, p.y);
    let mut out = [0u8; 256];
    let xbe = fq2_to_be64_pair(&x.c0, &x.c1);
    let ybe = fq2_to_be64_pair(&y.c0, &y.c1);
    out[..128].copy_from_slice(&xbe);
    out[128..].copy_from_slice(&ybe);
    out
}

pub fn eip2537_g1_to_affine(bytes128: &[u8]) -> anyhow::Result<<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine> {
    use ark_ec::AffineRepr;
    if bytes128.len() != 128 { anyhow::bail!("bad g1 len"); }
    let mut x_be48 = [0u8; 48];
    let mut y_be48 = [0u8; 48];
    x_be48.copy_from_slice(&bytes128[16..64]);
    y_be48.copy_from_slice(&bytes128[80..128]);
    let x = Fq::from_be_bytes_mod_order(&x_be48);
    let y = Fq::from_be_bytes_mod_order(&y_be48);
    let p = ark_bls12_381::G1Affine::new(x, y);
    Ok(p)
}

pub fn eip2537_g2_to_affine(bytes256: &[u8]) -> anyhow::Result<<Bls12_381 as ark_ec::pairing::Pairing>::G2Affine> {
    use ark_bls12_381::{Fq2, G2Affine};
    use ark_ec::AffineRepr;
    if bytes256.len() != 256 { anyhow::bail!("bad g2 len"); }
    // bytes are (x.c0||x.c1||y.c0||y.c1), each limb 64 bytes with left pad
    let mut x0_be48 = [0u8; 48];
    let mut x1_be48 = [0u8; 48];
    let mut y0_be48 = [0u8; 48];
    let mut y1_be48 = [0u8; 48];
    x0_be48.copy_from_slice(&bytes256[16..64]);
    x1_be48.copy_from_slice(&bytes256[80..128]);
    y0_be48.copy_from_slice(&bytes256[144..192]);
    y1_be48.copy_from_slice(&bytes256[208..256]);
    let x0 = Fq::from_be_bytes_mod_order(&x0_be48);
    let x1 = Fq::from_be_bytes_mod_order(&x1_be48);
    let y0 = Fq::from_be_bytes_mod_order(&y0_be48);
    let y1 = Fq::from_be_bytes_mod_order(&y1_be48);
    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);
    let p = G2Affine::new(x, y);
    Ok(p)
}

// fn bls12_381_g2_generator_bytes() -> [u8; 256] {
//     use ark_ec::CurveGroup;
//     let gen = <ark_bls12_381::G2Projective as CurveGroup>::Affine::generator();
//     g2_to_eip2537_bytes(&gen)
// }