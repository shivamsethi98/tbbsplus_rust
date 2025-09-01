
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



pub fn fq2_pair_to_be(x_c0: &Fq, x_c1: &Fq) -> [u8; 128] {
    let c0 = fq_to_be64(x_c0);
    let c1 = fq_to_be64(x_c1);
    let mut out = [0u8; 128];
    out[..64].copy_from_slice(&c0);
    out[64..].copy_from_slice(&c1);
    out
}


pub fn u256_to_fr<F: PrimeField>(v: &U256) -> F {
    let mut be = [0u8; 32];
    v.to_big_endian(&mut be);
    F::from_be_bytes_mod_order(&be)
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
    
    let (x, y) = (p.x, p.y);
    let mut out = [0u8; 256];
    let xbe = fq2_to_be64_pair(&x.c0, &x.c1);
    let ybe = fq2_to_be64_pair(&y.c0, &y.c1);
    out[..128].copy_from_slice(&xbe);
    out[128..].copy_from_slice(&ybe);
    out
}

pub fn eip2537_g1_to_affine(bytes128: &[u8]) -> anyhow::Result<<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine> {
    
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