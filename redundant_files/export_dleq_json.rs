use ark_bls12_381::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{PrimeField, UniformRand, Field, Zero};
use schnorr_pok::discrete_log::PokDiscreteLogProtocol;
use sha3::Digest;
use rand::thread_rng;
use serde::Serialize;
use std::fs::File;
use std::io::Write;

#[derive(Serialize)]
struct DleqVector {
    g1: String,
    ybar: String,
    t1: String,
    t2prime: String,
    u1: String,
    u2: String,
    z: String,
    c: String,
}

fn fq_to_be64(x: &Fq) -> [u8; 64] {
    let bi = x.into_bigint();
    // ark Fq big int uses 6 limbs (48 bytes LE)
    let limbs: [u64; 6] = bi.0;
    let mut le48 = [0u8; 48];
    for (i, limb) in limbs.iter().enumerate() {
        let bytes = limb.to_le_bytes();
        let o = i * 8;
        le48[o..o + 8].copy_from_slice(&bytes);
    }
    // Convert LE 48 -> BE 48 then left-pad to 64
    let mut be48 = [0u8; 48];
    for i in 0..48 {
        be48[i] = le48[47 - i];
    }
    let mut out = [0u8; 64];
    out[16..].copy_from_slice(&be48);
    out
}

fn g1_to_eip2537_bytes(p: &G1Affine) -> [u8; 128] {
    let (x, y) = (p.x, p.y);
    let xb = fq_to_be64(&x);
    let yb = fq_to_be64(&y);
    let mut out = [0u8; 128];
    out[..64].copy_from_slice(&xb);
    out[64..].copy_from_slice(&yb);
    out
}

fn fr_to_be32(x: &Fr) -> [u8; 32] {
    let bi = x.into_bigint();
    // Fr uses 4 limbs = 32 bytes LE
    let limbs: [u64; 4] = bi.0;
    let mut le32 = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let bytes = limb.to_le_bytes();
        let o = i * 8;
        le32[o..o + 8].copy_from_slice(&bytes);
    }
    let mut be32 = [0u8; 32];
    for i in 0..32 {
        be32[i] = le32[31 - i];
    }
    be32
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn keccak_to_fr(bytes: &[u8]) -> Fr {
    let mut h = sha3::Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    Fr::from_be_bytes_mod_order(&out)
}

fn main() -> anyhow::Result<()> {
    let mut rng = thread_rng();

    // Random scalars
    let y = Fr::rand(&mut rng);
    let k = Fr::rand(&mut rng);
    let a1 = loop {
        let t = Fr::rand(&mut rng);
        if !t.is_zero() { break t; }
    };
    let a3 = a1.inverse().unwrap();

    let gen = <G1Projective as Group>::generator().into_affine();
    let ybar = (G1Projective::from(gen) * y).into_affine();

    // Random A and A'
    let a_scalar = Fr::rand(&mut rng);
    let a = (G1Projective::from(gen) * a_scalar).into_affine();
    let aprime = (G1Projective::from(a) * a1).into_affine();

    // T1, T2, T2' = T2 * (A')^{-a3}  (additively: T2' = T2 - (A' * a3))
    let t1 = (G1Projective::from(gen) * k).into_affine();
    let t2 = (G1Projective::from(a) + (G1Projective::from(ybar) * k)).into_affine();
    let t2prime = (G1Projective::from(t2) - (G1Projective::from(aprime) * a3)).into_affine();

    // Build DLEQ using schnorr_pok with shared blinding r and witness k for both bases
    let r = Fr::rand(&mut rng);
    let p1 = PokDiscreteLogProtocol::init(k, r, &gen);   // base g1, Y = T1
    let p2 = PokDiscreteLogProtocol::init(k, r, &ybar);  // base Ybar, Y = T2'
    // Transcript: contributions from both
    let mut transcript = vec![];
    p1.challenge_contribution(&gen, &t1, &mut transcript).unwrap();
    p2.challenge_contribution(&ybar, &t2prime, &mut transcript).unwrap();
    let c = keccak_to_fr(&transcript);
    let pr1 = p1.clone().gen_proof(&c);
    let pr2 = p2.clone().gen_proof(&c);
    // Both responses equal z = r + c*k
    let z = pr1.response;
    let u1 = pr1.t;
    let u2 = pr2.t;

    let vec = DleqVector {
        g1: hex0x(&g1_to_eip2537_bytes(&gen)),
        ybar: hex0x(&g1_to_eip2537_bytes(&ybar)),
        t1: hex0x(&g1_to_eip2537_bytes(&t1)),
        t2prime: hex0x(&g1_to_eip2537_bytes(&t2prime)),
    u1: hex0x(&g1_to_eip2537_bytes(&u1)),
    u2: hex0x(&g1_to_eip2537_bytes(&u2)),
    z: hex0x(&fr_to_be32(&z)),
    c: hex0x(&fr_to_be32(&c)),
    };

    let out_path = std::env::var("DLEQ_JSON").unwrap_or_else(|_| "./dleq.json".to_string());
    let mut f = File::create(&out_path)?;
    let s = serde_json::to_string_pretty(&vec)?;
    f.write_all(s.as_bytes())?;
    eprintln!("[export_dleq_json] wrote {}", out_path);
    Ok(())
}
