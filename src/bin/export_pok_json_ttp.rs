use std::env;
use std::fs;
use std::path::PathBuf;

use ark_bls12_381::{Bls12_381 as E, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use bbs_plus::{
    prelude::*,
    proof::PoKOfSignatureG1Protocol,
};
use blake2::Blake2b512;
use dock_crypto_utils::signature::MessageOrBlinding;
use rand::{rngs::StdRng, SeedableRng};
use serde::Serialize;
use sha3::{Digest, Keccak256};

#[derive(Serialize)]
struct PokJson {
    messageCount: usize,
    g1: String,
    g2: String,
    h0: String,
    H: Vec<String>,
    // Original signature (for raw pairing debug)
    sigA: String,
    sigE: String,
    sigS: String,
    messages: Vec<String>,
    APrime: String,
    ABar: String,
    d: String,
    T1: String,
    T2: String,
    revealedIdx: Vec<usize>,
    revealedVals: Vec<String>,
    challenge: String,
    respA: String,
    respH0: String,
    respR3: String,
    respSPrime: String,
    respMsgs: Vec<String>,
}

fn keccak_to_fr(bytes: &[u8]) -> Fr {
    let mut h = Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    Fr::from_be_bytes_mod_order(&out)
}

fn fq_to_be64(x: &ark_bls12_381::Fq) -> [u8; 64] {
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

fn g1_to_eip2537_bytes(p: &G1Affine) -> [u8; 128] {
    let (x, y) = (p.x, p.y);
    let xb = fq_to_be64(&x);
    let yb = fq_to_be64(&y);
    let mut out = [0u8; 128];
    out[..64].copy_from_slice(&xb);
    out[64..].copy_from_slice(&yb);
    out
}

fn fr_to_be32_hex(x: &Fr) -> String {
    let bi = x.into_bigint();
    let limbs: [u64; 4] = bi.0;
    let mut le32 = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        le32[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    let mut be32 = [0u8; 32];
    for i in 0..32 { be32[i] = le32[31 - i]; }
    format!("0x{}", hex::encode(be32))
}

fn g1_hex(p: &G1Affine) -> String {
    let b = g1_to_eip2537_bytes(p);
    format!("0x{}", hex::encode(b))
}

fn g2_hex(p: &ark_bls12_381::G2Affine) -> String {
    use ark_bls12_381::Fq2;
    let (x, y) = (p.x, p.y);
    let mut out = [0u8; 256];
    let mut xbe = [0u8; 128];
    let mut ybe = [0u8; 128];
    let c0 = fq_to_be64(&x.c0); xbe[..64].copy_from_slice(&c0);
    let c1 = fq_to_be64(&x.c1); xbe[64..].copy_from_slice(&c1);
    let d0 = fq_to_be64(&y.c0); ybe[..64].copy_from_slice(&d0);
    let d1 = fq_to_be64(&y.c1); ybe[64..].copy_from_slice(&d1);
    out[..128].copy_from_slice(&xbe);
    out[128..].copy_from_slice(&ybe);
    format!("0x{}", hex::encode(out))
}

fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    // Output path: OUT env or default ./.runtime/pok.json
    let out_path = env::var("OUT").unwrap_or_else(|_| ".runtime/pok.json".to_string());

    // Reproduce TTP params and secret
    let name = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
    let mcount: u32 = env::var("MESSAGE_COUNT").unwrap_or_else(|_| "5".into()).parse()?;
    let t: u16 = env::var("THRESHOLD").unwrap_or_else(|_| "3".into()).parse()?;
    let n: u16 = env::var("TOTAL").unwrap_or_else(|_| "4".into()).parse()?;

    let params = SignatureParamsG1::<E>::new::<Blake2b512>(name.as_bytes(), mcount);
    // Derive the same secret as TTP: StdRng seeded with 42, then deal_random_secret(t, n)
    let mut rng_sk = StdRng::seed_from_u64(42);
    let (secret, _shares, _poly) = secret_sharing_and_dkg::shamir_ss::deal_random_secret(&mut rng_sk, t, n)
        .map_err(|e| anyhow::anyhow!("deal_random_secret failed: {:?}", e))?;
    let sk = SecretKey(secret);

    // Messages: deterministic vector 0..mcount-1 mapped to 5+i (matches exporters/test style)
    let m = mcount as usize;
    let msgs: Vec<Fr> = (0..m).map(|i| Fr::from((i as u64) + 5)).collect();
    let sig = SignatureG1::<E>::new(&mut StdRng::seed_from_u64(99), &msgs, &sk, &params)
        .map_err(|e| anyhow::anyhow!("sign failed: {:?}", e))?;

    // Reveal a simple set (index 1) for consistency
    let revealed_idx: Vec<usize> = vec![1usize.min(m.saturating_sub(1))];
    let mut revealed = std::collections::BTreeMap::<usize, Fr>::new();
    for &ix in &revealed_idx { revealed.insert(ix, msgs[ix]); }

    // Build PoK
    let message_iter = msgs.iter().enumerate().map(|(i, mm)| {
        if revealed.contains_key(&i) { MessageOrBlinding::RevealMessage(mm) } else { MessageOrBlinding::BlindMessageRandomly(mm) }
    });
    let mut rng = StdRng::seed_from_u64(23);
    let pok = PoKOfSignatureG1Protocol::<E>::init(&mut rng, &sig, &params, message_iter)
        .map_err(|e| anyhow::anyhow!("pok init failed: {:?}", e))?;

    // Transcript and challenge
    let mut transcript = vec![];
    pok.challenge_contribution(&revealed, &params, &mut transcript)
        .map_err(|e| anyhow::anyhow!("challenge contrib failed: {:?}", e))?;
    let c = keccak_to_fr(&transcript);
    let proof = pok.gen_proof(&c).map_err(|e| anyhow::anyhow!("gen_proof failed: {:?}", e))?;

    // Responses ordering
    let resp1 = proof.sc_resp_1;
    let (respA, respH0) = (resp1.response1, resp1.response2);

    let mut resp_msgs: Vec<String> = vec![];
    let (resp_r3_hex, resp_sprime_hex);
    if let Some(sc2) = &proof.sc_resp_2 { // complete
        let all = &sc2.0;
        let undis_count = m - revealed.len();
        resp_msgs.extend(all.iter().take(undis_count).map(fr_to_be32_hex));
        let resp_r3 = &all[undis_count + 0];
        let resp_sprime = &all[undis_count + 1];
        resp_r3_hex = fr_to_be32_hex(resp_r3);
        resp_sprime_hex = fr_to_be32_hex(resp_sprime);
    } else { anyhow::bail!("partial responses not supported"); }

    let pj = PokJson {
        messageCount: m,
        g1: g1_hex(&params.g1),
        g2: g2_hex(&params.g2),
        h0: g1_hex(&params.h_0),
        H: params.h.iter().map(g1_hex).collect(),
    sigA: g1_hex(&sig.A),
    sigE: fr_to_be32_hex(&sig.e),
    sigS: fr_to_be32_hex(&sig.s),
    messages: msgs.iter().map(fr_to_be32_hex).collect(),
        APrime: g1_hex(&proof.A_prime),
        ABar: g1_hex(&proof.A_bar),
        d: g1_hex(&proof.d),
        T1: g1_hex(&resp1.t),
        T2: g1_hex(&proof.T2),
        revealedIdx: revealed_idx.clone(),
        revealedVals: revealed_idx.iter().map(|i| fr_to_be32_hex(&msgs[*i])).collect(),
        challenge: fr_to_be32_hex(&c),
        respA: fr_to_be32_hex(&respA),
        respH0: fr_to_be32_hex(&respH0),
        respR3: resp_r3_hex,
        respSPrime: resp_sprime_hex,
        respMsgs: resp_msgs,
    };

    let json = serde_json::to_string_pretty(&pj)?;
    let p = PathBuf::from(out_path);
    if let Some(parent) = p.parent() { std::fs::create_dir_all(parent).ok(); }
    fs::write(&p, json)?;
    println!("Wrote PoK JSON to {}", p.display());
    Ok(())
}
