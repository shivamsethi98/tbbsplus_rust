use ark_bls12_381::{Bls12_381 as E, Fq, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use bbs_plus::{
    proof::PoKOfSignatureG1Protocol,
    setup::{KeypairG2, SignatureParamsG1},
    signature::SignatureG1,
};
use blake2::Blake2b512;
use dock_crypto_utils::signature::MessageOrBlinding;
use eyre::Result;
use rand::{rngs::StdRng, SeedableRng};
use serde::Serialize;
use sha3::{Digest, Keccak256};
use std::{collections::BTreeMap, env, fs, path::PathBuf};

#[derive(Serialize)]
struct PokJson {
    messageCount: usize,
    g1: String,
    h0: String,
    H: Vec<String>,
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

fn fq_to_be64(x: &Fq) -> [u8; 64] {
    // Convert Fq into 48-byte big-endian then left-pad to 64
    let bi = x.into_bigint(); // Little-endian limbs
    let limbs: [u64; 6] = bi.0;
    // Build 48 bytes little-endian
    let mut le48 = [0u8; 48];
    for (i, limb) in limbs.iter().enumerate() {
        le48[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    // Reverse to big-endian
    let mut be48 = [0u8; 48];
    for i in 0..48 { be48[i] = le48[47 - i]; }
    // Left-pad to 64
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
    // Convert Fr into 32-byte big-endian
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

fn main() -> Result<()> {
    // Output path: first CLI arg or env OUT or default ./pok.json
    let out_path = env::args().nth(1).or_else(|| env::var("OUT").ok()).unwrap_or_else(|| "pok.json".to_string());
    let mut rng = StdRng::seed_from_u64(23);

    // Demo setup
    let m: usize = env::var("MSG_COUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    let params = SignatureParamsG1::<E>::new::<Blake2b512>(b"demo-pok", m as u32);
    let keypair = KeypairG2::<E>::generate_using_rng(&mut rng, &params);
    let msgs: Vec<Fr> = (0..m).map(|i| Fr::from((i as u64) + 5)).collect();
    let sig = SignatureG1::<E>::new(&mut rng, &msgs, &keypair.secret_key, &params).expect("sign");

    // Choose a revealed set (indices strictly increasing)
    let revealed_idx: Vec<usize> = env::var("REVEALED")
        .ok()
        .map(|s| s.split(',').filter(|t| !t.is_empty()).map(|t| t.parse::<usize>().unwrap()).collect())
        .unwrap_or_else(|| vec![1]);
    let mut revealed = BTreeMap::<usize, Fr>::new();
    for &ix in &revealed_idx { revealed.insert(ix, msgs[ix]); }

    // Build PoK protocol
    let message_iter = msgs.iter().enumerate().map(|(i, m)| {
        if revealed.contains_key(&i) { MessageOrBlinding::RevealMessage(m) } else { MessageOrBlinding::BlindMessageRandomly(m) }
    });
    let pok = PoKOfSignatureG1Protocol::<E>::init(&mut rng, &sig, &params, message_iter)
        .expect("pok init");

    // Transcript bytes and challenge
    let mut transcript = vec![];
    pok.challenge_contribution(&revealed, &params, &mut transcript)
        .expect("challenge contrib");
    let c = keccak_to_fr(&transcript);
    let proof = pok.gen_proof(&c).expect("gen proof");

    // Extract responses/order
    let resp1 = proof.sc_resp_1; // contains t (T1) and 2 responses
    let (respA, respH0) = (resp1.response1, resp1.response2);

    // bases_2 order: undisclosed H (in param index order), then d, then h0
    let mut resp_msgs = vec![];
    if let Some(sc) = &proof.sc_resp_2 { // complete responses
        let all = &sc.0;
        let undis_count = m - revealed.len();
        resp_msgs.extend(all.iter().take(undis_count).map(fr_to_be32_hex));
        let resp_r3 = &all[undis_count + 0];
        let resp_sprime = &all[undis_count + 1];
        // Build JSON
        let pj = PokJson {
            messageCount: m,
            g1: g1_hex(&params.g1),
            h0: g1_hex(&params.h_0),
            H: params.h.iter().map(g1_hex).collect(),
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
            respR3: fr_to_be32_hex(resp_r3),
            respSPrime: fr_to_be32_hex(resp_sprime),
            respMsgs: resp_msgs,
        };
    let json = serde_json::to_string_pretty(&pj)?;
        let p = PathBuf::from(out_path);
    fs::write(&p, json)?;
        println!("Wrote PoK JSON to {}", p.display());
    } else {
        eprintln!("Partial responses not supported in this exporter");
    }

    Ok(())
}
