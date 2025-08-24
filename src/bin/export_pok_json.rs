use ark_bls12_381::{Bls12_381 as E, Fq, Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use bbs_plus::prelude::*;
use blake2::Blake2b512;
use dock_crypto_utils::signature::MessageOrBlinding;
use eyre::Result;
use rand::{rngs::StdRng, SeedableRng};
use serde::Serialize;
use sha3::{Digest, Keccak256};
use std::{collections::BTreeMap, env, fs, path::PathBuf};
use secret_sharing_and_dkg::shamir_ss::deal_random_secret;

#[derive(Serialize)]
struct PokJson {
    message_count: usize,
    g1: String,
    h0: String,
    h: Vec<String>,
    aprime: String,
    abar: String,
    d: String,
    t1: String,
    t2: String,
    revealed_idx: Vec<usize>,
    revealed_vals: Vec<String>,
    challenge: String,
    resp_a: String,
    resp_h0: String,
    resp_r3: String,
    resp_sprime: String,
    resp_msgs: Vec<String>,
    // Optional encryption relation
    ybar: Option<String>,
    t1enc: Option<String>,
    t2enc: Option<String>,
    tenc: Option<String>,
    resp_a3: Option<String>,
    resp_k: Option<String>,
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

    // Params aligned with TTP (same label and count)
    let cred_name = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".to_string());
    let m: usize = env::var("MESSAGE_COUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    let params = SignatureParamsG1::<E>::new::<Blake2b512>(cred_name.as_bytes(), m as u32);
    let msgs: Vec<Fr> = (0..m).map(|i| Fr::from((i as u64) + 5)).collect();
    // Secret aligned with TTP (seeded, threshold/n)
    let t: u16 = env::var("THRESHOLD").unwrap_or_else(|_| "3".into()).parse().unwrap_or(3);
    let n: u16 = env::var("TOTAL").unwrap_or_else(|_| "4".into()).parse().unwrap_or(4);
    let mut rng_sk = StdRng::seed_from_u64(42);
    let (secret, _shares, _poly) = deal_random_secret::<_, Fr>(&mut rng_sk, t, n)
        .map_err(|e| eyre::eyre!("deal_random_secret failed: {:?}", e))?;
    let sk = SecretKey(secret);
    let sig = SignatureG1::<E>::new(&mut rng, &msgs, &sk, &params).expect("sign");

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
    // Build Ybar and use the new init_with_encryption; fallback to init if needed in future
    let y_sk = Fr::rand(&mut rng);
    let ybar = params.g1.mul_bigint(y_sk.into_bigint()).into_affine();
    let pok = PoKOfSignatureG1Protocol::<E>::init_with_encryption(&mut rng, &sig, &params, message_iter, &ybar)
        .expect("pok init with enc");

    // Transcript bytes and challenge
    let mut transcript = vec![];
    pok.challenge_contribution(&revealed, &params, &mut transcript)
        .expect("challenge contrib");
    let c = keccak_to_fr(&transcript);
    let proof = pok.gen_proof(&c).expect("gen proof");

    // Extract responses/order (borrow to avoid moving out of `proof`)
    let resp1_ref = &proof.sc_resp_1; // contains t (T1) and 2 responses
    let (resp_a_ref, resp_h0_ref) = (&resp1_ref.response1, &resp1_ref.response2);

    // bases_2 order: undisclosed H (in param index order), then d, then h0
    let mut resp_msgs = vec![];
    if let Some(sc) = &proof.sc_resp_2 { // complete responses
        let all = &sc.0;
        let undis_count = m - revealed.len();
        resp_msgs.extend(all.iter().take(undis_count).map(fr_to_be32_hex));
        let resp_r3 = &all[undis_count + 0];
        let resp_sprime = &all[undis_count + 1];
        // Verify all Schnorr relations (except pairing). This includes optional encryption relation.
        proof
            .verify_schnorr_proofs(&revealed, &c, params.g1, params.h_0, params.h.clone(), None)
            .map_err(|e| eyre::eyre!("verify_schnorr_proofs failed: {:?}", e))?;
        if proof.Y_bar.is_some() { println!("[export] verify_schnorr_proofs (incl. encryption) = OK"); }
        // Use library verification (includes both Schnorr relations and optional encryption, plus pairing)
        let pk = PublicKeyG2::generate_using_secret_key(&sk, &params);
        proof
            .verify(&revealed, &c, pk, params.clone())
            .map_err(|e| eyre::eyre!("off-chain proof.verify failed: {:?}", e))?;

        // Optional encryption relation fields for JSON (no extra manual checks needed)
        let (y_hex, t1e_hex, t2e_hex, tenc_hex, resp_a3_hex, resp_k_hex) = if let (Some(yb), Some(t1e), Some(t2e), Some(enc)) = (
            proof.Y_bar.as_ref(),
            proof.T1_enc.as_ref(),
            proof.T2_enc.as_ref(),
            proof.sc_resp_enc.as_ref(),
        ) {
            (Some(g1_hex(yb)), Some(g1_hex(t1e)), Some(g1_hex(t2e)), Some(g1_hex(&enc.t)), Some(fr_to_be32_hex(&enc.response1)), Some(fr_to_be32_hex(&enc.response2)))
        } else { (None, None, None, None, None, None) };
        // Build JSON
        if let (Some(y_hex), Some(t1e_hex), Some(t2e_hex), Some(tenc_hex), Some(resp_a3_hex), Some(resp_k_hex)) =
            (&y_hex, &t1e_hex, &t2e_hex, &tenc_hex, &resp_a3_hex, &resp_k_hex)
        {
            println!(
            "Encryption relation:\n  Ybar: {}\n  T1enc: {}\n  T2enc: {}\n  Tenc: {}\n  respA3: {}\n  respK: {}",
            y_hex, t1e_hex, t2e_hex, tenc_hex, resp_a3_hex, resp_k_hex
            );
        }
        let pj = PokJson {
            message_count: m,
            g1: g1_hex(&params.g1),
            h0: g1_hex(&params.h_0),
            h: params.h.iter().map(g1_hex).collect(),
            aprime: g1_hex(&proof.A_prime),
            abar: g1_hex(&proof.A_bar),
            d: g1_hex(&proof.d),
            t1: g1_hex(&resp1_ref.t),
            t2: g1_hex(&proof.T2),
            revealed_idx: revealed_idx.clone(),
            revealed_vals: revealed_idx.iter().map(|i| fr_to_be32_hex(&msgs[*i])).collect(),
            challenge: fr_to_be32_hex(&c),
            resp_a: fr_to_be32_hex(resp_a_ref),
            resp_h0: fr_to_be32_hex(resp_h0_ref),
            resp_r3: fr_to_be32_hex(resp_r3),
            resp_sprime: fr_to_be32_hex(resp_sprime),
            resp_msgs: resp_msgs,
            ybar: y_hex,
            t1enc: t1e_hex,
            t2enc: t2e_hex,
            tenc: tenc_hex,
            resp_a3: resp_a3_hex,
            resp_k: resp_k_hex,
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
