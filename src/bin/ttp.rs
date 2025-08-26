// TTP process: deploys/initializes Params, derives threshold key shares, and associates shares to issuers by index.
// Usage: cargo run --bin ttp --features mpc
// Env: ETH_WS, CHAIN_ID, OWNER_PK, PARAMS_CONTRACT? (optional), CRED_NAME, THRESHOLD, TOTAL, MESSAGE_COUNT

use std::env;
use std::fs;
use std::path::Path;

use anyhow::Context;
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;
use base64::Engine;
use ethers::contract::abigen;
use ethers::prelude::*;
use ethers::abi::Abi;
use ethers::providers::{Provider, Ws};
use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
use ark_ec::{CurveGroup, AffineRepr};
use ark_ff::PrimeField;
use blake2::Blake2b512;
use bbs_plus::prelude::*;
use tbbsplus_rust::orchestration::crypto::encoding::{
    g2_to_eip2537_bytes,
    fq2_pair_to_be,
};

abigen!(
    Params,
    "artifacts/contracts/Params.sol/Params.json"
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let chain_id: u64 = env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse()?;
    let owner_pk: LocalWallet = env::var("OWNER_PK")
        .context("OWNER_PK missing")?
        .parse::<LocalWallet>()?
        .with_chain_id(chain_id);
    let cred_name = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
    let t: u16 = env::var("THRESHOLD").unwrap_or_else(|_| "3".into()).parse()?;
    let n: u16 = env::var("TOTAL").unwrap_or_else(|_| "4".into()).parse()?;
    let mcount: u32 = env::var("MESSAGE_COUNT").unwrap_or_else(|_| "5".into()).parse()?;

    let ws = Provider::<Ws>::connect(ws_url).await?;
    let client = std::sync::Arc::new(SignerMiddleware::new(ws, owner_pk));

    // Attach or deploy Params
    let params_addr = match env::var("PARAMS_CONTRACT") {
        Ok(a) => a.parse()?,
        Err(_) => {
            let factory = Params::deploy(client.clone(), ())?;
            let contract = factory.send().await?;
            let addr = contract.address();
            println!("export PARAMS_CONTRACT={addr:?}");
            addr
        }
    };
    let params = Params::new(params_addr, client.clone());

    // Sanity-check that contract code exists at address
    let code = client.provider().get_code(params.address(), None).await?;
    println!(
        "TTP: attached Params at {:?}, code_len={} bytes",
        params.address(),
        code.as_ref().len()
    );
    if code.as_ref().is_empty() {
        return Err(anyhow::anyhow!(
            "no contract code at PARAMS_CONTRACT {}; check deployment",
            params.address()
        ));
    }

    // Generate threshold keys
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
    let (secret, shares, _poly) = deal_random_secret(&mut rng, t, n)
        .map_err(|e| anyhow::anyhow!("deal_random_secret: {:?}", e))?;
    let shares: Vec<Fr> = shares.0.into_iter().map(|s| s.share).collect();

    // Compute pkG2 from the same secret deterministically and store in Params for client pairing checks
    let params_bbs = SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(cred_name.as_bytes(), mcount);
    let g2 = params_bbs.g2;
    let pk_proj = g2.mul_bigint(secret.into_bigint());
    let pk_affine = pk_proj.into_affine();


    // EIP-2537 expects FP2 limbs in (c0 || c1) order per coordinate
    let xbe = fq2_pair_to_be(&pk_affine.x.c0, &pk_affine.x.c1);
    let ybe = fq2_pair_to_be(&pk_affine.y.c0, &pk_affine.y.c1);
    let mut pk_bytes = vec![0u8; 256];
    pk_bytes[..128].copy_from_slice(&xbe);
    pk_bytes[128..].copy_from_slice(&ybe);

    // Write pkG2 hex for setup script to set on-chain via Hardhat (owner signer)
    let pk_hex = format!("0x{}", hex::encode(&pk_bytes));
    let _ = std::fs::write(".runtime.pk_g2.hex", &pk_hex);
    println!("export PK_G2_HEX={}", pk_hex);

    // Also export the canonical G2 generator bytes in the same 256-byte format for consumers that need it (e.g., tests)
    let g2gen_affine = <ark_bls12_381::G2Projective as CurveGroup>::Affine::generator();
    let xgen = fq2_pair_to_be(&g2gen_affine.x.c0, &g2gen_affine.x.c1);
    let ygen = fq2_pair_to_be(&g2gen_affine.y.c0, &g2gen_affine.y.c1);
    let mut g2gen_bytes = vec![0u8; 256];
    g2gen_bytes[..128].copy_from_slice(&xgen);
    g2gen_bytes[128..].copy_from_slice(&ygen);
    println!("export G2_GEN_256=0x{}", hex::encode(&g2gen_bytes));

    // Also export the params-specific G2 base used to compute pk (since it's not the canonical generator)
    let xg2 = fq2_pair_to_be(&g2.x.c0, &g2.x.c1);
    let yg2 = fq2_pair_to_be(&g2.y.c0, &g2.y.c1);
    let mut g2base_bytes = vec![0u8; 256];
    g2base_bytes[..128].copy_from_slice(&xg2);
    g2base_bytes[128..].copy_from_slice(&yg2);
    println!("export G2_BASE_256=0x{}", hex::encode(&g2base_bytes));

    // --- Opener accumulator secret: Shamir shares (t-of-n) and commitments ---
    // Generate a fresh secret alpha for openers (per-credential), deal t-of-n shares among openers
    let (alpha, opener_shares, _poly) = deal_random_secret::<_, Fr>(&mut rng, t, n)
        .map_err(|e| anyhow::anyhow!("deal_random_secret (openers): {:?}", e))?;
    use ark_ec::CurveGroup as _;
    // Ybar = g1 * alpha (used by encryption/opening relation)
    let ybar_aff = params_bbs.g1.mul_bigint(alpha.into_bigint()).into_affine();
    let ybar_bytes = g1_to_eip2537_bytes(&ybar_aff).to_vec();
    // Accumulator public key in G2: pkAcc = g2 * alpha
    let opener_pk_aff = params_bbs.g2.mul_bigint(alpha.into_bigint()).into_affine();
    let opener_pk_bytes = g2_to_eip2537_bytes(&opener_pk_aff).to_vec();

    // Also set g1, h0, H, g2base, pkG2 on-chain (requires OWNER to call onlyOwner fns)
    // Helper: convert G1 affine to 128-byte EIP-2537 format (x||y with 16-byte zero pad per coord)
    fn fq_to_be64_g1(x: &ark_bls12_381::Fq) -> [u8; 64] {
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
    fn g1_to_eip2537_bytes(p: &<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine) -> [u8; 128] {
        let (x, y) = (p.x, p.y);
        let xb = fq_to_be64_g1(&x);
        let yb = fq_to_be64_g1(&y);
        let mut out = [0u8; 128];
        out[..64].copy_from_slice(&xb);
        out[64..].copy_from_slice(&yb);
        out
    }

    // g1/h0/H from label-derived params
    let g1_b = g1_to_eip2537_bytes(&params_bbs.g1).to_vec();
    let h0_b = g1_to_eip2537_bytes(&params_bbs.h_0).to_vec();
    let mut h_bytes: Vec<Vec<u8>> = Vec::with_capacity(params_bbs.h.len());
    for h in params_bbs.h.iter() { h_bytes.push(g1_to_eip2537_bytes(h).to_vec()); }

    // Build opener commitments Y_i = g2 * y_i (indices 1..=n)
    let mut indices: Vec<u16> = Vec::new();
    let mut commits: Vec<ethers::types::Bytes> = Vec::new();
    for (idx1, share) in opener_shares.0.iter().enumerate() {
        let y_i: Fr = share.share;
        let y_i_g2 = params_bbs.g2.mul_bigint(y_i.into_bigint()).into_affine();
        let y_i_bytes = g2_to_eip2537_bytes(&y_i_g2).to_vec();
        indices.push((idx1 as u16) + 1);
        commits.push(ethers::types::Bytes::from(y_i_bytes));
    }

    // Build compact blob: g1 || h0 || g2base || pkG2 || openerYbar || openerPkG2 (no H)
    let mut blob: Vec<u8> = Vec::with_capacity(128 + 128 + 256 + 256 + 128 + 256);
    blob.extend_from_slice(&g1_b);
    blob.extend_from_slice(&h0_b);
    blob.extend_from_slice(&g2base_bytes);
    blob.extend_from_slice(&pk_bytes);
    blob.extend_from_slice(&ybar_bytes);
    blob.extend_from_slice(&opener_pk_bytes);

    // One-shot setup: params scalars, blob, and opener commitments
    params
        .setup_all(
            cred_name.clone(),
            mcount.into(),
            t.into(),
            n.into(),
            vec![U256::from(1u64), U256::from(2u64)],
            blob.clone().into(),
            indices.clone(),
            commits.clone(),
        )
        .send()
        .await?
        .await?;

    // Verify on-chain dataHash matches the blob we set
    let on_hash: [u8; 32] = params.get_data_hash_by_name(cred_name.clone()).call().await?;
    let local_hash = ethers::utils::keccak256(&blob);
    if on_hash != local_hash { println!("WARNING: dataHash mismatch: on-chain {:x?} vs local {:x?}", on_hash, local_hash); }

    // Set H separately (allows future changes per suite)
    params
        .set_h_by_name(
            cred_name.clone(),
            h_bytes.clone().into_iter().map(ethers::types::Bytes::from).collect(),
        )
        .send()
        .await?
        .await?;

    // Persist opener secret shares for openers to read (t-of-n)
    {
        use ark_serialize::CanonicalSerialize as _;
        use tbbsplus_rust::orchestration::crypto::encoding::g2_to_eip2537_bytes;
        let mut shares_map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        let mut commits_map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        for (idx1, share) in opener_shares.0.iter().enumerate() {
            let y_i: Fr = share.share;
            let mut y_bytes = Vec::new();
            y_i.serialize_compressed(&mut y_bytes)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(y_bytes);
            shares_map.insert(((idx1 as u16) + 1).to_string(), serde_json::json!({"y_b64": b64}));
            let y_i_g2 = params_bbs.g2.mul_bigint(y_i.into_bigint()).into_affine();
            let y_i_bytes = g2_to_eip2537_bytes(&y_i_g2).to_vec();
            commits_map.insert(((idx1 as u16) + 1).to_string(), serde_json::json!(format!("0x{}", hex::encode(y_i_bytes))));
        }
        let out = serde_json::json!({
            "t": t,
            "n": n,
            "openers": shares_map,
            "commitments_g2": commits_map
        });
        let data = serde_json::to_vec_pretty(&out)?;
        let tmp = ".runtime.openers.json.tmp";
        fs::write(tmp, &data)?;
        fs::rename(tmp, ".runtime.openers.json")?;
        println!("TTP: wrote opener secrets and commitments to .runtime.openers.json");
    }

    // Write a .runtime.env for tests/clients to source
    {
        use std::io::Write as _;
        let mut lines = String::new();
        lines.push_str(&format!("PK_G2_HEX={}\n", pk_hex));
        lines.push_str(&format!("G2_GEN_256=0x{}\n", hex::encode(&g2gen_bytes)));
        lines.push_str(&format!("G2_BASE_256=0x{}\n", hex::encode(&g2base_bytes)));
        lines.push_str(&format!("THRESHOLD={}\n", t));
        lines.push_str(&format!("TOTAL={}\n", n));
        lines.push_str(&format!("OPENER_YBAR_128=0x{}\n", hex::encode(&ybar_bytes)));
        // Avoid clashing with EOA private-key env var name; export G2 public key under an explicit name
        lines.push_str(&format!("OPENER_PK_G2_256=0x{}\n", hex::encode(&opener_pk_bytes)));
        
        use std::fs::OpenOptions;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(".runtime.env")?;
        file.write_all(lines.as_bytes())?;
        println!("Appended to .runtime.env with PK_G2_HEX, G2_GEN_256, G2_BASE_256");
    }

    // Discover issuers and their indices
    let issuers: Vec<Address> = params.get_issuers().call().await?;
    println!("TTP: {} issuers discovered", issuers.len());

    // Assign shares by issuerIndex (1..=n) and persist to a local JSON file for issuers to load
    // Structure: { "t": <u16>, "n": <u16>, "shares": { "1": "<b64>", ... } }
    let mut jshares: std::collections::BTreeMap<u16, String> = Default::default();
    for issuer in issuers {
        let allowed: bool = params.issuer_allowed(issuer).call().await?;
        if !allowed { continue; }
        let idx: u16 = params.issuer_index(issuer).call().await?;
        if idx == 0 || (idx as usize) > shares.len() { continue; }
        let sk_share = shares[idx as usize - 1];
        let mut bytes = Vec::new();
        sk_share.serialize_compressed(&mut bytes)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        jshares.insert(idx, b64);
        println!("TTP: issuer {issuer:?} idx {idx} share persisted");
    }

    let shares_file = env::var("SHARES_FILE").unwrap_or_else(|_| ".runtime.shares.json".into());
    let out = serde_json::json!({
        "t": t,
        "n": n,
        "shares": jshares,
    });
    let data = serde_json::to_vec_pretty(&out)?;
    // Write atomically
    let tmp_path = format!("{shares_file}.tmp");
    fs::write(&tmp_path, &data)?;
    fs::rename(&tmp_path, &shares_file)?;
    if Path::new(&shares_file).exists() {
        println!("TTP: wrote shares file at {shares_file}");
    }

    println!("TTP ready: Params at {params_addr:?}, t={t}, n={n}");
    Ok(())
}
