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
use ethers::providers::{Provider, Ws};
use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
use ark_ec::{CurveGroup, AffineRepr};
use ark_ff::PrimeField;
use blake2::Blake2b512;
use bbs_plus::prelude::*;
use tbbsplus_rust::orchestration::helpers::{
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
            // Initialize params once
            contract
                .set_params_once(
                    cred_name.clone(),
                    mcount.into(),
                    t.into(),
                    n.into(),
                    vec![U256::from(1u64), U256::from(2u64)],
                    mcount.into(),
                )
                .send()
                .await?
                .await?;
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

    // --- Opener strategy: derive opener secret deterministically and compute Ybar (G1) and opener pkG2 ---
    // For demo, derive opener secret from label + fixed suffix
    use blake2::Digest as _;
    let mut h = blake2::Blake2b512::new();
    h.update(b"TBBS+_OPENER_SK_v1");
    h.update(cred_name.as_bytes());
    let dig = h.finalize();
    let mut le32 = [0u8; 32];
    le32.copy_from_slice(&dig[..32]);
    let opener_sk = <Fr as PrimeField>::from_be_bytes_mod_order(&le32);
    // Ybar = g1 * opener_sk
    use ark_ec::CurveGroup as _;
    let ybar_aff = params_bbs.g1.mul_bigint(opener_sk.into_bigint()).into_affine();
    let ybar_bytes = g1_to_eip2537_bytes(&ybar_aff).to_vec();
    // opener pk in G2: g2 * opener_sk
    let opener_pk_aff = params_bbs.g2.mul_bigint(opener_sk.into_bigint()).into_affine();
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

    params
        .set_g1h0g2(
            cred_name.clone(),
            g1_b.clone().into(),
            h0_b.clone().into(),
            g2base_bytes.clone().into(),
        )
        .send()
        .await?
        .await?;
    params
        .set_h_by_name(
            cred_name.clone(),
            h_bytes.clone().into_iter().map(ethers::types::Bytes::from).collect(),
        )
        .send()
        .await?
        .await?;
    params
        .set_pk_g2(cred_name.clone(), pk_bytes.clone().into())
        .send()
        .await?
        .await?;

    // Set opener keys on-chain
    params
        .set_opener_keys(cred_name.clone(), ybar_bytes.clone().into(), opener_pk_bytes.clone().into())
        .send()
        .await?
        .await?;

    // Persist opener secret shares for openers to read (single opener v1: index 1)
    {
        use ark_serialize::CanonicalSerialize as _;
        let mut sk_bytes = Vec::new();
        opener_sk.serialize_compressed(&mut sk_bytes)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(sk_bytes);
        let out = serde_json::json!({
            "openers": {
                "1": { "y_b64": b64 }
            }
        });
        let data = serde_json::to_vec_pretty(&out)?;
        let tmp = ".runtime.openers.json.tmp";
        fs::write(tmp, &data)?;
        fs::rename(tmp, ".runtime.openers.json")?;
        println!("TTP: wrote opener secret to .runtime.openers.json (index 1)");
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
