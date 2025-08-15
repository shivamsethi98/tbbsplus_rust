// TTP process: deploys/initializes Params, derives threshold key shares, and associates shares to issuers by index.
// Usage: cargo run --bin ttp --features mpc
// Env: ETH_WS, CHAIN_ID, OWNER_PK, PARAMS_CONTRACT? (optional), CRED_NAME, THRESHOLD, TOTAL, MESSAGE_COUNT

use std::env;
use std::fs;
use std::path::Path;

use anyhow::Context;
use ark_bls12_381::Fr;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;
use base64::Engine;
use ethers::contract::abigen;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use secret_sharing_and_dkg::shamir_ss::deal_random_secret;

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
    let cred_name = env::var("CRED_NAME").unwrap_or_else(|_| "IITH_UG_AC".into());
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
    let (_secret, shares, _poly) = deal_random_secret(&mut rng, t, n)
        .map_err(|e| anyhow::anyhow!("deal_random_secret: {:?}", e))?;
    let shares: Vec<Fr> = shares.0.into_iter().map(|s| s.share).collect();

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
