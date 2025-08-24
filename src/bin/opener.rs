// Single-opener service: listens for CredentialRegistry.Confirmed, computes accumulator updates
// off-chain using vb_accumulator, and publishes Delta and membership witnesses to Accumulator.sol.

use std::env;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ethers::prelude::*;
use ethers::abi::{Abi, RawLog, Token};
use ethers::providers::{Provider, Ws};
use futures::StreamExt;

use std::collections::HashSet;
use vb_accumulator::persistence::State;
use vb_accumulator::positive::{Accumulator as _, PositiveAccumulator};
use vb_accumulator::setup::{SecretKey as AccumSecretKey, SetupParams as AccumSetupParams};

use tbbsplus_rust::orchestration::helpers::{
    eip2537_g1_to_affine,
    eip2537_g2_to_affine,
    g1_to_eip2537_bytes,
    u256_to_fr,
};

// Avoid abigen for Params to prevent artifact path issues; load dynamically like others

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let chain_id: u64 = env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse()?;

    // Signer: opener EOA (must be added as accumulatorManager in CredentialRegistry)
    // Be resilient to missing/invalid key and fall back to a known dev key.
    fn parse_wallet(pk: &str, chain_id: u64) -> anyhow::Result<LocalWallet> {
        let s = pk.trim();
        if !s.starts_with("0x") || s.len() != 66 {
            anyhow::bail!("bad private key length (expect 0x + 64 hex)");
        }
        Ok(s.parse::<LocalWallet>()?.with_chain_id(chain_id))
    }
    let wallet: LocalWallet = match env::var("OPENER_PK").or_else(|_| env::var("OWNER_PK")) {
        Ok(pk) => parse_wallet(&pk, chain_id).unwrap_or_else(|e| {
            eprintln!("[opener] invalid OPENER_PK/OWNER_PK: {:?}; falling back to dev key", e);
            // Hardhat/Anvil default dev key (0x7099... account)
            "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
                .parse::<LocalWallet>()
                .unwrap()
                .with_chain_id(chain_id)
        }),
        Err(_) => {
            eprintln!("[opener] OPENER_PK/OWNER_PK missing; using dev key");
            "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
                .parse::<LocalWallet>()
                .unwrap()
                .with_chain_id(chain_id)
        }
    };
    let ws = Provider::<Ws>::connect(ws_url.clone()).await?;
    let client = std::sync::Arc::new(SignerMiddleware::new(ws, wallet));

    // Contracts
    let params_addr: Address = env::var("PARAMS_CONTRACT")?.parse()?;
    let registry_addr: Address = env::var("REGISTRY_CONTRACT")?.parse()?;
    let acc_addr: Address = env::var("ACC_CONTRACT")?.parse()?;
    let cred_name = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());

    // Load Params ABI dynamically
    let params = {
        let abi = load_abi("artifacts/contracts/Params.sol/Params.json", "params")?;
        Contract::new(params_addr, abi, client.clone())
    };
    // Dynamic contracts to avoid abigen error name collisions
    fn load_abi(path: &str, tag: &str) -> anyhow::Result<Abi> {
        let art = std::fs::read(path).map_err(|e| anyhow::anyhow!("[opener] read {} failed: {:?}", path, e))?;
        eprintln!("[opener] {} artifact bytes: {}", tag, art.len());
        let v: serde_json::Value = serde_json::from_slice(&art)
            .map_err(|e| anyhow::anyhow!("[opener] parse {} failed: {:?}", path, e))?;
        let abi_val = v.get("abi").cloned().ok_or_else(|| anyhow::anyhow!("[opener] {} abi missing in {}", tag, path))?;
        let abi: Abi = serde_json::from_value(abi_val)
            .map_err(|e| anyhow::anyhow!("[opener] {} abi decode failed: {:?}", tag, e))?;
        Ok(abi)
    }
    let registry = {
        let abi = load_abi("artifacts/contracts/CredentialRegistry.sol/CredentialRegistry.json", "registry")?;
        Contract::new(registry_addr, abi, client.clone())
    };
    let accumulator = {
        let abi = load_abi("artifacts/contracts/Accumulator.sol/Accumulator.json", "accumulator")?;
        Contract::new(acc_addr, abi, client.clone())
    };

    // Build vb_accumulator params from on-chain g1/g2base for this credential
    let (g1_b, _h0_b, g2_b): (ethers::types::Bytes, ethers::types::Bytes, ethers::types::Bytes) = params
        .method("getG1H0G2ByName", (cred_name.clone(),))?
        .call()
        .await?;
    let g1 = eip2537_g1_to_affine(&g1_b.0[..])?;
    let g2 = eip2537_g2_to_affine(&g2_b.0[..])?;
    let accum_params = AccumSetupParams::<Bls12_381> { P: g1, P_tilde: g2 };

    // Derive opener secret deterministically (must match ttp.rs derivation) or read from .runtime.openers.json
    let derived_opener_sk = derive_opener_secret::<Fr>(&cred_name);
    let opener_sk: Fr = match std::fs::read_to_string(".runtime.openers.json") {
        Ok(s) => {
            use base64::Engine as _;
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                if let Some(b64) = v.get("openers").and_then(|o| o.get("1")).and_then(|o1| o1.get("y_b64")).and_then(|b| b.as_str()) {
                    let raw = base64::engine::general_purpose::STANDARD.decode(b64)
                        .unwrap_or_default();
                    if let Ok(fr) = ark_serialize::CanonicalDeserialize::deserialize_compressed(raw.as_slice()) {
                        fr
                    } else { derived_opener_sk }
                } else { derived_opener_sk }
            } else { derived_opener_sk }
        }
        Err(_) => derived_opener_sk,
    };
    let accum_sk = AccumSecretKey::<Fr>(opener_sk);

    // Initialize local accumulator state from on-chain Delta if present
    let mut state = LocalState::new();
    let delta_bytes: ethers::types::Bytes = accumulator
        .method("getDelta", (cred_name.clone(),))?
        .call()
        .await
        .unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
    let mut accumulator_local = if delta_bytes.0.len() == 128 {
        let delta_aff = eip2537_g1_to_affine(&delta_bytes.0[..])?;
        PositiveAccumulator::<ark_bls12_381::G1Affine>::from_accumulated(delta_aff)
    } else {
        PositiveAccumulator::<ark_bls12_381::G1Affine>::initialize(&accum_params)
    };

    // Subscribe to Confirmed(name,sid) events (auto-confirm path will also emit Confirmed)
    use ethers::types::{Filter, ValueOrArray, H256, BlockNumber};
    let event_sig = H256::from(ethers::utils::keccak256(b"Confirmed(string,uint256)"));
    let name_topic = H256::from(ethers::utils::keccak256(cred_name.as_bytes()));
    let filter = Filter::new()
        .address(ValueOrArray::Value(registry_addr))
        .topic0(ValueOrArray::Value(event_sig))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Latest);
    let mut stream = client.provider().subscribe_logs(&filter).await?;
    println!("opener: listening for Confirmed events for '{}'...", cred_name);

    // Spawn open loop in background to handle Accumulator.OpenRequested events
    {
        let client_c = client.clone();
        let accumulator_c = accumulator.clone();
        let cred_name_c = cred_name.clone();
        let accum_sk_c = accum_sk.clone();
        let opener_sk_c = opener_sk;
        tokio::spawn(async move {
            let _ = run_open_loop(client_c, accumulator_c, cred_name_c, accum_sk_c, opener_sk_c).await;
        });
    }

    while let Some(_log) = stream.next().await {
        // Fetch signature (A,e,s,status) for latest sid from the event's topics
        // topic2 is sid; decode it
        let sid_h = _log.topics.get(2).cloned().unwrap_or_default();
        let sid_u = U256::from_big_endian(sid_h.as_bytes());
        let (A_bytes, e_u, _s_u, _st): (ethers::types::Bytes, U256, U256, u8) = registry
            .method("getSignature", (cred_name.clone(), sid_u))?
            .call()
            .await?;

        // Compute new accumulator and witness for e
        let e_fr: Fr = u256_to_fr::<Fr>(&e_u);
        accumulator_local = accumulator_local
            .add(e_fr, &accum_sk, &mut state)
            .map_err(|e| anyhow::anyhow!("accumulator add failed: {:?}", e))?;
        let wit = accumulator_local
            .get_membership_witness(&e_fr, &accum_sk, &mut state)
            .map_err(|e| anyhow::anyhow!("witness failed: {:?}", e))?;

        // Publish on-chain
        let delta_aff = *accumulator_local.value();
        let delta_b = ethers::types::Bytes::from(g1_to_eip2537_bytes(&delta_aff).to_vec());
        let wit_b = ethers::types::Bytes::from(g1_to_eip2537_bytes(&wit.0).to_vec());
        let _ = accumulator
            .method::<_, ()>("setDelta", (cred_name.clone(), delta_b.clone()))?
            .send()
            .await?
            .await?;
        let _ = accumulator
            .method::<_, ()>("publishWitness", (cred_name.clone(), e_u, wit_b.clone()))?
            .send()
            .await?
            .await?;
        // Publish A -> e mapping for opening
        let _ = accumulator
            .method::<_, ()>("publishMapping", (cred_name.clone(), sid_u, A_bytes.clone(), e_u))?
            .send()
            .await?
            .await?;
        println!("opener: updated Delta and published witness for e=0x{:x}", e_u);
    }

    Ok(())
}

fn derive_opener_secret<F: PrimeField>(cred_name: &str) -> F {
    use blake2::Digest as _;
    let mut h = blake2::Blake2b512::new();
    h.update(b"TBBS+_OPENER_SK_v1");
    h.update(cred_name.as_bytes());
    let dig = h.finalize();
    let mut be32 = [0u8; 32];
    be32.copy_from_slice(&dig[..32]);
    F::from_be_bytes_mod_order(&be32)
}

// Minimal local state implementing vb_accumulator::persistence::State for Fr elements
#[derive(Clone, Debug)]
struct LocalState {
    db: HashSet<Fr>,
}

impl LocalState {
    fn new() -> Self { Self { db: HashSet::new() } }
}

impl State<Fr> for LocalState {
    fn add(&mut self, element: Fr) { self.db.insert(element); }
    fn remove(&mut self, element: &Fr) { self.db.remove(element); }
    fn has(&self, element: &Fr) -> bool { self.db.get(element).is_some() }
    fn size(&self) -> u64 { self.db.len() as u64 }
}

// --- Opening and revocation helpers (single opener v1) ---

#[allow(dead_code)]
async fn compute_tbar_and_a(
    t1_bytes: &[u8],
    t2_bytes: &[u8],
    opener_sk: Fr,
) -> anyhow::Result<(ethers::types::Bytes, ethers::types::Bytes)> {
    use ark_ec::CurveGroup as _;
    let t1 = eip2537_g1_to_affine(t1_bytes)?;
    let t2 = eip2537_g1_to_affine(t2_bytes)?;
    let tbar = t1.mul_bigint(opener_sk.into_bigint()).into_affine();
    let tbar_b = ethers::types::Bytes::from(g1_to_eip2537_bytes(&tbar).to_vec());
    // A = T2 - Tbar
    let a = (t2.into_group() + (-tbar).into_group()).into_affine();
    let a_b = ethers::types::Bytes::from(g1_to_eip2537_bytes(&a).to_vec());
    Ok((tbar_b, a_b))
}

// Subscribe to Accumulator.OpenRequested and perform opening + revocation
async fn run_open_loop(
    client: std::sync::Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    accumulator: Contract<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    cred_name: String,
    accum_sk: AccumSecretKey<Fr>,
    opener_sk: Fr,
) -> anyhow::Result<()> {
    use ethers::types::{Filter, ValueOrArray, H256, BlockNumber};
    let acc_addr = accumulator.address();
    let event_sig = H256::from(ethers::utils::keccak256(b"OpenRequested(string,address,bytes,bytes)"));
    let name_topic = H256::from(ethers::utils::keccak256(cred_name.as_bytes()));
    let filter = Filter::new()
        .address(ValueOrArray::Value(acc_addr))
        .topic0(ValueOrArray::Value(event_sig))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Latest);
    let mut stream = client.provider().subscribe_logs(&filter).await?;
    // Prepare ABI event for decoding
    let acc_abi = accumulator.abi().clone();
    let ev = acc_abi.event("OpenRequested")?;

    loop {
        let opt = stream.next().await;
        let Some(log) = opt else { break };
        let raw = RawLog { topics: log.topics.clone(), data: log.data.to_vec() };
        let parsed = match ev.parse_log(raw) { Ok(p) => p, Err(_) => continue };
        // params expected: T1, T2 (both bytes)
        let mut t1_b = Vec::new();
        let mut t2_b = Vec::new();
        for p in parsed.params.iter() {
            match &p.value {
                Token::Bytes(b) => {
                    if t1_b.is_empty() { t1_b = b.clone(); } else { t2_b = b.clone(); }
                }
                _ => {}
            }
        }
        if t1_b.len() != 128 || t2_b.len() != 128 { continue; }
        let (_tbar_b, a_b) = compute_tbar_and_a(&t1_b, &t2_b, opener_sk).await?;
        // Optional: publish recovered A
        let _ = accumulator
            .method::<_, ()>("publishOpenResult", (cred_name.clone(), ethers::types::Bytes::from(a_b.clone())))?
            .send()
            .await?
            .await?;
        // Lookup e by A
        let e_u: U256 = accumulator
            .method("getEByA", (cred_name.clone(), ethers::types::Bytes::from(a_b.clone())))?
            .call()
            .await?;
        if e_u.is_zero() { continue; }
        // Fetch current Delta and compute new after removal
        let delta_bytes: ethers::types::Bytes = accumulator
            .method("getDelta", (cred_name.clone(),))?
            .call()
            .await
            .unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
        if delta_bytes.0.len() != 128 { continue; }
        let delta_aff = eip2537_g1_to_affine(&delta_bytes.0[..])?;
        let acc_local = PositiveAccumulator::<ark_bls12_381::G1Affine>::from_accumulated(delta_aff);
        let e_fr: Fr = u256_to_fr::<Fr>(&e_u);
        let new_delta_aff = acc_local.compute_new_post_remove(&e_fr, &accum_sk);
        let new_delta_b = ethers::types::Bytes::from(g1_to_eip2537_bytes(&new_delta_aff).to_vec());
        let _ = accumulator
            .method::<_, ()>("deleteMember", (cred_name.clone(), e_u, new_delta_b))?
            .send()
            .await?
            .await?;
        println!("opener: opened and revoked e=0x{:x}", e_u);
    }
    Ok(())
}


