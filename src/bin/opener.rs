// Single-opener service: listens for CredentialRegistry.Confirmed, computes accumulator updates
// off-chain using vb_accumulator, and publishes Delta and membership witnesses to Accumulator.sol.

use std::env;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ethers::prelude::*;
use ethers::abi::Abi;
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

abigen!(
    Params,
    "artifacts/contracts/Params.sol/Params.json"
);

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
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
                .parse::<LocalWallet>()
                .unwrap()
                .with_chain_id(chain_id)
        }),
        Err(_) => {
            eprintln!("[opener] OPENER_PK/OWNER_PK missing; using dev key");
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
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

    let params = Params::new(params_addr, client.clone());
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
    let (g1_b, _h0_b, g2_b) = params.get_g1h0g2_by_name(cred_name.clone()).call().await?;
    let g1 = eip2537_g1_to_affine(&g1_b.0[..])?;
    let g2 = eip2537_g2_to_affine(&g2_b.0[..])?;
    let accum_params = AccumSetupParams::<Bls12_381> { P: g1, P_tilde: g2 };

    // Derive opener secret deterministically (must match ttp.rs derivation)
    let opener_sk = derive_opener_secret::<Fr>(&cred_name);
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

    // Subscribe to Confirmed(name,sid) events
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

    while let Some(_log) = stream.next().await {
        // Fetch signature (A,e,s,status) for latest sid from the event's topics
        // topic2 is sid; decode it
        let sid_h = _log.topics.get(2).cloned().unwrap_or_default();
        let sid_u = U256::from_big_endian(sid_h.as_bytes());
        let (_A, e_u, _s_u, _st): (ethers::types::Bytes, U256, U256, u8) = registry
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


