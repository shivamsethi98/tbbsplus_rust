// Off-chain test: Prepare (placeholder) Groth16 proof + public inputs and validate
// connectivity to EIP-2537 precompiles. Full encoding to the Solidity verifier
// will be added after the contract is wired.

use bbs_pok_circuits as circuits;
use circuits::{Fr, PublicInputs};
use dotenvy::dotenv;
use ethers::providers::{Http, Provider};
use ethers::providers::Middleware;
use ethers::types::{Bytes, TransactionRequest, H160};
use ethers::types::transaction::eip2718::TypedTransaction;
use std::env;

const PAIR_ADDR: &str = "000000000000000000000000000000000000000f";

fn hex_to_h160(s: &str) -> H160 { H160::from_slice(&hex::decode(s).unwrap()) }

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv().ok();
    // 1) Build a minimal circuit vk/pk and a trivial proof (same as smoke test)
    let (pk, _vk) = circuits::setup(8, 4).expect("setup");
    let mut messages = vec![Fr::from(0u64); 8];
    messages[1] = Fr::from(42u64);
    let pi = PublicInputs { message_count: 3, revealed_idx: vec![1], revealed_vals: vec![messages[1]], ..Default::default() };
    let snark = circuits::proof::create_proof(&pk, &pi, &messages, 8, 4).expect("prove");
    let _proof_bytes = snark.to_bytes();
    let _public_inputs = snark.public_inputs.clone();

    // 2) Sanity-call EIP-2537 pairing precompile (empty input)
    // Try common env vars, fall back to local anvil/hardhat
    let rpc = env::var("ETH_RPC_URL")
        .or_else(|_| env::var("SEPOLIA_URL"))
        .or_else(|_| env::var("HOODI_URL"))
        .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let provider = Provider::<Http>::try_from(rpc)?;
    let to = hex_to_h160(PAIR_ADDR);
    let tx: TypedTransaction = TransactionRequest::new().to(to).data(Bytes::from_static(&[])).into();
    let res: Bytes = provider.call(&tx, None).await?;
    println!("pair-empty result: 0x{} ({} bytes)", hex::encode(&res.0), res.0.len());
    Ok(())
}
