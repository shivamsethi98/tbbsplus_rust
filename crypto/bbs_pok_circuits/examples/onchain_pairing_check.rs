// Off-chain rust example that calls EIP-2537 pairing precompile via eth_call
// to validate a dummy Groth16 pairing check structure (here we just sanity-check
// the empty input and decode output). Later we will construct the full ABI data.

use dotenvy::dotenv;
use ethers::providers::{Http, Provider};
use ethers::providers::Middleware;
use ethers::types::{Bytes, TransactionRequest, H160, U256};
use ethers::types::transaction::eip2718::TypedTransaction;
use std::env;

// EIP-2537 precompile addresses
const PAIR_ADDR: &str = "000000000000000000000000000000000000000f";

fn hex_to_h160(s: &str) -> H160 { H160::from_slice(&hex::decode(s).unwrap()) }

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv().ok();
    let rpc = env::var("ETH_RPC_URL")
        .or_else(|_| env::var("SEPOLIA_URL"))
        .or_else(|_| env::var("HOODI_URL"))
        .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let provider = Provider::<Http>::try_from(rpc)?;

    // Empty input to pairing precompile should return 1 (true) per EIP-2537
    let to = hex_to_h160(PAIR_ADDR);
    let tx: TypedTransaction = TransactionRequest::new()
        .to(to)
        .data(Bytes::from_static(&[]))
        .into();

    let res: Bytes = provider.call(&tx, None).await?;
    println!("pair-empty result len={} bytes: 0x{}", res.0.len(), hex::encode(&res.0));

    Ok(())
}
