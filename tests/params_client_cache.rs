use std::sync::Arc;
use ethers::providers::{Provider, Ws};
use ethers::signers::LocalWallet;
use ethers::middleware::SignerMiddleware;
use ethers::types::Address;
use tbbsplus_rust::orchestration::chain::clients::ParamsClient;

// NOTE: These are light, integration-style tests that require ETH_WS and PARAMS_CONTRACT
// to be set to a node and deployed Params contract. We'll skip if env isn't set.

fn req_env(k: &str) -> Option<String> { std::env::var(k).ok() }

#[tokio::test]
async fn test_params_client_caches_when_env_present() -> anyhow::Result<()> {
    let ws = match req_env("ETH_WS") { Some(u) => u, None => return Ok(()) };
    let params_addr: Address = match req_env("PARAMS_CONTRACT").and_then(|s| s.parse().ok()) { Some(a) => a, None => return Ok(()) };
    let provider = Provider::<Ws>::connect(ws).await?;
    // No signing needed for view calls
    let client = Arc::new(provider);

    let pc: ParamsClient<_> = ParamsClient::new(params_addr, client.clone())?;
    let cred = req_env("CRED_NAME").unwrap_or_else(|| "ANON_CRED".into());

    // First fetches populate caches
    let _ = pc.get_threshold_cached(cred.clone()).await?;
    let _ = pc.get_message_count_cached(cred.clone()).await?;
    let _ = pc.get_g1h0g2_cached(cred.clone()).await?;
    let _ = pc.get_h_cached(cred.clone()).await?;

    // Second fetches should hit caches (no assertion on timing, just ensure calls succeed)
    let _t2 = pc.get_threshold_cached(cred.clone()).await?;
    let _m2 = pc.get_message_count_cached(cred.clone()).await?;
    let _g2 = pc.get_g1h0g2_cached(cred.clone()).await?;
    let _h2 = pc.get_h_cached(cred.clone()).await?;
    Ok(())
}
