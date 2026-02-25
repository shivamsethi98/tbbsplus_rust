//! Presentation Aggregator — Persistent Batched Credential Presentation Verification
//!
//! Runs as a background service, polling a JSON batch file for incoming
//! credential presentations.  When the file accumulates >= `batchSizePres`
//! entries (read from the on-chain Params contract), it drains them and
//! submits a single batch tx to `BatchVerifyWrapper.verifyPresentationBatch`.
//!
//! Env vars:
//!   BATCH_PRESENTATION_FILE — path to the shared JSON file (default: batch_presentation.json)
//!   AGG_POLL_SECS           — polling interval in seconds (default: 2)
//!   BATCH_VERIFY_CONTRACT, PARAMS_CONTRACT, ACC_CONTRACT, CRED_NAME,
//!   ETH_RPC / ETH_HTTP, CHAIN_ID, AGG_PK / DEPLOYER_PK

use std::env;
use std::sync::Arc;
use std::time::Duration;

use ethers::prelude::*;
use ethers::providers::Provider;
use tokio::time::sleep;
use tracing::{error, info, warn};

use tbbsplus_rust::orchestration::batching::{
    consume_batch_if_ready, pack_batch_input, PresentationData,
};
use tbbsplus_rust::orchestration::chain::clients::{BatchVerifyClient, ParamsClient};

fn resolve_env(env_key: &str) -> anyhow::Result<String> {
    env::var(env_key)
        .map_err(|_| anyhow::anyhow!("{} env required", env_key))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // ── Config ──
    let batch_file = env::var("BATCH_PRESENTATION_FILE")
        .unwrap_or_else(|_| "batch_presentation.json".into());
    let poll_secs: u64 = env::var("AGG_POLL_SECS")
        .unwrap_or_else(|_| "2".into())
        .parse()
        .unwrap_or(2);
    let poll_interval = Duration::from_secs(poll_secs);

    // ── Connect to chain ──
    let rpc_url = env::var("ETH_RPC")
        .or_else(|_| env::var("ETH_HTTP"))
        .unwrap_or_else(|_| "http://127.0.0.1:8545".into());
    let chain_id: u64 = env::var("CHAIN_ID")
        .unwrap_or_else(|_| "31337".into())
        .parse()?;
    let pk: LocalWallet = env::var("AGG_PK")
        .or_else(|_| env::var("DEPLOYER_PK"))
        .unwrap_or_else(|_| {
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into()
        })
        .parse::<LocalWallet>()?
        .with_chain_id(chain_id);

    let provider = Provider::try_from(&rpc_url)?;
    let client = Arc::new(SignerMiddleware::new(provider, pk));

    // ── Resolve contracts ──
    let batch_verify_addr: Address = resolve_env("BATCH_VERIFY_CONTRACT")?.parse()?;
    let params_addr: Address = resolve_env("PARAMS_CONTRACT")?.parse()?;
    let acc_addr: Address = resolve_env("ACC_CONTRACT")?.parse()?;
    let cred_name = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());

    let batch_client = BatchVerifyClient::new(batch_verify_addr, client.clone())?;
    let params_client = ParamsClient::new(params_addr, client.clone())?;

    // ── Read batch size from Params contract ──
    let (_, batch_size_pres) = params_client.get_batch_sizes(cred_name.clone()).await?;
    let threshold = if batch_size_pres == 0 { 1 } else { batch_size_pres as usize };

    info!(
        batch_size = %threshold,
        file = %batch_file,
        poll_secs = %poll_secs,
        "presentation aggregator watching…"
    );

    // ── Persistent polling loop ──
    loop {
        sleep(poll_interval).await;

        let presentations =
            match consume_batch_if_ready::<PresentationData>(&batch_file, threshold) {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "failed to read batch file");
                    continue;
                }
            };
        if presentations.is_empty() {
            continue;
        }

        let b = presentations.len();
        // Validate all entries
        let mut valid = true;
        for (j, p) in presentations.iter().enumerate() {
            if let Err(e) = p.validate() {
                error!(j, error = %e, "invalid presentation — skipping batch");
                valid = false;
                break;
            }
        }
        if !valid {
            let dead = format!("{}.dead.json", batch_file);
            warn!(dead_letter = %dead, "writing failed batch to dead-letter file");
            let _ = std::fs::write(
                &dead,
                serde_json::to_string_pretty(&presentations).unwrap_or_default(),
            );
            continue;
        }

        info!(b = %b, "batch ready — packing and submitting…");

        // ── Pack BatchPresInput ──
        let batch_token = match pack_batch_input(&presentations) {
            Ok(t) => t,
            Err(e) => {
                error!(error = %e, "failed to pack batch input");
                continue;
            }
        };

        // ── Build and send tx ──
        let call = match batch_client.contract.method::<_, bool>(
            "verifyPresentationBatch",
            (
                cred_name.clone(),
                params_addr,
                acc_addr,
                batch_token,
            ),
        ) {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "failed to build tx");
                continue;
            }
        };

        info!("sending verifyPresentationBatch tx…");
        let send_result = call.send().await;
        match send_result {
            Ok(pending_tx) => {
                info!(tx_hash = ?pending_tx.tx_hash(), "tx submitted, waiting for receipt…");
                let receipt = pending_tx.await;
                match receipt {
                    Ok(Some(r)) => {
                        let gas_used = r.gas_used.unwrap_or_default();
                        let status = r.status.unwrap_or_default();
                        if status == U64::from(1) {
                            info!(
                                gas_used = %gas_used,
                                per_user = %(gas_used / b as u64),
                                "batch presentation verified ({} users)", b
                            );
                        } else {
                            error!(gas_used = %gas_used, "tx reverted (status=0)");
                        }
                    }
                    Ok(None) => warn!("tx receipt was None"),
                    Err(e) => error!(error = %e, "tx receipt error"),
                }
            }
            Err(e) => {
                error!(error = %e, "tx send failed");
            }
        }
    }
}
