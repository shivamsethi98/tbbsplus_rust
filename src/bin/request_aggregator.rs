//! Request Aggregator — Persistent Batched Credential Request Verification
//!
//! Runs as a background service, polling a JSON batch file for incoming
//! credential request proofs.  When the file accumulates >= `batchSizeReq`
//! entries (read from the on-chain Params contract), it drains them and
//! submits a single batch tx to `RequestCredential.batchBroadcastSigReqBBSPlusVerified`.
//!
//! Each `SigReqBBSPlusVerified` event is emitted per-user, so existing issuers
//! pick them up exactly as if each user had submitted individually.
//!
//! Env vars:
//!   BATCH_REQUEST_FILE  — path to the shared JSON file (default: batch_request.json)
//!   AGG_POLL_SECS       — polling interval in seconds (default: 2)
//!   REQ_CONTRACT, PARAMS_CONTRACT, ETH_RPC / ETH_HTTP, CHAIN_ID, AGG_PK / DEPLOYER_PK

use std::env;
use std::sync::Arc;
use std::time::Duration;

use ethers::prelude::*;
use ethers::providers::Provider;
use ethers::types::{H256, U256};
use tokio::time::sleep;
use tracing::{error, info, warn};

use tbbsplus_rust::orchestration::batching::{
    consume_batch_if_ready, pack_batch_request_input, RequestData,
};
use tbbsplus_rust::orchestration::chain::clients::ParamsClient;

abigen!(
    RequestCredential,
    "artifacts/contracts/RequestCredential.sol/RequestCredential.json"
);

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
    let batch_file = env::var("BATCH_REQUEST_FILE")
        .unwrap_or_else(|_| "batch_request.json".into());
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
    let req_addr: Address = resolve_env("REQ_CONTRACT")?.parse()?;
    let params_addr: Address = resolve_env("PARAMS_CONTRACT")?.parse()?;
    let cred_name = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());

    let req_contract = RequestCredential::new(req_addr, client.clone());
    let params_client = ParamsClient::new(params_addr, client.clone())?;

    // ── Read batch size from Params contract ──
    let (batch_size_req, _) = params_client.get_batch_sizes(cred_name.clone()).await?;
    let threshold = if batch_size_req == 0 { 1 } else { batch_size_req as usize };

    info!(
        batch_size = %threshold,
        file = %batch_file,
        poll_secs = %poll_secs,
        "request aggregator watching…"
    );

    // ── Persistent polling loop ──
    loop {
        sleep(poll_interval).await;

        let requests = match consume_batch_if_ready::<RequestData>(&batch_file, threshold) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "failed to read batch file");
                continue;
            }
        };
        if requests.is_empty() {
            continue;
        }

        let n = requests.len();
        // Validate all entries
        let mut valid = true;
        for (j, r) in requests.iter().enumerate() {
            if let Err(e) = r.validate() {
                error!(j, error = %e, "invalid request — skipping batch");
                valid = false;
                break;
            }
        }
        if !valid {
            // Write invalid batch to dead-letter file
            let dead = format!("{}.dead.json", batch_file);
            warn!(dead_letter = %dead, "writing failed batch to dead-letter file");
            let _ = std::fs::write(&dead, serde_json::to_string_pretty(&requests).unwrap_or_default());
            continue;
        }

        info!(n = %n, "batch ready — packing and submitting…");

        // ── Pack batch input ──
        let packed = match pack_batch_request_input(&requests) {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "failed to pack batch input");
                continue;
            }
        };
        let (
            cn,
            user_addrs,
            commitment_us,
            commitment_bs,
            h0,
            h_vec,
            hidden_idx,
            ts,
            challenges,
            flat_responses,
            all_revealed_idx,
            all_revealed_vals,
            contexts,
        ) = packed;

        // ── Build and send tx ──
        let call = req_contract
            .batch_broadcast_sig_req_bbs_plus_verified(
                cn,
                user_addrs,
                commitment_us,
                commitment_bs,
                h0,
                h_vec,
                hidden_idx,
                ts,
                challenges,
                flat_responses,
                all_revealed_idx,
                all_revealed_vals,
                contexts,
            );

        info!("sending batchBroadcastSigReqBBSPlusVerified tx…");
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
                            let event_sig = H256::from(ethers::utils::keccak256(
                                b"SigReqBBSPlusVerified(address,uint256,string,bytes,uint32[],uint256[],uint32[],bytes,uint256,uint256[],bytes)",
                            ));
                            let event_count = r
                                .logs
                                .iter()
                                .filter(|lg| lg.topics.first() == Some(&event_sig))
                                .count();
                            info!(
                                gas_used = %gas_used,
                                per_user = %(gas_used / n as u64),
                                events = %event_count,
                                "batch request verified ({} users)", n
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
