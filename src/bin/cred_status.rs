use std::env;
use std::time::Duration;

use anyhow::Context;
use ethers::abi::Abi;
use ethers::contract::Contract;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::{Bytes as EthBytes, U256};
use tokio::time::sleep;

fn decode_status(s: u8) -> &'static str {
    match s {
        0 => "None",
        1 => "Unverified",
        2 => "Verified",
        3 => "Revoked",
        _ => "Unknown",
    }
}

fn parse_args() -> anyhow::Result<(String, u64, bool)> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let mut name = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
    let mut sid: Option<u64> = env::var("SID").ok().and_then(|v| v.parse().ok());
    let mut watch = env::var("WATCH").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                if i + 1 >= args.len() { anyhow::bail!("--name requires value"); }
                name = args[i + 1].clone();
                i += 2;
            }
            "--sid" => {
                if i + 1 >= args.len() { anyhow::bail!("--sid requires value"); }
                sid = Some(args[i + 1].parse()?);
                i += 2;
            }
            "--watch" => {
                watch = true;
                i += 1;
            }
            v if sid.is_none() && v.chars().all(|c| c.is_ascii_digit()) => {
                sid = Some(v.parse()?);
                i += 1;
            }
            _ => {
                eprintln!("unknown arg: {}", args[i]);
                i += 1;
            }
        }
    }

    let sid = sid.ok_or_else(|| anyhow::anyhow!("sid not provided (use --sid <n> or SID env)"))?;
    Ok((name, sid, watch))
}

async fn load_registry_contract<M: Middleware>(
    provider: std::sync::Arc<M>,
) -> anyhow::Result<(Contract<M>, Address)> {
    let registry_addr: Address = env::var("REGISTRY_CONTRACT")
        .context("REGISTRY_CONTRACT env missing")?
        .parse()
        .context("bad REGISTRY_CONTRACT address")?;

    let art_path = "artifacts/contracts/CredentialRegistry.sol/CredentialRegistry.json";
    let art_json = std::fs::read_to_string(art_path)
        .with_context(|| format!("failed reading {}", art_path))?;
    let v: serde_json::Value = serde_json::from_str(&art_json).context("parse artifact JSON")?;
    let abi_val = v.get("abi").ok_or_else(|| anyhow::anyhow!("abi missing in artifact"))?.clone();
    let abi: Abi = serde_json::from_value(abi_val).context("abi decode")?;

    let contract = Contract::new(registry_addr, abi, provider);
    Ok((contract, registry_addr))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let (name, sid, watch) = parse_args()?;

    let provider = Provider::<Ws>::connect(ws_url.clone()).await?;
    let provider = std::sync::Arc::new(provider);
    let (registry, _addr) = load_registry_contract(provider.clone()).await?;

    // One-shot read
    let read_once = || async {
        let (a, e_u, s_u, st): (EthBytes, U256, U256, u8) = registry
            .method("getSignature", (name.clone(), U256::from(sid)))?
            .call()
            .await?;
        let status = decode_status(st);
        println!(
            "getSignature(name='{}', sid={}): A.len={}, e=0x{:x}, s=0x{:x}, Status={}",
            name,
            sid,
            a.0.len(),
            e_u,
            s_u,
            status
        );
        Ok::<u8, anyhow::Error>(st)
    };

    let mut last = read_once().await?;
    if watch {
        let interval_ms: u64 = env::var("POLL_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
        let exit_on_verified = env::var("EXIT_ON_VERIFIED").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(true);
        loop {
            sleep(Duration::from_millis(interval_ms)).await;
            match read_once().await {
                Ok(cur) => {
                    if cur != last {
                        println!("Status changed: {} -> {}", decode_status(last), decode_status(cur));
                        last = cur;
                    }
                    if exit_on_verified && cur == 2 {
                        println!("Verified reached; exiting.");
                        break;
                    }
                }
                Err(e) => eprintln!("poll error: {:?}", e),
            }
        }
    }

    Ok(())
}
