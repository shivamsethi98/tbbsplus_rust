use std::env;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::abi::RawLog;
use futures::StreamExt;
use tbbsplus_rust::orchestration::chain::clients::{VerifyClient, AccumulatorClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let chain_id: u64 = env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse()?;
    // Use SP_PK for service provider; fallback to requested dev key
    let owner_pk: LocalWallet = env::var("SP_PK")
        .unwrap_or_else(|_| "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6".into())
        .parse::<LocalWallet>()?
        .with_chain_id(chain_id);

    let ws = Provider::<Ws>::connect(ws_url).await?;
    let client = std::sync::Arc::new(SignerMiddleware::new(ws, owner_pk));

    // Resolve VerifyWrapper address(es)
    let verify_addr_env = env::var("POK_VERIFY_WRAPPER").ok();
    let verify_addr_fallback = env::var("VERIFY_CONTRACT").ok();
    let mut verify_addrs: Vec<Address> = Vec::new();
    if let Some(s) = verify_addr_env { if let Ok(a) = s.parse::<Address>() { verify_addrs.push(a); } }
    if let Some(s) = verify_addr_fallback { if let Ok(a) = s.parse::<Address>() { if !verify_addrs.contains(&a) { verify_addrs.push(a); } } }
    if verify_addrs.is_empty() { anyhow::bail!("POK_VERIFY_WRAPPER/VERIFY_CONTRACT env missing or invalid"); }
    let acc_addr: Address = env::var("ACC_CONTRACT")?.parse()?;

    let verify = VerifyClient::new(verify_addrs[0], client.clone())?;
    let accumulator = AccumulatorClient::new(acc_addr, client.clone())?;

    // No persistent modes; only interactive

    // Subscribe to PresentationVerified(name, prover, T1, T2)
    // (already imported above) use ethers::types::{Filter, ValueOrArray, H256, BlockNumber};
    let event_sig = H256::from(ethers::utils::keccak256(b"PresentationVerified(string,address,bytes,bytes)"));
    let filter = Filter::new()
        .address(ValueOrArray::Array(verify_addrs.clone()))
        .topic0(ValueOrArray::Value(event_sig))
        .from_block(BlockNumber::Latest);
    let mut stream = client.provider().subscribe_logs(&filter).await?;

    // Decode helper
    let ev = verify.contract.abi().event("PresentationVerified")?;
    // Also subscribe to Accumulator events for status reporting
    use ethers::types::{Filter, ValueOrArray, H256, BlockNumber};
    let acc_addr_h = acc_addr;
    let ev_opened = H256::from(ethers::utils::keccak256(b"Opened(string,bytes)"));
    let ev_revoked = H256::from(ethers::utils::keccak256(b"MemberRevoked(string,uint256,bytes)"));
    let mut status_stream = client.provider().subscribe_logs(&Filter::new().address(ValueOrArray::Value(acc_addr_h)).from_block(BlockNumber::Latest)).await?;

    println!("service_provider: listening for PresentationVerified from {:?}", verify_addrs);
    while let Some(log) = stream.next().await {
        let raw = RawLog { topics: log.topics.clone(), data: log.data.to_vec() };
        let parsed = match ev.parse_log(raw) { Ok(p) => p, Err(e) => { eprintln!("parse err: {:?}", e); continue; } };
        // params: name (indexed), prover (indexed), T1 (bytes), T2 (bytes)
        let _name_topic = log.topics.get(1).cloned().unwrap_or_default();
        let _prover = log.topics.get(2).cloned().unwrap_or_default();
        let mut t1: Vec<u8> = Vec::new();
        let mut t2: Vec<u8> = Vec::new();
        for p in &parsed.params {
            if p.name == "T1" { if let ethers::abi::Token::Bytes(b) = &p.value { t1 = b.clone(); } }
            if p.name == "T2" { if let ethers::abi::Token::Bytes(b) = &p.value { t2 = b.clone(); } }
        }
        if t1.len() != 128 || t2.len() != 128 { eprintln!("bad T lens (T1={}, T2={})", t1.len(), t2.len()); continue; }
        // Interactive prompt
        println!("ServiceProvider: PresentationVerified received (T1.len={}, T2.len={}). Open now? [y/N]", t1.len(), t2.len());
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans).ok();
        if matches!(ans.trim(), "y"|"Y"|"yes"|"YES") {
            let name_env = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
            let t1b = ethers::types::Bytes::from(t1);
            let t2b = ethers::types::Bytes::from(t2);
            let call = accumulator.contract.method::<_, ()>("requestOpen", (name_env, t1b, t2b))?;
            let pending = call.send().await?;
            let rcpt = pending.await?;
            println!("ServiceProvider: requestOpen sent; tx status={:?}", rcpt.as_ref().and_then(|r| r.status));
            // Show follow-up status from Accumulator (Opened/MemberRevoked)
            let mut notified = false;
            let start = std::time::Instant::now();
            while start.elapsed().as_secs() < 10 {
                if let Some(lg) = status_stream.next().await {
                    if lg.address == acc_addr_h && !lg.topics.is_empty() {
                        if lg.topics[0] == ev_opened { println!("ServiceProvider: Opened emitted"); notified = true; break; }
                        if lg.topics[0] == ev_revoked { println!("ServiceProvider: MemberRevoked emitted"); notified = true; break; }
                    }
                } else { break; }
            }
            if !notified { println!("ServiceProvider: no Opened/MemberRevoked within 10s"); }
        } else {
            println!("ServiceProvider: skipped opening");
        }
    }
    Ok(())
}
