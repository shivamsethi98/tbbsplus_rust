use std::env;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::abi::RawLog;
use futures::StreamExt;
use tbbsplus_rust::orchestration::chain::clients::{VerifyClient, AccumulatorClient};
use std::io::Write as _;

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
    let metrics_on = std::env::var("METRICS").map(|v| v=="1"||v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let metrics_file = std::env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/service_provider.ndjson".into());

    // Non-interactive defaults for testing: auto open and auto revoke
    let auto_open = env::var("SP_AUTO_OPEN").map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("y")).unwrap_or(true);
    let auto_revoke = env::var("SP_AUTO_REVOKE").map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("y")).unwrap_or(true);

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
    let name_topic = {
        let name_env0 = env::var("CRED_NAME").expect("CRED_NAME");
        H256::from(ethers::utils::keccak256(name_env0.as_bytes()))
    };
    let mut status_stream = client.provider().subscribe_logs(&Filter::new().address(ValueOrArray::Value(acc_addr_h)).from_block(BlockNumber::Latest)).await?;
    let acc_opened_abi = accumulator.contract.abi().event("Opened")?;

    println!("service_provider: listening for PresentationVerified from {:?} (auto_open={}, auto_revoke={})", verify_addrs, auto_open, auto_revoke);
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
        if auto_open {
            let name_env = env::var("CRED_NAME").expect("CRED_NAME");
            let t1b = ethers::types::Bytes::from(t1.clone());
            let t2b = ethers::types::Bytes::from(t2.clone());
            let call = accumulator.contract.method::<_, ()>("requestOpen", (name_env.clone(), t1b, t2b))?;
            let t0 = std::time::Instant::now();
            let pending = call.send().await?;
            let rcpt = pending.await?;
            println!("ServiceProvider(auto): requestOpen sent; tx status={:?}", rcpt.as_ref().and_then(|r| r.status));
            if metrics_on {
                let _ = (||{
                    let _=std::fs::create_dir_all(std::path::Path::new(&metrics_file).parent().unwrap());
                    let mut f=std::fs::OpenOptions::new().create(true).append(true).open(&metrics_file).unwrap();
                    let gas = rcpt.as_ref().and_then(|r| r.gas_used).map(|g| g.to_string());
                    let eff = rcpt.as_ref().and_then(|r| r.effective_gas_price).map(|p| p.to_string());
                    let hash = rcpt.as_ref().map(|r| format!("0x{:x}", r.transaction_hash));
                    let blk = rcpt.as_ref().and_then(|r| r.block_number).map(|b| b.as_u64());
                    let cost = match (rcpt.as_ref().and_then(|r| r.gas_used), rcpt.as_ref().and_then(|r| r.effective_gas_price)) { (Some(g), Some(p)) => Some((g*p).to_string()), _ => None };
                    let _=writeln!(f, "{}", serde_json::json!({
                        "scenario":"sp_requestOpen",
                        "hash": hash,
                        "blockNumber": blk,
                        "gasUsed": gas,
                        "effectiveGasPrice": eff,
                        "costWei": cost
                    }));
                    Ok::<(),()>(())
                })();
            }
            let mut notified = false;
            let start = std::time::Instant::now();
            let mut e_for_revoke: Option<U256> = None;
            while start.elapsed().as_secs() < 30 {
                if let Some(lg) = status_stream.next().await {
                    if lg.address == acc_addr_h && !lg.topics.is_empty() {
                        if lg.topics[0] == ev_opened && lg.topics.get(1).map(|t| *t == name_topic).unwrap_or(false) {
                            println!("ServiceProvider(auto): Opened emitted");
                            if metrics_on {
                                let _ = (||{ let _=std::fs::create_dir_all(std::path::Path::new(&metrics_file).parent().unwrap()); let mut f=std::fs::OpenOptions::new().create(true).append(true).open(&metrics_file).unwrap();
                                    use std::io::Write; let _=writeln!(f, "{}", serde_json::json!({"scenario":"sp_open_e2e","ms": t0.elapsed().as_millis() as u64})); Ok::<(),()>(())})();
                            }
                            let raw = RawLog { topics: lg.topics.clone(), data: lg.data.to_vec() };
                            if let Ok(parsed) = acc_opened_abi.parse_log(raw) {
                                let mut a_bytes: Vec<u8> = Vec::new();
                                for p in parsed.params.iter() {
                                    if p.name == "A" { if let ethers::abi::Token::Bytes(b) = &p.value { a_bytes = b.clone(); } }
                                }
                                if a_bytes.len() == 128 {
                                    let mut e_u = U256::zero();
                                    for _ in 0..50 {
                                        match accumulator.contract.method::<_, U256>("getEByA", (name_env.clone(), ethers::types::Bytes::from(a_bytes.clone()))) {
                                            Ok(call) => { match call.call().await { Ok(x) => { e_u = x; }, Err(err) => { eprintln!("ServiceProvider: getEByA call error: {:?}", err); } } }
                                            Err(err) => { eprintln!("ServiceProvider: getEByA method error: {:?}", err); }
                                        }
                                        if e_u != U256::zero() { break; }
                                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                    }
                                    if e_u != U256::zero() {
                                        println!("ServiceProvider: resolved e=0x{:x} via A->e mapping", e_u);
                                        e_for_revoke = Some(e_u);
                                    } else {
                                        println!("ServiceProvider: A->e mapping not yet populated; will be available soon if on-chain mapping is enabled");
                                    }
                                }
                            }
                            notified = true; break;
                        } else if lg.topics[0] == ev_revoked {
                            // Ignore unrelated MemberRevoked during open E2E window
                            continue;
                        }
                    }
                } else { break; }
            }
            if !notified { println!("ServiceProvider: no Opened/MemberRevoked within 30s"); }
            if auto_revoke {
                if let Some(e_u) = e_for_revoke {
                    let call = accumulator.contract.method::<_, ()>("requestRevokeByE", (name_env.clone(), e_u))?;
                    let t0 = std::time::Instant::now();
                    let pending = call.send().await?;
                    let rcpt = pending.await?;
                    println!("ServiceProvider(auto): requestRevokeByE sent; tx status={:?}", rcpt.as_ref().and_then(|r| r.status));
                    if metrics_on {
                        let _ = (||{
                            let _=std::fs::create_dir_all(std::path::Path::new(&metrics_file).parent().unwrap());
                            let mut f=std::fs::OpenOptions::new().create(true).append(true).open(&metrics_file).unwrap();
                            let gas = rcpt.as_ref().and_then(|r| r.gas_used).map(|g| g.to_string());
                            let eff = rcpt.as_ref().and_then(|r| r.effective_gas_price).map(|p| p.to_string());
                            let hash = rcpt.as_ref().map(|r| format!("0x{:x}", r.transaction_hash));
                            let blk = rcpt.as_ref().and_then(|r| r.block_number).map(|b| b.as_u64());
                            let cost = match (rcpt.as_ref().and_then(|r| r.gas_used), rcpt.as_ref().and_then(|r| r.effective_gas_price)) { (Some(g), Some(p)) => Some((g*p).to_string()), _ => None };
                            let _=writeln!(f, "{}", serde_json::json!({
                                "scenario":"sp_requestRevokeByE",
                                "hash": hash,
                                "blockNumber": blk,
                                "gasUsed": gas,
                                "effectiveGasPrice": eff,
                                "costWei": cost
                            }));
                            Ok::<(),()>(())
                        })();
                    }
                    // Wait for MemberRevoked to compute revoke E2E
                    let rev_start = std::time::Instant::now();
                    let mut saw_rev = false;
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                    while std::time::Instant::now() < deadline {
                        if let Some(lg) = status_stream.next().await {
                            if lg.address == acc_addr_h && !lg.topics.is_empty() && lg.topics[0] == ev_revoked {
                                // Filter by name and expected e
                                let mut e_be = [0u8; 32];
                                e_u.to_big_endian(&mut e_be);
                                let e_topic = H256::from(e_be);
                                if lg.topics.get(1).map(|t| *t == name_topic).unwrap_or(false) == false { continue; }
                                if lg.topics.get(2).map(|t| *t == e_topic).unwrap_or(false) == false { continue; }
                                println!("ServiceProvider: MemberRevoked emitted");
                                if metrics_on {
                                    let _ = (||{ let _=std::fs::create_dir_all(std::path::Path::new(&metrics_file).parent().unwrap()); let mut f=std::fs::OpenOptions::new().create(true).append(true).open(&metrics_file).unwrap(); use std::io::Write; let _=writeln!(f, "{}", serde_json::json!({"scenario":"sp_revoke_e2e","ms": rev_start.elapsed().as_millis() as u64})); Ok::<(),()>(())})();
                                }
                                saw_rev = true; break;
                            }
                        } else { break; }
                    }
                    if !saw_rev { println!("ServiceProvider: MemberRevoked not observed within 30s"); }
                } else {
                    println!("ServiceProvider(auto): skip revoke (e not resolved)");
                }
            }
            continue;
        }
        // Interactive prompt fallback
        println!("ServiceProvider: choose action: [1] open-only  [2] revoke-by-e  [other] skip");
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans).ok();
        match ans.trim() {
            "1" | "" => {
                let name_env = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
                let t1b = ethers::types::Bytes::from(t1);
                let t2b = ethers::types::Bytes::from(t2);
                let call = accumulator.contract.method::<_, ()>("requestOpen", (name_env, t1b, t2b))?;
                let pending = call.send().await?;
                let rcpt = pending.await?;
                println!("ServiceProvider: requestOpen sent; tx status={:?}", rcpt.as_ref().and_then(|r| r.status));
                let mut notified = false;
                let start = std::time::Instant::now();
                while start.elapsed().as_secs() < 10 {
                    if let Some(lg) = status_stream.next().await {
                        if lg.address == acc_addr_h && !lg.topics.is_empty() {
                            if lg.topics[0] == ev_opened {
                                println!("ServiceProvider: Opened emitted");
                                // Decode (name, A)
                                let raw = RawLog { topics: lg.topics.clone(), data: lg.data.to_vec() };
                                if let Ok(parsed) = acc_opened_abi.parse_log(raw) {
                                    // We cannot recover indexed string param from topics; use configured credential name
                                    let name_env = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
                                    let mut a_bytes: Vec<u8> = Vec::new();
                                    for p in parsed.params.iter() {
                                        if p.name == "A" { if let ethers::abi::Token::Bytes(b) = &p.value { a_bytes = b.clone(); } }
                                    }
                                    if a_bytes.len() == 128 {
                                        // Try to resolve e via A->e mapping with a few retries (mapping may be populated just after Opened)
                                        let mut e_u = U256::zero();
                                        for _ in 0..10 {
                                            match accumulator.contract.method::<_, U256>("getEByA", (name_env.clone(), ethers::types::Bytes::from(a_bytes.clone()))) {
                                                Ok(call) => {
                                                    match call.call().await {
                                                        Ok(x) => { e_u = x; }
                                                        Err(err) => { eprintln!("ServiceProvider: getEByA call error: {:?}", err); }
                                                    }
                                                }
                                                Err(err) => { eprintln!("ServiceProvider: getEByA method error: {:?}", err); }
                                            }
                                            if e_u != U256::zero() { break; }
                                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                        }
                                        if e_u != U256::zero() {
                                            println!("ServiceProvider: resolved e=0x{:x} via A->e mapping", e_u);
                                            // Fetch witness for e (may not be available immediately)
                                            let mut witness_ok = false;
                                            for _ in 0..10 {
                                                match accumulator.contract.method::<_, ethers::types::Bytes>("getWitness", (name_env.clone(), e_u)) {
                                                    Ok(wc) => {
                                                        match wc.call().await {
                                                            Ok(wb) => {
                                                                if wb.0.len() == 128 { witness_ok = true; break; }
                                                            }
                                                            Err(err) => eprintln!("ServiceProvider: getWitness call error: {:?}", err),
                                                        }
                                                    }
                                                    Err(err) => eprintln!("ServiceProvider: getWitness method error: {:?}", err),
                                                }
                                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                            }
                                            if witness_ok {
                                                println!("ServiceProvider: witness available (len=128) for e=0x{:x}", e_u);
                                            } else {
                                                println!("ServiceProvider: witness not yet available for e=0x{:x}", e_u);
                                            }
                                        } else {
                                            println!("ServiceProvider: A->e mapping not yet populated; will be available soon if on-chain mapping is enabled");
                                        }
                                    }
                                }
                                notified = true; break;
                            }
                            if lg.topics[0] == ev_revoked { println!("ServiceProvider: MemberRevoked emitted"); notified = true; break; }
                        }
                    } else { break; }
                }
                if !notified { println!("ServiceProvider: no Opened/MemberRevoked within 10s"); }
            }
            "2" => {
                use std::io::Write as _;
                print!("Enter e (hex 0x..): ");
                let _ = std::io::stdout().flush();
                let mut e_hex = String::new();
                std::io::stdin().read_line(&mut e_hex).ok();
                let e_hex = e_hex.trim();
                let e_u = match U256::from_str_radix(e_hex.trim_start_matches("0x"), 16) { Ok(v) => v, Err(_) => { eprintln!("bad e"); continue; } };
                let name_env = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
                let call = accumulator.contract.method::<_, ()>("requestRevokeByE", (name_env, e_u))?;
                let pending = call.send().await?;
                let rcpt = pending.await?;
                println!("ServiceProvider: requestRevokeByE sent; tx status={:?}", rcpt.as_ref().and_then(|r| r.status));
            }
            _ => { println!("ServiceProvider: skipped"); }
        }
    }
    Ok(())
}
