use std::env;
use std::collections::HashMap;
use std::sync::Arc;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::abi::RawLog;
use futures::StreamExt;

use tbbsplus_rust::orchestration::chain::clients::{VerifyClient, AccumulatorClient};
use std::io::Write as _;

/// Status of an opened credential entry tracked by the SP.
#[derive(Clone, Debug)]
enum EntryStatus {
    /// requestOpen sent, waiting for Opened event
    Opening,
    /// Opened received, e resolved — available for manual revocation
    Opened,
    /// requestRevokeByE sent, waiting for MemberRevoked
    Revoking,
    /// MemberRevoked confirmed
    Revoked,
}

impl std::fmt::Display for EntryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntryStatus::Opening => write!(f, "OPENING"),
            EntryStatus::Opened => write!(f, "OPENED"),
            EntryStatus::Revoking => write!(f, "REVOKING.."),
            EntryStatus::Revoked => write!(f, "REVOKED"),
        }
    }
}

#[derive(Clone, Debug)]
struct OpenedEntry {
    /// Credential element in the accumulator
    e: U256,
    /// Truncated hex of A (the opened signature point)
    a_short: String,
    /// Prover address topic (if available)
    prover: H256,
    status: EntryStatus,
}

fn print_table(entries: &HashMap<usize, OpenedEntry>) {
    if entries.is_empty() {
        println!("\n  (no opened signatures yet)\n");
        return;
    }
    println!();
    println!("  {:<4} {:<12} {:<20} {:<44}", "#", "STATUS", "A (short)", "e");
    println!("  {}", "-".repeat(82));
    let mut keys: Vec<usize> = entries.keys().copied().collect();
    keys.sort();
    for k in keys {
        let ent = &entries[&k];
        let e_str = if ent.e.is_zero() { "pending...".to_string() } else { format!("0x{:x}", ent.e) };
        let e_display = if e_str.len() > 42 { format!("{}...", &e_str[..42]) } else { e_str };
        println!("  {:<4} {:<12} {:<20} {}", k, ent.status, ent.a_short, e_display);
    }
    println!();
}

fn print_help() {
    println!("  Commands:");
    println!("    r <N>   revoke entry N");
    println!("    l       list opened signatures");
    println!("    q       quit");
    println!();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let chain_id: u64 = env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse()?;
    let owner_pk: LocalWallet = env::var("SP_PK")
        .unwrap_or_else(|_| "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6".into())
        .parse::<LocalWallet>()?
        .with_chain_id(chain_id);

    let ws = Provider::<Ws>::connect(ws_url).await?;
    let client = Arc::new(SignerMiddleware::new(ws, owner_pk));

    let verify_addr_env = env::var("POK_VERIFY_WRAPPER").ok();
    let verify_addr_fallback = env::var("VERIFY_CONTRACT").ok();
    let mut verify_addrs: Vec<Address> = Vec::new();
    if let Some(s) = verify_addr_env { if let Ok(a) = s.parse::<Address>() { verify_addrs.push(a); } }
    if let Some(s) = verify_addr_fallback { if let Ok(a) = s.parse::<Address>() { if !verify_addrs.contains(&a) { verify_addrs.push(a); } } }
    if verify_addrs.is_empty() { anyhow::bail!("POK_VERIFY_WRAPPER/VERIFY_CONTRACT env missing or invalid"); }
    let acc_addr: Address = env::var("ACC_CONTRACT")?.parse()?;
    let name_env = env::var("CRED_NAME").expect("CRED_NAME");

    let verify = VerifyClient::new(verify_addrs[0], client.clone())?;
    let accumulator = AccumulatorClient::new(acc_addr, client.clone())?;

    // Optional BatchVerifyWrapper support
    let batch_verify_addr: Option<Address> = env::var("BATCH_VERIFY_CONTRACT")
        .ok()
        .and_then(|s| s.parse::<Address>().ok());

    // --- Event subscriptions ---
    use ethers::types::{Filter, ValueOrArray, H256, BlockNumber};

    // PresentationVerified (single)
    let ev_pres_sig = H256::from(ethers::utils::keccak256(b"PresentationVerified(string,address,bytes,bytes)"));
    let mut pres_stream = client.provider().subscribe_logs(
        &Filter::new()
            .address(ValueOrArray::Array(verify_addrs.clone()))
            .topic0(ValueOrArray::Value(ev_pres_sig))
            .from_block(BlockNumber::Latest),
    ).await?;
    let pres_abi = verify.contract.abi().event("PresentationVerified")?;

    // BatchPresentationVerified (from BatchVerifyWrapper)
    let ev_batch_pres_sig = H256::from(ethers::utils::keccak256(
        b"BatchPresentationVerified(string,uint256,bytes,bytes)",
    ));
    let batch_pres_stream = if let Some(ba) = batch_verify_addr {
        Some(
            client.provider().subscribe_logs(
                &Filter::new()
                    .address(ValueOrArray::Value(ba))
                    .topic0(ValueOrArray::Value(ev_batch_pres_sig))
                    .from_block(BlockNumber::Latest),
            ).await?,
        )
    } else {
        None
    };
    // Wrap in a fuse-able stream so tokio::select! can use it
    let mut batch_pres_stream = batch_pres_stream;

    // Accumulator events (Opened, MemberRevoked)
    let ev_opened = H256::from(ethers::utils::keccak256(b"Opened(string,bytes)"));
    let ev_revoked = H256::from(ethers::utils::keccak256(b"MemberRevoked(string,uint256,bytes)"));
    let name_topic = H256::from(ethers::utils::keccak256(name_env.as_bytes()));
    let mut acc_stream = client.provider().subscribe_logs(
        &Filter::new()
            .address(ValueOrArray::Value(acc_addr))
            .from_block(BlockNumber::Latest),
    ).await?;
    let acc_opened_abi = accumulator.contract.abi().event("Opened")?;

    // Async stdin via channel + blocking reader
    let (line_tx, mut line_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        loop {
            let mut buf = String::new();
            if stdin.read_line(&mut buf).is_err() { break; }
            if line_tx.send(buf).is_err() { break; }
        }
    });

    // --- State ---
    let mut entries: HashMap<usize, OpenedEntry> = HashMap::new();
    let mut next_idx: usize = 1;
    // Map from pending (T1 hash) → entry idx, so we can correlate Opened events
    let mut pending_opens: HashMap<Vec<u8>, usize> = HashMap::new();

    println!("Service Provider — interactive mode");
    println!("  Listening for PresentationVerified from {:?}", verify_addrs);
    if let Some(ba) = batch_verify_addr {
        println!("  Listening for BatchPresentationVerified from {:?}", ba);
    }
    println!("  Auto-opens presentations, then YOU choose when to revoke.");
    print_help();
    print!("> ");
    let _ = std::io::stdout().flush();

    loop {
        tokio::select! {
            // --- Branch 1: PresentationVerified event ---
            Some(log) = pres_stream.next() => {
                let raw = RawLog { topics: log.topics.clone(), data: log.data.to_vec() };
                let parsed = match pres_abi.parse_log(raw) { Ok(p) => p, Err(e) => { eprintln!("parse err: {:?}", e); continue; } };
                let prover = log.topics.get(2).cloned().unwrap_or_default();
                let mut t1: Vec<u8> = Vec::new();
                let mut t2: Vec<u8> = Vec::new();
                for p in &parsed.params {
                    if p.name == "T1" { if let ethers::abi::Token::Bytes(b) = &p.value { t1 = b.clone(); } }
                    if p.name == "T2" { if let ethers::abi::Token::Bytes(b) = &p.value { t2 = b.clone(); } }
                }
                if t1.len() != 128 || t2.len() != 128 { eprintln!("bad T lens"); continue; }

                println!("\n[event] PresentationVerified from prover {:?}", prover);

                // Auto-open
                let t1b = ethers::types::Bytes::from(t1.clone());
                let t2b = ethers::types::Bytes::from(t2.clone());
                let call = accumulator.contract.method::<_, ()>("requestOpen", (name_env.clone(), t1b, t2b))?;
                let pending = call.send().await?;
                let rcpt = pending.await?;
                let status_ok = rcpt.as_ref().and_then(|r| r.status).unwrap_or(U64::from(0)) == U64::from(1);
                println!("[sp] requestOpen tx status={}", if status_ok { "OK" } else { "FAIL" });

                if status_ok {
                    let idx = next_idx;
                    next_idx += 1;
                    entries.insert(idx, OpenedEntry {
                        e: U256::zero(),
                        a_short: "...".to_string(),
                        prover,
                        status: EntryStatus::Opening,
                    });
                    // Track by T1 hash so we can match the Opened event
                    let t1_hash = ethers::utils::keccak256(&t1).to_vec();
                    pending_opens.insert(t1_hash, idx);
                    print_table(&entries);
                }
                print!("> ");
                let _ = std::io::stdout().flush();
            }

            // --- Branch 1b: BatchPresentationVerified event ---
            Some(log) = async {
                match batch_pres_stream.as_mut() {
                    Some(s) => s.next().await,
                    None => std::future::pending::<Option<ethers::types::Log>>().await,
                }
            } => {
                // Decode batchSize, T1s, T2s from ABI-encoded event data
                // Event: BatchPresentationVerified(string indexed name, uint256 batchSize, bytes T1s, bytes T2s)
                let data = &log.data;
                if data.len() < 32 {
                    eprintln!("[batch] event data too short");
                } else {
                    // ABI decode: batchSize (uint256) + offset T1s + offset T2s + T1s bytes + T2s bytes
                    let tokens = match ethers::abi::decode(
                        &[
                            ethers::abi::ParamType::Uint(256),
                            ethers::abi::ParamType::Bytes,
                            ethers::abi::ParamType::Bytes,
                        ],
                        data,
                    ) {
                        Ok(t) => t,
                        Err(e) => { eprintln!("[batch] decode err: {:?}", e); continue; }
                    };
                    let batch_size = tokens[0].clone().into_uint().unwrap_or_default().as_u64() as usize;
                    let t1s_bytes = tokens[1].clone().into_bytes().unwrap_or_default();
                    let t2s_bytes = tokens[2].clone().into_bytes().unwrap_or_default();

                    println!("\n[event] BatchPresentationVerified — {} users", batch_size);

                    if t1s_bytes.len() != batch_size * 128 || t2s_bytes.len() != batch_size * 128 {
                        eprintln!("[batch] T1s/T2s length mismatch: {}*128 vs {}/{}", batch_size, t1s_bytes.len(), t2s_bytes.len());
                    } else {
                        // Auto-open each user in the batch
                        for j in 0..batch_size {
                            let t1 = &t1s_bytes[j * 128..(j + 1) * 128];
                            let t2 = &t2s_bytes[j * 128..(j + 1) * 128];
                            let t1b = ethers::types::Bytes::from(t1.to_vec());
                            let t2b = ethers::types::Bytes::from(t2.to_vec());
                            let call = accumulator.contract.method::<_, ()>("requestOpen", (name_env.clone(), t1b, t2b));
                            match call {
                                Ok(c) => {
                                    match c.send().await {
                                        Ok(pending) => {
                                            let rcpt = pending.await;
                                            let ok = rcpt.as_ref().ok()
                                                .and_then(|r| r.as_ref())
                                                .and_then(|r| r.status)
                                                .unwrap_or(U64::from(0)) == U64::from(1);
                                            println!("[sp] batch[{}] requestOpen tx status={}", j, if ok { "OK" } else { "FAIL" });
                                            if ok {
                                                let idx = next_idx;
                                                next_idx += 1;
                                                entries.insert(idx, OpenedEntry {
                                                    e: U256::zero(),
                                                    a_short: format!("batch#{}", j),
                                                    prover: H256::zero(),
                                                    status: EntryStatus::Opening,
                                                });
                                                let t1_hash = ethers::utils::keccak256(t1).to_vec();
                                                pending_opens.insert(t1_hash, idx);
                                            }
                                        }
                                        Err(e) => { eprintln!("[sp] batch[{}] requestOpen send err: {:?}", j, e); }
                                    }
                                }
                                Err(e) => { eprintln!("[sp] batch[{}] requestOpen build err: {:?}", j, e); }
                            }
                        }
                        print_table(&entries);
                    }
                }
                print!("> ");
                let _ = std::io::stdout().flush();
            }

            // --- Branch 2: Accumulator events (Opened / MemberRevoked) ---
            Some(lg) = acc_stream.next() => {
                if lg.topics.is_empty() { continue; }

                if lg.topics[0] == ev_opened && lg.topics.get(1).map(|t| *t == name_topic).unwrap_or(false) {
                    // Parse A from Opened event
                    let raw = RawLog { topics: lg.topics.clone(), data: lg.data.to_vec() };
                    let mut a_bytes: Vec<u8> = Vec::new();
                    if let Ok(parsed) = acc_opened_abi.parse_log(raw) {
                        for p in parsed.params.iter() {
                            if p.name == "A" { if let ethers::abi::Token::Bytes(b) = &p.value { a_bytes = b.clone(); } }
                        }
                    }
                    let a_short = if a_bytes.len() >= 8 { format!("0x{}...", hex::encode(&a_bytes[..8])) } else { "??".into() };
                    println!("\n[event] Opened — A={}", a_short);

                    // Resolve e via A→e mapping
                    let mut e_u = U256::zero();
                    if a_bytes.len() == 128 {
                        for _ in 0..50 {
                            match accumulator.contract.method::<_, U256>("getEByA", (name_env.clone(), ethers::types::Bytes::from(a_bytes.clone()))) {
                                Ok(call) => { if let Ok(x) = call.call().await { e_u = x; } }
                                Err(_) => {}
                            }
                            if !e_u.is_zero() { break; }
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        }
                    }

                    // Try to find which pending entry this belongs to.
                    // Heuristic: take the oldest Opening entry (FIFO), since we can't
                    // directly correlate T1→A without the opener's secret.
                    let matched_idx = {
                        let mut oldest: Option<usize> = None;
                        let mut keys: Vec<usize> = entries.keys().copied().collect();
                        keys.sort();
                        for k in keys {
                            if matches!(entries[&k].status, EntryStatus::Opening) {
                                oldest = Some(k);
                                break;
                            }
                        }
                        oldest
                    };

                    if let Some(idx) = matched_idx {
                        let ent = entries.get_mut(&idx).unwrap();
                        ent.e = e_u;
                        ent.a_short = a_short;
                        ent.status = EntryStatus::Opened;
                        if e_u.is_zero() {
                            println!("[sp] could not resolve e for entry #{} (A->e mapping missing?)", idx);
                        } else {
                            println!("[sp] entry #{} opened: e=0x{:x}", idx, e_u);
                        }
                    } else {
                        // No pending entry — might be from a different SP or stale event
                        if !e_u.is_zero() {
                            let idx = next_idx; next_idx += 1;
                            entries.insert(idx, OpenedEntry { e: e_u, a_short, prover: H256::zero(), status: EntryStatus::Opened });
                            println!("[sp] new entry #{} from external open: e=0x{:x}", idx, e_u);
                        }
                    }
                    print_table(&entries);
                    print!("> ");
                    let _ = std::io::stdout().flush();
                }
                else if lg.topics[0] == ev_revoked && lg.topics.get(1).map(|t| *t == name_topic).unwrap_or(false) {
                    let e_topic = lg.topics.get(2).cloned().unwrap_or_default();
                    let e_u = U256::from_big_endian(e_topic.as_bytes());
                    println!("\n[event] MemberRevoked — e=0x{:x}", e_u);
                    // Update any matching entry
                    for ent in entries.values_mut() {
                        if ent.e == e_u && matches!(ent.status, EntryStatus::Revoking) {
                            ent.status = EntryStatus::Revoked;
                        }
                    }
                    print_table(&entries);
                    print!("> ");
                    let _ = std::io::stdout().flush();
                }
            }

            // --- Branch 3: User input ---
            Some(line) = line_rx.recv() => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    print!("> ");
                    let _ = std::io::stdout().flush();
                    continue;
                }
                if line == "q" || line == "quit" {
                    println!("Bye.");
                    break;
                }
                if line == "l" || line == "list" {
                    print_table(&entries);
                    print!("> ");
                    let _ = std::io::stdout().flush();
                    continue;
                }
                if line == "h" || line == "help" || line == "?" {
                    print_help();
                    print!("> ");
                    let _ = std::io::stdout().flush();
                    continue;
                }
                if line.starts_with("r ") || line.starts_with("revoke ") {
                    let num_str = line.split_whitespace().nth(1).unwrap_or("");
                    let idx: usize = match num_str.parse() {
                        Ok(n) => n,
                        Err(_) => { println!("  usage: r <N>"); print!("> "); let _ = std::io::stdout().flush(); continue; }
                    };
                    let ent = match entries.get(&idx) {
                        Some(e) => e.clone(),
                        None => { println!("  entry #{} not found", idx); print!("> "); let _ = std::io::stdout().flush(); continue; }
                    };
                    if !matches!(ent.status, EntryStatus::Opened) {
                        println!("  entry #{} is {} — can only revoke OPENED entries", idx, ent.status);
                        print!("> ");
                        let _ = std::io::stdout().flush();
                        continue;
                    }
                    if ent.e.is_zero() {
                        println!("  entry #{} has no resolved e — cannot revoke", idx);
                        print!("> ");
                        let _ = std::io::stdout().flush();
                        continue;
                    }
                    println!("[sp] requesting revocation for entry #{} (e=0x{:x})...", idx, ent.e);
                    let call = accumulator.contract.method::<_, ()>("requestRevokeByE", (name_env.clone(), ent.e))?;
                    match call.send().await {
                        Ok(pending) => {
                            match pending.await {
                                Ok(rcpt) => {
                                    let ok = rcpt.as_ref().and_then(|r| r.status).unwrap_or(U64::from(0)) == U64::from(1);
                                    println!("[sp] requestRevokeByE tx status={}", if ok { "OK" } else { "FAIL" });
                                    if ok {
                                        entries.get_mut(&idx).unwrap().status = EntryStatus::Revoking;
                                    }
                                }
                                Err(e) => { eprintln!("[sp] revoke tx error: {:?}", e); }
                            }
                        }
                        Err(e) => { eprintln!("[sp] revoke send error: {:?}", e); }
                    }
                    print_table(&entries);
                    print!("> ");
                    let _ = std::io::stdout().flush();
                    continue;
                }
                println!("  unknown command: {}", line);
                print_help();
                print!("> ");
                let _ = std::io::stdout().flush();
            }
        }
    }
    Ok(())
}
