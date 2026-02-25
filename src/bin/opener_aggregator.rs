use std::env;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_serialize::CanonicalDeserialize;
use ark_ec::Group;
use ark_ff::{Zero, PrimeField};
use base64::Engine as _;
use ethers::abi::Abi;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use futures::StreamExt;

use tbbsplus_rust::orchestration::crypto::encoding::{
    eip2537_g1_to_affine,
    eip2537_g2_to_affine,
    g1_to_eip2537_bytes,
};
use tbbsplus_rust::orchestration::mesh::p2p::Mesh;
#[cfg(feature = "mpc")]
use libp2p::Multiaddr;
use secret_sharing_and_dkg::common::lagrange_basis_at_0;
// Use vb_accumulator directly for membership verification (no witness batch updates)
use std::time::Instant;
use std::io::Write as _;
use vb_accumulator::positive::Accumulator as _;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OpenAnnounceMsg {
    sid: u64,
    name: String,
    aggregator_idx: u16,
    aggregator_peer_id: String,
    t1: Vec<u8>,
    t2: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RevokeAnnounceMsg {
    sid: u64,
    name: String,
    aggregator_idx: u16,
    aggregator_peer_id: String,
    e_hex: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OpenPartialMsg {
    sid: u64,
    from_idx: u16,
    tbar_128: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AccDelSigShareMsg {
    sid: u64,
    from: u16,
    share_b64: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AccAddAnnounceMsg {
    sid: u64,
    name: String,
    aggregator_idx: u16,
    aggregator_peer_id: String,
    subset: Vec<u16>,
    v128: Vec<u8>,
    e_hex: String,
    seq: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AccAddContribMsg {
    sid: u64,
    from_idx: u16,
    contrib_128: Vec<u8>,
}

fn lagrange_coeffs_at_zero(indices: &[u16]) -> Vec<Fr> {
    use ark_ff::Field;
    let xs: Vec<Fr> = indices.iter().map(|i| Fr::from(*i as u64)).collect();
    let mut lambdas = vec![Fr::from(0u64); indices.len()];
    for i in 0..indices.len() {
        let mut num = Fr::from(1u64);
        let mut den = Fr::from(1u64);
        for j in 0..indices.len() {
            if i == j { continue; }
            num *= -xs[j];
            den *= xs[i] - xs[j];
        }
        lambdas[i] = num * den.inverse().unwrap();
    }
    lambdas
}

fn load_abi(path: &str, tag: &str) -> anyhow::Result<Abi> {
    let art = std::fs::read(path).map_err(|e| anyhow::anyhow!("[opener_agg] read {} failed: {:?}", path, e))?;
    let v: serde_json::Value = serde_json::from_slice(&art)
        .map_err(|e| anyhow::anyhow!("[opener_agg] parse {} failed: {:?}", path, e))?;
    let abi_val = v.get("abi").cloned().ok_or_else(|| anyhow::anyhow!("[opener_agg] {} abi missing in {}", tag, path))?;
    let abi: Abi = serde_json::from_value(abi_val)
        .map_err(|e| anyhow::anyhow!("[opener_agg] {} abi decode failed: {:?}", tag, e))?;
    Ok(abi)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let chain_id: u64 = env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse()?;
    let cred_name = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
    let participant_id: u16 = env::var("PID").unwrap_or_else(|_| "1".into()).parse()?;

    // --- Batch accumulator config ---
    let batch_add_size: usize = env::var("BATCH_ADD_SIZE").unwrap_or_else(|_| "1".into()).parse()?;
    let batch_add_timeout_ms: u64 = env::var("BATCH_ADD_TIMEOUT_MS").unwrap_or_else(|_| "5000".into()).parse()?;
    let reannounce_ms: u64 = env::var("AGG_REANNOUNCE_MS").unwrap_or_else(|_| "800".into()).parse().unwrap_or(800);

    let wallet: LocalWallet = env::var("AGGREGATOR_PK")
        .or_else(|_| env::var("OWNER_PK"))
        .unwrap_or_else(|_| "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6".into())
        .parse::<LocalWallet>()?
        .with_chain_id(chain_id);

    let ws = Provider::<Ws>::connect(ws_url.clone()).await?;
    let client = std::sync::Arc::new(SignerMiddleware::new(ws, wallet));

    // Contracts
    let params_addr: Address = env::var("PARAMS_CONTRACT")?.parse()?;
    let acc_addr: Address = env::var("ACC_CONTRACT")?.parse()?;
    let registry_addr: Address = env::var("REGISTRY_CONTRACT")?.parse()?;

    let params = {
        let abi = load_abi("artifacts/contracts/Params.sol/Params.json", "params")?;
        Contract::new(params_addr, abi, client.clone())
    };
    let accumulator = {
        let abi = load_abi("artifacts/contracts/Accumulator.sol/Accumulator.json", "accumulator")?;
        Contract::new(acc_addr, abi, client.clone())
    };
    let registry = {
        let abi = load_abi("artifacts/contracts/CredentialRegistry.sol/CredentialRegistry.json", "registry")?;
        Contract::new(registry_addr, abi, client.clone())
    };

    // Params data used for pairing checks
    let (g1_b, _h0_b, g2_b): (ethers::types::Bytes, ethers::types::Bytes, ethers::types::Bytes) = params
        .method("getG1H0G2ByName", (cred_name.clone(),))?
        .call()
        .await?;
    let g1 = eip2537_g1_to_affine(&g1_b.0[..])?;
    let g2 = eip2537_g2_to_affine(&g2_b.0[..])?;
    // Build vb_accumulator params and public key directly from on-chain Params
    let pk_acc_bytes: ethers::types::Bytes = params
        .method("getOpenerPkG2ByName", (cred_name.clone(),))?
        .call()
        .await
        .unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
    if pk_acc_bytes.0.len() != 256 { anyhow::bail!("opener pkG2 missing in Params"); }
    let vb_params = vb_accumulator::setup::SetupParams::<Bls12_381> { P: g1, P_tilde: g2 };
    let vb_pk = vb_accumulator::setup::PublicKey::<Bls12_381>(eip2537_g2_to_affine(&pk_acc_bytes.0[..])?);

    // Mesh peers from openers (optional dialing)
    let openers: Vec<Address> = params.method::<_, Vec<Address>>("getOpeners", ())?.call().await.unwrap_or_default();
    let mut peers = Vec::new();
    for addr in openers {
        let allowed: bool = params.method::<_, bool>("openerAllowed", (addr,))?.call().await.unwrap_or(false);
        if !allowed { continue; }
        let idx: u16 = params.method::<_, u16>("openerIndex", (addr,))?.call().await.unwrap_or(0);
        if idx == 0 { continue; }
        let addrs: Vec<String> = params.method::<_, Vec<String>>("getOpenerMultiaddrs", (addr,))?.call().await.unwrap_or_default();
        if let Some(ma) = addrs.get(0) { if let Ok(m) = ma.parse() { peers.push((idx, m)); } }
    }

    // Start mesh
    let base_port: u16 = env::var("BASE_PORT").unwrap_or_else(|_| "10900".into()).parse()?;
    let listen_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", base_port + participant_id - 1).parse()?;
    let mut mesh = Mesh::new(participant_id, Some(listen_addr), peers.clone()).await?;
    let mut direct_rx = mesh.subscribe_direct().await?;
    let local_peer_id_str = mesh.local_peer_id().to_string();
    let handle = mesh.run_background();

    // Subscribe to chain events
    use ethers::types::{Filter, ValueOrArray, H256, BlockNumber};
    let ev_open = H256::from(ethers::utils::keccak256(b"OpenRequested(string,address,bytes,bytes)"));
    let name_topic = H256::from(ethers::utils::keccak256(cred_name.as_bytes()));
    let filter_open = Filter::new()
        .address(ValueOrArray::Value(acc_addr))
        .topic0(ValueOrArray::Value(ev_open))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Latest);
    let mut stream_open = client.provider().subscribe_logs(&filter_open).await?;

    let ev_rev = H256::from(ethers::utils::keccak256(b"RevokeRequested(string,uint256)"));
    let filter_rev = Filter::new()
        .address(ValueOrArray::Value(acc_addr))
        .topic0(ValueOrArray::Value(ev_rev))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Latest);
    let mut stream_rev = client.provider().subscribe_logs(&filter_rev).await?;

    let ev_memrev = H256::from(ethers::utils::keccak256(b"MemberRevoked(string,uint256,bytes)"));
    let filter_memrev_latest = Filter::new()
        .address(ValueOrArray::Value(acc_addr))
        .topic0(ValueOrArray::Value(ev_memrev))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Latest);
    let mut stream_memrev = client.provider().subscribe_logs(&filter_memrev_latest).await?;

    // removed per-e witness event subscription

    let ev_conf = H256::from(ethers::utils::keccak256(b"Confirmed(string,uint256)"));
    let filter_conf = Filter::new()
        .address(ValueOrArray::Value(registry.address()))
        .topic0(ValueOrArray::Value(ev_conf))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Latest);
    let mut stream_conf = client.provider().subscribe_logs(&filter_conf).await?;

    use std::collections::{BTreeMap, BTreeSet};
    let mut partials: BTreeMap<u64, Vec<(u16, Vec<u8>, Vec<u8>)>> = BTreeMap::new();
    let mut open_seen: BTreeMap<u64, BTreeSet<u16>> = BTreeMap::new(); // dedup: sid -> set of from_idx received
    let mut announces: BTreeMap<u64, (Vec<u8>, Vec<u8>)> = BTreeMap::new();
    let mut del_shares: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();
    let mut e_by_sid: BTreeMap<u64, U256> = BTreeMap::new();
    // Use THRESHOLD_OPENER for scaling studies;
    let threshold: u16 = env::var("THRESHOLD_OPENER")
        .unwrap_or_else(|_| "3".into())
        .parse()?;

    // Track addition round metadata and contributions per sid
    use std::collections::BTreeMap as Map;
    let mut add_meta: Map<u64, (Vec<u16>, Vec<u8>, U256, u64)> = Map::new(); // sid -> (subset, V128, e, seq)
    let mut add_contribs: Map<u64, Vec<(u16, Vec<u8>)>> = Map::new(); // sid -> vec[(idx, contrib)]
    let mut add_seen: Map<u64, std::collections::BTreeSet<u16>> = Map::new(); // sid -> set of idx received
    let mut add_start: Map<u64, std::time::Instant> = Map::new(); // sid -> start time at Confirmed
    let mut members: std::collections::BTreeSet<U256> = std::collections::BTreeSet::new(); // all added e values
    let mut revoked_set: std::collections::BTreeSet<U256> = std::collections::BTreeSet::new(); // revoked e values

    // Accumulator addition state
    let mut local_v: Option<Vec<u8>> = None; // locally-tracked V (not yet submitted to chain)
    let mut pending_adds: Vec<U256> = Vec::new(); // buffered elements for batch chain submission
    let mut pending_v_new: Option<ethers::types::Bytes> = None; // final delta for the batch
    let mut batch_add_first: Option<std::time::Instant> = None; // first arrival timestamp
    // Serialized addition queue: buffer Confirmed events and process one V-chain round at a time
    let mut add_queue: std::collections::VecDeque<(u64, U256)> = std::collections::VecDeque::new();
    let mut add_in_progress: bool = false;

    // Initialize members from past Confirmed events (through registry)
    let filter_conf_all = Filter::new()
        .address(ValueOrArray::Value(registry.address()))
        .topic0(ValueOrArray::Value(ev_conf))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Earliest)
        .to_block(BlockNumber::Latest);
    if let Ok(init_logs) = client.provider().get_logs(&filter_conf_all).await {
        for lg in init_logs {
            if let Some(uid_topic) = lg.topics.get(2) {
                let uid_u = U256::from_big_endian(uid_topic.as_bytes());
                let (_a_bytes, e_u, _s_u, _status): (ethers::types::Bytes, U256, U256, u8) = registry
                    .method("getSignature", (cred_name.clone(), uid_u))?
                    .call().await
                    .unwrap_or((ethers::types::Bytes::from_static(&[]), U256::zero(), U256::zero(), 0));
                if !e_u.is_zero() { members.insert(e_u); }
            }
        }
    }
    // Initialize revoked set and subtract from members
    let filter_memrev_all = Filter::new()
        .address(ValueOrArray::Value(acc_addr))
        .topic0(ValueOrArray::Value(ev_memrev))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Earliest)
        .to_block(BlockNumber::Latest);
    if let Ok(init_logs) = client.provider().get_logs(&filter_memrev_all).await {
        for lg in init_logs {
            if let Some(e_topic) = lg.topics.get(2) {
                let e_u = U256::from_big_endian(e_topic.as_bytes());
                if !e_u.is_zero() { revoked_set.insert(e_u); members.remove(&e_u); }
            }
        }
    }

    loop {
        tokio::select! {
            ev = stream_conf.next() => {
                if let Some(lg) = ev {
                    let uid_topic = lg.topics.get(2).cloned().unwrap_or_default();
                    let user_id_u = U256::from_big_endian(uid_topic.as_bytes());
                    println!("[agg] Confirmed event for userId={}", user_id_u);
                    let t0_reg = std::time::Instant::now();
                    // Derive a u64 session id by hashing the userId (userId is U256, too large for u64 cast)
                    let add_sid: u64 = {
                        let mut uid_be = [0u8; 32]; user_id_u.to_big_endian(&mut uid_be);
                        let h = ethers::utils::keccak256(uid_be);
                        u64::from_be_bytes(h[..8].try_into().unwrap())
                    };
                    let (a_bytes, e_u, _s_u, _status): (ethers::types::Bytes, U256, U256, u8) = registry
                        .method("getSignature", (cred_name.clone(), user_id_u))?
                        .call().await
                        .unwrap_or((ethers::types::Bytes::from_static(&[]), U256::zero(), U256::zero(), 0));
                    if a_bytes.0.len() == 128 && !e_u.is_zero() {
                        // Queue for serialized processing (V-chain: each round must complete before next)
                        add_queue.push_back((add_sid, e_u));
                        add_start.insert(add_sid, t0_reg);
                        println!("[agg] Confirmed queued userId={} sid={} queue_len={}", user_id_u, add_sid, add_queue.len());
                        // Start immediately if no round in progress
                        if !add_in_progress {
                            let (next_sid, next_e) = add_queue.pop_front().unwrap();
                            let v128: Vec<u8> = if let Some(ref lv) = local_v {
                                lv.clone()
                            } else {
                                let delta_bytes: ethers::types::Bytes = accumulator.method("getDelta", (cred_name.clone(),))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
                                if delta_bytes.0.len() == 128 { delta_bytes.0.to_vec() } else {
                                    let (g1_b, _h0_b, _g2_b): (ethers::types::Bytes, ethers::types::Bytes, ethers::types::Bytes) = params.method("getG1H0G2ByName", (cred_name.clone(),))?.call().await?;
                                    g1_b.0.to_vec()
                                }
                            };
                            let mut subset: Vec<u16> = peers.iter().map(|(i, _)| *i).collect();
                            subset.sort_unstable();
                            if subset.len() > threshold as usize { subset.truncate(threshold as usize); }
                            if subset.len() < threshold as usize { println!("[agg] WARN: subset smaller than threshold: {} < {}", subset.len(), threshold); }
                            let msg = AccAddAnnounceMsg { sid: next_sid, name: cred_name.clone(), aggregator_idx: participant_id, aggregator_peer_id: local_peer_id_str.clone(), subset: subset.clone(), v128: v128.clone(), e_hex: format!("0x{:x}", next_e), seq: 1 };
                            handle.broadcast("acc-add-announce", serde_json::to_vec(&msg)?).await?;
                            add_meta.insert(next_sid, (subset.clone(), v128.clone(), next_e, 1));
                            add_in_progress = true;
                            println!("[agg] addition announced sid={} subset={:?}", next_sid, subset);
                        }
                    } else {
                        println!("[agg] WARN: Confirmed but missing/invalid (A,e) for userId={}", user_id_u);
                    }
                }
            },
            ev = stream_open.next() => {
                if let Some(log) = ev {
                    let raw = ethers::abi::RawLog { topics: log.topics.clone(), data: log.data.to_vec() };
                    let evabi = accumulator.abi().event("OpenRequested")?;
                    let parsed = match evabi.parse_log(raw) { Ok(p) => p, Err(_) => continue };
                    let mut t1_b = Vec::new(); let mut t2_b = Vec::new();
                    for p in parsed.params.iter() { if let ethers::abi::Token::Bytes(b) = &p.value { if t1_b.is_empty() { t1_b=b.clone(); } else { t2_b=b.clone(); } } }
                    if t1_b.len()!=128 || t2_b.len()!=128 { continue; }
                    let mut sid_be=[0u8;8]; let mut h=[0u8;32]; h.copy_from_slice(&ethers::utils::keccak256([t1_b.as_slice(), t2_b.as_slice()].concat())); sid_be.copy_from_slice(&h[..8]); let sid=u64::from_be_bytes(sid_be);
                    println!("[agg] caught OpenRequested -> sid={} (T1/T2 hashed)", sid);
                    announces.insert(sid, (t1_b.clone(), t2_b.clone()));
                    partials.entry(sid).or_default();
                    let announce = OpenAnnounceMsg { sid, name: cred_name.clone(), aggregator_idx: participant_id, aggregator_peer_id: local_peer_id_str.clone(), t1: t1_b, t2: t2_b };
                    handle.broadcast("open-announce", serde_json::to_vec(&announce)?).await?;
                }
            },
            ev = stream_rev.next() => {
                if let Some(lg) = ev {
                    let e_topic = lg.topics.get(2).cloned().unwrap_or_default();
                    let e_u = U256::from_big_endian(e_topic.as_bytes());
                    if e_u.is_zero() { continue; }
                    let mut sid_be=[0u8;8]; let mut e_be32=[0u8;32]; U256::from(e_u).to_big_endian(&mut e_be32); let mut h=[0u8;32]; h.copy_from_slice(&ethers::utils::keccak256(e_be32)); sid_be.copy_from_slice(&h[..8]); let sid=u64::from_be_bytes(sid_be);
                    println!("[agg] caught RevokeRequested -> sid={} e=0x{:x}", sid, e_u);
                    e_by_sid.insert(sid, e_u);
                    let msg = RevokeAnnounceMsg { sid, name: cred_name.clone(), aggregator_idx: participant_id, aggregator_peer_id: local_peer_id_str.clone(), e_hex: format!("0x{:x}", e_u) };
                    handle.broadcast("revoke-announce", serde_json::to_vec(&msg)?).await?;
                }
            },
            ev = stream_memrev.next() => {
                if let Some(lg) = ev {
                    if let Some(e_topic) = lg.topics.get(2) {
                        let e_u = U256::from_big_endian(e_topic.as_bytes());
                        if !e_u.is_zero() { revoked_set.insert(e_u); members.remove(&e_u); }
                    }
                }
            },
            // removed per-e witness event arm
            dm = direct_rx.recv() => {
                if let Some(dm) = dm {
                    // Open partials, deletion shares, or addition contributions
                    if let Ok(msg) = serde_json::from_slice::<OpenPartialMsg>(&dm.data) {
                        // Deduplicate: skip if this opener already submitted a partial for this sid
                        let seen = open_seen.entry(msg.sid).or_default();
                        if !seen.insert(msg.from_idx) {
                            println!("[agg] duplicate open partial from {} (sid={}) ignored", msg.from_idx, msg.sid);
                            continue;
                        }
                        let entry = partials.entry(msg.sid).or_default();
                        entry.push((msg.from_idx, msg.tbar_128.clone(), Vec::new()));
                        println!("[agg] open partial from {} (sid={}, {}/{})", msg.from_idx, msg.sid, entry.len(), threshold);
                        if entry.len() as u16 >= threshold {
                            // Verify and recombine
                            let t0_recon = Instant::now();
                            let Some((t1b, t2b)) = announces.get(&msg.sid) else { continue };
                            let t1 = match eip2537_g1_to_affine(&t1b[..]) { Ok(v) => v, Err(_) => continue };
                            let mut verified = Vec::new();
                            for (idx, tbar_b, _proof_b) in entry.iter().take(threshold as usize) {
                                let y_i_bytes: ethers::types::Bytes = params.method("getOpenerCommitment", (cred_name.clone(), *idx))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
                                if y_i_bytes.0.len()!=256 { continue; }
                                let y_i = eip2537_g2_to_affine(&y_i_bytes.0[..])?;
                                let tbar = eip2537_g1_to_affine(&tbar_b[..])?;
                                // pairing check e(T1, Y_i) == e(tbar, g2)
                                let lhs = Bls12_381::pairing(t1, y_i);
                                let rhs = Bls12_381::pairing(tbar, g2);
                                if lhs != rhs { continue; }
                                verified.push((*idx, tbar));
                            }
                            if verified.len() as u16 >= threshold {
                                let indices: Vec<u16> = verified.iter().map(|(i, _)| *i).collect();
                                let lambdas = lagrange_coeffs_at_zero(&indices);
                                let mut acc_g = <Bls12_381 as Pairing>::G1::zero();
                                for ((_, tbar_i), lam) in verified.iter().zip(lambdas.iter()) {
                                    acc_g += tbar_i.into_group().mul_bigint((*lam).into_bigint());
                                }
                                let tbar_agg = acc_g.into_affine();
                                let t2 = match eip2537_g1_to_affine(&t2b[..]) { Ok(v) => v, Err(_) => continue };
                                let a = (t2.into_group() + (-tbar_agg).into_group()).into_affine();
                                let a_bytes = g1_to_eip2537_bytes(&a).to_vec();
                                let rcpt = accumulator.method::<_, ()>("publishOpenResult", (cred_name.clone(), ethers::types::Bytes::from(a_bytes.clone())))?.send().await?.await?;
                                if std::env::var("METRICS").map(|v| v=="1"||v.eq_ignore_ascii_case("true")).unwrap_or(false) {
                                    if let Some(r) = rcpt.as_ref() {
                                        let gas_used = r.gas_used.unwrap_or_default();
                                        let eff_price = r.effective_gas_price.unwrap_or_default();
                                        let cost = gas_used * eff_price;
                                        let blk = r.block_number.unwrap_or_default();
                                        let mf = std::env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/aggregator.ndjson".into());
                                        let _ = (||{
                                            let _=std::fs::create_dir_all(std::path::Path::new(&mf).parent().unwrap());
                                            let mut f=std::fs::OpenOptions::new().create(true).append(true).open(&mf).unwrap();
                                            let _=writeln!(f, "{}", serde_json::json!({
                                                "scenario":"agg_publishOpenResult",
                                                "sid": msg.sid,
                                                "threshold": threshold,
                                                "hash": format!("0x{:x}", r.transaction_hash),
                                                "blockNumber": blk.as_u64(),
                                                "gasUsed": gas_used.to_string(),
                                                "effectiveGasPrice": eff_price.to_string(),
                                                "costWei": cost.to_string()
                                            }));
                                            Ok::<(),()>(())
                                        })();
                                    }
                                }
                                // resolve e
                                let mut e_u = U256::zero();
                                for _ in 0..10 {
                                    let x: U256 = accumulator.method("getEByA", (cred_name.clone(), ethers::types::Bytes::from(a_bytes.clone()),))?.call().await.unwrap_or(U256::zero());
                                    if x != U256::zero() { e_u = x; break; }
                                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                }
                                if e_u != U256::zero() {
                                    println!("[agg] opened: e=0x{:x}", e_u);
                                } else {
                                    println!("[agg] opened: e unresolved yet");
                                }
                                // Clean up completed open session so it won't be re-announced
                                announces.remove(&msg.sid);
                                partials.remove(&msg.sid);
                                open_seen.remove(&msg.sid);
                            }
                        }
                    } else if let Ok(v) = serde_json::from_slice::<AccDelSigShareMsg>(&dm.data) {
                        let entry = del_shares.entry(v.sid).or_default();
                        let data = base64::engine::general_purpose::STANDARD.decode(v.share_b64).unwrap_or_default();
                        entry.push(data);
                        if entry.len() as u16 >= threshold {
                            use short_group_sig::threshold_weak_bb_sig::SigShare as AccSigShare;
                            let mut shares = Vec::with_capacity(threshold as usize);
                            for b in entry.iter().take(threshold as usize) {
                                let mut rb = &b[..]; let sh: AccSigShare<<Bls12_381 as Pairing>::G1Affine> = CanonicalDeserialize::deserialize_compressed(&mut rb).unwrap();
                                shares.push(sh);
                            }
                            let t0_agg = Instant::now();
                            let new_delta_aff = AccSigShare::aggregate(shares);
                            let new_delta_b = ethers::types::Bytes::from(g1_to_eip2537_bytes(&new_delta_aff).to_vec());
                            if let Some(e_u) = e_by_sid.get(&v.sid).cloned() {
                                let rcpt = accumulator.method::<_, ()>("deleteMember", (cred_name.clone(), e_u, new_delta_b.clone()))?.send().await?.await?;
                                println!("[agg] deleteMember executed for sid={} e=0x{:x}", v.sid, e_u);
                                // Witnesses are now computed off-chain by users from event logs.
                                // No publishWitnessBatch needed.
                                // Update local sets
                                revoked_set.insert(e_u);
                                members.remove(&e_u);
                                if std::env::var("METRICS").map(|v| v=="1"||v.eq_ignore_ascii_case("true")).unwrap_or(false) {
                                    if let Some(r) = rcpt.as_ref() {
                                        let gas_used = r.gas_used.unwrap_or_default();
                                        let eff_price = r.effective_gas_price.unwrap_or_default();
                                        let cost = gas_used * eff_price;
                                        let blk = r.block_number.unwrap_or_default();
                                        let mf = std::env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/aggregator.ndjson".into());
                                        let _ = (||{
                                            let _=std::fs::create_dir_all(std::path::Path::new(&mf).parent().unwrap());
                                            let mut f=std::fs::OpenOptions::new().create(true).append(true).open(&mf).unwrap();
                                            let _=writeln!(f, "{}", serde_json::json!({
                                                "scenario":"agg_deleteMember",
                                                "sid": v.sid,
                                                "threshold": threshold,
                                                "hash": format!("0x{:x}", r.transaction_hash),
                                                "blockNumber": blk.as_u64(),
                                                "gasUsed": gas_used.to_string(),
                                                "effectiveGasPrice": eff_price.to_string(),
                                                "costWei": cost.to_string()
                                            }));
                                            Ok::<(),()>(())
                                        })();
                                    }
                                }
                            } else {
                                println!("[agg] deleteMember: e missing for sid={}", v.sid);
                            }
                        }
                    } else if let Ok(ac) = serde_json::from_slice::<AccAddContribMsg>(&dm.data) {
                        // Collect addition contrib with de-dup per (sid, from_idx)
                        let seen = add_seen.entry(ac.sid).or_default();
                        if !seen.insert(ac.from_idx) {
                            println!("[agg] duplicate add-contrib from {} (sid={}) ignored", ac.from_idx, ac.sid);
                            continue;
                        }
                        let entry = add_contribs.entry(ac.sid).or_default();
                        entry.push((ac.from_idx, ac.contrib_128.clone()));
                        println!("[agg] add-contrib from {} (sid={})", ac.from_idx, ac.sid);
                        // Only proceed when we have threshold unique contributors from the announced subset
                        if let Some((subset, v128, e_u, _seq)) = add_meta.get(&ac.sid).cloned() {
                            let ready = subset.iter().all(|i| seen.contains(i));
                            if !ready { continue; }
                            // Prepare V and constants
                            let v_anchor = match eip2537_g1_to_affine(&v128[..]) { Ok(v) => v, Err(_) => { println!("[agg] invalid V bytes"); continue; } };
                            let e_fr: Fr = tbbsplus_rust::orchestration::crypto::encoding::u256_to_fr(&e_u);
                            // Verify contributions for exactly the designated subset and sum
                            let t0_verify = Instant::now();
                            let mut sum_c = <Bls12_381 as Pairing>::G1::zero();
                            let mut ok_subset = true;
                            for idx in subset.iter() {
                                // find contribution for this idx
                                let Some((_, contrib_b)) = entry.iter().find(|(i, _)| i == idx) else { ok_subset = false; break; };
                                let lam = match lagrange_basis_at_0::<Fr>(&subset, *idx) { Ok(l) => l, Err(_) => { println!("[agg] lagrange failed for {}", idx); ok_subset = false; break; } };
                                let contrib = match eip2537_g1_to_affine(&contrib_b[..]) { Ok(v) => v, Err(_) => { ok_subset = false; break; } };
                                // Fetch Y_i, compute Y_i^lambda
                                let y_i_bytes: ethers::types::Bytes = params.method("getOpenerCommitment", (cred_name.clone(), *idx))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
                                if y_i_bytes.0.len() != 256 { println!("[agg] missing Y_i for idx {}", idx); ok_subset = false; break; }
                                let y_i = eip2537_g2_to_affine(&y_i_bytes.0[..])?;
                                let y_lam = (y_i.into_group().mul_bigint(lam.into_bigint())).into_affine();
                                // Pairing check: e(C_i, g2) == e(V, Y_i^lambda)
                                let lhs = Bls12_381::pairing(contrib, g2);
                                let rhs = Bls12_381::pairing(v_anchor, y_lam);
                                if lhs != rhs { println!("[agg] pairing check failed for idx {}", idx); ok_subset = false; break; }
                                sum_c += contrib.into_group();
                            }
                            if !ok_subset { continue; }
                            // Compute V' = sum_c + e*V (keep V_old for witness updates)
                            let v_old_anchor = v_anchor;
                            let v_e = v_old_anchor.into_group().mul_bigint(e_fr.into_bigint());
                            let v_new = (sum_c + v_e).into_affine();
                            // vb_accumulator: verify membership of e in new Delta with witness W = old V
                            let ok = vb_accumulator::positive::PositiveAccumulator::<ark_bls12_381::G1Affine>::verify_membership_given_accumulated::<Bls12_381>(
                                &v_new,
                                &e_fr,
                                &vb_accumulator::witness::MembershipWitness::<ark_bls12_381::G1Affine>(v_old_anchor),
                                &vb_pk,
                                &vb_params,
                            );
                            if !ok {
                                println!("[agg] ERROR: vb_accumulator membership verify failed; aborting setDelta for sid={}", ac.sid);
                                add_meta.remove(&ac.sid);
                                add_contribs.remove(&ac.sid);
                                add_seen.remove(&ac.sid);
                                // Release lock and drain queue even on failure
                                add_in_progress = false;
                                if !add_queue.is_empty() {
                                    let (next_sid, next_e) = add_queue.pop_front().unwrap();
                                    let v128: Vec<u8> = if let Some(ref lv) = local_v {
                                        lv.clone()
                                    } else {
                                        let delta_bytes: ethers::types::Bytes = accumulator.method("getDelta", (cred_name.clone(),))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
                                        if delta_bytes.0.len() == 128 { delta_bytes.0.to_vec() } else {
                                            let (g1_b, _h0_b, _g2_b): (ethers::types::Bytes, ethers::types::Bytes, ethers::types::Bytes) = params.method("getG1H0G2ByName", (cred_name.clone(),))?.call().await?;
                                            g1_b.0.to_vec()
                                        }
                                    };
                                    let mut subset: Vec<u16> = peers.iter().map(|(i, _)| *i).collect();
                                    subset.sort_unstable();
                                    if subset.len() > threshold as usize { subset.truncate(threshold as usize); }
                                    let msg = AccAddAnnounceMsg { sid: next_sid, name: cred_name.clone(), aggregator_idx: participant_id, aggregator_peer_id: local_peer_id_str.clone(), subset: subset.clone(), v128: v128.clone(), e_hex: format!("0x{:x}", next_e), seq: 1 };
                                    handle.broadcast("acc-add-announce", serde_json::to_vec(&msg)?).await?;
                                    add_meta.insert(next_sid, (subset.clone(), v128.clone(), next_e, 1));
                                    add_in_progress = true;
                                    println!("[agg] next queued addition started after error: sid={}", next_sid);
                                }
                                continue;
                            }
                            if std::env::var("METRICS").map(|v| v=="1"||v.eq_ignore_ascii_case("true")).unwrap_or(false) {
                                let mf = std::env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/aggregator.ndjson".into());
                                let _ = (||{ let _=std::fs::create_dir_all(std::path::Path::new(&mf).parent().unwrap()); let mut f=std::fs::OpenOptions::new().create(true).append(true).open(&mf).unwrap(); let _=writeln!(f, "{}", serde_json::json!({"scenario":"acc_add_verify_sum","sid": ac.sid, "threshold": threshold, "ms": t0_verify.elapsed().as_millis() as u64})); Ok::<(),()>(())})();
                            }
                            // Buffer for batch submission
                            let v_new_b = ethers::types::Bytes::from(g1_to_eip2537_bytes(&v_new).to_vec());
                            local_v = Some(g1_to_eip2537_bytes(&v_new).to_vec());
                            pending_adds.push(e_u);
                            pending_v_new = Some(v_new_b.clone());
                            if batch_add_first.is_none() { batch_add_first = Some(std::time::Instant::now()); }
                            members.insert(e_u);
                            println!("[agg] addition verified for sid={}, buffered ({}/{})", ac.sid, pending_adds.len(), batch_add_size);
                            add_meta.remove(&ac.sid);
                            add_contribs.remove(&ac.sid);
                            add_seen.remove(&ac.sid);

                            // Flush batch if full or in single mode
                            if pending_adds.len() >= batch_add_size || batch_add_size <= 1 {
                                let metrics = std::env::var("METRICS").map(|v| v=="1"||v.eq_ignore_ascii_case("true")).unwrap_or(false);
                                let final_v = pending_v_new.take().unwrap();
                                let es: Vec<U256> = pending_adds.drain(..).collect();
                                let n = es.len();
                                let rcpt = if n == 1 {
                                    accumulator.method::<_, ()>("addMember", (cred_name.clone(), es[0], final_v))?.send().await?.await?
                                } else {
                                    accumulator.method::<_, ()>("addMembers", (cred_name.clone(), es.clone(), final_v))?.send().await?.await?
                                };
                                let gas_total = rcpt.as_ref().and_then(|r| r.gas_used).unwrap_or_default();
                                let scenario = if n == 1 { "acc_register_info_e2e" } else { "acc_addMembers_batch" };
                                if metrics {
                                    let mf = std::env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/aggregator.ndjson".into());
                                    let ms: u64 = add_start.remove(&ac.sid).map(|t0| t0.elapsed().as_millis() as u64).unwrap_or(0);
                                    let _ = (||{ let _=std::fs::create_dir_all(std::path::Path::new(&mf).parent().unwrap()); let mut f=std::fs::OpenOptions::new().create(true).append(true).open(&mf).unwrap(); let _=writeln!(f, "{}", serde_json::json!({"scenario": scenario, "batch_size": n, "sid": ac.sid, "threshold": threshold, "ms": ms, "gasUsedTotal": gas_total.to_string()})); Ok::<(),()>(())})();
                                }
                                local_v = None;
                                batch_add_first = None;
                                println!("[agg] {} done: {} member(s) added", scenario, n);
                            }
                            // V-chain round complete: start next queued addition
                            add_in_progress = false;
                            if !add_queue.is_empty() {
                                let (next_sid, next_e) = add_queue.pop_front().unwrap();
                                let v128: Vec<u8> = if let Some(ref lv) = local_v {
                                    lv.clone()
                                } else {
                                    let delta_bytes: ethers::types::Bytes = accumulator.method("getDelta", (cred_name.clone(),))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
                                    if delta_bytes.0.len() == 128 { delta_bytes.0.to_vec() } else {
                                        let (g1_b, _h0_b, _g2_b): (ethers::types::Bytes, ethers::types::Bytes, ethers::types::Bytes) = params.method("getG1H0G2ByName", (cred_name.clone(),))?.call().await?;
                                        g1_b.0.to_vec()
                                    }
                                };
                                let mut subset: Vec<u16> = peers.iter().map(|(i, _)| *i).collect();
                                subset.sort_unstable();
                                if subset.len() > threshold as usize { subset.truncate(threshold as usize); }
                                if subset.len() < threshold as usize { println!("[agg] WARN: subset smaller than threshold"); }
                                let msg = AccAddAnnounceMsg { sid: next_sid, name: cred_name.clone(), aggregator_idx: participant_id, aggregator_peer_id: local_peer_id_str.clone(), subset: subset.clone(), v128: v128.clone(), e_hex: format!("0x{:x}", next_e), seq: 1 };
                                handle.broadcast("acc-add-announce", serde_json::to_vec(&msg)?).await?;
                                add_meta.insert(next_sid, (subset.clone(), v128.clone(), next_e, 1));
                                add_in_progress = true;
                                println!("[agg] next queued addition started: sid={}", next_sid);
                            }
                        }
                    }
                }
            }
            // Periodically re-announce pending sessions + flush batch on timeout
            _ = tokio::time::sleep(std::time::Duration::from_millis(reannounce_ms)) => {
                // Flush pending batch adds if timeout expired
                if !pending_adds.is_empty() {
                    let timeout_elapsed = batch_add_first
                        .map(|t| t.elapsed().as_millis() as u64 >= batch_add_timeout_ms)
                        .unwrap_or(false);
                    if timeout_elapsed {
                        let metrics = std::env::var("METRICS").map(|v| v=="1"||v.eq_ignore_ascii_case("true")).unwrap_or(false);
                        let final_v = pending_v_new.take().unwrap();
                        let es: Vec<U256> = pending_adds.drain(..).collect();
                        let n = es.len();
                        let rcpt = if n == 1 {
                            accumulator.method::<_, ()>("addMember", (cred_name.clone(), es[0], final_v))?.send().await?.await?
                        } else {
                            accumulator.method::<_, ()>("addMembers", (cred_name.clone(), es.clone(), final_v))?.send().await?.await?
                        };
                        let gas_total = rcpt.as_ref().and_then(|r| r.gas_used).unwrap_or_default();
                        let scenario = if n == 1 { "acc_register_info_e2e" } else { "acc_addMembers_batch" };
                        if metrics {
                            let mf = std::env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/aggregator.ndjson".into());
                            let _ = (||{ let _=std::fs::create_dir_all(std::path::Path::new(&mf).parent().unwrap()); let mut f=std::fs::OpenOptions::new().create(true).append(true).open(&mf).unwrap(); let _=writeln!(f, "{}", serde_json::json!({"scenario": scenario, "batch_size": n, "threshold": threshold, "gasUsedTotal": gas_total.to_string()})); Ok::<(),()>(())})();
                        }
                        local_v = None;
                        batch_add_first = None;
                        println!("[agg] batch timeout flush: {} member(s) added", n);
                    }
                }
                // Timer: drain queue if idle (safety net for edge cases)
                if !add_in_progress && !add_queue.is_empty() {
                    let (next_sid, next_e) = add_queue.pop_front().unwrap();
                    let v128: Vec<u8> = if let Some(ref lv) = local_v {
                        lv.clone()
                    } else {
                        let delta_bytes: ethers::types::Bytes = accumulator.method("getDelta", (cred_name.clone(),))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
                        if delta_bytes.0.len() == 128 { delta_bytes.0.to_vec() } else {
                            let (g1_b, _h0_b, _g2_b): (ethers::types::Bytes, ethers::types::Bytes, ethers::types::Bytes) = params.method("getG1H0G2ByName", (cred_name.clone(),))?.call().await?;
                            g1_b.0.to_vec()
                        }
                    };
                    let mut subset: Vec<u16> = peers.iter().map(|(i, _)| *i).collect();
                    subset.sort_unstable();
                    if subset.len() > threshold as usize { subset.truncate(threshold as usize); }
                    let msg = AccAddAnnounceMsg { sid: next_sid, name: cred_name.clone(), aggregator_idx: participant_id, aggregator_peer_id: local_peer_id_str.clone(), subset: subset.clone(), v128: v128.clone(), e_hex: format!("0x{:x}", next_e), seq: 1 };
                    handle.broadcast("acc-add-announce", serde_json::to_vec(&msg)?).await?;
                    add_meta.insert(next_sid, (subset.clone(), v128.clone(), next_e, 1));
                    add_in_progress = true;
                    println!("[agg] timer: queued addition started: sid={}", next_sid);
                }
                let keys: Vec<u64> = add_meta.keys().cloned().collect();
                for sid in keys {
                    if let Some((subset, v128, e_u, seq)) = add_meta.get_mut(&sid) {
                        // Gate: stop re-announcing if we already have all subset contributions
                        let covered = if let Some(seen) = add_seen.get(&sid) {
                            subset.iter().all(|i| seen.contains(i))
                        } else { false };
                        if covered { continue; }
                        *seq = seq.saturating_add(1);
                        let msg = AccAddAnnounceMsg {
                            sid,
                            name: cred_name.clone(),
                            aggregator_idx: participant_id,
                            aggregator_peer_id: local_peer_id_str.clone(),
                            subset: subset.clone(),
                            v128: v128.clone(),
                            e_hex: format!("0x{:x}", *e_u),
                            seq: *seq,
                        };
                        let payload = serde_json::to_vec(&msg)?;
                        let _ = handle.broadcast("acc-add-announce", payload).await;
                        println!("[agg] re-announced addition for sid={} subset={:?}", sid, subset);
                    }
                }
                // Re-announce pending open sessions that haven't reached threshold yet
                let open_sids: Vec<u64> = announces.keys().cloned().collect();
                for sid in open_sids {
                    let num_partials = partials.get(&sid).map(|v| v.len()).unwrap_or(0);
                    if (num_partials as u16) < threshold {
                        if let Some((t1, t2)) = announces.get(&sid) {
                            let announce = OpenAnnounceMsg {
                                sid,
                                name: cred_name.clone(),
                                aggregator_idx: participant_id,
                                aggregator_peer_id: local_peer_id_str.clone(),
                                t1: t1.clone(),
                                t2: t2.clone(),
                            };
                            let _ = handle.broadcast("open-announce", serde_json::to_vec(&announce)?).await;
                            println!("[agg] re-announced open sid={} ({}/{} partials)", sid, num_partials, threshold);
                        }
                    }
                }
            }
        }
    }
}

