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
// Use vb_accumulator directly (no wrapper)
use std::time::Instant;
use std::io::Write as _;
use vb_accumulator::witness::{MembershipWitness as VbMembershipWitness, Witness as VbWitnessTrait};
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

    let ev_wit = H256::from(ethers::utils::keccak256(b"WitnessAvailable(string,uint256,bytes,bytes)"));
    let filter_wit_latest = Filter::new()
        .address(ValueOrArray::Value(acc_addr))
        .topic0(ValueOrArray::Value(ev_wit))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Latest);
    let mut stream_wit = client.provider().subscribe_logs(&filter_wit_latest).await?;

    let ev_conf = H256::from(ethers::utils::keccak256(b"Confirmed(string,uint256)"));
    let filter_conf = Filter::new()
        .address(ValueOrArray::Value(registry.address()))
        .topic0(ValueOrArray::Value(ev_conf))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Latest);
    let mut stream_conf = client.provider().subscribe_logs(&filter_conf).await?;

    use std::collections::{BTreeMap};
    let mut partials: BTreeMap<u64, Vec<(u16, Vec<u8>, Vec<u8>)>> = BTreeMap::new();
    let mut announces: BTreeMap<u64, (Vec<u8>, Vec<u8>)> = BTreeMap::new();
    let mut del_shares: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();
    let mut e_by_sid: BTreeMap<u64, U256> = BTreeMap::new();
    let threshold: u16 = env::var("THRESHOLD").unwrap_or_else(|_| "3".into()).parse()?;

    // Track addition round metadata and contributions per sid
    use std::collections::BTreeMap as Map;
    let mut add_meta: Map<u64, (Vec<u16>, Vec<u8>, U256, u64)> = Map::new(); // sid -> (subset, V128, e, seq)
    let mut add_contribs: Map<u64, Vec<(u16, Vec<u8>)>> = Map::new(); // sid -> vec[(idx, contrib)]
    let mut add_seen: Map<u64, std::collections::BTreeSet<u16>> = Map::new(); // sid -> set of idx received
    let mut members: std::collections::BTreeSet<U256> = std::collections::BTreeSet::new(); // all added e values
    let mut revoked_set: std::collections::BTreeSet<U256> = std::collections::BTreeSet::new(); // revoked e values

    // Initialize members from past WitnessAvailable events (chain scan)
    let filter_wit_all = Filter::new()
        .address(ValueOrArray::Value(acc_addr))
        .topic0(ValueOrArray::Value(ev_wit))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Earliest)
        .to_block(BlockNumber::Latest);
    if let Ok(init_logs) = client.provider().get_logs(&filter_wit_all).await {
        for lg in init_logs {
            if let Some(e_topic) = lg.topics.get(2) {
                let e_u = U256::from_big_endian(e_topic.as_bytes());
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
                    let sid_topic = lg.topics.get(2).cloned().unwrap_or_default();
                    let sid_u = U256::from_big_endian(sid_topic.as_bytes());
                    println!("[agg] Confirmed event for sid={}", sid_u);
                    let (a_bytes, e_u, _s_u, _status): (ethers::types::Bytes, U256, U256, u8) = registry
                        .method("getSignature", (cred_name.clone(), sid_u))?
                        .call().await
                        .unwrap_or((ethers::types::Bytes::from_static(&[]), U256::zero(), U256::zero(), 0));
                    if a_bytes.0.len() == 128 && !e_u.is_zero() {
                        let _ah = H256::from(ethers::utils::keccak256(&a_bytes.0));
                        // Threshold addition announce
                        // Get current V (Delta) or fall back to g1
                        let delta_bytes: ethers::types::Bytes = accumulator.method("getDelta", (cred_name.clone(),))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
let v128: Vec<u8> = if delta_bytes.0.len() == 128 { delta_bytes.0.to_vec() } else {
                            let (g1_b, _h0_b, _g2_b): (ethers::types::Bytes, ethers::types::Bytes, ethers::types::Bytes) = params.method("getG1H0G2ByName", (cred_name.clone(),))?.call().await?;
g1_b.0.to_vec()
                        };
                        // Choose subset of openers (first threshold indices from peers)
                        let mut subset: Vec<u16> = peers.iter().map(|(i, _)| *i).collect();
                        subset.sort_unstable();
                        if subset.len() > threshold as usize { subset.truncate(threshold as usize); }
                        if subset.len() < threshold as usize { println!("[agg] WARN: subset smaller than threshold: {} < {}", subset.len(), threshold); }
                        // Broadcast add announce
let msg = AccAddAnnounceMsg { sid: sid_u.as_u64(), name: cred_name.clone(), aggregator_idx: participant_id, aggregator_peer_id: local_peer_id_str.clone(), subset: subset.clone(), v128: v128.clone(), e_hex: format!("0x{:x}", e_u), seq: 1 };
                        let payload = serde_json::to_vec(&msg)?;
                        handle.broadcast("acc-add-announce", payload).await?;
add_meta.insert(sid_u.as_u64(), (subset.clone(), v128.clone(), e_u, 1));
                        println!("[agg] addition round announced for sid={} subset={:?}", sid_u, subset);
                    } else {
                        println!("[agg] WARN: Confirmed but missing/invalid (A,e) for sid={}", sid_u);
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
            ev = stream_wit.next() => {
                if let Some(lg) = ev {
                    if let Some(e_topic) = lg.topics.get(2) {
                        let e_u = U256::from_big_endian(e_topic.as_bytes());
                        if !e_u.is_zero() { members.insert(e_u); }
                    }
                }
            },
            dm = direct_rx.recv() => {
                if let Some(dm) = dm {
                    // Open partials, deletion shares, or addition contributions
                    if let Ok(msg) = serde_json::from_slice::<OpenPartialMsg>(&dm.data) {
                        let entry = partials.entry(msg.sid).or_default();
                        entry.push((msg.from_idx, msg.tbar_128.clone(), Vec::new()));
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
                                let _ = accumulator.method::<_, ()>("publishOpenResult", (cred_name.clone(), ethers::types::Bytes::from(a_bytes.clone())))?.send().await?.await?;
                                if std::env::var("METRICS").map(|v| v=="1"||v.eq_ignore_ascii_case("true")).unwrap_or(false) {
                                    let mf = std::env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/aggregator.ndjson".into());
                                    let _ = (||{ let _=std::fs::create_dir_all(std::path::Path::new(&mf).parent().unwrap()); let mut f=std::fs::OpenOptions::new().create(true).append(true).open(&mf).unwrap(); let _=writeln!(f, "{}", serde_json::json!({"scenario":"open_reconstruct","sid": msg.sid, "ms": t0_recon.elapsed().as_millis() as u64})); Ok::<(),()>(())})();
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
                                let _ = accumulator.method::<_, ()>("deleteMember", (cred_name.clone(), e_u, new_delta_b.clone()))?.send().await?.await?;
                                println!("[agg] deleteMember executed for sid={} e=0x{:x}", v.sid, e_u);
                                // After removal, update witnesses for remaining members using library helper (public update after single removal)
                                let V_new = new_delta_aff;
                                let e_removed_fr: Fr = tbbsplus_rust::orchestration::crypto::encoding::u256_to_fr(&e_u);
                                let to_update: Vec<U256> = members.iter().cloned().collect();
                                for e_old in to_update.into_iter() {
                                    if revoked_set.contains(&e_old) { continue; }
                                    if e_old == e_u { continue; }
                                    let wit_b: ethers::types::Bytes = accumulator.method("getWitness", (cred_name.clone(), e_old))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
                                    if wit_b.0.len() != 128 { continue; }
                                    let w_old = match eip2537_g1_to_affine(&wit_b.0[..]) { Ok(v) => v, Err(_) => continue };
                                    let e_old_fr: Fr = tbbsplus_rust::orchestration::crypto::encoding::u256_to_fr(&e_old);
                                    if let Ok((_d, w_new)) = VbMembershipWitness::<ark_bls12_381::G1Affine>::compute_update_after_removal(
                                        &e_old_fr,
                                        &e_removed_fr,
                                        &w_old,
                                        &V_new,
                                    ) {
                                        let w_new_b = ethers::types::Bytes::from(g1_to_eip2537_bytes(&w_new).to_vec());
                                        let _ = accumulator.method::<_, ()>("publishWitness", (cred_name.clone(), e_old, w_new_b))?.send().await?.await?;
                                    }
                                }
                                // Update local sets
                                revoked_set.insert(e_u);
                                members.remove(&e_u);
                                if std::env::var("METRICS").map(|v| v=="1"||v.eq_ignore_ascii_case("true")).unwrap_or(false) {
                                    let mf = std::env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/aggregator.ndjson".into());
                                    let _ = (||{ let _=std::fs::create_dir_all(std::path::Path::new(&mf).parent().unwrap()); let mut f=std::fs::OpenOptions::new().create(true).append(true).open(&mf).unwrap(); let _=writeln!(f, "{}", serde_json::json!({"scenario":"acc_delete_aggregate","sid": v.sid, "ms": t0_agg.elapsed().as_millis() as u64})); Ok::<(),()>(())})();
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
                            let V = match eip2537_g1_to_affine(&v128[..]) { Ok(v) => v, Err(_) => { println!("[agg] invalid V bytes"); continue; } };
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
                                let rhs = Bls12_381::pairing(V, y_lam);
                                if lhs != rhs { println!("[agg] pairing check failed for idx {}", idx); ok_subset = false; break; }
                                sum_c += contrib.into_group();
                            }
                            if !ok_subset { continue; }
                            // Compute V' = sum_c + e*V (keep V_old for witness updates)
                            let V_old = V;
                            let v_e = V_old.into_group().mul_bigint(e_fr.into_bigint());
                            let v_new = (sum_c + v_e).into_affine();
                            // vb_accumulator: verify membership of e in new Delta with witness W = old V
                            let ok = vb_accumulator::positive::PositiveAccumulator::<ark_bls12_381::G1Affine>::verify_membership_given_accumulated::<Bls12_381>(
                                &v_new,
                                &e_fr,
                                &vb_accumulator::witness::MembershipWitness::<ark_bls12_381::G1Affine>(V),
                                &vb_pk,
                                &vb_params,
                            );
                            if !ok {
                                println!("[agg] ERROR: vb_accumulator membership verify failed; aborting setDelta for sid={}", ac.sid);
                                // hard fail this round; clear pending state to avoid spinning
                                add_meta.remove(&ac.sid);
                                add_contribs.remove(&ac.sid);
                                add_seen.remove(&ac.sid);
                                continue;
                            }
                            if std::env::var("METRICS").map(|v| v=="1"||v.eq_ignore_ascii_case("true")).unwrap_or(false) {
                                let mf = std::env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/aggregator.ndjson".into());
                                let _ = (||{ let _=std::fs::create_dir_all(std::path::Path::new(&mf).parent().unwrap()); let mut f=std::fs::OpenOptions::new().create(true).append(true).open(&mf).unwrap(); let _=writeln!(f, "{}", serde_json::json!({"scenario":"acc_add_verify_sum","sid": ac.sid, "ms": t0_verify.elapsed().as_millis() as u64})); Ok::<(),()>(())})();
                            }
                            let v_new_b = ethers::types::Bytes::from(g1_to_eip2537_bytes(&v_new).to_vec());
                            let _ = accumulator.method::<_, ()>("setDelta", (cred_name.clone(), v_new_b))?.send().await?.await?;
                            // Update witnesses for all existing members using library helper (public update after single addition)
                            let mut to_update: Vec<U256> = members.iter().cloned().collect();
                            for e_old in to_update.into_iter() {
                                if revoked_set.contains(&e_old) { continue; }
                                let wit_b: ethers::types::Bytes = accumulator.method("getWitness", (cred_name.clone(), e_old))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
                                if wit_b.0.len() != 128 { continue; }
                                let w_old = match eip2537_g1_to_affine(&wit_b.0[..]) { Ok(v) => v, Err(_) => continue };
                                let e_old_fr: Fr = tbbsplus_rust::orchestration::crypto::encoding::u256_to_fr(&e_old);
                                let (_d, w_new) = VbMembershipWitness::<ark_bls12_381::G1Affine>::compute_update_after_addition(
                                    &e_old_fr,
                                    &e_fr,
                                    &w_old,
                                    &V_old,
                                );
                                let w_new_b = ethers::types::Bytes::from(g1_to_eip2537_bytes(&w_new).to_vec());
                                let _ = accumulator.method::<_, ()>("publishWitness", (cred_name.clone(), e_old, w_new_b))?.send().await?.await?;
                            }
                            // Publish witness for the newly added element: W_new(e_new) = V_old
                            let w_b = ethers::types::Bytes::from(g1_to_eip2537_bytes(&V_old).to_vec());
                            let _ = accumulator.method::<_, ()>("publishWitness", (cred_name.clone(), e_u, w_b))?.send().await?.await?;
                            members.insert(e_u);
                            println!("[agg] addition complete for sid={}, setDelta+publishWitness done", ac.sid);
                            add_meta.remove(&ac.sid);
                            add_contribs.remove(&ac.sid);
                            add_seen.remove(&ac.sid);
                        }
                    }
                }
            }
            // Periodically re-announce pending additions for late-joining openers (no seq)
            _ = tokio::time::sleep(std::time::Duration::from_millis(800)) => {
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
            }
        }
    }
}

