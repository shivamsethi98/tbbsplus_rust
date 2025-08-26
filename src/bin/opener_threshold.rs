use std::env;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ff::PrimeField;
use ark_std::{Zero, UniformRand, rand::{SeedableRng}};
use base64::Engine as _;
use blake2::Blake2b512;
use ethers::abi::Abi;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use futures::StreamExt;
use schnorr_pok::discrete_log::PokDiscreteLogProtocol;
use schnorr_pok::pok_generalized_pedersen::compute_random_oracle_challenge;

use tbbsplus_rust::orchestration::crypto::encoding::{
    eip2537_g1_to_affine,
    eip2537_g2_to_affine,
    g1_to_eip2537_bytes,
    u256_to_fr,
};
use tbbsplus_rust::orchestration::mesh::p2p::Mesh;
#[cfg(feature = "mpc")]
use libp2p::Multiaddr;
// Added for threshold accumulator deletion MPC
use tbbsplus_rust::orchestration::threshold_phases::{KAPPA, STATISTICAL_SECURITY_PARAMETER, BASE_OT_KEY_SIZE};
use tbbsplus_rust::orchestration::crypto::seeds;
use oblivious_transfer_protocols::ot_based_multiplication::{
    base_ot_multi_party_pairwise::BaseOTOutput,
    dkls18_mul_2p::MultiplicationOTEParams,
    dkls19_batch_mul_2p::GadgetVector,
};
use oblivious_transfer_protocols::cointoss::Commitments;
use short_group_sig::threshold_weak_bb_sig as tbb;
use sha3::Shake256;
use test_utils::ot::do_pairwise_base_ot;
use secret_sharing_and_dkg::common::lagrange_basis_at_0;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OpenAnnounceMsg {
    sid: u64,
    name: String,
    aggregator_idx: u16,
    #[serde(default)]
    aggregator_peer_id: Option<String>,
    t1: Vec<u8>,
    t2: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RevokeAnnounceMsg {
    sid: u64,
    name: String,
    aggregator_idx: u16,
    #[serde(default)]
    aggregator_peer_id: Option<String>,
    e_hex: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OpenPartialMsg {
    sid: u64,
    from_idx: u16,
    tbar_128: Vec<u8>,
    proof_bytes: Vec<u8>,
}

// Accumulator deletion MPC messages
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AccDelP1CommitMsg {
    sid: u64,
    from: u16,
    peer_id: String,
    zero_commitments: std::collections::BTreeMap<u16, String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AccDelP1ShareMsg {
    sid: u64,
    from: u16,
    to: u16,
    zero_shares_b64: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AccDelP2Msg {
    sid: u64,
    round: u8,
    from: u16,
    to: u16,
    data_b64: String,
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
    #[serde(default)]
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
    let art = std::fs::read(path).map_err(|e| anyhow::anyhow!("[opener_threshold] read {} failed: {:?}", path, e))?;
    let v: serde_json::Value = serde_json::from_slice(&art)
        .map_err(|e| anyhow::anyhow!("[opener_threshold] parse {} failed: {:?}", path, e))?;
    let abi_val = v.get("abi").cloned().ok_or_else(|| anyhow::anyhow!("[opener_threshold] {} abi missing in {}", tag, path))?;
    let abi: Abi = serde_json::from_value(abi_val)
        .map_err(|e| anyhow::anyhow!("[opener_threshold] {} abi decode failed: {:?}", tag, e))?;
    Ok(abi)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let chain_id: u64 = env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse()?;
    let is_aggregator: bool = env::var("AGGREGATOR").unwrap_or_else(|_| "0".into()) == "1";
    let cred_name = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
    let participant_id: u16 = env::var("PID").unwrap_or_else(|_| "1".into()).parse()?;

    // Signer
    let wallet: LocalWallet = env::var("OPENER_PK")
        .unwrap_or_else(|_| "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6".into())
        .parse::<LocalWallet>()?
        .with_chain_id(chain_id);

    let ws = Provider::<Ws>::connect(ws_url.clone()).await?;
    let client = std::sync::Arc::new(SignerMiddleware::new(ws, wallet));

    // Contracts
    let params_addr: Address = env::var("PARAMS_CONTRACT")?.parse()?;
    let acc_addr: Address = env::var("ACC_CONTRACT")?.parse()?;

    let params = {
        let abi = load_abi("artifacts/contracts/Params.sol/Params.json", "params")?;
        Contract::new(params_addr, abi, client.clone())
    };
    let accumulator = {
        let abi = load_abi("artifacts/contracts/Accumulator.sol/Accumulator.json", "accumulator")?;
        Contract::new(acc_addr, abi, client.clone())
    };

    // Get G2 base from Params
    let (_g1_b, _h0_b, g2_b): (ethers::types::Bytes, ethers::types::Bytes, ethers::types::Bytes) = params
        .method("getG1H0G2ByName", (cred_name.clone(),))?
        .call()
        .await?;
    let g2 = eip2537_g2_to_affine(&g2_b.0[..])?;

    // Mesh discovery: get opener roster and multiaddrs
    let openers: Vec<Address> = params.method::<_, Vec<Address>>("getOpeners", ())?.call().await.unwrap_or_default();
    // Map indices and addrs
    let mut peers = Vec::new();
    for addr in openers.iter().cloned() {
        // Skip disallowed
        let allowed: bool = params.method::<_, bool>("openerAllowed", (addr,))?.call().await.unwrap_or(false);
        if !allowed { continue; }
        let idx: u16 = params.method::<_, u16>("openerIndex", (addr,))?.call().await.unwrap_or(0);
        if idx == 0 { continue; }
        let addrs: Vec<String> = params.method::<_, Vec<String>>("getOpenerMultiaddrs", (addr,))?.call().await.unwrap_or_default();
        if let Some(ma) = addrs.get(0) {
            if let Ok(maddr) = ma.parse() { peers.push((idx, maddr)); }
        }
    }

    // Start mesh
    let base_port: u16 = env::var("BASE_PORT").unwrap_or_else(|_| "10900".into()).parse()?;
    // Proactively dial aggregator (if AGG_PID is set) to ensure we receive its broadcasts even if it started first
    if let Ok(agg_pid_s) = env::var("AGG_PID") {
        if let Ok(agg_pid) = agg_pid_s.parse::<u16>() {
            if agg_pid != participant_id {
                if let Ok(agg_ma) = format!("/ip4/127.0.0.1/tcp/{}", base_port + agg_pid - 1).parse() {
                    peers.push((agg_pid, agg_ma));
                }
            }
        }
    }
    let listen_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", base_port + participant_id - 1).parse()?;
    let mut mesh = Mesh::new(participant_id, Some(listen_addr), peers).await?;
    let mut open_rx = mesh.subscribe_broadcast("open-announce").await?;
    let mut revoke_rx = mesh.subscribe_broadcast("revoke-announce").await?;
    let mut add_rx = mesh.subscribe_broadcast("acc-add-announce").await?;
    // Pre-subscribe additional topics needed by participant branch before moving mesh
    let mut p1_commit_rx_opt = Some(mesh.subscribe_broadcast("acc-del-p1-commitments").await?);
    let mut p1_shares_rx_opt = Some(mesh.subscribe_broadcast("acc-del-p1-shares").await?);
    let mut direct_rx = mesh.subscribe_direct().await?;
    let local_peer_id_str = mesh.local_peer_id().to_string();
    let handle = mesh.run_background();

    // Proactively register with aggregator via a direct ping so it learns our PeerId
    if let Ok(agg_pid_s) = env::var("AGG_PID") {
        if let Ok(agg_pid) = agg_pid_s.parse::<u16>() {
            let _ = handle.send_to(agg_pid, b"opener-hello".to_vec()).await;
            println!("[opener-{}] pinged aggregator {} for peer registration", participant_id, agg_pid);
        }
    }

    if is_aggregator {
        // Subscribe to Accumulator.OpenRequested(name,T1,T2) and RevokeRequested(name,e)
        use ethers::types::{Filter, ValueOrArray, H256, BlockNumber};
        let event_sig = H256::from(ethers::utils::keccak256(b"OpenRequested(string,address,bytes,bytes)"));
        let name_topic = H256::from(ethers::utils::keccak256(cred_name.as_bytes()));
        let filter = Filter::new()
            .address(ValueOrArray::Value(acc_addr))
            .topic0(ValueOrArray::Value(event_sig))
            .topic1(ValueOrArray::Value(name_topic))
            .from_block(BlockNumber::Latest);
        let mut stream = client.provider().subscribe_logs(&filter).await?;

        // RevokeRequested
        let ev_rev = H256::from(ethers::utils::keccak256(b"RevokeRequested(string,uint256)"));
        let filter_rev = Filter::new()
            .address(ValueOrArray::Value(acc_addr))
            .topic0(ValueOrArray::Value(ev_rev))
            .topic1(ValueOrArray::Value(name_topic))
            .from_block(BlockNumber::Latest);
        let mut stream_rev = client.provider().subscribe_logs(&filter_rev).await?;

        // Aggregator collections per sid
        use std::collections::{BTreeMap, BTreeSet};
        let mut partials: BTreeMap<u64, Vec<(u16, Vec<u8>, Vec<u8>)>> = BTreeMap::new(); // sid -> vec[(idx, tbar, proof)]
        let mut announces: BTreeMap<u64, (Vec<u8>, Vec<u8>)> = BTreeMap::new(); // sid -> (t1,t2)
        let threshold: u16 = env::var("THRESHOLD").unwrap_or_else(|_| "3".into()).parse()?;

        loop {
            tokio::select! {
                ev_opt = stream.next() => {
                    let Some(log) = ev_opt else { break };
                    // decode T1,T2
                    let raw = ethers::abi::RawLog { topics: log.topics.clone(), data: log.data.to_vec() };
                    let ev = accumulator.abi().event("OpenRequested")?;
                    let parsed = match ev.parse_log(raw) { Ok(p) => p, Err(_) => continue };
                    let mut t1_b = Vec::new();
                    let mut t2_b = Vec::new();
                    for p in parsed.params.iter() { if let ethers::abi::Token::Bytes(b) = &p.value { if t1_b.is_empty() { t1_b = b.clone(); } else { t2_b = b.clone(); } } }
                    if t1_b.len() != 128 || t2_b.len() != 128 { continue; }
                    // sid is not indexed in this event; use a rolling counter or hash as sid. For now derive from keccak(t1||t2)
                    let mut sid_be = [0u8; 8];
                    let mut h = [0u8; 32]; h.copy_from_slice(&ethers::utils::keccak256([t1_b.as_slice(), t2_b.as_slice()].concat()));
                    sid_be.copy_from_slice(&h[..8]);
                    let sid = u64::from_be_bytes(sid_be);
                    // announce over mesh
                    announces.insert(sid, (t1_b.clone(), t2_b.clone()));
                    let announce = OpenAnnounceMsg { sid, name: cred_name.clone(), aggregator_idx: participant_id, aggregator_peer_id: Some(local_peer_id_str.clone()), t1: t1_b.clone(), t2: t2_b.clone() };
                    handle.broadcast("open-announce", serde_json::to_vec(&announce)?).await?;
                    // initialize collection
                    partials.entry(sid).or_default();
                    println!("[agg] announced open sid={}", sid);
                }
                evr_opt = stream_rev.next() => {
                    let Some(lg) = evr_opt else { break };
                    // topic2 is e
                    let e_topic = lg.topics.get(2).cloned().unwrap_or_default();
                    let e_u = U256::from_big_endian(e_topic.as_bytes());
                    if e_u.is_zero() { continue; }
                    let mut sid_be = [0u8; 8];
                    let mut e_be32 = [0u8; 32]; e_u.to_big_endian(&mut e_be32);
                    let mut h = [0u8; 32]; h.copy_from_slice(&ethers::utils::keccak256(e_be32));
                    sid_be.copy_from_slice(&h[..8]);
                    let sid = u64::from_be_bytes(sid_be);
                    let msg = RevokeAnnounceMsg { sid, name: cred_name.clone(), aggregator_idx: participant_id, aggregator_peer_id: Some(local_peer_id_str.clone()), e_hex: format!("0x{:x}", e_u) };
                    handle.broadcast("revoke-announce", serde_json::to_vec(&msg)?).await?;
                    println!("[agg] announced revoke sid={} e={:x}", sid, e_u);
                }
                dm_res = direct_rx.recv() => {
                    if let Some(dm) = dm_res {
                        // Expect JSON OpenPartialMsg
                        if let Ok(msg) = serde_json::from_slice::<OpenPartialMsg>(&dm.data) {
                            let entry = partials.entry(msg.sid).or_default();
                            entry.push((msg.from_idx, msg.tbar_128.clone(), msg.proof_bytes.clone()));
                            println!("[agg] got partial from {} (sid={})", msg.from_idx, msg.sid);
                            if entry.len() as u16 >= threshold {
                                // Verify and recombine using first t
                                let Some((t1b, t2b)) = announces.get(&msg.sid) else { continue };
                                let t1 = match eip2537_g1_to_affine(&t1b[..]) { Ok(v) => v, Err(_) => continue };
                                // fetch commitments and verify each
                                let mut verified: Vec<(u16, <Bls12_381 as Pairing>::G1Affine)> = Vec::new();
                                for (idx, tbar_b, proof_b) in entry.iter().take(threshold as usize) {
                                    let y_i_bytes: ethers::types::Bytes = params.method("getOpenerCommitment", (cred_name.clone(), *idx))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
                                    if y_i_bytes.0.len() != 256 { continue; }
                                    let y_i = eip2537_g2_to_affine(&y_i_bytes.0[..])?;
                                    let tbar = eip2537_g1_to_affine(&tbar_b[..])?;
                                    // pairing check e(T1, Y_i) == e(tbar, g2)
                                    let lhs = Bls12_381::pairing(t1, y_i);
                                    let rhs = Bls12_381::pairing(tbar, g2);
                                    if lhs != rhs { continue; }
                                    // verify Schnorr DLEQ in G2: base=g2, y=Y_i
                                    let proof: schnorr_pok::discrete_log::PokDiscreteLog<<Bls12_381 as Pairing>::G2Affine> = CanonicalDeserialize::deserialize_compressed(&proof_b[..]).unwrap_or_default();
                                    let mut chal_contrib = Vec::new();
                                    proof.challenge_contribution(&g2, &y_i, &mut chal_contrib).ok();
                                    let chal = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib);
                                    if !proof.verify(&y_i, &g2, &chal) { continue; }
                                    verified.push((*idx, tbar));
                                }
                                if verified.len() as u16 >= threshold {
                                    // recombine
                                    let indices: Vec<u16> = verified.iter().map(|(i, _)| *i).collect();
                                    let lambdas = lagrange_coeffs_at_zero(&indices);
                                    let mut acc_g = <Bls12_381 as Pairing>::G1::zero();
                                    for ((_, tbar_i), lam) in verified.iter().zip(lambdas.iter()) {
                                        acc_g += tbar_i.into_group().mul_bigint((*lam).into_bigint());
                                    }
                                    let tbar_agg = acc_g.into_affine();
                                    // compute A = T2 - Tbar
                                    let t2 = match eip2537_g1_to_affine(&t2b[..]) { Ok(v) => v, Err(_) => continue };
                                    let a = (t2.into_group() + (-tbar_agg).into_group()).into_affine();
                                    let a_bytes = g1_to_eip2537_bytes(&a).to_vec();
                                    // Publish Opened for audit (contract supports it). Mapping A->e will be handled by single-opener publisher or by existing mapping.
                                    let _ = accumulator
                                        .method::<_, ()>("publishOpenResult", (cred_name.clone(), ethers::types::Bytes::from(a_bytes)))?
                                        .send()
                                        .await?
                                        .await?;
                                    let tbar_bytes = g1_to_eip2537_bytes(&tbar_agg).to_vec();
                                    println!("[agg] Tbar aggregated and Opened published for sid={}", msg.sid);
                                    // Optionally publish Opened A if available; keeping current contract, single-opener path handles A->e mapping
                                }
                            }
                        }
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
            }
        }
    } else {
        // Participant: compute tbar_i and DLEQ proof when announced
        // Load our opener share y_i
        let y_i: Fr = {
            let file = std::fs::read_to_string(".runtime.openers.json").unwrap_or_default();
            let v: serde_json::Value = serde_json::from_str(&file).unwrap_or(serde_json::json!({}));
            let key = participant_id.to_string();
            let b64 = v.get("openers").and_then(|o| o.get(&key)).and_then(|j| j.get("y_b64")).and_then(|s| s.as_str()).unwrap_or("");
            let raw = base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_default();
            CanonicalDeserialize::deserialize_compressed(raw.as_slice()).unwrap_or(Fr::from(0u64))
        };

        // Subscribe MPC topics for accumulator deletion
        let mut p1_commit_rx = p1_commit_rx_opt.take().unwrap();
        let mut p1_shares_rx = p1_shares_rx_opt.take().unwrap();

        loop {
            if let Ok(bytes) = open_rx.try_recv() {
if let Ok(ann) = serde_json::from_slice::<OpenAnnounceMsg>(&bytes) {
                    // Register aggregator mapping if provided
                    if let Some(pid_str) = &ann.aggregator_peer_id { if let Ok(pid) = pid_str.parse() { let _ = handle.register_peer(ann.aggregator_idx, pid).await; println!("[opener-{}] registered aggregator peer_id for open sid={}", participant_id, ann.sid); } }
                    println!("[opener-{}] open-announce: sid={} name={}", participant_id, ann.sid, ann.name);
                    // Compute tbar = T1 * y_i
                    let t1 = match eip2537_g1_to_affine(&ann.t1[..]) { Ok(v) => v, Err(_) => continue };
                    let tbar = t1.mul_bigint(y_i.into_bigint()).into_affine();

                    // Build DLEQ proof in G2: base=g2, y=Y_i
                    let y_i_bytes: ethers::types::Bytes = params.method("getOpenerCommitment", (ann.name.clone(), participant_id))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
                    if y_i_bytes.0.len() != 256 { continue; }
                    let y_g2 = eip2537_g2_to_affine(&y_i_bytes.0[..])?;
                    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(ann.sid);
                    let blind = Fr::rand(&mut rng);
                    let protocol = PokDiscreteLogProtocol::<<Bls12_381 as Pairing>::G2Affine>::init(y_i, blind, &g2);
                    let mut chal_contrib = Vec::new();
                    let _ = protocol.challenge_contribution(&g2, &y_g2, &mut chal_contrib);
                    let chal = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib);
                    let proof = protocol.gen_proof(&chal);
                    let mut proof_bytes = Vec::new();
                    proof.serialize_compressed(&mut proof_bytes)?;

                    // Send to aggregator
                    let msg = OpenPartialMsg { sid: ann.sid, from_idx: participant_id, tbar_128: g1_to_eip2537_bytes(&tbar).to_vec(), proof_bytes };
                    let payload = serde_json::to_vec(&msg)?;
                    let _ = handle.send_to(ann.aggregator_idx, payload).await;
                    println!("[opener-{}] sent open partial to agg idx={} for sid={}", participant_id, ann.aggregator_idx, ann.sid);
                }
            }

            if let Ok(bytes) = add_rx.try_recv() {
                if let Ok(aa) = serde_json::from_slice::<AccAddAnnounceMsg>(&bytes) {
                    // Register aggregator mapping if provided
                    if let Ok(pid) = aa.aggregator_peer_id.parse() { let _ = handle.register_peer(aa.aggregator_idx, pid).await; println!("[opener-{}] registered aggregator peer_id for add sid={}", participant_id, aa.sid); }
                    println!("[opener-{}] acc-add-announce: sid={} subset={:?} e={}", participant_id, aa.sid, aa.subset, aa.e_hex);
                    // Compute lambda for me
                    let lam = match lagrange_basis_at_0::<Fr>(&aa.subset, participant_id) { Ok(l) => l, Err(_) => continue };
                    // Load my secret share y_i
                    let y_i: Fr = {
                        let file = std::fs::read_to_string(".runtime.openers.json").unwrap_or_default();
                        let v: serde_json::Value = serde_json::from_str(&file).unwrap_or(serde_json::json!({}));
                        let key = participant_id.to_string();
                        let b64 = v.get("openers").and_then(|o| o.get(&key)).and_then(|j| j.get("y_b64")).and_then(|s| s.as_str()).unwrap_or("");
                        let raw = base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_default();
                        CanonicalDeserialize::deserialize_compressed(raw.as_slice()).unwrap_or(Fr::from(0u64))
                    };
                    // Decode V and compute contrib: (lam*y_i)*V
                    let V = match eip2537_g1_to_affine(&aa.v128[..]) { Ok(v) => v, Err(_) => continue };
                    let coeff = lam * y_i;
                    let contrib = V.mul_bigint(coeff.into_bigint()).into_affine();
                    let msg = AccAddContribMsg { sid: aa.sid, from_idx: participant_id, contrib_128: g1_to_eip2537_bytes(&contrib).to_vec() };
                    let _ = handle.send_to(aa.aggregator_idx, serde_json::to_vec(&msg)?).await;
                    println!("[opener-{}] sent add-contrib to agg idx={} for sid={}", participant_id, aa.aggregator_idx, aa.sid);
                }
            }

            if let Ok(bytes) = revoke_rx.try_recv() {
if let Ok(ra) = serde_json::from_slice::<RevokeAnnounceMsg>(&bytes) {
                    // Register aggregator mapping if provided
                    if let Some(pid_str) = &ra.aggregator_peer_id { if let Ok(pid) = pid_str.parse() { let _ = handle.register_peer(ra.aggregator_idx, pid).await; println!("[opener-{}] registered aggregator peer_id for revoke sid={}", participant_id, ra.sid); } }
                    println!("[opener-{}] revoke-announce: sid={} e={}", participant_id, ra.sid, ra.e_hex);
                    // Deterministic base OT shared across openers
                    let threshold: u16 = env::var("THRESHOLD").unwrap_or_else(|_| "3".into()).parse().unwrap_or(3);
                    let total: u16 = env::var("TOTAL").unwrap_or_else(|_| "5".into()).parse().unwrap_or(5);
                    let ote = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
                    let seed = seeds::base_ot_seed(&cred_name, total, KAPPA as usize, STATISTICAL_SECURITY_PARAMETER as usize);
                    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
                    let party_set = (1..=total).collect::<std::collections::BTreeSet<u16>>();
                    let base_ot = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(&mut rng, ote.num_base_ot(), total, party_set);

                    // Phase1: init and broadcast commitments
                    use std::collections::{BTreeSet, BTreeMap};
                    let mut others = BTreeSet::new();
                    for j in 1..=threshold { if j != participant_id { others.insert(j); } }
                    let mut prng = ark_std::rand::rngs::StdRng::seed_from_u64(0xACC0DE ^ (ra.sid as u64));
                    let (mut p1, comm_zero) = tbb::Phase1::<Fr, 256>::init::<_, Blake2b512>(&mut prng, participant_id, others.clone(), b"acc-del".to_vec()).unwrap();

                    // Broadcast zero commitments
                    let mut zc_map = BTreeMap::new();
                    for (who, zc) in comm_zero {
                        let mut b = Vec::new(); zc.serialize_compressed(&mut b).unwrap();
                        zc_map.insert(who, base64::engine::general_purpose::STANDARD.encode(b));
                    }
                    let commit_msg = AccDelP1CommitMsg { sid: ra.sid, from: participant_id, peer_id: local_peer_id_str.clone(), zero_commitments: zc_map };
                    handle.broadcast("acc-del-p1-commitments", serde_json::to_vec(&commit_msg)?).await?;
                    println!("[opener-{}] broadcasted P1 commitments for sid={}", participant_id, ra.sid);

                    // Collect commitments for me
                    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
                    let mut commitments_got: BTreeSet<u16> = BTreeSet::new();
                    while tokio::time::Instant::now() < deadline {
                        loop {
                            match p1_commit_rx.try_recv() {
                                Ok(bytes) => {
                                    if let Ok(v) = serde_json::from_slice::<AccDelP1CommitMsg>(&bytes) {
                                        if v.sid != ra.sid || v.from == participant_id { continue; }
                                        if let Ok(peer_id) = v.peer_id.parse() { let _ = handle.register_peer(v.from, peer_id).await; }
                                        if let Some(zc_b64) = v.zero_commitments.get(&participant_id) {
                                            let zc = base64::engine::general_purpose::STANDARD.decode(zc_b64).unwrap_or_default();
                                            let mut rz = &zc[..]; let zc_for_me: Commitments = CanonicalDeserialize::deserialize_compressed(&mut rz).unwrap();
                                            p1.receive_commitment(v.from, zc_for_me).unwrap();
                                            commitments_got.insert(v.from);
                                        }
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        if commitments_got.len() as u16 >= threshold - 1 { println!("[opener-{}] received P1 commitments from {} peers for sid={}", participant_id, commitments_got.len(), ra.sid); break; }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }

                    // Broadcast Phase1 shares
                    for to in others.iter().copied() {
                        let zs = p1.get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&to);
                        let mut zb = Vec::new(); zs.serialize_compressed(&mut zb).unwrap();
                        let msg = AccDelP1ShareMsg { sid: ra.sid, from: participant_id, to, zero_shares_b64: base64::engine::general_purpose::STANDARD.encode(zb) };
                        handle.broadcast("acc-del-p1-shares", serde_json::to_vec(&msg)?).await?;
                        println!("[opener-{}] broadcasted P1 shares to {} for sid={}", participant_id, to, ra.sid);
                    }

                    // Receive shares for me
                    let mut shares_got: BTreeSet<u16> = BTreeSet::new();
                    let deadline2 = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
                    while tokio::time::Instant::now() < deadline2 {
                        loop {
                            match p1_shares_rx.try_recv() {
                                Ok(bytes) => {
                                    if let Ok(v) = serde_json::from_slice::<AccDelP1ShareMsg>(&bytes) {
                                        if v.sid != ra.sid || v.to != participant_id { continue; }
                                        let z = base64::engine::general_purpose::STANDARD.decode(v.zero_shares_b64).unwrap_or_default();
                                        let mut rz = &z[..]; let zero: Vec<(Fr, [u8;256])> = CanonicalDeserialize::deserialize_compressed(&mut rz).unwrap();
                                        p1.receive_shares::<Blake2b512>(v.from, zero).unwrap();
                                        shares_got.insert(v.from);
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        if shares_got.len() as u16 >= threshold - 1 { println!("[opener-{}] received P1 shares from {} peers for sid={}", participant_id, shares_got.len(), ra.sid); break; }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }

                    let phase1_output = p1.finish::<Blake2b512>().unwrap();

                    // Phase2 for known element e
                    let gadget = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<Blake2b512>(ote, b"acc-del-gadget");
                    let mut r = ark_std::rand::rngs::StdRng::seed_from_u64(0xACC0DE ^ (ra.sid as u64));
                    let e_u = U256::from_str_radix(ra.e_hex.trim_start_matches("0x"), 16).unwrap_or(U256::from(0));
                    let e_fr: Fr = {
                        u256_to_fr(&e_u)
                    };
                    let (mut p2, msgs) = tbb::Phase2::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::init_for_known_message::<_, Shake256>(
                        &mut r,
                        participant_id,
                        y_i,
                        e_fr,
                        phase1_output.clone(),
                        base_ot[(participant_id - 1) as usize].clone(),
                        ote,
                        &gadget,
                        b"acc-del"
                    ).unwrap();

                    // Send R1
                    for (to, m1) in msgs {
                        let mut b = Vec::new(); m1.serialize_compressed(&mut b).unwrap();
                        let j = AccDelP2Msg { sid: ra.sid, round: 1, from: participant_id, to, data_b64: base64::engine::general_purpose::STANDARD.encode(b) };
                        let _ = handle.send_to(to, serde_json::to_vec(&j)?).await;
                        println!("[opener-{}] sent P2 msg1->2 to {} for sid={}", participant_id, to, ra.sid);
                    }

                    // Handle direct messages for R1/R2
                    let start = tokio::time::Instant::now();
                    while start.elapsed() < std::time::Duration::from_secs(10) {
                        match direct_rx.try_recv() {
                            Ok(dm) => {
                                if let Ok(v) = serde_json::from_slice::<AccDelP2Msg>(&dm.data) {
                                    if v.sid != ra.sid || v.to != participant_id { continue; }
                                    let data = base64::engine::general_purpose::STANDARD.decode(v.data_b64).unwrap_or_default();
                                    if v.round == 1 {
                                        let mut r1 = &data[..];
                                        let m1 = CanonicalDeserialize::deserialize_compressed(&mut r1).unwrap();
                                        let m2 = p2.receive_message1::<Blake2b512, Shake256>(v.from, m1, &gadget).unwrap();
                                        let mut bb = Vec::new(); m2.serialize_compressed(&mut bb).unwrap();
                                        let j = AccDelP2Msg { sid: ra.sid, round: 2, from: participant_id, to: v.from, data_b64: base64::engine::general_purpose::STANDARD.encode(bb) };
                                        let _ = handle.send_to(v.from, serde_json::to_vec(&j)?).await;
                                        println!("[opener-{}] replied P2 msg2 to {} for sid={}", participant_id, v.from, ra.sid);
                                    } else if v.round == 2 {
                                        let mut r2 = &data[..]; let m2 = CanonicalDeserialize::deserialize_compressed(&mut r2).unwrap();
                                        p2.receive_message2::<Blake2b512>(v.from, m2, &gadget).unwrap();
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }

                    // Finish and send SigShare to aggregator
                    let sigshare = p2.finish(&eip2537_g1_to_affine(&{
                        // Use Delta from chain as pk_gen surrogate; in strict math, pk_gen is g1 base
                        let (g1_b, _h0_b, _g2_b): (ethers::types::Bytes, ethers::types::Bytes, ethers::types::Bytes) = params.method("getG1H0G2ByName", (cred_name.clone(),))?.call().await.unwrap_or((ethers::types::Bytes::from_static(&[0u8;128]), ethers::types::Bytes::from_static(&[0u8;128]), ethers::types::Bytes::from_static(&[0u8;256])));
                        g1_b.0
                    }[..]).unwrap());
                    let mut sb = Vec::new(); sigshare.serialize_compressed(&mut sb).unwrap();
                    let j = AccDelSigShareMsg { sid: ra.sid, from: participant_id, share_b64: base64::engine::general_purpose::STANDARD.encode(sb) };
                    let _ = handle.send_to(ra.aggregator_idx, serde_json::to_vec(&j)?).await;
                    println!("[opener-{}] sent deletion SigShare to agg idx={} for sid={}", participant_id, ra.aggregator_idx, ra.sid);
                }
            }
        }
    }

    // End
    Ok(())
}


