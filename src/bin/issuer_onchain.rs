// Issuer binary: listens to RequestCredential.SigReqBBSPlus events,
// runs threshold MPC (Phase1 broadcast + Phase2 direct) for the session,
// and submits partial signature shares to CredentialRegistry.
//
// Batch mode (BATCH_SIZE > 1): buffers N credential requests, coordinates
// a batch manifest via gossipsub, then runs a single MPC session with
// batch_size=N producing N shares submitted via submitShareBatch.
//
// Build/run: cargo run --features mpc --bin issuer_onchain

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;
use std::str::FromStr;

use base64::Engine;
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalSerialize;
use ark_ff::PrimeField;

use ark_std::rand::{rngs::StdRng, SeedableRng};
use bbs_plus::prelude::*;
use ethers::contract::abigen;
use ethers::contract::Contract;
use ethers::prelude::*;
use ethers::signers::{coins_bip39::English, MnemonicBuilder};
use ethers::providers::{Provider, Ws};
use futures::StreamExt;
use tracing::{info, warn, error, instrument};
// use secret_sharing_and_dkg::shamir_ss::deal_random_secret; // now loaded from TTP shares file
use tokio::time::{sleep, Duration};
use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use serde_json::json;

use oblivious_transfer_protocols::ot_based_multiplication::dkls18_mul_2p::MultiplicationOTEParams;
use test_utils::ot::do_pairwise_base_ot;

use tbbsplus_rust::orchestration::mesh::p2p::Mesh;
use tbbsplus_rust::orchestration::threshold_phases::{BASE_OT_KEY_SIZE, KAPPA, STATISTICAL_SECURITY_PARAMETER};

use tbbsplus_rust::orchestration::crypto::encoding::{eip2537_g1_to_affine, eip2537_g2_to_affine, u256_to_fr, fr_to_u256, g1_to_eip2537_bytes};
use tbbsplus_rust::orchestration::chain::clients::RegistryClient;
use tbbsplus_rust::orchestration::chain::clients::ParamsClient;
use tbbsplus_rust::orchestration::crypto::pok;
use tbbsplus_rust::orchestration::crypto::{seeds, shares};

abigen!(
    RequestCredential,
    "artifacts/contracts/RequestCredential.sol/RequestCredential.json"
);

// Avoid abigen for CredentialRegistry to prevent error type collisions; use dynamic Contract instead

abigen!(
    Params,
    "artifacts/contracts/Params.sol/Params.json"
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // init tracing
    let _ = tracing_subscriber::fmt::try_init();
    // --- Config ---
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let req_addr: Address = env::var("REQ_CONTRACT").expect("REQ_CONTRACT").parse()?;
    // PartialSignatureRelay deprecated for aggregation; using CredentialRegistry instead
    // let relay_addr: Address = env::var("RELAY_CONTRACT").expect("RELAY_CONTRACT").parse()?;
    let registry_addr: Address = env::var("REGISTRY_CONTRACT").expect("REGISTRY_CONTRACT").parse()?;
    let chain_id: u64 = env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse()?;
    // Issuer PK no longer passed explicitly; use local dev anvil keys or pre-funded wallet if needed.
    // For demo, derive from anvil default via index (PID-1) if PRIVATE_KEY not provided.
    let participant_id: u16 = env::var("PID").unwrap_or_else(|_| "1".into()).parse()?;
    let threshold: u16 = env::var("THRESHOLD").unwrap_or_else(|_| "3".into()).parse()?;
    let total: u16 = env::var("TOTAL").unwrap_or_else(|_| "4".into()).parse()?;
    let message_count: u32 = env::var("MESSAGE_COUNT").unwrap_or_else(|_| "5".into()).parse()?;
    let base_port: u16 = env::var("BASE_PORT").unwrap_or_else(|_| "9900".into()).parse()?;
    let cred_name: String = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());

    // --- Batch config ---
    let batch_size: u32 = env::var("BATCH_SIZE").unwrap_or_else(|_| "1".into()).parse()?;
    let batch_timeout_ms: u64 = env::var("BATCH_TIMEOUT_MS").unwrap_or_else(|_| "5000".into()).parse()?;
    let is_batch_leader = participant_id == 1; // lowest PID = batch leader

    // --- Ethereum client ---
    let ws = Provider::<Ws>::connect(ws_url.clone()).await?;
    // Use deterministic mnemonic-based funded accounts (aligns with TTP demo; no private_key handling).
    let phrase = env::var("MNEMONIC").unwrap_or_else(|_| {
        // Default Anvil/Hardhat test mnemonic
        "digital humor toss grant absorb fold dry dynamic crew wagon cute hint".into()
    });
    let wallet: LocalWallet = MnemonicBuilder::<English>::default()
        .phrase(phrase.as_str())
        .index(participant_id as u32)?
        .build()?;
    let wallet = wallet.with_chain_id(chain_id);
    let client = ethers::middleware::SignerMiddleware::new(ws, wallet);
    let client = std::sync::Arc::new(client);

    let req = RequestCredential::new(req_addr, client.clone());
    // Typed client for CredentialRegistry (prefers embedded ABI)
    let registry = RegistryClient::new(registry_addr, client.clone())?;
    // Params for multiaddr discovery
    let params_addr: Address = env::var("PARAMS_CONTRACT").expect("PARAMS_CONTRACT").parse()?;
    let params = Params::new(params_addr, client.clone());
    let params_client = ParamsClient::new(params_addr, client.clone())?;

    // Metrics config
    let metrics = env::var("METRICS").map(|v| v=="1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let metrics_file = env::var("METRICS_FILE").unwrap_or_else(|_| format!("metrics/results/issuer_{}.ndjson", participant_id));

    fn metrics_append(enabled: bool, path: &str, value: serde_json::Value) {
        if !enabled { return; }
        let _ = (|| -> Result<(), Box<dyn std::error::Error>> {
            if let Some(dir) = std::path::Path::new(path).parent() { let _ = std::fs::create_dir_all(dir); }
            let mut f = OpenOptions::new().create(true).append(true).open(path)?;
            let s = serde_json::to_string(&value)?;
            writeln!(f, "{}", s)?;
            Ok(())
        })();
    }

    // Top up balance on local anvil, if needed
    if ws_url.contains("127.0.0.1") || ws_url.contains("localhost") {
        let addr = client.address();
        let bal = client.get_balance(addr, None).await.unwrap_or_default();
        if bal < U256::from(10u64.pow(17)) {
            // ~0.1 ETH
            let _ = client
                .provider()
                .request::<_, ()>(
                    "anvil_setBalance",
                    (addr, "0x56BC75E2D63100000"), // 100 ETH
                )
                .await;
        }
    }

    // --- Mesh setup ---
    let listen_addr = format!("/ip4/127.0.0.1/tcp/{}", base_port + participant_id - 1).parse()?;
    // Proactively dial peers based on on-chain multiaddrs from Params
    let mut peers = Vec::new();
    // Enumerate all issuers and map their libp2p addrs; fall back to local tcp range
    let issuers: Vec<Address> = params_client.get_issuers().await.unwrap_or_default();
    for issuer in issuers {
        let allowed: bool = params_client.issuer_allowed(issuer).await.unwrap_or(false);
        if !allowed { continue; }
        let idx: u16 = params_client.issuer_index(issuer).await.unwrap_or(0);
        if idx == 0 || idx == participant_id { continue; }
        // Prefer on-chain multiaddrs
        let addrs: Vec<String> = params_client.get_issuer_multiaddrs(issuer).await.unwrap_or_default();
        if let Some(addr) = addrs.get(0) {
            if let Ok(ma) = addr.parse() { peers.push((idx, ma)); continue; }
        }
        // Fallback: local 127.0.0.1 ports
        let fallback = format!("/ip4/127.0.0.1/tcp/{}", base_port + idx - 1).parse()?;
        peers.push((idx, fallback));
    }
    let mut mesh = Mesh::new(participant_id, Some(listen_addr), peers).await?;
    // Subscribe to topics before running in background
    let mut commit_rx = mesh.subscribe_broadcast("phase1-commitments").await?;
    let mut shares_rx = mesh.subscribe_broadcast("phase1-shares").await?;
    let mut manifest_rx = mesh.subscribe_broadcast("batch-manifest").await?;
    let mut direct_rx = mesh.subscribe_direct().await?;
    let peer_id_str = mesh.local_peer_id().to_string();
    let handle = mesh.run_background();

    // --- Load TTP-dealt key share and construct params ---
    // Fetch BBS+ params directly from Params to avoid local derivation
    let onchain_mcount: u32 = params_client.get_message_count_cached(cred_name.clone()).await?;
    if onchain_mcount != message_count { eprintln!("[issuer] WARNING: MESSAGE_COUNT env {} != on-chain {}", message_count, onchain_mcount); }
    let (g1_b, h0_b, g2_b) = params_client.get_g1h0g2_cached(cred_name.clone()).await?;
    let mut h_bytes: Vec<ethers::types::Bytes> = params_client.get_h_cached(cred_name.clone()).await?;
    let g1 = eip2537_g1_to_affine(&g1_b.0[..])?;
    let h0 = eip2537_g1_to_affine(&h0_b.0[..])?;
    let g2 = eip2537_g2_to_affine(&g2_b.0[..])?;
    let mut h: Vec<<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine> = Vec::with_capacity(h_bytes.len());
    for hb in h_bytes.drain(..) { h.push(eip2537_g1_to_affine(&hb.0[..])?); }
    let params_bbs = SignatureParamsG1::<Bls12_381> { g1, g2, h_0: h0, h };
    let shares_file = env::var("SHARES_FILE").unwrap_or_else(|_| ".runtime.shares.json".into());
    let my_share: Fr = shares::load_share_from_file(&shares_file, participant_id)?;
    let key_shares: Vec<Fr> = {
        // Build a vec with my index set; others unused for this participant
        let mut v = vec![Fr::from(0u64); total as usize];
        v[(participant_id - 1) as usize] = my_share;
        v
    };
    // Note: public key is only needed for final verification (client side). Issuer holds its own share.

    // --- Base OT (reused) ---
    // IMPORTANT: Base-OT must be consistent across all participants. We derive a shared seed
    // from fixed domain separation + credential name + TOTAL + KAPPA + SSP so each issuer
    // computes identical BaseOTOutput set locally and then selects its own index.
    let ote = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
    let shared_seed = seeds::base_ot_seed(&cred_name, total, KAPPA as usize, STATISTICAL_SECURITY_PARAMETER as usize);
    let mut rng = StdRng::seed_from_u64(shared_seed);
    let party_set = (1..=total).collect::<BTreeSet<_>>();
    let base_ot = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(&mut rng, ote.num_base_ot(), total, party_set);
    println!(
        "[base-ot] PID={} init ok: num_base_ot={}, shared_seed=0x{:016x}",
        participant_id,
        ote.num_base_ot(),
        shared_seed
    );

    // --- Listen to SigReqBBSPlusVerified events only (enforce on-chain commitment PoK) ---
    use ethers::types::BlockNumber;
    let current_block_u64 = client.provider().get_block_number().await?.as_u64();
    let from_block = BlockNumber::Number(((current_block_u64 + 1) as u64).into());
    let event_builder = req
        .event::<request_credential::SigReqBBSPlusVerifiedFilter>()
        .from_block(from_block);
    let mut stream = event_builder.stream().await?;
    info!(pid=%participant_id, from_block=%(current_block_u64 + 1), batch_size, "listening for SigReqBBSPlusVerified");

    // Per-user verified request data, used in batch sessions
    #[derive(Clone)]
    struct VerifiedRequest {
        user_id: U256,
        commitment: <Bls12_381 as ark_ec::pairing::Pairing>::G1Affine,
        revealed_idx: Vec<u32>,
        revealed_vals: Vec<U256>,
    }

    // Avoid processing the same userId more than once in this run
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SidState { WaitingP1, P1Done, P2Done, ShareSubmitted }
    let mut sessions: std::collections::BTreeMap<U256, SidState> = std::collections::BTreeMap::new();

    use std::time::Instant;
    let mut deadlines: std::collections::BTreeMap<U256, Instant> = std::collections::BTreeMap::new();

    // Batch buffering state
    let mut pending_batch: Vec<VerifiedRequest> = Vec::new();
    let mut batch_first_arrival: Option<tokio::time::Instant> = None;
    let batch_timeout = Duration::from_millis(batch_timeout_ms);

    loop {
        // Determine timeout for batch trigger
        let timeout_fut = if batch_size > 1 && !pending_batch.is_empty() {
            let elapsed = batch_first_arrival.unwrap().elapsed();
            if elapsed >= batch_timeout { Duration::from_millis(0) } else { batch_timeout - elapsed }
        } else {
            Duration::from_secs(3600) // effectively infinite when not batching
        };

        let ev_opt = tokio::select! {
            ev = stream.next() => ev,
            _ = tokio::time::sleep(timeout_fut) => None,
        };

        // Process incoming event (if any)
        if let Some(ev) = ev_opt {
            let ev = ev?;
            let user_id: U256 = ev.user_id;
            if let Some(state) = sessions.get(&user_id) {
                if matches!(state, SidState::ShareSubmitted) { continue; }
            }
            info!(pid=%participant_id, %user_id, "SigReqBBSPlusVerified");

            let commitment = eip2537_g1_to_affine(ev.commitment_b.as_ref())?;
            let hidden_idx: Vec<u32> = ev.hidden_idx.clone();
            let t_eip: Vec<u8> = ev.t.to_vec();
            let c_fr: Fr = u256_to_fr(&ev.challenge);
            let resp_fr: Vec<Fr> = ev.responses.iter().map(u256_to_fr::<Fr>).collect();
            let pok_res = pok::verify_commitment_pok_from_fields(
                &params_bbs, &commitment, &user_id, &cred_name,
                &ev.revealed_idx, &ev.revealed_vals, ev.context.as_ref(),
                hidden_idx, &t_eip, &c_fr, &resp_fr,
            );
            match pok_res {
                Ok(()) => {
                    info!(pid=%participant_id, %user_id, "commitment PoK OK");
                    sessions.insert(user_id, SidState::WaitingP1);
                    deadlines.insert(user_id, Instant::now() + Duration::from_secs(60));
                    pending_batch.push(VerifiedRequest {
                        user_id,
                        commitment,
                        revealed_idx: ev.revealed_idx.clone(),
                        revealed_vals: ev.revealed_vals.clone(),
                    });
                    if batch_first_arrival.is_none() {
                        batch_first_arrival = Some(tokio::time::Instant::now());
                    }
                }
                Err(e) => {
                    warn!(pid=%participant_id, %user_id, error=?e, "commitment PoK FAILED; skipping");
                    continue;
                }
            }

            // In non-batch mode (batch_size=1), process immediately
            if batch_size <= 1 {
                // Fall through to batch processing below
            } else if pending_batch.len() < batch_size as usize {
                // Need more events before triggering batch
                info!(pid=%participant_id, pending=%pending_batch.len(), target=%batch_size, "buffering request");
                continue;
            }
        } else if pending_batch.is_empty() {
            // Timeout fired but nothing buffered — loop back
            continue;
        }

        // ══════════════════════════════════════════════════════════════════
        // Trigger batch: either batch_size reached, timeout fired, or single mode
        // ══════════════════════════════════════════════════════════════════
        let actual_batch_size = pending_batch.len() as u32;
        let batch_requests: Vec<VerifiedRequest> = pending_batch.drain(..).collect();
        batch_first_arrival = None;

        // Sort by user_id for deterministic ordering across all issuers
        let mut batch_requests = batch_requests;
        batch_requests.sort_by_key(|r| r.user_id);
        let batch_user_ids: Vec<U256> = batch_requests.iter().map(|r| r.user_id).collect();

        // Derive a single batch session ID from the sorted user_ids
        let batch_sid: u64 = {
            use ethers::utils::keccak256;
            let mut buf = Vec::new();
            for uid in &batch_user_ids {
                let mut be = [0u8; 32];
                uid.to_big_endian(&mut be);
                buf.extend_from_slice(&be);
            }
            let h = keccak256(&buf);
            u64::from_be_bytes(h[..8].try_into().unwrap())
        };

        // Batch manifest coordination (batch_size > 1 only)
        if batch_size > 1 {
            if is_batch_leader {
                // Leader broadcasts manifest
                let manifest = serde_json::json!({
                    "from": participant_id,
                    "batch_sid": batch_sid,
                    "user_ids": batch_user_ids.iter().map(|u| format!("0x{:x}", u)).collect::<Vec<_>>(),
                });
                info!(pid=%participant_id, batch_sid, n=%actual_batch_size, "broadcasting batch manifest");
                handle.broadcast("batch-manifest", serde_json::to_vec(&manifest)?).await?;
            } else {
                // Non-leader: wait for manifest to confirm same batch
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                let mut manifest_ok = false;
                while tokio::time::Instant::now() < deadline {
                    match manifest_rx.try_recv() {
                        Ok(bytes) => {
                            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
                            let m_sid = v["batch_sid"].as_u64().unwrap_or_default();
                            if m_sid == batch_sid {
                                info!(pid=%participant_id, batch_sid, "batch manifest confirmed from leader");
                                manifest_ok = true;
                                break;
                            }
                        }
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                        Err(_) => break,
                    }
                    sleep(Duration::from_millis(50)).await;
                }
                if !manifest_ok {
                    warn!(pid=%participant_id, batch_sid, "batch manifest timeout — proceeding with local ordering");
                }
            }
        }

        info!(pid=%participant_id, batch_sid, n=%actual_batch_size, "starting MPC session");

        // ── Phase 1 ──
        use ark_serialize::CanonicalDeserialize;
        use blake2::Blake2b512;
        use bbs_plus::threshold::randomness_generation_phase::Phase1;
        use oblivious_transfer_protocols::cointoss::Commitments;
        use oblivious_transfer_protocols::ot_based_multiplication::dkls19_batch_mul_2p::GadgetVector;
        use sha3::Shake256;

        let protocol_id = b"threshold-bbs-demo".to_vec();
        let mut others = BTreeSet::new();
        for j in 1..=threshold {
            if j != participant_id { others.insert(j); }
        }

        let mut prng = StdRng::seed_from_u64(seeds::phase1_seed(participant_id, batch_sid));
        let (mut p1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs_plus::<_, Blake2b512>(
            &mut prng, actual_batch_size, participant_id, others.clone(), protocol_id.clone(),
        ).map_err(|e| anyhow::anyhow!("phase1 init failed: {:?}", e))?;

        // Broadcast commitments
        info!(pid=%participant_id, batch_sid, ?others, "phase1 broadcast commitments");
        let mut comm_bytes = Vec::new();
        comm.serialize_compressed(&mut comm_bytes)?;
        let mut zc_map = BTreeMap::new();
        for (who, zc) in comm_zero {
            let mut b = Vec::new();
            zc.serialize_compressed(&mut b)?;
            zc_map.insert(who, base64::engine::general_purpose::STANDARD.encode(b));
        }
        let msg = serde_json::json!({
            "from": participant_id,
            "sid": batch_sid,
            "peer_id": peer_id_str,
            "commitment": base64::engine::general_purpose::STANDARD.encode(comm_bytes),
            "zero_commitments": zc_map
        });
        handle.broadcast("phase1-commitments", serde_json::to_vec(&msg)?).await?;

        // Collect commitments from others
        let mut commitments_got: BTreeSet<u16> = BTreeSet::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline {
            loop {
                match commit_rx.try_recv() {
                    Ok(bytes) => {
                        let v: serde_json::Value = serde_json::from_slice(&bytes)?;
                        let msg_sid = v["sid"].as_u64().unwrap_or_default();
                        if msg_sid != batch_sid { continue; }
                        let from = v["from"].as_u64().unwrap() as u16;
                        if from == participant_id { continue; }
                        if let Some(peer_id_str) = v.get("peer_id").and_then(|s| s.as_str()) {
                            if let Ok(peer_id) = libp2p::PeerId::from_str(peer_id_str) {
                                let _ = handle.register_peer(from, peer_id).await;
                            }
                        }
                        let cmt = base64::engine::general_purpose::STANDARD.decode(v["commitment"].as_str().unwrap())?;
                        let mut rdr = &cmt[..];
                        let comm: Commitments = CanonicalDeserialize::deserialize_compressed(&mut rdr)?;
                        match v["zero_commitments"].get(&participant_id.to_string()).and_then(|x| x.as_str()) {
                            Some(zc_b64) => {
                                let zc = base64::engine::general_purpose::STANDARD.decode(zc_b64)?;
                                let mut rz = &zc[..];
                                let zc_for_me: Commitments = CanonicalDeserialize::deserialize_compressed(&mut rz)?;
                                p1.receive_commitment(from, comm, zc_for_me)
                                    .map_err(|e| anyhow::anyhow!("receive_commitment from {} failed: {:?}", from, e))?;
                                commitments_got.insert(from);
                                info!(pid=%participant_id, batch_sid, from, "phase1 got commitment");
                            }
                            None => { warn!(pid=%participant_id, batch_sid, from, "phase1 missing zero_commitment for me") }
                        }
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(_) => break,
                }
            }
            if commitments_got.len() as u16 >= threshold - 1 { break; }
            sleep(Duration::from_millis(20)).await;
        }
        if (commitments_got.len() as u16) < threshold - 1 {
            warn!(pid=%participant_id, batch_sid, ?commitments_got, "phase1 timeout waiting for commitments");
        }

        // Broadcast shares
        info!(pid=%participant_id, batch_sid, ?others, "phase1 broadcast shares");
        for to in others.iter().copied() {
            let s = p1.get_comm_shares_and_salts();
            let zs = p1.get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&to);
            let mut sb = Vec::new(); s.serialize_compressed(&mut sb)?;
            let mut zb = Vec::new(); zs.serialize_compressed(&mut zb)?;
            let msg = serde_json::json!({
                "from": participant_id, "sid": batch_sid, "to": to,
                "shares": base64::engine::general_purpose::STANDARD.encode(sb),
                "zero_shares": base64::engine::general_purpose::STANDARD.encode(zb)
            });
            handle.broadcast("phase1-shares", serde_json::to_vec(&msg)?).await?;
        }

        // Receive shares
        let mut shares_got: BTreeSet<u16> = BTreeSet::new();
        let deadline2 = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline2 {
            loop {
                match shares_rx.try_recv() {
                    Ok(bytes) => {
                        let v: serde_json::Value = serde_json::from_slice(&bytes)?;
                        let msg_sid = v["sid"].as_u64().unwrap_or_default();
                        if msg_sid != batch_sid { continue; }
                        let to = v["to"].as_u64().unwrap() as u16;
                        if to != participant_id { continue; }
                        let from = v["from"].as_u64().unwrap() as u16;
                        let s = base64::engine::general_purpose::STANDARD.decode(v["shares"].as_str().unwrap())?;
                        let z = base64::engine::general_purpose::STANDARD.decode(v["zero_shares"].as_str().unwrap())?;
                        let mut rs = &s[..];
                        let shares: Vec<(Fr, [u8; 256])> = <Vec<(Fr, [u8; 256])> as CanonicalDeserialize>::deserialize_compressed(&mut rs)?;
                        let mut rz = &z[..];
                        let zero: Vec<(Fr, [u8; 256])> = <Vec<(Fr, [u8; 256])> as CanonicalDeserialize>::deserialize_compressed(&mut rz)?;
                        p1.receive_shares::<blake2::Blake2b512>(from, shares, zero)
                            .map_err(|e| anyhow::anyhow!("receive_shares from {} failed: {:?}", from, e))?;
                        shares_got.insert(from);
                        info!(pid=%participant_id, batch_sid, from, "phase1 got shares");
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(_) => break,
                }
            }
            if shares_got.len() as u16 >= threshold - 1 { break; }
            sleep(Duration::from_millis(20)).await;
        }
        if (shares_got.len() as u16) < threshold - 1 {
            warn!(pid=%participant_id, batch_sid, ?shares_got, "phase1 timeout waiting for shares");
        }

        let phase1_output = p1
            .finish_for_bbs_plus::<blake2::Blake2b512>(&key_shares[(participant_id - 1) as usize])
            .map_err(|e| anyhow::anyhow!("phase1 finish failed: {:?}", e))?;
        for req in &batch_requests { sessions.insert(req.user_id, SidState::P1Done); }

        // ── Phase 2 ──
        use blake2::Blake2b512 as B2b;
        let ote_params_p2 = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
        let gadget = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<B2b>(
            ote_params_p2, b"threshold-bbs-plus-gadget",
        );

        let others_set = phase1_output.others.iter().copied().collect::<BTreeSet<u16>>();
        let mut r = StdRng::seed_from_u64(seeds::phase2_seed(participant_id, batch_sid));
        let (mut p2, msgs) = bbs_plus::threshold::multiplication_phase::Phase2::<
            Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER,
        >::init::<_, Shake256>(
            &mut r, participant_id,
            phase1_output.masked_signing_key_shares.clone(),
            phase1_output.masked_rs.clone(),
            base_ot[(participant_id - 1) as usize].clone(),
            others_set.clone(), ote_params_p2, &gadget,
        ).map_err(|e| anyhow::anyhow!("phase2 init failed: {:?}", e))?;

        // Send round1 messages
        for (to, m1) in msgs {
            let mut b = Vec::new(); m1.serialize_compressed(&mut b)?;
            let j = serde_json::json!({
                "round": 1, "from": participant_id, "sid": batch_sid, "to": to,
                "data": base64::engine::general_purpose::STANDARD.encode(b)
            });
            let payload = serde_json::to_vec(&j)?;
            let mut attempts = 0;
            loop {
                attempts += 1;
                match handle.send_to(to, payload.clone()).await {
                    Ok(_) => break,
                    Err(e) if attempts < 5 => {
                        warn!(pid=%participant_id, to, attempts, error=?e, "direct send R1 retry");
                        sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => return Err(anyhow::anyhow!("send R1 failed: {:?}", e)),
                }
            }
        }

        let exp_r1: BTreeSet<u16> = others_set.iter().copied().filter(|x| *x < participant_id).collect();
        let exp_r2: BTreeSet<u16> = others_set.iter().copied().filter(|x| *x > participant_id).collect();
        let mut got_r1: BTreeSet<u16> = BTreeSet::new();
        let mut got_r2: BTreeSet<u16> = BTreeSet::new();

        let start = tokio::time::Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            loop {
                match direct_rx.try_recv() {
                    Ok(dm) => {
                        let v: serde_json::Value = serde_json::from_slice(&dm.data)?;
                        let msg_sid = v["sid"].as_u64().unwrap_or_default();
                        if msg_sid != batch_sid { continue; }
                        let to = v["to"].as_u64().unwrap() as u16;
                        if to != participant_id { continue; }
                        let from = v["from"].as_u64().unwrap() as u16;
                        let round = v["round"].as_u64().unwrap() as u8;
                        let data = base64::engine::general_purpose::STANDARD.decode(v["data"].as_str().unwrap())?;
                        if round == 1 {
                            let mut r1 = &data[..];
                            let m1 = CanonicalDeserialize::deserialize_compressed(&mut r1)?;
                            let m2 = p2.receive_message1::<B2b, Shake256>(from, m1, &gadget)
                                .map_err(|e| anyhow::anyhow!(
                                    "[phase2] pid={} batch_sid={} recv1 from {} failed: {:?}",
                                    participant_id, batch_sid, from, e
                                ))?;
                            if exp_r1.contains(&from) { got_r1.insert(from); }
                            let mut bb = Vec::new(); m2.serialize_compressed(&mut bb)?;
                            let j = serde_json::json!({
                                "round": 2, "from": participant_id, "sid": batch_sid, "to": from,
                                "data": base64::engine::general_purpose::STANDARD.encode(bb)
                            });
                            let payload = serde_json::to_vec(&j)?;
                            let mut attempts = 0;
                            loop {
                                attempts += 1;
                                match handle.send_to(from, payload.clone()).await {
                                    Ok(_) => break,
                                    Err(e) if attempts < 5 => {
                                        warn!(pid=%participant_id, from, attempts, error=?e, "direct send R2 retry");
                                        sleep(Duration::from_millis(100)).await;
                                    }
                                    Err(e) => return Err(anyhow::anyhow!("send R2 failed: {:?}", e)),
                                }
                            }
                        } else if round == 2 {
                            let mut r2 = &data[..];
                            let m2 = CanonicalDeserialize::deserialize_compressed(&mut r2)?;
                            p2.receive_message2::<B2b>(from, m2, &gadget)
                                .map_err(|e| anyhow::anyhow!("[phase2] recv2 failed: {:?}", e))?;
                            if exp_r2.contains(&from) { got_r2.insert(from); }
                        }
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(_) => break,
                }
            }
            if got_r1.len() == exp_r1.len() && got_r2.len() == exp_r2.len() { break; }
            sleep(Duration::from_millis(20)).await;
        }

        let phase2_output = p2.finish();
        for req in &batch_requests { sessions.insert(req.user_id, SidState::P2Done); }

        // ── Phase 3: Create signature shares for each user in the batch ──
        let onchain_t: u16 = params_client.get_threshold_cached(cred_name.clone()).await?;

        if actual_batch_size == 1 {
            // Single-user path: submitShare (backward compatible)
            let vreq = &batch_requests[0];
            let mut tmp_pairs: Vec<(usize, Fr)> = Vec::new();
            let mut uid_ok = false;
            for (i, v) in vreq.revealed_idx.iter().zip(vreq.revealed_vals.iter()) {
                let idx = (*i) as usize;
                if idx == 0 { uid_ok = true; }
                tmp_pairs.push((idx, u256_to_fr::<Fr>(v)));
            }
            if !uid_ok { tmp_pairs.push((0usize, u256_to_fr::<Fr>(&vreq.user_id))); }
            let values_store: Vec<Fr> = tmp_pairs.iter().map(|(_, fr)| fr.clone()).collect();
            let mut uncommitted: BTreeMap<usize, &Fr> = BTreeMap::new();
            for (k, (idx, _)) in tmp_pairs.iter().enumerate() {
                uncommitted.insert(*idx, &values_store[k]);
            }
            let share = bbs_plus::threshold::threshold_bbs_plus::BBSPlusSignatureShare::new_with_committed_messages(
                &vreq.commitment, uncommitted, 0, &phase1_output, &phase2_output, &params_bbs,
            ).map_err(|e| anyhow::anyhow!("create signature share failed: {:?}", e))?;

            let r_bytes128 = ethers::types::Bytes::from(g1_to_eip2537_bytes(&share.R).to_vec());
            let u_u256 = fr_to_u256(&share.u);
            let e_u256 = fr_to_u256(&share.e);
            let s_u256 = fr_to_u256(&share.s);
            let mut call = registry.submit_share_call(
                cred_name.clone(), vreq.user_id, participant_id,
                r_bytes128, u_u256, e_u256, s_u256, onchain_t,
            )?;
            if ws_url.contains("127.0.0.1") || ws_url.contains("localhost") {
                call = call.gas_price(U256::from(1_000_000_000u64));
            }
            match call.send().await {
                Ok(pend) => {
                    let rcpt = pend.await?.ok_or_else(|| anyhow::anyhow!("no receipt"))?;
                    info!(pid=%participant_id, user_id=%vreq.user_id, tx=?rcpt.transaction_hash, "submitShare ok");
                    let gas_used = rcpt.gas_used.unwrap_or_default();
                    let eff_price = rcpt.effective_gas_price.unwrap_or_default();
                    let cost = gas_used * eff_price;
                    metrics_append(metrics, &metrics_file, json!({
                        "scenario":"submitShare", "userId": format!("0x{:x}", vreq.user_id),
                        "idx": participant_id, "gasUsed": gas_used.to_string(),
                        "effectiveGasPrice": eff_price.to_string(), "costWei": cost.to_string()
                    }));
                    sessions.insert(vreq.user_id, SidState::ShareSubmitted);
                }
                Err(e) => { error!(pid=%participant_id, error=?e, "submitShare failed"); }
            };
        } else {
            // Batch path: create N shares, submit via submitShareBatch
            let mut r_concat = Vec::with_capacity(actual_batch_size as usize * 128);
            let mut us = Vec::with_capacity(actual_batch_size as usize);
            let mut es = Vec::with_capacity(actual_batch_size as usize);
            let mut ss = Vec::with_capacity(actual_batch_size as usize);
            let mut user_ids_u256 = Vec::with_capacity(actual_batch_size as usize);

            for (sig_idx, vreq) in batch_requests.iter().enumerate() {
                let mut tmp_pairs: Vec<(usize, Fr)> = Vec::new();
                let mut uid_ok = false;
                for (i, v) in vreq.revealed_idx.iter().zip(vreq.revealed_vals.iter()) {
                    let idx = (*i) as usize;
                    if idx == 0 { uid_ok = true; }
                    tmp_pairs.push((idx, u256_to_fr::<Fr>(v)));
                }
                if !uid_ok { tmp_pairs.push((0usize, u256_to_fr::<Fr>(&vreq.user_id))); }
                let values_store: Vec<Fr> = tmp_pairs.iter().map(|(_, fr)| fr.clone()).collect();
                let mut uncommitted: BTreeMap<usize, &Fr> = BTreeMap::new();
                for (k, (idx, _)) in tmp_pairs.iter().enumerate() {
                    uncommitted.insert(*idx, &values_store[k]);
                }
                let share = bbs_plus::threshold::threshold_bbs_plus::BBSPlusSignatureShare::new_with_committed_messages(
                    &vreq.commitment, uncommitted, sig_idx, &phase1_output, &phase2_output, &params_bbs,
                ).map_err(|e| anyhow::anyhow!("batch share[{}] failed: {:?}", sig_idx, e))?;

                r_concat.extend_from_slice(&g1_to_eip2537_bytes(&share.R));
                us.push(fr_to_u256(&share.u));
                es.push(fr_to_u256(&share.e));
                ss.push(fr_to_u256(&share.s));
                user_ids_u256.push(vreq.user_id);
                info!(pid=%participant_id, sig_idx, user_id=%vreq.user_id, "share[{}] created", sig_idx);
            }

            let mut call = registry.submit_share_batch_call(
                cred_name.clone(), user_ids_u256.clone(), participant_id,
                ethers::types::Bytes::from(r_concat), us, es, ss,
            )?;
            if ws_url.contains("127.0.0.1") || ws_url.contains("localhost") {
                call = call.gas_price(U256::from(1_000_000_000u64));
            }
            match call.send().await {
                Ok(pend) => {
                    let rcpt = pend.await?.ok_or_else(|| anyhow::anyhow!("no receipt"))?;
                    let gas_used = rcpt.gas_used.unwrap_or_default();
                    let eff_price = rcpt.effective_gas_price.unwrap_or_default();
                    let cost = gas_used * eff_price;
                    info!(
                        pid=%participant_id, batch_sid, n=%actual_batch_size,
                        gas=%gas_used, tx=?rcpt.transaction_hash,
                        "submitShareBatch ok"
                    );
                    metrics_append(metrics, &metrics_file, json!({
                        "scenario":"submitShareBatch", "batch_size": actual_batch_size,
                        "idx": participant_id, "gasUsed": gas_used.to_string(),
                        "effectiveGasPrice": eff_price.to_string(), "costWei": cost.to_string()
                    }));
                    for uid in &user_ids_u256 {
                        sessions.insert(*uid, SidState::ShareSubmitted);
                    }

                    // Batch leader waits for Aggregated events (threshold reached)
                    // for all users in the batch, then calls confirmBatchRandomized.
                    if is_batch_leader {
                        info!(pid=%participant_id, batch_sid, n=%actual_batch_size,
                              "batch leader: waiting for Aggregated events for all {} users…", actual_batch_size);

                        let topic_agg = H256::from(ethers::utils::keccak256(
                            b"Aggregated(string,uint256,bytes,uint256,uint256)"
                        ));
                        let name_topic = H256::from(ethers::utils::keccak256(cred_name.as_bytes()));
                        let filter_agg = ethers::types::Filter::new()
                            .address(ethers::types::ValueOrArray::Value(registry.address()))
                            .topic0(ethers::types::ValueOrArray::Value(topic_agg))
                            .topic1(ethers::types::ValueOrArray::Value(name_topic))
                            .from_block(ethers::types::BlockNumber::Latest);
                        let agg_stream_res = client.provider().subscribe_logs(&filter_agg).await;

                        let mut pending: HashSet<U256> = user_ids_u256.iter().cloned().collect();
                        let confirm_timeout = Duration::from_secs(30);
                        let deadline = tokio::time::Instant::now() + confirm_timeout;

                        match agg_stream_res {
                            Ok(mut agg_stream) => {
                                while !pending.is_empty() {
                                    match tokio::time::timeout_at(deadline, agg_stream.next()).await {
                                        Ok(Some(log)) => {
                                            if log.topics.len() >= 3 {
                                                let uid = U256::from_big_endian(log.topics[2].as_bytes());
                                                if pending.remove(&uid) {
                                                    info!(pid=%participant_id, userId=%uid,
                                                          remaining=%pending.len(), "Aggregated event received");
                                                }
                                            }
                                        }
                                        Ok(None) => { warn!(pid=%participant_id, "agg_stream ended unexpectedly"); break; }
                                        Err(_) => {
                                            warn!(pid=%participant_id, batch_sid,
                                                  remaining=%pending.len(),
                                                  "timeout (30s) waiting for Aggregated events; proceeding anyway");
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(pid=%participant_id, error=?e,
                                      "failed to subscribe to Aggregated events; falling back to 8s delay");
                                sleep(Duration::from_secs(8)).await;
                            }
                        }

                        if pending.is_empty() {
                            info!(pid=%participant_id, batch_sid, "all users aggregated; calling confirmBatchRandomized");
                        }

                        let mut confirm_call = registry.confirm_batch_randomized_call(
                            cred_name.clone(), user_ids_u256.clone(),
                        )?;
                        if ws_url.contains("127.0.0.1") || ws_url.contains("localhost") {
                            confirm_call = confirm_call.gas_price(U256::from(1_000_000_000u64));
                        }
                        match confirm_call.send().await {
                            Ok(pend) => {
                                let rcpt = pend.await?.ok_or_else(|| anyhow::anyhow!("no confirm receipt"))?;
                                let gas_used = rcpt.gas_used.unwrap_or_default();
                                let eff_price = rcpt.effective_gas_price.unwrap_or_default();
                                let cost = gas_used * eff_price;
                                info!(
                                    pid=%participant_id, batch_sid, n=%actual_batch_size,
                                    gas=%gas_used, tx=?rcpt.transaction_hash,
                                    "confirmBatchRandomized ok"
                                );
                                metrics_append(metrics, &metrics_file, json!({
                                    "scenario":"confirmBatchRandomized", "batch_size": actual_batch_size,
                                    "idx": participant_id, "gasUsed": gas_used.to_string(),
                                    "effectiveGasPrice": eff_price.to_string(), "costWei": cost.to_string()
                                }));
                            }
                            Err(e) => {
                                warn!(pid=%participant_id, batch_sid, error=?e, "confirmBatchRandomized failed (may retry)");
                            }
                        };
                    }
                }
                Err(e) => { error!(pid=%participant_id, error=?e, "submitShareBatch failed"); }
            };
        }

        // Prune stale sessions
        let now = Instant::now();
        deadlines.retain(|uid_k, dl| {
            if *dl < now {
                warn!(userId=%uid_k, "session deadline elapsed; pruning");
                sessions.remove(uid_k);
                false
            } else { true }
        });
    }

    Ok(())
}


