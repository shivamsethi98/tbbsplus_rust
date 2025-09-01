// Issuer binary: listens to RequestCredential.SigReqBBSPlus events,
// runs threshold MPC (Phase1 broadcast + Phase2 direct) for the session,
// and submits a partial signature share to PartialSignatureRelay.
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
    // Subscribe from the next block after we connect, to ensure all issuers
    // are listening before the client emits a new event (avoids race).
    let current_block_u64 = client.provider().get_block_number().await?.as_u64();
    let from_block = BlockNumber::Number(((current_block_u64 + 1) as u64).into());
    let event_builder = req
        .event::<request_credential::SigReqBBSPlusVerifiedFilter>()
        .from_block(from_block);
    let mut stream = event_builder.stream().await?;
    info!(pid=%participant_id, from_block=%(current_block_u64 + 1), "listening for SigReqBBSPlusVerified");

    // Avoid processing the same sid more than once in this run
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SidState { WaitingP1, P1Done, P2Done, ShareSubmitted }
    let mut sessions: std::collections::BTreeMap<u64, SidState> = std::collections::BTreeMap::new();

    // Simple session deadline map
    use std::time::{Instant};
    let mut deadlines: std::collections::BTreeMap<u64, Instant> = std::collections::BTreeMap::new();

    while let Some(ev) = stream.next().await {
        let ev = ev?;
        let sid = ev.sid.as_u64();
        // Note: `name` is indexed in the event and comes as a topic hash (H256), not the raw string.
        // We don't gate on name to avoid topic/string mismatch; we dedup purely by sid.
        if let Some(state) = sessions.get(&sid) {
            if matches!(state, SidState::ShareSubmitted) { continue; }
        }
    info!(pid=%participant_id, sid, "SigReqBBSPlusVerified");


    let commitment: <Bls12_381 as ark_ec::pairing::Pairing>::G1Affine = eip2537_g1_to_affine(ev.commitment_b.as_ref())?;
    let hidden_idx: Vec<u32> = ev.hidden_idx.clone();
    let t_eip: Vec<u8> = ev.t.to_vec();
    let c_fr: Fr = u256_to_fr(&ev.challenge);
    let resp_fr: Vec<Fr> = ev.responses.iter().map(u256_to_fr::<Fr>).collect();
    // Fallback off-chain PoK check mirroring on-chain verification (double-check; cheap)
    let pok_res = pok::verify_commitment_pok_from_fields(
        &params_bbs,
        &commitment,
        sid,
        &cred_name,
        &ev.revealed_idx,
        &ev.revealed_vals,
        ev.context.as_ref(),
        hidden_idx,
        &t_eip,
        &c_fr,
        &resp_fr,
    );
    match pok_res {
        Ok(()) => {
            info!(pid=%participant_id, sid, revealed=%ev.revealed_idx.len(), ctx_len=%ev.context.len(), "commitment PoK OK");
            sessions.insert(sid, SidState::WaitingP1);
            deadlines.insert(sid, Instant::now() + Duration::from_secs(60));
        }
        Err(e) => {
            warn!(pid=%participant_id, sid, error=?e, "commitment PoK FAILED; skipping");
            continue;
        }
    }

        // Phase 1 and Phase 2: inline minimal orchestration for THIS participant only.
        use ark_serialize::CanonicalDeserialize;
        use blake2::Blake2b512;
    // Phase2 is referenced below via fully-qualified path; keep import minimal to avoid warnings.
        use bbs_plus::threshold::randomness_generation_phase::Phase1;
        use oblivious_transfer_protocols::cointoss::Commitments;
        use oblivious_transfer_protocols::ot_based_multiplication::dkls19_batch_mul_2p::GadgetVector;
        use sha3::Shake256;

        let protocol_id = b"threshold-bbs-demo".to_vec();

        // Phase 1 init for our participant
        let mut others = BTreeSet::new();
        for j in 1..=threshold {
            if j != participant_id {
                others.insert(j);
            }
        }
    let mut prng = StdRng::seed_from_u64(seeds::phase1_seed(participant_id, sid));
    let (mut p1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs_plus::<_, Blake2b512>(
            &mut prng,
            1,
            participant_id,
            others.clone(),
            protocol_id.clone(),
    )
    .map_err(|e| anyhow::anyhow!("phase1 init failed: {:?}", e))?;

        // Broadcast our commitment along with our libp2p peer id for mapping
    info!(pid=%participant_id, sid, ?others, "phase1 broadcast commitments");
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
            "sid": sid,
            "peer_id": peer_id_str,
            "commitment": base64::engine::general_purpose::STANDARD.encode(comm_bytes),
            "zero_commitments": zc_map
        });
        handle
            .broadcast("phase1-commitments", serde_json::to_vec(&msg)?)
            .await?;

        // Collect commitments from others
        let mut commitments_got: BTreeSet<u16> = BTreeSet::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline {
            loop {
                match commit_rx.try_recv() {
                    Ok(bytes) => {
                        let v: serde_json::Value = serde_json::from_slice(&bytes)?;
                        let msg_sid = v["sid"].as_u64().unwrap_or_default();
                        if msg_sid != sid { continue; }
                        let from = v["from"].as_u64().unwrap() as u16;
                        if from == participant_id {
                            continue;
                        }
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
                                p1
                                    .receive_commitment(from, comm, zc_for_me)
                                    .map_err(|e| anyhow::anyhow!("receive_commitment from {} failed: {:?}", from, e))?;
                                commitments_got.insert(from);
                                info!(pid=%participant_id, sid, from, "phase1 got commitment");
                            }
                            None => { warn!(pid=%participant_id, sid, from, "phase1 missing zero_commitment for me") }
                        }
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(_) => break,
                }
            }
            if commitments_got.len() as u16 >= threshold - 1 {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    if (commitments_got.len() as u16) < threshold - 1 {
            warn!(pid=%participant_id, sid, ?commitments_got, "phase1 timeout waiting for commitments");
        }

        // Broadcast our shares to others
    info!(pid=%participant_id, sid, ?others, "phase1 broadcast shares");
    for to in others.iter().copied() {
            let s = p1.get_comm_shares_and_salts();
            let zs = p1.get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&to);
            let mut sb = Vec::new();
            s.serialize_compressed(&mut sb)?;
            let mut zb = Vec::new();
            zs.serialize_compressed(&mut zb)?;
            let msg = serde_json::json!({
                "from": participant_id,
        "sid": sid,
                "to": to,
                "shares": base64::engine::general_purpose::STANDARD.encode(sb),
                "zero_shares": base64::engine::general_purpose::STANDARD.encode(zb)
            });
            handle
                .broadcast("phase1-shares", serde_json::to_vec(&msg)?)
                .await?;
        }

        // Receive shares addressed to us
        let mut shares_got: BTreeSet<u16> = BTreeSet::new();
        let deadline2 = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline2 {
            loop {
                match shares_rx.try_recv() {
                    Ok(bytes) => {
                        let v: serde_json::Value = serde_json::from_slice(&bytes)?;
                        let msg_sid = v["sid"].as_u64().unwrap_or_default();
                        if msg_sid != sid { continue; }
                        let to = v["to"].as_u64().unwrap() as u16;
                        if to != participant_id {
                            continue;
                        }
                        let from = v["from"].as_u64().unwrap() as u16;
                        let s = base64::engine::general_purpose::STANDARD.decode(v["shares"].as_str().unwrap())?;
                        let z = base64::engine::general_purpose::STANDARD.decode(v["zero_shares"].as_str().unwrap())?;
                        let mut rs = &s[..];
                        let shares: Vec<(Fr, [u8; 256])> = <Vec<(Fr, [u8; 256])> as CanonicalDeserialize>::deserialize_compressed(&mut rs)?;
                        let mut rz = &z[..];
                        let zero: Vec<(Fr, [u8; 256])> = <Vec<(Fr, [u8; 256])> as CanonicalDeserialize>::deserialize_compressed(&mut rz)?;
                        p1
                            .receive_shares::<blake2::Blake2b512>(from, shares, zero)
                            .map_err(|e| anyhow::anyhow!("receive_shares from {} failed: {:?}", from, e))?;
                        shares_got.insert(from);
                        info!(pid=%participant_id, sid, from, "phase1 got shares");
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(_) => break,
                }
            }
            if shares_got.len() as u16 >= threshold - 1 {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    if (shares_got.len() as u16) < threshold - 1 {
            warn!(pid=%participant_id, sid, ?shares_got, "phase1 timeout waiting for shares");
        }

        // Finalize Phase 1 for our participant
    let phase1_output = p1
            .finish_for_bbs_plus::<blake2::Blake2b512>(&key_shares[(participant_id - 1) as usize])
            .map_err(|e| anyhow::anyhow!("phase1 finish failed for PID={} sid={}: {:?}", participant_id, sid, e))?;
    sessions.insert(sid, SidState::P1Done);

        // Phase 2 for our participant
        use blake2::Blake2b512 as B2b;
        let ote_params_p2 = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
        let gadget = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<B2b>(
            ote_params_p2,
            b"threshold-bbs-plus-gadget",
        );

    let others_set = phase1_output
            .others
            .iter()
            .copied()
            .collect::<BTreeSet<u16>>();
    let mut r = StdRng::seed_from_u64(seeds::phase2_seed(participant_id, sid));
    let (mut p2, msgs) = bbs_plus::threshold::multiplication_phase::Phase2::<
            Fr,
            KAPPA,
            STATISTICAL_SECURITY_PARAMETER,
        >::init::<_, Shake256>(
            &mut r,
            participant_id,
            phase1_output.masked_signing_key_shares.clone(),
            phase1_output.masked_rs.clone(),
            base_ot[(participant_id - 1) as usize].clone(),
            others_set.clone(),
            ote_params_p2,
            &gadget,
    )
    .map_err(|e| anyhow::anyhow!("phase2 init failed: {:?}", e))?;

        // Send round1 messages
    for (to, m1) in msgs {
            let mut b = Vec::new();
            m1.serialize_compressed(&mut b)?;
            let j = serde_json::json!({
                "round": 1,
                "from": participant_id,
        "sid": sid,
                "to": to,
                "data": base64::engine::general_purpose::STANDARD.encode(b)
            });
            // Retry a few times until mapping is learned
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

        // Expectations
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
                        if msg_sid != sid { continue; }
                        let to = v["to"].as_u64().unwrap() as u16;
                        if to != participant_id {
                            continue;
                        }
                        let from = v["from"].as_u64().unwrap() as u16;
                        let round = v["round"].as_u64().unwrap() as u8;
                        let data = base64::engine::general_purpose::STANDARD.decode(v["data"].as_str().unwrap())?;
                        if round == 1 {
                            let mut r1 = &data[..];
                            let m1 = CanonicalDeserialize::deserialize_compressed(&mut r1)?;
                            let m2 = p2
                                .receive_message1::<B2b, Shake256>(from, m1, &gadget)
                                .map_err(|e| anyhow::anyhow!(
                                    "[phase2] pid={} sid={} recv1 from {} failed: {:?}",
                                    participant_id, sid, from, e
                                ))?;
                            if exp_r1.contains(&from) {
                                got_r1.insert(from);
                            }
                            let mut bb = Vec::new();
                            m2.serialize_compressed(&mut bb)?;
                            let j = serde_json::json!({
                                "round": 2,
                                "from": participant_id,
                                "sid": sid,
                                "to": from,
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
                            p2
                                .receive_message2::<B2b>(from, m2, &gadget)
                                .map_err(|e| anyhow::anyhow!("[phase2] recv2 failed pid={} sid={} from {}: {:?}", participant_id, sid, from, e))?;
                            if exp_r2.contains(&from) {
                                got_r2.insert(from);
                            }
                        }
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(_) => break,
                }
            }
            if got_r1.len() == exp_r1.len() && got_r2.len() == exp_r2.len() {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }

    let phase2_output = p2.finish();
    sessions.insert(sid, SidState::P2Done);

    // Create our signature share using blind commitment: uncommitted messages are revealed pairs
    let mut tmp_pairs: Vec<(usize, Fr)> = Vec::new();
    let mut sid_ok = false;
    for (i, v) in ev.revealed_idx.iter().zip(ev.revealed_vals.iter()) {
        let idx = (*i) as usize;
        if idx == 0 { sid_ok = true; }
        tmp_pairs.push((idx, u256_to_fr::<Fr>(v)));
    }
    if !sid_ok { tmp_pairs.push((0usize, Fr::from(sid))); }
    let values_store: Vec<Fr> = tmp_pairs.iter().map(|(_, fr)| fr.clone()).collect();
    let mut uncommitted: BTreeMap<usize, &Fr> = BTreeMap::new();
    for (k, (idx, _)) in tmp_pairs.iter().enumerate() {
        let fr_ref: &Fr = &values_store[k];
        uncommitted.insert(*idx, fr_ref);
    }
    let share = bbs_plus::threshold::threshold_bbs_plus::BBSPlusSignatureShare::new_with_committed_messages(
            &commitment,
            uncommitted,
            0,
            &phase1_output,
            &phase2_output,
            &params_bbs,
    )
    .map_err(|e| anyhow::anyhow!("create signature share (blind) failed: {:?}", e))?;
        let mut payload_vec = Vec::new();
        share.serialize_compressed(&mut payload_vec)?;

        // Submit share to CredentialRegistry for on-chain aggregation
        // Extract (R,u,e,s) and convert to EVM types
        let r_bytes128 = ethers::types::Bytes::from(g1_to_eip2537_bytes(&share.R).to_vec());
        let u_u256 = fr_to_u256(&share.u);
        let e_u256 = fr_to_u256(&share.e);
        let s_u256 = fr_to_u256(&share.s);
        // Fetch threshold t from Params (authoritative)
    let onchain_t: u16 = params_client.get_threshold_cached(cred_name.clone()).await?;
        let mut call = registry.submit_share_call(
            cred_name.clone(),
            U256::from(sid),
            participant_id,
            r_bytes128,
            u_u256,
            e_u256,
            s_u256,
            params_client.get_threshold_cached(cred_name.clone()).await.unwrap_or(onchain_t),
        )?;
        if ws_url.contains("127.0.0.1") || ws_url.contains("localhost") {
            call = call.gas_price(U256::from(1_000_000_000u64));
        }
        let send_res = call.send().await;
        match send_res {
            Ok(pend) => {
                let rcpt = pend.await?.ok_or_else(|| anyhow::anyhow!("no receipt"))?;
                info!(pid=%participant_id, sid, tx=?rcpt.transaction_hash, "submitShare ok");
                // Metrics: record gas for this issuer submitShare
                let gas_used = rcpt.gas_used.unwrap_or_default();
                let eff_price = rcpt.effective_gas_price.unwrap_or_default();
                let cost = gas_used * eff_price;
                let blk = rcpt.block_number.unwrap_or_default();
                metrics_append(metrics, &metrics_file, json!({
                    "scenario":"submitShare",
                    "sid": sid,
                    "idx": participant_id,
                    "hash": format!("0x{:x}", rcpt.transaction_hash),
                    "blockNumber": blk.as_u64(),
                    "gasUsed": gas_used.to_string(),
                    "effectiveGasPrice": eff_price.to_string(),
                    "costWei": cost.to_string()
                }));
                sessions.insert(sid, SidState::ShareSubmitted);
            }
            Err(e) => {
                return Err(anyhow::anyhow!("submitShare failed: {:?}", e));
            }
        }
        // prune stale sessions occasionally
        let now = Instant::now();
        deadlines.retain(|sid_k, dl| {
            if *dl < now {
                warn!(sid=%sid_k, "session deadline elapsed; pruning");
                sessions.remove(sid_k);
                false
            } else { true }
        });
    }

    Ok(())
}


