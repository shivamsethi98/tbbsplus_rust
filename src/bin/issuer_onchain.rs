// Issuer binary: listens to RequestCredential.SigReqBBSPlus events,
// runs threshold MPC (Phase1 broadcast + Phase2 direct) for the session,
// and submits a partial signature share to PartialSignatureRelay.
// Build/run: cargo run --features mpc --bin issuer_onchain

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;
use std::str::FromStr;

use base64::Engine;
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use std::io::Read;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use bbs_plus::prelude::*;
use ethers::contract::abigen;
use ethers::prelude::*;
use ethers::signers::{coins_bip39::English, MnemonicBuilder};
use ethers::providers::{Provider, Ws};
use futures::StreamExt;
// use secret_sharing_and_dkg::shamir_ss::deal_random_secret; // now loaded from TTP shares file
use tokio::time::{sleep, Duration};

use oblivious_transfer_protocols::ot_based_multiplication::dkls18_mul_2p::MultiplicationOTEParams;
use test_utils::ot::do_pairwise_base_ot;

use tbbsplus_rust::orchestration::mesh_v2_simple::p2p::Mesh;
use tbbsplus_rust::orchestration::threshold_phases::{BASE_OT_KEY_SIZE, KAPPA, STATISTICAL_SECURITY_PARAMETER};

abigen!(
    RequestCredential,
    "artifacts/contracts/RequestCredential.sol/RequestCredential.json"
);

abigen!(
    PartialSignatureRelay,
    "artifacts/contracts/PartialSignatureRelay.sol/PartialSignatureRelay.json"
);

abigen!(
    Params,
    "artifacts/contracts/Params.sol/Params.json"
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --- Config ---
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let req_addr: Address = env::var("REQ_CONTRACT").expect("REQ_CONTRACT").parse()?;
    let relay_addr: Address = env::var("RELAY_CONTRACT").expect("RELAY_CONTRACT").parse()?;
    let chain_id: u64 = env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse()?;
    // Issuer PK no longer passed explicitly; use local dev anvil keys or pre-funded wallet if needed.
    // For demo, derive from anvil default via index (PID-1) if PRIVATE_KEY not provided.
    let participant_id: u16 = env::var("PID").unwrap_or_else(|_| "1".into()).parse()?;
    let threshold: u16 = env::var("THRESHOLD").unwrap_or_else(|_| "3".into()).parse()?;
    let total: u16 = env::var("TOTAL").unwrap_or_else(|_| "4".into()).parse()?;
    let message_count: u32 = env::var("MESSAGE_COUNT").unwrap_or_else(|_| "5".into()).parse()?;
    let base_port: u16 = env::var("BASE_PORT").unwrap_or_else(|_| "9900".into()).parse()?;
    let cred_name: String = env::var("CRED_NAME").unwrap_or_else(|_| "IITH_UG_AC".into());

    // --- Ethereum client ---
    let ws = Provider::<Ws>::connect(ws_url.clone()).await?;
    // Use deterministic mnemonic-based funded accounts (aligns with TTP demo; no private_key handling).
    let phrase = env::var("MNEMONIC").unwrap_or_else(|_| {
        // Default Anvil/Hardhat test mnemonic
        "test test test test test test test test test test test junk".into()
    });
    let wallet: LocalWallet = MnemonicBuilder::<English>::default()
        .phrase(phrase.as_str())
        .index(participant_id as u32)?
        .build()?;
    let wallet = wallet.with_chain_id(chain_id);
    let client = ethers::middleware::SignerMiddleware::new(ws, wallet);
    let client = std::sync::Arc::new(client);

    let req = RequestCredential::new(req_addr, client.clone());
    let relay = PartialSignatureRelay::new(relay_addr, client.clone());
    // Params for multiaddr discovery
    let params_addr: Address = env::var("PARAMS_CONTRACT").expect("PARAMS_CONTRACT").parse()?;
    let params = Params::new(params_addr, client.clone());

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
    let issuers: Vec<Address> = params.get_issuers().call().await.unwrap_or_default();
    for issuer in issuers {
    let allowed: bool = params.issuer_allowed(issuer).call().await.unwrap_or(false);
        if !allowed { continue; }
    let idx: u16 = params.issuer_index(issuer).call().await.unwrap_or(0);
        if idx == 0 || idx == participant_id { continue; }
        // Prefer on-chain multiaddrs
    let addrs: Vec<String> = params.get_issuer_multiaddrs(issuer).call().await.unwrap_or_default();
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
    let params = SignatureParamsG1::<Bls12_381>::new::<blake2::Blake2b512>(cred_name.as_bytes(), message_count);
    let shares_file = env::var("SHARES_FILE").unwrap_or_else(|_| ".runtime.shares.json".into());
    let data = std::fs::read(&shares_file)
        .map_err(|e| anyhow::anyhow!("failed to read shares file {shares_file}: {:?}", e))?;
    let v: serde_json::Value = serde_json::from_slice(&data)?;
    let shares_obj = v.get("shares").and_then(|s| s.as_object()).ok_or_else(|| anyhow::anyhow!("shares missing in {shares_file}"))?;
    let key_b64 = shares_obj
        .get(&participant_id.to_string())
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow::anyhow!("no share for PID {} in {shares_file}", participant_id))?;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|e| anyhow::anyhow!("bad base64 in shares file: {:?}", e))?;
    let mut rdr = &key_bytes[..];
    let my_share: Fr = ark_serialize::CanonicalDeserialize::deserialize_compressed(&mut rdr)?;
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
    let mut seed_hasher = blake2::Blake2b512::new();
    use blake2::Digest;
    seed_hasher.update(b"TBBS+_BASE_OT_SEED_v1");
    seed_hasher.update(cred_name.as_bytes());
    seed_hasher.update(total.to_be_bytes());
    seed_hasher.update(KAPPA.to_be_bytes());
    seed_hasher.update(STATISTICAL_SECURITY_PARAMETER.to_be_bytes());
    let seed_bytes = seed_hasher.finalize();
    let mut seed_arr = [0u8; 8];
    seed_arr.copy_from_slice(&seed_bytes[..8]);
    let shared_seed = u64::from_be_bytes(seed_arr);
    let mut rng = StdRng::seed_from_u64(shared_seed);
    let party_set = (1..=total).collect::<BTreeSet<_>>();
    let base_ot = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(&mut rng, ote.num_base_ot(), total, party_set);
    println!(
        "[base-ot] PID={} init ok: num_base_ot={}, shared_seed=0x{:016x}",
        participant_id,
        ote.num_base_ot(),
        shared_seed
    );

    // --- Listen to SigReqBBSPlus events ---
    use ethers::types::BlockNumber;
    // Subscribe from the next block after we connect, to ensure all issuers
    // are listening before the client emits a new event (avoids race).
    let current_block_u64 = client.provider().get_block_number().await?.as_u64();
    let from_block = BlockNumber::Number(((current_block_u64 + 1) as u64).into());
    let event_builder = req
        .event::<request_credential::SigReqBBSPlusFilter>()
        .from_block(from_block);
    let mut stream = event_builder.stream().await?;
    println!(
        "issuer_onchain PID={} listening for SigReqBBSPlus from block {}...",
        participant_id,
        current_block_u64 + 1
    );

    // Avoid processing the same sid more than once in this run
    let mut processed_sids: HashSet<u64> = HashSet::new();

    while let Some(ev) = stream.next().await {
        let ev = ev?;
        let sid = ev.sid.as_u64();
        // Note: `name` is indexed in the event and comes as a topic hash (H256), not the raw string.
        // We don't gate on name to avoid topic/string mismatch; we dedup purely by sid.
        if processed_sids.contains(&sid) {
            // Already processed in this run
            continue;
        }
    println!("[event] SigReqBBSPlus: sid={}", sid);
    // Parse commitment and PoK from event
    let commitment_bytes: Vec<u8> = ev.commitment_b.to_vec();
    let mut cr = &commitment_bytes[..];
    let commitment: <Bls12_381 as ark_ec::pairing::Pairing>::G1Affine = CanonicalDeserialize::deserialize_compressed(&mut cr)?;
    let proof_bytes: Vec<u8> = ev.proof.to_vec();
    // We'll verify Schnorr PoK over generalized Pedersen relation using Blake2b512
    // Verify PoK using the same params used for signing
    let pok_res = verify_commitment_pok(
        &params,
        &commitment,
        sid,
        &cred_name,
        &ev.revealed_idx,
        &ev.revealed_vals,
        ev.context.as_ref(),
        proof_bytes.as_slice(),
    );
    match pok_res {
        Ok(()) => {
            println!(
                "[pok] PID={} sid={} OK (revealed={}, ctx_len={})",
                participant_id,
                sid,
                ev.revealed_idx.len(),
                ev.context.len()
            );
        }
        Err(e) => {
            eprintln!(
                "[pok] PID={} sid={} FAILED: {} — skipping event",
                participant_id, sid, e
            );
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
        let mut prng = StdRng::seed_from_u64(42 + participant_id as u64 * 1000 + sid);
    let (mut p1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs_plus::<_, Blake2b512>(
            &mut prng,
            1,
            participant_id,
            others.clone(),
            protocol_id.clone(),
    )
    .map_err(|e| anyhow::anyhow!("phase1 init failed: {:?}", e))?;

        // Broadcast our commitment along with our libp2p peer id for mapping
        println!(
            "[phase1] PID={} sid={} broadcasting commitments to peers {:?}",
            participant_id, sid, others
        );
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
                                println!("[phase1] PID={} sid={} received commitment from {}", participant_id, sid, from);
                            }
                            None => {
                                eprintln!("[phase1] PID={} sid={} missing zero_commitment for me from {}; skipping for now", participant_id, sid, from);
                            }
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
            eprintln!(
                "[phase1] PID={} sid={} timed out waiting for commitments: got {:?}",
                participant_id, sid, commitments_got
            );
        }

        // Broadcast our shares to others
        println!(
            "[phase1] PID={} sid={} broadcasting shares to: {:?}",
            participant_id, sid, others
        );
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
                        println!("[phase1] PID={} sid={} received shares from {}", participant_id, sid, from);
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
            eprintln!(
                "[phase1] PID={} sid={} timed out waiting for shares: got {:?}",
                participant_id, sid, shares_got
            );
        }

        // Finalize Phase 1 for our participant
        let phase1_output = p1
            .finish_for_bbs_plus::<blake2::Blake2b512>(&key_shares[(participant_id - 1) as usize])
            .map_err(|e| anyhow::anyhow!("phase1 finish failed for PID={} sid={}: {:?}", participant_id, sid, e))?;

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
        let mut r = StdRng::seed_from_u64(42 + participant_id as u64 * 2000 + sid);
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
                        eprintln!(
                            "[direct] send R1 {}->{} retry {}: {:?}",
                            participant_id, to, attempts, e
                        );
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
                                    "[phase2] PID={} sid={} recv1 from {} failed: {:?}",
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
                                        eprintln!(
                                            "[direct] send R2 {}->{} retry {}: {:?}",
                                            participant_id, from, attempts, e
                                        );
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
                                .map_err(|e| anyhow::anyhow!(
                                    "[phase2] PID={} sid={} recv2 from {} failed: {:?}",
                                    participant_id, sid, from, e
                                ))?;
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

    // Create our signature share using blind commitment: uncommitted messages are revealed pairs
    let mut tmp_pairs: Vec<(usize, Fr)> = Vec::new();
    let mut sid_ok = false;
    for (i, v) in ev.revealed_idx.iter().zip(ev.revealed_vals.iter()) {
        let idx = (*i) as usize;
        if idx == 0 { sid_ok = true; }
        tmp_pairs.push((idx, u256_to_fr::<Fr>(v)));
    }
    if !sid_ok { tmp_pairs.push((0usize, Fr::from(sid))); }
    let mut values_store: Vec<Fr> = tmp_pairs.iter().map(|(_, fr)| fr.clone()).collect();
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
            &params,
    )
    .map_err(|e| anyhow::anyhow!("create signature share (blind) failed: {:?}", e))?;
        let mut payload_vec = Vec::new();
        share.serialize_compressed(&mut payload_vec)?;

        // Submit partial share
        let mut method = relay.submit_partial_share(
            cred_name.clone(),
            sid.into(),
            participant_id,
            payload_vec.into(),
        );
        // For local anvil, ensure gas price is set (some providers might return 0)
        if ws_url.contains("127.0.0.1") || ws_url.contains("localhost") {
            method = method.gas_price(U256::from(1_000_000_000u64)); // 1 gwei
        }
        let send_res = method.send().await;
        match send_res {
            Ok(pend) => {
                let rcpt = pend.await?.ok_or_else(|| anyhow::anyhow!("no receipt"))?;
                println!("submitted partial share: hash={:?}", rcpt.transaction_hash);
                processed_sids.insert(sid);
            }
            Err(e) => {
                // Gracefully handle duplicate submission reverts
                let msg = format!("{:?}", e);
                if msg.contains("dup share") || msg.contains("revert") {
                    eprintln!("duplicate or reverted share for sid {}: {}", sid, msg);
                    processed_sids.insert(sid);
                } else {
                    return Err(anyhow::anyhow!("submit_partial_share failed: {}", msg));
                }
            }
        }
    }

    Ok(())
}

fn u256_to_fr<F: ark_ff::PrimeField>(v: &U256) -> F {
    let mut be = [0u8; 32];
    v.to_big_endian(&mut be);
    F::from_be_bytes_mod_order(&be)
}

fn verify_commitment_pok(
    params: &SignatureParamsG1<Bls12_381>,
    commitment: &<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine,
    sid: u64,
    cred_name: &str,
    revealed_idx: &Vec<u32>,
    revealed_vals: &Vec<U256>,
    context: &[u8],
    proof: &[u8],
) -> anyhow::Result<()> {
    use blake2::Blake2b512;
    use schnorr_pok::pok_generalized_pedersen::{SchnorrResponse, compute_random_oracle_challenge};
    // Decode proof: hidden_len || hidden_indices || t || c || rlen || responses
    let mut rdr = std::io::Cursor::new(proof);
    let mut u32buf = [0u8; 4];
    if rdr.read_exact(&mut u32buf).is_err() { anyhow::bail!("proof too short"); }
    let hidden_len = u32::from_be_bytes(u32buf) as usize;
    let mut hidden_indices = Vec::with_capacity(hidden_len);
    for _ in 0..hidden_len { rdr.read_exact(&mut u32buf)?; hidden_indices.push(u32::from_be_bytes(u32buf) as usize); }
    let t: <Bls12_381 as ark_ec::pairing::Pairing>::G1Affine = CanonicalDeserialize::deserialize_compressed(&mut rdr)?;
    let c: Fr = CanonicalDeserialize::deserialize_compressed(&mut rdr)?;
    rdr.read_exact(&mut u32buf)?;
    let rlen = u32::from_be_bytes(u32buf) as usize;
    let mut responses = Vec::with_capacity(rlen);
    for _ in 0..rlen { let rj: Fr = CanonicalDeserialize::deserialize_compressed(&mut rdr)?; responses.push(rj); }
    // Build bases and y
    let mut bases = Vec::with_capacity(1 + hidden_len);
    bases.push(params.h_0);
    for i in hidden_indices.iter() { bases.push(params.h[*i]); }
    let y = *commitment;
    let resp = SchnorrResponse::<ark_bls12_381::G1Affine>(responses);
    // Recompute challenge transcript
    let mut chal_bytes = Vec::new();
    chal_bytes.extend_from_slice(b"TBBS+_Blind_PoK_v1");
    chal_bytes.extend_from_slice(&sid.to_be_bytes());
    chal_bytes.extend_from_slice(&(params.h.len() as u64).to_be_bytes());
    chal_bytes.extend_from_slice(cred_name.as_bytes());
    let mut pairs: Vec<(u32, &U256)> = revealed_idx.iter().cloned().zip(revealed_vals.iter()).collect();
    pairs.sort_by_key(|(i, _)| *i);
    for (i, v) in pairs.into_iter() { chal_bytes.extend_from_slice(&i.to_be_bytes()); let mut be=[0u8;32]; v.to_big_endian(&mut be); chal_bytes.extend_from_slice(&be); }
    for i in hidden_indices.iter() { let i_u32 = *i as u32; chal_bytes.extend_from_slice(&i_u32.to_be_bytes()); }
    commitment.serialize_compressed(&mut chal_bytes)?;
    // commitment t
    t.serialize_compressed(&mut chal_bytes)?;
    chal_bytes.extend_from_slice(context);
    let c_check: Fr = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
    if c != c_check { anyhow::bail!("commitment PoK challenge mismatch"); }
    // Verify Schnorr relation
    resp.is_valid(&bases, &y, &t, &c).map_err(|e| anyhow::anyhow!("invalid PoK: {:?}", e))
}
