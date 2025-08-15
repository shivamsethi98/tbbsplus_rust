#[cfg(feature = "mpc")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
    use bbs_plus::prelude::*;
    use libp2p::{Multiaddr, PeerId};
    use std::{collections::{BTreeSet, BTreeMap}, str::FromStr};
    use tokio::time::{sleep, Duration};
    
    use tbbsplus_rust::orchestration::{
        mesh_v2_simple::p2p::{Mesh, DirectMessage, MeshHandle},
        threshold_phases::{aggregate_signature_shares, BASE_OT_KEY_SIZE},
    };
    use bbs_plus::threshold::{
        threshold_bbs_plus::{BBSPlusSignatureShare, Phase1Output as BBSPhase1Output},
        multiplication_phase::{Phase2, Phase2Output},
        randomness_generation_phase::Phase1,
    };
    use oblivious_transfer_protocols::ot_based_multiplication::{
        dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::GadgetVector,
    };
    use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
    use test_utils::ot::do_pairwise_base_ot;
    use oblivious_transfer_protocols::cointoss::Commitments;
    use serde_json::{self, Value};
    use blake2::Blake2b512;
    use sha3::Shake256;

    println!("🚀 Threshold BBS+ with Hybrid Mesh Network Demo");
    println!("==============================================\n");

    // Configuration
    const THRESHOLD: u16 = 3;
    const TOTAL: u16 = 4;
    const MESSAGE_COUNT: u32 = 5;
    const BATCH_SIZE: u32 = 1;
    const KAPPA: u16 = 256;
    const STATISTICAL_SECURITY_PARAMETER: u16 = 80;

    let mut master_rng = StdRng::seed_from_u64(42);

    // Step 1: Setup parameters
    println!("📋 Step 1: Setup Parameters");
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut master_rng, MESSAGE_COUNT);
    
    // Simulate trusted key generation
    let (secret_key, key_shares) = {
        let (secret, shares, _) = deal_random_secret(&mut master_rng, THRESHOLD, TOTAL)
            .map_err(|e| anyhow::anyhow!("deal_random_secret failed: {:?}", e))?;
        (secret, shares.0.into_iter().map(|s| s.share).collect::<Vec<_>>())
    };
    
    let public_key = PublicKeyG2::generate_using_secret_key(&SecretKey(secret_key), &params);
    println!("  ✓ Generated threshold keypair with {} shares", key_shares.len());

    // Step 2: Setup base OT
    println!("\n🔗 Step 2: Base OT Setup");
    let party_set: BTreeSet<_> = (1..=TOTAL).collect();
    let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
    let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<Blake2b512>(
        ote_params,
        b"threshold-bbs-plus-gadget",
    );
    
    let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
        &mut master_rng,
        ote_params.num_base_ot(),
        TOTAL,
        party_set.clone(),
    );
    println!("  ✓ Completed base OT setup");

    // Step 3: Setup mesh network with new architecture
    println!("\n🌐 Step 3: Setup Hybrid Mesh Network");
    
    let base_port = 9700; // Different port range
    let mut meshes = Vec::new();
    let mut handles = Vec::new();
    
    // Create bootstrap peer list (everyone knows node 1's address)
    let bootstrap_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", base_port).parse()?;
    
    for i in 1..=TOTAL {
        let listen_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", base_port + i - 1).parse()?;
        
        // Proactively dial all other participants (1..=THRESHOLD) so direct channels exist between any pair.
        // This avoids relying solely on hub (node 1) or mDNS timing for 2<->3 connectivity in 3-of-4.
        let mut bootstrap_peers = Vec::new();
        for j in 1..=THRESHOLD {
            if j != i as u16 {
                let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", base_port + j as u16 - 1).parse()?;
                bootstrap_peers.push((j as u16, addr));
            }
        }
        
    let mut mesh = Mesh::new(i, Some(listen_addr.clone()), bootstrap_peers).await?;
    // Subscribe before moving mesh into background
    let commitment_sub = mesh.subscribe_broadcast("phase1-commitments").await?;
    let shares_sub = mesh.subscribe_broadcast("phase1-shares").await?;
    let _signature_sub = mesh.subscribe_broadcast("signature-shares").await?;
    let direct_sub = mesh.subscribe_direct().await?;

    // Capture local_peer_id string before move
    let peer_id_str = mesh.local_peer_id().to_string();
    let handle = mesh.run_background();
        
    handles.push(handle);
    meshes.push((peer_id_str, commitment_sub, shares_sub, direct_sub));
        
        println!("  ✓ Node {} listening on {}", i, listen_addr);
    }
    
    // Give mesh time to establish connections
    sleep(Duration::from_secs(1)).await;
    
    // Step 4: Execute Phase 1
    println!("\n🎯 Step 4: Phase 1 - Randomness Generation");
    
    let protocol_id = b"threshold-bbs-demo".to_vec();
    let mut phase1_instances: Vec<(u16, Phase1<Fr, 256>, BTreeSet<u16>)> = Vec::new();
    let mut phase1_outputs = Vec::new();
    
    // Initialize Phase 1 for threshold participants
    for i in 0..THRESHOLD as usize {
        let participant_id = (i + 1) as u16;
        let mut participant_rng = StdRng::seed_from_u64(42 + participant_id as u64 * 1000);
        
        let mut others = BTreeSet::new();
        for j in 1..=THRESHOLD {
            if j != participant_id {
                others.insert(j);
            }
        }
        
    let (phase1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs_plus::<_, Blake2b512>(
            &mut participant_rng,
            BATCH_SIZE,
            participant_id,
            others.clone(),
            protocol_id.clone(),
    ).map_err(|e| anyhow::anyhow!("phase1 init failed: {:?}", e))?;
        
    // Broadcast commitment
        let mut comm_bytes = Vec::new();
        comm.serialize_compressed(&mut comm_bytes)?;
        
        let mut zero_comms_map = BTreeMap::new();
        for (pid, zc) in comm_zero {
            let mut zc_bytes = Vec::new();
            zc.serialize_compressed(&mut zc_bytes)?;
            zero_comms_map.insert(pid, zc_bytes);
        }
        
        // Create commitment message
        let commitment_msg = serde_json::json!({
            "from": participant_id,
            "peer_id": meshes[i].0.clone(),
            "commitment": base64::encode(&comm_bytes),
            "zero_commitments": zero_comms_map.iter()
                .map(|(k, v)| (k.to_string(), base64::encode(v)))
                .collect::<BTreeMap<_, _>>()
        });
        
        handles[i].broadcast("phase1-commitments", serde_json::to_vec(&commitment_msg)?).await?;
        
        phase1_instances.push((participant_id, phase1, others));
        println!("  ✓ Node {} initialized and broadcast commitment", participant_id);
    }
    
    // Pump commitments from gossipsub until each participant has commitments from all others
    println!("\n  � Receiving commitments (via broadcast)...");
    let mut commitments_got: Vec<BTreeSet<u16>> = vec![BTreeSet::new(); THRESHOLD as usize];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut all_done = true;
        for i in 0..THRESHOLD as usize {
            let (pid, phase1, _others) = &mut phase1_instances[i];
            // drain queue
            loop {
                match meshes[i].1.try_recv() {
                    Ok(bytes) => {
                        let v: Value = serde_json::from_slice(&bytes)?;
                        let from = v["from"].as_u64().unwrap() as u16;
                        if from == *pid { continue; }
                        if let Some(peer_id_str) = v.get("peer_id").and_then(|s| s.as_str()) {
                            let peer_id = PeerId::from_str(peer_id_str)
                                .map_err(|e| anyhow::anyhow!("parse peer id: {:?}", e))?;
                            println!("  [MeshMap] Node {} registering participant {} -> {}", pid, from, peer_id);
                            handles[i].register_peer(from, peer_id).await?;
                        }
                        let commitment_b64 = v["commitment"].as_str().unwrap();
                        let commitment: Commitments = CanonicalDeserialize::deserialize_compressed(
                            &base64::decode(commitment_b64)?[..]
                        ).map_err(|e| anyhow::anyhow!("deserialize commitment: {:?}", e))?;
                        if let Some(zc) = v.get("zero_commitments").and_then(|z| z.get(&pid.to_string())) {
                            let bytes = base64::decode(zc.as_str().unwrap())?;
                            let zc_for_me: Commitments = CanonicalDeserialize::deserialize_compressed(&bytes[..])
                                .map_err(|e| anyhow::anyhow!("deserialize zero commitment: {:?}", e))?;
                            phase1.receive_commitment(from, commitment, zc_for_me)
                                .map_err(|e| anyhow::anyhow!("receive_commitment failed: {:?}", e))?;
                            commitments_got[i].insert(from);
                        }
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(_) => break,
                }
            }
            if commitments_got[i].len() < (THRESHOLD - 1) as usize {
                all_done = false;
            }
        }
        if all_done { break; }
        if tokio::time::Instant::now() > deadline { break; }
        sleep(Duration::from_millis(50)).await;
    }

    // Broadcast shares after all commitments are in
    println!("\n  📤 Exchanging shares (via broadcast)...");
    for i in 0..THRESHOLD as usize {
        let (pid, phase1, others) = &mut phase1_instances[i];
        for to in others.clone() {
            let shares = phase1.get_comm_shares_and_salts();
            let zero_shares = phase1.get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&to);
            let mut shares_bytes = Vec::new();
            shares.serialize_compressed(&mut shares_bytes)?;
            let mut zero_shares_bytes = Vec::new();
            zero_shares.serialize_compressed(&mut zero_shares_bytes)?;
            let share_msg = serde_json::json!({
                "from": pid,
                "to": to,
                "shares": base64::encode(&shares_bytes),
                "zero_shares": base64::encode(&zero_shares_bytes),
            });
            handles[i].broadcast("phase1-shares", serde_json::to_vec(&share_msg)?).await?;
        }
    }
    // Small settle delay to allow broadcast delivery in 3-of-4
    sleep(Duration::from_millis(200)).await;
    // Process incoming shares until each participant has received from all others
    let mut shares_got: Vec<BTreeSet<u16>> = vec![BTreeSet::new(); THRESHOLD as usize];
    let shares_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut all_done = true;
        for i in 0..THRESHOLD as usize {
            let (pid, phase1, _others) = &mut phase1_instances[i];
            loop {
                match meshes[i].2.try_recv() {
                    Ok(bytes) => {
                        let v: serde_json::Value = serde_json::from_slice(&bytes)?;
                        let to = v["to"].as_u64().unwrap() as u16;
                        if to != *pid { continue; }
                        let from = v["from"].as_u64().unwrap() as u16;
                        let shares = base64::decode(v["shares"].as_str().unwrap())?;
                        let zero = base64::decode(v["zero_shares"].as_str().unwrap())?;
                        let shares_data: Vec<(Fr, [u8; 256])> = CanonicalDeserialize::deserialize_compressed(&shares[..])
                            .map_err(|e| anyhow::anyhow!("deserialize shares: {:?}", e))?;
                        let zero_data: Vec<(Fr, [u8; 256])> = CanonicalDeserialize::deserialize_compressed(&zero[..])
                            .map_err(|e| anyhow::anyhow!("deserialize zero shares: {:?}", e))?;
                        phase1.receive_shares::<Blake2b512>(from, shares_data, zero_data)
                            .map_err(|e| anyhow::anyhow!("receive_shares failed: {:?}", e))?;
                        shares_got[i].insert(from);
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(_) => break,
                }
            }
            if shares_got[i].len() < (THRESHOLD - 1) as usize {
                all_done = false;
            }
        }
        if all_done { break; }
        if tokio::time::Instant::now() > shares_deadline { break; }
        sleep(Duration::from_millis(50)).await;
    }
    
    // Finalize Phase 1 (only after each participant reports readiness)
    for i in 0..THRESHOLD as usize {
        let (participant_id, phase1, _) = phase1_instances.remove(0);
        if !phase1.ready_to_compute_randomness_and_arguments_for_multiplication() {
            println!("  ⚠️ Node {} not ready according to Phase1::ready_to_compute...", participant_id);
        }
        let output = phase1.finish_for_bbs_plus::<Blake2b512>(&key_shares[(participant_id - 1) as usize])
            .map_err(|e| anyhow::anyhow!("phase1 finalize failed: {:?}", e))?;
        phase1_outputs.push(output);
        println!("  ✓ Node {} completed Phase 1", participant_id);
    }
    
    // Step 5: Execute Phase 2
    println!("\n🔄 Step 5: Phase 2 - Multiplication Protocol");
    
    let mut phase2_states: Vec<(u16, Phase2<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>, BTreeSet<u16>, BTreeSet<u16>, BTreeSet<u16>, BTreeSet<u16>)> = Vec::new();
    // tuple: (id, phase2, expected_r1_from, expected_r2_from, got_r1_from, got_r2_from)

    for i in 0..THRESHOLD as usize {
        let pid = (i + 1) as u16;
        let mut rng_i = StdRng::seed_from_u64(42 + pid as u64 * 2000);
        let others: BTreeSet<u16> = phase1_outputs[i].others.iter().cloned().collect();
    let (mut phase2, messages) = Phase2::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::init::<_, Shake256>(
            &mut rng_i,
            pid,
            phase1_outputs[i].masked_signing_key_shares.clone(),
            phase1_outputs[i].masked_rs.clone(),
            base_ot_outputs[(pid - 1) as usize].clone(),
            others.clone(),
            ote_params,
            &gadget_vector,
    ).map_err(|e| anyhow::anyhow!("phase2 init failed: {:?}", e))?;
        // compute expectations
        let expected_r1_from: BTreeSet<u16> = others.iter().copied().filter(|peer| *peer < pid).collect();
        let expected_r2_from: BTreeSet<u16> = others.iter().copied().filter(|peer| *peer > pid).collect();
        let got_r1_from = BTreeSet::new();
        let got_r2_from = BTreeSet::new();
        // send round1
        for (to_id, msg) in &messages {
            let mut msg_bytes = Vec::new();
            msg.serialize_compressed(&mut msg_bytes)?;
            println!("  [Direct] send R1 from {} to {}", pid, to_id);
            let round1_msg = serde_json::json!({
                "round": 1,
                "from": pid,
                "to": to_id,
                "data": base64::encode(&msg_bytes),
            });
            // Conservative: retry a few times in case participant->peer mapping isn't ready yet
            let payload = serde_json::to_vec(&round1_msg)?;
            let mut attempts = 0;
            loop {
                attempts += 1;
                match handles[i].send_to(*to_id, payload.clone()).await {
                    Ok(_) => break,
                    Err(e) if attempts < 5 => {
                        println!("    [Direct] send R1 {}->{} pending mapping, retry {}: {:?}", pid, to_id, attempts, e);
                        sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => return Err(anyhow::anyhow!("send R1 {}->{} failed: {:?}", pid, to_id, e)),
                }
            }
        }
        phase2_states.push((pid, phase2, expected_r1_from, expected_r2_from, got_r1_from, got_r2_from));
        println!("  ✓ Node {} sent {} round1 messages", pid, messages.len());
    }

    // Process direct messages until all ready or timeout
    let start = tokio::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        let mut all_ready = true;
        for i in 0..THRESHOLD as usize {
            let (pid, phase2, expected_r1_from, expected_r2_from, got_r1_from, got_r2_from) = &mut phase2_states[i];
            // drain direct inbox
            loop {
                match meshes[i].3.try_recv() {
                    Ok(dm) => {
                        let v: Value = serde_json::from_slice(&dm.data)?;
                        let to = v["to"].as_u64().unwrap() as u16;
                        if to != *pid { continue; }
                        let from = v["from"].as_u64().unwrap() as u16;
                        let round = v["round"].as_u64().unwrap() as u8;
                        let data = base64::decode(v["data"].as_str().unwrap())?;
                        if round == 1 {
                            let msg1 = CanonicalDeserialize::deserialize_compressed(&data[..])
                                .map_err(|e| anyhow::anyhow!("deserialize round1: {:?}", e))?;
                            let msg2 = phase2.receive_message1::<Blake2b512, Shake256>(from, msg1, &gadget_vector)
                                .map_err(|e| anyhow::anyhow!("receive_message1 failed: {:?}", e))?;
                            if expected_r1_from.contains(&from) { got_r1_from.insert(from); }
                            // send round2 back
                            let mut msg2_bytes = Vec::new();
                            msg2.serialize_compressed(&mut msg2_bytes)?;
                            println!("  [Direct] send R2 from {} to {}", pid, from);
                            let round2_msg = serde_json::json!({
                                "round": 2,
                                "from": pid,
                                "to": from,
                                "data": base64::encode(&msg2_bytes),
                            });
                            let payload = serde_json::to_vec(&round2_msg)?;
                            let mut attempts = 0;
                            loop {
                                attempts += 1;
                                match handles[i].send_to(from, payload.clone()).await {
                                    Ok(_) => break,
                                    Err(e) if attempts < 5 => {
                                        println!("    [Direct] send R2 {}->{} pending mapping, retry {}: {:?}", pid, from, attempts, e);
                                        sleep(Duration::from_millis(100)).await;
                                    }
                                    Err(e) => return Err(anyhow::anyhow!("send R2 {}->{} failed: {:?}", pid, from, e)),
                                }
                            }
                        } else if round == 2 {
                            let msg2 = CanonicalDeserialize::deserialize_compressed(&data[..])
                                .map_err(|e| anyhow::anyhow!("deserialize round2: {:?}", e))?;
                            phase2.receive_message2::<Blake2b512>(from, msg2, &gadget_vector)
                                .map_err(|e| anyhow::anyhow!("receive_message2 failed: {:?}", e))?;
                            if expected_r2_from.contains(&from) { got_r2_from.insert(from); }
                        }
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(_) => break,
                }
            }
            if !(got_r1_from.len() == expected_r1_from.len() && got_r2_from.len() == expected_r2_from.len()) {
                all_ready = false;
            }
        }
        if all_ready { break; }
        sleep(Duration::from_millis(50)).await;
    }

    // Debug summary of Phase2 expectations vs receipts
    for i in 0..THRESHOLD as usize {
        let (pid, _p2, expected_r1_from, expected_r2_from, got_r1_from, got_r2_from) = &phase2_states[i];
        println!(
            "  [Phase2 Debug] Node {}: expect R1 {:?} got {:?} | expect R2 {:?} got {:?}",
            pid, expected_r1_from, got_r1_from, expected_r2_from, got_r2_from
        );
    }

    // Finish phase2
    let mut phase2_outputs = Vec::new();
    for i in 0..THRESHOLD as usize {
    let (pid, phase2, ..) = phase2_states.remove(0);
        phase2_outputs.push(phase2.finish());
        println!("  ✓ Node {} completed Phase 2", pid);
    }
    
    // Step 6: Generate and aggregate signature shares
    println!("\n✍️ Step 6: Generate Signature Shares");
    let messages: Vec<Fr> = (0..MESSAGE_COUNT)
        .map(|i| Fr::from(100 + i as u64))
        .collect();
    
    let mut signature_shares = Vec::new();
    
    for i in 0..THRESHOLD as usize {
    let share = BBSPlusSignatureShare::new(
            &messages,
            0,
            &phase1_outputs[i],
            &phase2_outputs[i],
            &params,
    ).map_err(|e| anyhow::anyhow!("create signature share failed: {:?}", e))?;
        
        signature_shares.push(share);
        println!("  ✓ Node {} generated signature share", i + 1);
    }
    
    // Step 7: Aggregate and verify
    println!("\n🔗 Step 7: Aggregate Signature Shares");
    let signature = aggregate_signature_shares(signature_shares)?;
    println!("  ✓ Aggregated {} signature shares", THRESHOLD);
    
    println!("\n🔍 Step 8: Verify Threshold Signature");
    match signature.verify(&messages, public_key.clone(), params.clone()) {
        Ok(_) => {
            println!("  ✅ Threshold signature is VALID!");
            println!("\n🎉 Demo Complete! Hybrid mesh networking successful!");
        }
        Err(e) => {
            println!("  ❌ Verification failed: {:?}", e);
            return Err(anyhow::anyhow!("Signature verification failed"));
        }
    }
    
    Ok(())
}

#[cfg(not(feature = "mpc"))]
fn main() {
    eprintln!("This demo requires the 'mpc' feature to be enabled.");
    eprintln!("Try: cargo run --features mpc --bin threshold_mesh_v2_demo");
}
