#[cfg(feature = "mpc")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
    use bbs_plus::prelude::*;
    use libp2p::Multiaddr;
    use std::collections::{BTreeSet, BTreeMap};
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
        let (secret, shares, _) = deal_random_secret(&mut master_rng, THRESHOLD, TOTAL)?;
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
        
        // Bootstrap peers for nodes 2+ 
        let bootstrap_peers = if i == 1 {
            vec![]
        } else {
            vec![(1u16, bootstrap_addr.clone())]
        };
        
        let mut mesh = Mesh::new(i, Some(listen_addr.clone()), bootstrap_peers).await?;
        
        // Subscribe to broadcast topics
        let _commitment_sub = mesh.subscribe_broadcast("phase1-commitments").await?;
        let _signature_sub = mesh.subscribe_broadcast("signature-shares").await?;
        
        // Subscribe to direct messages
        let _direct_sub = mesh.subscribe_direct().await?;
        
        let handle = mesh.run_background();
        
        handles.push(handle);
        meshes.push(mesh);
        
        println!("  ✓ Node {} listening on {}", i, listen_addr);
    }
    
    // Give mesh time to establish connections
    sleep(Duration::from_secs(1)).await;
    
    // Step 4: Execute Phase 1
    println!("\n🎯 Step 4: Phase 1 - Randomness Generation");
    
    let protocol_id = b"threshold-bbs-demo".to_vec();
    let mut phase1_instances = Vec::new();
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
        )?;
        
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
            "commitment": base64::encode(&comm_bytes),
            "zero_commitments": zero_comms_map.iter()
                .map(|(k, v)| (k.to_string(), base64::encode(v)))
                .collect::<BTreeMap<_, _>>()
        });
        
        handles[i].broadcast("phase1-commitments", serde_json::to_vec(&commitment_msg)?).await?;
        
        phase1_instances.push((participant_id, phase1, others));
        println!("  ✓ Node {} initialized and broadcast commitment", participant_id);
    }
    
    // Process commitments (simplified - in real implementation, would handle async)
    sleep(Duration::from_millis(500)).await;
    
    // Exchange shares directly between peers
    println!("\n  📤 Exchanging shares...");
    for i in 0..THRESHOLD as usize {
        let (from_id, phase1, others) = &phase1_instances[i];
        
        for to_id in others {
            let shares = phase1.get_comm_shares_and_salts();
            let zero_shares = phase1.get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(to_id);
            
            let mut shares_bytes = Vec::new();
            shares.serialize_compressed(&mut shares_bytes)?;
            
            let mut zero_shares_bytes = Vec::new();
            zero_shares.serialize_compressed(&mut zero_shares_bytes)?;
            
            // Send directly to peer
            let share_msg = serde_json::json!({
                "from": from_id,
                "to": to_id,
                "shares": base64::encode(&shares_bytes),
                "zero_shares": base64::encode(&zero_shares_bytes),
            });
            
            handles[i].send_to(*to_id, serde_json::to_vec(&share_msg)?).await?;
        }
        println!("    ✓ Node {} sent shares to peers", from_id);
    }
    
    // Simplified: In real implementation, would process received shares
    sleep(Duration::from_millis(500)).await;
    
    // Finalize Phase 1
    for i in 0..THRESHOLD as usize {
        let (participant_id, phase1, _) = phase1_instances.into_iter().nth(i).unwrap();
        
        // In real implementation: process received commitments and shares here
        // For demo, we skip to finalization
        
        let output = phase1.finish_for_bbs_plus::<Blake2b512>(&key_shares[i])?;
        phase1_outputs.push(output);
        println!("  ✓ Node {} completed Phase 1", participant_id);
    }
    
    // Step 5: Execute Phase 2
    println!("\n🔄 Step 5: Phase 2 - Multiplication Protocol");
    
    let mut phase2_outputs = Vec::new();
    
    for i in 0..THRESHOLD as usize {
        let participant_id = (i + 1) as u16;
        let mut participant_rng = StdRng::seed_from_u64(42 + participant_id as u64 * 2000);
        
        let others: BTreeSet<u16> = phase1_outputs[i].others.iter().cloned().collect();
        
        let (phase2, messages) = Phase2::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::init::<_, Shake256>(
            &mut participant_rng,
            participant_id,
            phase1_outputs[i].masked_signing_key_shares.clone(),
            phase1_outputs[i].masked_rs.clone(),
            base_ot_outputs[i].clone(),
            others.clone(),
            ote_params,
            &gadget_vector,
        )?;
        
        // Send round 1 messages directly to peers
        for (to_id, msg) in &messages {
            let mut msg_bytes = Vec::new();
            msg.serialize_compressed(&mut msg_bytes)?;
            
            let round1_msg = serde_json::json!({
                "from": participant_id,
                "to": to_id,
                "round": 1,
                "data": base64::encode(&msg_bytes),
            });
            
            handles[i].send_to(*to_id, serde_json::to_vec(&round1_msg)?).await?;
        }
        
        println!("  ✓ Node {} sent {} round 1 messages", participant_id, messages.len());
        
        // Simplified: skip round 2 for demo
        phase2_outputs.push(phase2.finish());
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
        )?;
        
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
