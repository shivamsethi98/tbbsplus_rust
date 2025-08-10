#[cfg(feature = "mpc")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use bbs_plus::prelude::*;
    use libp2p::Multiaddr;
    use std::collections::BTreeSet;
    use tokio::time::{sleep, Duration};
    
    use tbbsplus_rust::orchestration::{
        mesh::p2p::Mesh,
        threshold_phases::{
            ThresholdMessage, Phase1Message, Phase2Message,
            aggregate_signature_shares, BASE_OT_KEY_SIZE,
        },
        threshold_robust::{RobustPhase1Coordinator, RobustPhase2Coordinator},
    };
    use bbs_plus::threshold::threshold_bbs_plus::BBSPlusSignatureShare;
    use oblivious_transfer_protocols::ot_based_multiplication::{
        dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::GadgetVector,
    };
    use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
    use test_utils::ot::do_pairwise_base_ot;
    use blake2::Blake2b512;

    println!("🚀 Robust Threshold BBS+ with Mesh Network Demo");
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
    
    // Simulate trusted key generation (in practice, use DKG)
    let (secret_key, key_shares) = {
        let (secret, shares, _) = deal_random_secret(&mut master_rng, THRESHOLD, TOTAL)
            .map_err(|e| anyhow::anyhow!("deal_random_secret failed: {:?}", e))?;
        (secret, shares.0.into_iter().map(|s| s.share).collect::<Vec<_>>())
    };
    
    let public_key = PublicKeyG2::generate_using_secret_key(&SecretKey(secret_key), &params);
    println!("  ✓ Generated threshold keypair with {} shares", key_shares.len());

    // Step 2: Setup base OT (one-time setup)
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

    // Step 3: Setup mesh network
    println!("\n🌐 Step 3: Setup Mesh Network");
    
    // Create mesh nodes for each participant
    let base_port = 9600; // Different port to avoid conflicts
    let mut meshes = Vec::new();
    let mut subs_phase1 = Vec::new();
    let mut subs_phase2 = Vec::new();
    
    // Create separate RNGs for each participant
    let mut participant_rngs: Vec<StdRng> = Vec::new();
    for i in 1..=TOTAL {
        participant_rngs.push(StdRng::seed_from_u64(42 + i as u64 * 1000));
    }
    
    // Create robust coordinators for each participant
    let mut phase1_coordinators = Vec::new();
    let mut phase2_coordinators = Vec::new();
    let protocol_id = b"threshold-bbs-robust-demo".to_vec();
    
    // Create all mesh nodes and subscribe to topics
    for i in 1..=TOTAL {
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", base_port + i - 1).parse()?;
        let mut mesh = Mesh::new(Some(addr.clone())).await?;
        
        // Subscribe to topics before running in background
        let sub1 = mesh.subscribe::<ThresholdMessage>("threshold-phase1").await?;
        let sub2 = mesh.subscribe::<ThresholdMessage>("threshold-phase2").await?;
        let _sub3 = mesh.subscribe::<ThresholdMessage>("threshold-signatures").await?;
        
        // Run mesh in background to get handle
        let handle = mesh.run_background();
        
        // Create Phase 1 coordinator
        let mut p1_coord = RobustPhase1Coordinator::new(
            i,
            THRESHOLD,
            TOTAL,
            BATCH_SIZE,
            protocol_id.clone(),
        );
        p1_coord.set_mesh_handle(handle.clone());
        
        // Create Phase 2 coordinator
        let participant_set: BTreeSet<_> = (1..=THRESHOLD).collect();
        let mut p2_coord = RobustPhase2Coordinator::new(i, participant_set);
        p2_coord.set_mesh_handle(handle.clone());
        
        meshes.push(handle);
        phase1_coordinators.push(p1_coord);
        phase2_coordinators.push(p2_coord);
        subs_phase1.push(sub1);
        subs_phase2.push(sub2);
        
        println!("  ✓ Node {} listening on {}", i, addr);
    }
    
    // Connect mesh nodes using handles
    println!("\n🔄 Connecting Mesh Nodes");
    for i in 2..=TOTAL {
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", base_port).parse()?;
        meshes[(i - 1) as usize].dial(addr).await?;
    }
    
    // Wait for connections to establish
    println!("\n📡 Waiting for peer connections...");
    for (i, handle) in meshes.iter().enumerate() {
        if i > 0 {  // First node doesn't need to wait
            handle.await_peers(1).await?;
            println!("  ✓ Node {} connected to peers", i + 1);
        }
    }
    
    // Give mesh time to stabilize
    sleep(Duration::from_millis(500)).await;

    // Helper: process messages for all nodes
    async fn process_all_messages(
        phase1_coordinators: &mut [RobustPhase1Coordinator],
        phase2_coordinators: &mut [RobustPhase2Coordinator],
        subs_phase1: &mut [tokio::sync::mpsc::Receiver<ThresholdMessage>],
        subs_phase2: &mut [tokio::sync::mpsc::Receiver<ThresholdMessage>],
        gadget_vector: &GadgetVector<Fr, 256, 80>,
        duration: Duration,
    ) -> anyhow::Result<()> {
        let start = tokio::time::Instant::now();
        let mut message_count = 0;
        
        while start.elapsed() < duration {
            for i in 0..phase1_coordinators.len() {
                // Process Phase 1 messages
                while let Ok(msg) = subs_phase1[i].try_recv() {
                    message_count += 1;
                    match msg {
                        ThresholdMessage::Phase1(p1_msg) => {
                            match &p1_msg {
                                Phase1Message::Commitment { .. } => {
                                    phase1_coordinators[i].store_commitment(p1_msg)?;
                                }
                                Phase1Message::ShareExchange { .. } => {
                                    phase1_coordinators[i].store_share(p1_msg)?;
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                
                // Process Phase 2 messages
                while let Ok(msg) = subs_phase2[i].try_recv() {
                    message_count += 1;
                    match msg {
                        ThresholdMessage::Phase2(p2_msg) => {
                            match &p2_msg {
                                Phase2Message::Round1 { from, to, .. } => {
                                    println!("[Node {}] Received Phase2 Round1 from {} to {}", i + 1, from, to);
                                    phase2_coordinators[i].store_round1(p2_msg, gadget_vector).await?;
                                }
                                Phase2Message::Round2 { from, to, .. } => {
                                    println!("[Node {}] Received Phase2 Round2 from {} to {}", i + 1, from, to);
                                    phase2_coordinators[i].store_round2(p2_msg, gadget_vector)?;
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
            }
            
            if message_count > 0 {
                println!("    Processed {} messages", message_count);
                message_count = 0;
            }
            
            sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }

    // Step 4: Execute Phase 1
    println!("\n🎯 Step 4: Phase 1 - Randomness Generation");
    
    // Initialize Phase 1 for threshold participants
    for i in 0..THRESHOLD as usize {
        phase1_coordinators[i].initialize(&mut participant_rngs[i]).await?;
        println!("  ✓ Node {} initialized Phase 1", i + 1);
    }
    
    // Process commitment messages
    println!("  ⏳ Exchanging commitments...");
    process_all_messages(
        &mut phase1_coordinators,
        &mut phase2_coordinators,
        &mut subs_phase1,
        &mut subs_phase2,
        &gadget_vector,
        Duration::from_secs(2),
    ).await?;
    
    // Check if all commitments received
    for i in 0..THRESHOLD as usize {
        if phase1_coordinators[i].all_commitments_received() {
            println!("  ✓ Node {} received all commitments", i + 1);
        }
    }
    
    // Send shares
    println!("  ⏳ Sending shares...");
    for i in 0..THRESHOLD as usize {
        phase1_coordinators[i].send_shares().await?;
        println!("  ✓ Node {} sent shares", i + 1);
    }
    
    // Process share messages
    println!("  ⏳ Processing shares...");
    process_all_messages(
        &mut phase1_coordinators,
        &mut phase2_coordinators,
        &mut subs_phase1,
        &mut subs_phase2,
        &gadget_vector,
        Duration::from_secs(2),
    ).await?;
    
    // Check readiness and finalize Phase 1
    let mut phase1_outputs = Vec::new();
    for i in 0..THRESHOLD as usize {
        if phase1_coordinators[i].is_ready() {
            let output = phase1_coordinators[i].finalize(&key_shares[i])?;
            phase1_outputs.push(output);
            println!("  ✓ Node {} completed Phase 1", i + 1);
        } else {
            return Err(anyhow::anyhow!("Node {} not ready for Phase 1 finalization", i + 1));
        }
    }

    // Step 5: Execute Phase 2
    println!("\n🔄 Step 5: Phase 2 - Multiplication Protocol");
    
    // Initialize Phase 2 for threshold participants
    for i in 0..THRESHOLD as usize {
        phase2_coordinators[i].initialize(
            &mut participant_rngs[i],
            &phase1_outputs[i],
            base_ot_outputs[i].clone(),
            ote_params,
            &gadget_vector,
        ).await?;
        println!("  ✓ Node {} initialized Phase 2 (sent round 1 messages)", i + 1);
    }
    
    // Process Phase 2 messages (both rounds)
    println!("  ⏳ Executing multiplication protocol...");
    
    // Process both round 1 and round 2 messages in one go
    // The robust coordinator handles message ordering internally
    process_all_messages(
        &mut phase1_coordinators,
        &mut phase2_coordinators,
        &mut subs_phase1,
        &mut subs_phase2,
        &gadget_vector,
        Duration::from_secs(5),  // Allow time for both rounds to complete
    ).await?;
    
    // Check readiness and finalize Phase 2
    let mut phase2_outputs = Vec::new();
    for i in 0..THRESHOLD as usize {
        if phase2_coordinators[i].is_ready() {
            let output = phase2_coordinators[i].finalize()?;
            phase2_outputs.push(output);
            println!("  ✓ Node {} completed Phase 2", i + 1);
        } else {
            // Debug: show what's missing
            let coord = &phase2_coordinators[i];
            let expected = coord.participant_set.len() - 1;
            println!("  ❌ Node {} not ready:", i + 1);
            println!("     Round 1 processed: {}/{}", coord.round1_processed.len(), expected);
            println!("     Round 2 processed: {}/{}", coord.round2_processed.len(), expected);
            println!("     Round 1 received: {:?}", coord.round1_received.keys().collect::<Vec<_>>());
            println!("     Round 2 received: {:?}", coord.round2_received.keys().collect::<Vec<_>>());
            return Err(anyhow::anyhow!("Node {} not ready for Phase 2 finalization", i + 1));
        }
    }

    // Step 6: Generate signature shares
    println!("\n✍️ Step 6: Generate Signature Shares");
    let messages: Vec<Fr> = (0..MESSAGE_COUNT)
        .map(|i| Fr::from(100 + i as u64))
        .collect();
    
    println!("  Messages to sign:");
    for (i, msg) in messages.iter().enumerate() {
        println!("    [{}] {}", i, msg);
    }
    
    let mut signature_shares = Vec::new();
    
    for i in 0..THRESHOLD as usize {
        let share = BBSPlusSignatureShare::new(
            &messages,
            0, // sig_index_in_batch
            &phase1_outputs[i],
            &phase2_outputs[i],
            &params,
        ).map_err(|e| anyhow::anyhow!("create signature share failed: {:?}", e))?;
        
        signature_shares.push(share);
        println!("  ✓ Node {} generated signature share", i + 1);
    }

    // Step 7: Aggregate signature shares
    println!("\n🔗 Step 7: Aggregate Signature Shares");
    let signature = aggregate_signature_shares(signature_shares)?;
    println!("  ✓ Aggregated {} signature shares", THRESHOLD);

    // Step 8: Verify the signature
    println!("\n🔍 Step 8: Verify Threshold Signature");
    
    // Debug: Print signature components
    println!("  Debug - Signature components:");
    println!("    A: {:?}", signature.A);
    println!("    e: {:?}", signature.e);
    println!("    s: {:?}", signature.s);
    
    match signature.verify(&messages, public_key.clone(), params.clone()) {
        Ok(_) => {
            println!("  ✅ Threshold signature is VALID!");
            println!("\n🎉 Demo Complete! Robust message handling successful!");
        }
        Err(e) => {
            println!("  ❌ Verification failed: {:?}", e);
            
            // Additional debugging
            println!("\n  Debug - Phase 1 outputs consistency:");
            for i in 0..THRESHOLD as usize {
                println!("    Node {} e[0]: {:?}", i + 1, phase1_outputs[i].e[0]);
                println!("    Node {} s[0]: {:?}", i + 1, phase1_outputs[i].s[0]);
            }
            
            return Err(anyhow::anyhow!("Signature verification failed"));
        }
    }

    Ok(())
}

#[cfg(not(feature = "mpc"))]
fn main() {
    eprintln!("This demo requires the 'mpc' feature to be enabled.");
    eprintln!("Try: cargo run --features mpc --bin threshold_mesh_robust");
}
