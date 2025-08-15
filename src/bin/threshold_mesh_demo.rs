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
            ThresholdSigningOrchestrator, ThresholdMessage,
            aggregate_signature_shares, BASE_OT_KEY_SIZE,
        },
    };
    use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
    use test_utils::ot::do_pairwise_base_ot;

    println!("🚀 Threshold BBS+ with Mesh Network Demo");
    println!("=========================================\n");

    // Configuration
    const THRESHOLD: u16 = 3; // quorum (matching working example)
    const TOTAL: u16 = 4;     // total signers available
    const MESSAGE_COUNT: u32 = 5;
    const BATCH_SIZE: u32 = 1;

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
    let ote_params = oblivious_transfer_protocols::ot_based_multiplication::dkls18_mul_2p::MultiplicationOTEParams::<256, 80> {};
    
    let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
        &mut master_rng,
        ote_params.num_base_ot(),
        TOTAL,
        party_set.clone(),
    );
    println!("  ✓ Completed base OT setup");

    // Step 3: Setup mesh network
    println!("\n🌐 Step 3: Setup Mesh Network");
    
    // Create mesh nodes for each participant (TOTAL)
    let base_port = 9500;
    let mut meshes = Vec::new();
    let mut orchestrators = Vec::new();
    let mut subs_phase1 = Vec::new();
    let mut subs_phase2 = Vec::new();
    
    // Create separate RNGs for each participant
    let mut participant_rngs: Vec<StdRng> = Vec::new();
    for i in 1..=TOTAL {
        // Each participant gets a unique RNG seeded deterministically
        participant_rngs.push(StdRng::seed_from_u64(42 + i as u64 * 1000));
    }
    
    for i in 1..=TOTAL {
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", base_port + i - 1).parse()?;
    let mut mesh = Mesh::new(Some(addr.clone())).await?;
        
    // Subscribe to all relevant topics
    let sub1 = mesh.subscribe::<ThresholdMessage>("threshold-phase1").await?;
    let sub2 = mesh.subscribe::<ThresholdMessage>("threshold-phase2").await?;
    let _sub3 = mesh.subscribe::<ThresholdMessage>("threshold-signatures").await?;
        
        let handle = mesh.run_background();
        
        // Create orchestrator for this participant
    let mut orchestrator = ThresholdSigningOrchestrator::new(
            i,
            THRESHOLD,
            TOTAL,
            key_shares[(i - 1) as usize].clone(),
        );
        orchestrator.set_base_ot(base_ot_outputs[(i - 1) as usize].clone());
        orchestrator.set_mesh_handle(handle.clone());
        
    meshes.push(handle);
        orchestrators.push(orchestrator);
    subs_phase1.push(sub1);
    subs_phase2.push(sub2);
        
        println!("  ✓ Node {} listening on {}", i, addr);
    }
    
    // Connect mesh nodes
    println!("\n🔄 Connecting Mesh Nodes");
    for i in 2..=TOTAL {
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", base_port).parse()?;
        meshes[(i - 1) as usize].dial(addr).await?;
    }
    
    // Wait for mesh to establish
    for (i, mesh) in meshes.iter().enumerate() {
        mesh.await_peers(1).await?;
        println!("  ✓ Node {} connected to peers", i + 1);
    }
    
    sleep(Duration::from_millis(500)).await;

    // Helper: pump messages from mesh into orchestrators for a short duration
    async fn pump_messages(
        orchestrators: &mut [ThresholdSigningOrchestrator],
        subs_phase1: &mut [tokio::sync::mpsc::Receiver<ThresholdMessage>],
        subs_phase2: &mut [tokio::sync::mpsc::Receiver<ThresholdMessage>],
        duration: Duration,
    ) -> anyhow::Result<()> {
        let start = tokio::time::Instant::now();
        while start.elapsed() < duration {
            for (i, orch) in orchestrators.iter_mut().enumerate() {
                // Phase 1 messages
                loop {
                    match subs_phase1[i].try_recv() {
                        Ok(m) => orch.process_message(m).await?,
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                // Phase 2 messages
                loop {
                    match subs_phase2[i].try_recv() {
                        Ok(m) => orch.process_message(m).await?,
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }

    // Step 4: Execute Phase 1
    println!("\n🎯 Step 4: Phase 1 - Randomness Generation");
    let protocol_id = b"threshold-bbs-demo".to_vec();
    
    // All participants start Phase 1
    // Only first THRESHOLD participants engage in this signing session
    for i in 0..THRESHOLD as usize {
        orchestrators[i].start_phase1(&mut participant_rngs[i], BATCH_SIZE, protocol_id.clone()).await?;
        println!("  ✓ Node {} initiated Phase 1", i + 1);
    }
    
    // Let commitments propagate
    println!("  ⏳ Exchanging commitments...");
    pump_messages(&mut orchestrators, &mut subs_phase1, &mut subs_phase2, Duration::from_secs(2)).await?;
    // Have each participant send shares to others
    for i in 0..THRESHOLD as usize {
        orchestrators[i].phase1_send_shares().await?;
    }
    // Let shares propagate
    println!("  ⏳ Exchanging shares...");
    pump_messages(&mut orchestrators, &mut subs_phase1, &mut subs_phase2, Duration::from_secs(2)).await?;
    
    // Wait until all orchestrators report ready
    let ready_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let all_ready = orchestrators.iter().take(THRESHOLD as usize).all(|o| o.phase1_ready());
        if all_ready { break; }
        if tokio::time::Instant::now() > ready_deadline { break; }
        pump_messages(&mut orchestrators, &mut subs_phase1, &mut subs_phase2, Duration::from_millis(200)).await?;
    }
    // Complete Phase 1
    let mut phase1_outputs = Vec::new();
    for i in 0..THRESHOLD as usize {
        let output = orchestrators[i].complete_phase1()?;
        phase1_outputs.push(output);
        println!("  ✓ Node {} completed Phase 1", i + 1);
    }

    // Step 5: Execute Phase 2
    println!("\n🔄 Step 5: Phase 2 - Multiplication Protocol");
    
    // All participants start Phase 2
    for i in 0..THRESHOLD as usize {
        orchestrators[i].start_phase2(&mut participant_rngs[i], &phase1_outputs[i]).await?;
        println!("  ✓ Node {} initiated Phase 2", i + 1);
    }
    
    // Pump until all participants are ready to finalize Phase 2 (or timeout)
    println!("  ⏳ Executing multiplication protocol...");
    let ready_deadline_p2 = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let all_ready = orchestrators
            .iter()
            .take(THRESHOLD as usize)
            .all(|o| o.phase2_ready());
        if all_ready { break; }
        if tokio::time::Instant::now() > ready_deadline_p2 { break; }
        pump_messages(&mut orchestrators, &mut subs_phase1, &mut subs_phase2, Duration::from_millis(200)).await?;
    }

    // Complete Phase 2
    let mut phase2_outputs = Vec::new();
    for i in 0..THRESHOLD as usize {
        let output = orchestrators[i].complete_phase2()?;
        phase2_outputs.push(output);
        println!("  ✓ Node {} completed Phase 2", i + 1);
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
    
    let session_id = 1001u64;
    let mut signature_shares = Vec::new();
    
    for i in 0..THRESHOLD as usize {
        let share = orchestrators[i].generate_signature_share(
            &messages,
            0, // sig_index_in_batch
            &phase1_outputs[i],
            &phase2_outputs[i],
            &params,
            session_id,
        ).await?;
        
        signature_shares.push(share);
        println!("  ✓ Node {} generated signature share", i + 1);
    }

    // Step 7: Aggregate signature shares
    println!("\n🔗 Step 7: Aggregate Signature Shares");
    let signature = aggregate_signature_shares(signature_shares)?;
    println!("  ✓ Aggregated {} signature shares", THRESHOLD);

    // Step 8: Verify the signature
    println!("\n🔍 Step 8: Verify Threshold Signature");
    signature
        .verify(&messages, public_key, params)
        .map_err(|e| anyhow::anyhow!("verify failed: {:?}", e))?;
    println!("  ✅ Threshold signature is VALID!");

    // Summary
    println!("\n🎉 Demo Complete!");
    println!("\n📊 Summary:");
    println!("  • Threshold: {} of {} participants", THRESHOLD, TOTAL);
    println!("  • Messages signed: {}", MESSAGE_COUNT);
    println!("  • Network: P2P mesh using libp2p gossipsub");
    println!("  • Phases completed:");
    println!("    - Phase 1: Randomness generation");
    println!("    - Phase 2: MPC multiplication");
    println!("    - Signature share generation and aggregation");
    println!("\n💡 Next Steps:");
    println!("  • Integrate with smart contracts for coordination");
    println!("  • Add fault tolerance and recovery mechanisms");
    println!("  • Implement selective disclosure proofs");
    println!("  • Scale to larger threshold configurations");

    Ok(())
}

#[cfg(not(feature = "mpc"))]
fn main() {
    eprintln!("This demo requires the 'mpc' feature to be enabled.");
    eprintln!("Try: cargo run --features mpc --bin threshold_mesh_demo");
}
