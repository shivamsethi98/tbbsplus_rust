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
        mesh_v2_simple::p2p::{Mesh, MeshHandle},
        threshold_coordinator::ThresholdCoordinator,
        threshold_phases::{aggregate_signature_shares, BASE_OT_KEY_SIZE},
    };
    use oblivious_transfer_protocols::ot_based_multiplication::{
        dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::GadgetVector,
    };
    use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
    use test_utils::ot::do_pairwise_base_ot;
    use blake2::Blake2b512;

    println!("🚀 Complete Threshold BBS+ Signing Demo");
    println!("========================================\n");

    // Configuration
    const THRESHOLD: u16 = 3;
    const TOTAL: u16 = 4;
    const MESSAGE_COUNT: u32 = 5;
    const BATCH_SIZE: u32 = 1;
    const KAPPA: u16 = 256;
    const STATISTICAL_SECURITY_PARAMETER: u16 = 80;

    let mut master_rng = StdRng::seed_from_u64(42);

    // Step 1: Setup cryptographic parameters
    println!("📋 Step 1: Setup Cryptographic Parameters");
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut master_rng, MESSAGE_COUNT);
    
    // Simulate trusted key generation (in practice, use DKG)
    let (secret_key, key_shares) = {
        let (secret, shares, _) = deal_random_secret(&mut master_rng, THRESHOLD, TOTAL)?;
        (secret, shares.0.into_iter().map(|s| s.share).collect::<Vec<_>>())
    };
    
    let public_key = PublicKeyG2::generate_using_secret_key(&SecretKey(secret_key), &params);
    println!("  ✓ Generated threshold keypair");
    println!("  ✓ Threshold: {}/{}", THRESHOLD, TOTAL);

    // Step 2: Setup base OT for Phase 2
    println!("\n🔗 Step 2: Setup Base Oblivious Transfer");
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
    println!("  ✓ Completed pairwise base OT setup");

    // Step 3: Setup network infrastructure
    println!("\n🌐 Step 3: Setup Network Infrastructure");
    
    let base_port = 9800;
    let bootstrap_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", base_port).parse()?;
    
    // Create network nodes and coordinators
    let mut coordinators = Vec::new();
    let mut handles = Vec::new();
    
    for i in 1..=TOTAL {
        let listen_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", base_port + i - 1).parse()?;
        
        // Bootstrap peers (everyone connects to node 1)
        let bootstrap_peers = if i == 1 {
            vec![]
        } else {
            vec![(1u16, bootstrap_addr.clone())]
        };
        
        // Create mesh node
        let mut mesh = Mesh::new(i, Some(listen_addr.clone()), bootstrap_peers).await?;
        
        // Subscribe to protocol topics
        let commitment_rx = mesh.subscribe_broadcast("phase1-commitments").await?;
        let signature_rx = mesh.subscribe_broadcast("signature-shares").await?;
        let direct_rx = mesh.subscribe_direct().await?;
        
        // Get handle for background operation
        let handle = mesh.run_background();
        
        // Create coordinator
        let coordinator = ThresholdCoordinator::new(
            i,
            THRESHOLD,
            TOTAL,
            BATCH_SIZE,
            b"threshold-bbs-demo".to_vec(),
            handle.clone(),
            commitment_rx,  // Will multiplex this for both commitments and signatures
            direct_rx,
        );
        
        coordinators.push(coordinator);
        handles.push(handle);
        
        println!("  ✓ Node {} initialized on {}", i, listen_addr);
    }
    
    // Wait for network to stabilize
    println!("  ⏳ Waiting for network connections...");
    sleep(Duration::from_secs(1)).await;
    println!("  ✓ Network ready");

    // Step 4: Run the protocol in parallel
    println!("\n🎯 Step 4: Execute Threshold Signing Protocol");
    
    // Create tasks for each participant
    let mut tasks = Vec::new();
    
    for i in 0..THRESHOLD as usize {
        let mut coordinator = coordinators.into_iter().nth(i).unwrap();
        let key_share = key_shares[i].clone();
        let base_ot = base_ot_outputs[i].clone();
        let gv = gadget_vector.clone();
        let ote_p = ote_params.clone();
        
        let task = tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(42 + coordinator.id as u64 * 1000);
            
            // Run Phase 1
            coordinator.run_phase1(&mut rng, &key_share).await?;
            
            // Run Phase 2
            coordinator.run_phase2(&mut rng, base_ot, ote_p, &gv).await?;
            
            Ok::<_, anyhow::Error>(coordinator)
        });
        
        tasks.push(task);
    }
    
    // Wait for all participants to complete
    let mut completed_coordinators = Vec::new();
    for task in tasks {
        let coordinator = task.await??;
        println!("  ✓ Node {} completed protocol", coordinator.id);
        completed_coordinators.push(coordinator);
    }

    // Step 5: Generate signature shares
    println!("\n✍️ Step 5: Generate Signature Shares");
    
    // Messages to sign
    let messages: Vec<Fr> = (0..MESSAGE_COUNT)
        .map(|i| Fr::from(100 + i as u64))
        .collect();
    
    println!("  Messages to sign:");
    for (i, msg) in messages.iter().enumerate() {
        println!("    [{}] Field element: {}", i, msg);
    }
    
    let mut signature_shares = Vec::new();
    
    for coordinator in &completed_coordinators {
        let share = coordinator.generate_signature_share(&messages, 0, &params)?;
        signature_shares.push(share);
        println!("  ✓ Node {} generated signature share", coordinator.id);
    }

    // Step 6: Aggregate signature shares
    println!("\n🔗 Step 6: Aggregate Signature Shares");
    let signature = aggregate_signature_shares(signature_shares)?;
    println!("  ✓ Aggregated {} signature shares into final signature", THRESHOLD);

    // Step 7: Verify the threshold signature
    println!("\n🔍 Step 7: Verify Threshold Signature");
    
    println!("  Signature components:");
    println!("    A: {} (G1 element)", if signature.A.is_zero() { "ZERO" } else { "valid" });
    println!("    e: {} (field element)", if signature.e == Fr::from(0) { "ZERO" } else { "valid" });
    println!("    s: {} (field element)", if signature.s == Fr::from(0) { "ZERO" } else { "valid" });
    
    match signature.verify(&messages, public_key.clone(), params.clone()) {
        Ok(_) => {
            println!("\n  ✅ SIGNATURE VERIFICATION SUCCESSFUL!");
            println!("\n🎉 Demo Complete!");
            println!("================");
            println!("  • Threshold {}/{} signing successful", THRESHOLD, TOTAL);
            println!("  • Network: Hybrid broadcast + point-to-point");
            println!("  • Privacy: Shares sent directly, not broadcast");
            println!("  • All {} messages signed correctly", MESSAGE_COUNT);
        }
        Err(e) => {
            println!("\n  ❌ Signature verification failed: {:?}", e);
            return Err(anyhow::anyhow!("Signature verification failed"));
        }
    }
    
    Ok(())
}

#[cfg(not(feature = "mpc"))]
fn main() {
    eprintln!("This demo requires the 'mpc' feature to be enabled.");
    eprintln!("Try: cargo run --features mpc --bin threshold_complete_demo");
}
