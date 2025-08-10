#[cfg(feature = "mpc")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use bbs_plus::prelude::*;
    use std::collections::BTreeSet;
    
    use bbs_plus::threshold::{
        threshold_bbs_plus::{BBSPlusSignatureShare, Phase1Output},
        multiplication_phase::{Phase2, Phase2Output},
        randomness_generation_phase::Phase1,
        ParticipantId,
    };
    use blake2::Blake2b512;
    use oblivious_transfer_protocols::ot_based_multiplication::{
        dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::GadgetVector,
    };
    use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
    use sha3::Shake256;
    use test_utils::ot::do_pairwise_base_ot;

    println!("🧪 Threshold BBS+ Debug Test");
    println!("============================\n");

    // Configuration - matching the working example exactly
    const THRESHOLD: u16 = 3;
    const TOTAL: u16 = 4;
    const MESSAGE_COUNT: u32 = 5;
    const BATCH_SIZE: u32 = 1;
    const BASE_OT_KEY_SIZE: u16 = 128;
    const KAPPA: u16 = 256;
    const STATISTICAL_SECURITY_PARAMETER: u16 = 80;

    let mut rng = StdRng::seed_from_u64(42);

    // Step 1: Setup parameters
    println!("📋 Step 1: Setup Parameters");
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, MESSAGE_COUNT);
    
    // Generate key shares
    let (secret_key, key_shares) = {
        let (secret, shares, _) = deal_random_secret(&mut rng, THRESHOLD, TOTAL)
            .map_err(|e| anyhow::anyhow!("deal_random_secret failed: {:?}", e))?;
        (secret, shares.0.into_iter().map(|s| s.share).collect::<Vec<_>>())
    };
    
    let public_key = PublicKeyG2::generate_using_secret_key(&SecretKey(secret_key), &params);
    println!("  ✓ Generated threshold keypair with {} shares", key_shares.len());
    println!("  Secret key: {:?}", secret_key);
    for (i, share) in key_shares.iter().enumerate() {
        println!("  Share[{}]: {:?}", i + 1, share);
    }

    // Step 2: Setup OTE parameters
    println!("\n⚙️ Step 2: Setup Multiplication Parameters");
    let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
    let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<Blake2b512>(
        ote_params, 
        b"test-gadget-vector"
    );

    // Step 3: Base OT setup
    println!("\n🔗 Step 3: Base OT Setup");
    let total_party_set = (1..=TOTAL).collect::<BTreeSet<_>>();
    let threshold_party_set = (1..=THRESHOLD).collect::<BTreeSet<_>>();
    
    let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
        &mut rng,
        ote_params.num_base_ot(),
        TOTAL,
        total_party_set.clone(),
    );
    println!("  ✓ Completed base OT setup");

    // Step 4: Prepare messages
    println!("\n📝 Step 4: Prepare Messages");
    let messages: Vec<Fr> = (0..MESSAGE_COUNT)
        .map(|i| Fr::from(100 + i as u64))
        .collect();
    
    println!("  Messages to sign:");
    for (i, msg) in messages.iter().enumerate() {
        println!("    [{}] {}", i, msg);
    }

    // Step 5: Phase 1 - Direct call without mesh
    println!("\n🎯 Step 5: Phase 1 - Randomness Generation");
    let protocol_id = b"threshold-bbs-plus-demo".to_vec();
    
    let mut round1s = Vec::new();
    let mut commitments = Vec::new();
    let mut commitments_zero_share = Vec::new();

    // Each signer initiates Phase 1
    for i in 1..=THRESHOLD {
        let mut others = threshold_party_set.clone();
        others.remove(&i);
        
        println!("  Signer {} initiating with others: {:?}", i, others);
        
        let (round1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs_plus::<_, Blake2b512>(
            &mut rng,
            BATCH_SIZE,
            i,
            others,
            protocol_id.clone(),
        )?;
        
        round1s.push(round1);
        commitments.push(comm);
        commitments_zero_share.push(comm_zero);
    }

    // Signers exchange commitments
    for i in 1..=THRESHOLD {
        for j in 1..=THRESHOLD {
            if i != j {
                round1s[i as usize - 1]
                    .receive_commitment(
                        j,
                        commitments[j as usize - 1].clone(),
                        commitments_zero_share[j as usize - 1]
                            .get(&i)
                            .unwrap()
                            .clone(),
                    )?;
            }
        }
    }

    // Signers exchange shares
    for i in 1..=THRESHOLD {
        for j in 1..=THRESHOLD {
            if i != j {
                let share = round1s[j as usize - 1].get_comm_shares_and_salts();
                let zero_share = round1s[j as usize - 1]
                    .get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i);
                
                round1s[i as usize - 1]
                    .receive_shares::<Blake2b512>(j, share, zero_share)?;
            }
        }
    }

    // Finish Phase 1
    let mut round1_outputs = Vec::new();
    for (i, round1) in round1s.into_iter().enumerate() {
        let output = round1
            .finish_for_bbs_plus::<Blake2b512>(&key_shares[i])?;
        
        println!("  Phase1Output[{}]:", i + 1);
        println!("    e: {:?}", output.e);
        println!("    s: {:?}", output.s);
        
        round1_outputs.push(output);
    }
    println!("  ✓ Phase 1 completed");

    // Step 6: Phase 2 - Multiplication Protocol
    println!("\n🔄 Step 6: Phase 2 - Multiplication Protocol");
    
    let mut round2s = Vec::new();
    let mut all_msg_1s = Vec::new();

    // Each signer initiates Phase 2
    for i in 1..=THRESHOLD {
        let mut others = threshold_party_set.clone();
        others.remove(&i);
        
        let (phase, msg1s) = Phase2::init::<_, Shake256>(
            &mut rng,
            i,
            round1_outputs[i as usize - 1].masked_signing_key_shares.clone(),
            round1_outputs[i as usize - 1].masked_rs.clone(),
            base_ot_outputs[i as usize - 1].clone(),
            others,
            ote_params,
            &gadget_vector,
        )?;
        
        round2s.push(phase);
        all_msg_1s.push((i, msg1s));
    }

    // Process messages round 1
    let mut all_msg_2s = Vec::new();
    for (sender_id, msg_1s) in all_msg_1s {
        for (receiver_id, m) in msg_1s {
            let m2 = round2s[receiver_id as usize - 1]
                .receive_message1::<Blake2b512, Shake256>(sender_id, m, &gadget_vector)?;
            all_msg_2s.push((receiver_id, sender_id, m2));
        }
    }

    // Process messages round 2
    for (sender_id, receiver_id, m2) in all_msg_2s {
        round2s[receiver_id as usize - 1]
            .receive_message2::<Blake2b512>(sender_id, m2, &gadget_vector)?;
    }

    // Finish Phase 2
    let round2_outputs: Vec<_> = round2s
        .into_iter()
        .map(|p| p.finish())
        .collect();
    println!("  ✓ Phase 2 completed");

    // Step 7: Generate signature shares
    println!("\n✍️ Step 7: Generate Signature Shares");
    let mut signature_shares = Vec::new();
    
    for i in 0..THRESHOLD as usize {
        let share = BBSPlusSignatureShare::new(
            &messages,
            0, // sig_index_in_batch
            &round1_outputs[i],
            &round2_outputs[i],
            &params,
        )?;
        
        println!("  Share[{}]:", i + 1);
        println!("    e: {:?}", share.e);
        println!("    s: {:?}", share.s);
        println!("    u: {:?}", share.u);
        println!("    R: {:?}", share.R);
        
        signature_shares.push(share);
    }

    // Step 8: Aggregate signature shares
    println!("\n🔗 Step 8: Aggregate Signature Shares");
    let signature = BBSPlusSignatureShare::aggregate(signature_shares)?;
    println!("  Aggregated signature:");
    println!("    A: {:?}", signature.A);
    println!("    e: {:?}", signature.e);
    println!("    s: {:?}", signature.s);

    // Step 9: Verify the signature
    println!("\n🔍 Step 9: Verify Threshold Signature");
    match signature.verify(&messages, public_key.clone(), params.clone()) {
        Ok(_) => {
            println!("  ✅ Threshold signature is VALID!");
        }
        Err(e) => {
            println!("  ❌ Verification failed: {:?}", e);
            
            // Try to understand why it failed
            println!("\n  Debugging info:");
            println!("    Public key: {:?}", public_key);
            println!("    Params h_len: {}", params.h.len());
            println!("    Messages count: {}", messages.len());
        }
    }

    Ok(())
}

#[cfg(not(feature = "mpc"))]
fn main() {
    eprintln!("This demo requires the 'mpc' feature to be enabled.");
    eprintln!("Try: cargo run --features mpc --bin threshold_mesh_debug");
}
