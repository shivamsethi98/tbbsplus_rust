#[cfg(feature = "mpc")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use bbs_plus::prelude::*;
    use std::collections::BTreeSet;
    
    use bbs_plus::threshold::{
        threshold_bbs_plus::BBSPlusSignatureShare,
        multiplication_phase::Phase2,
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

    println!("🔍 Threshold BBS+ Debug Comparison");
    println!("===================================\n");

    // Use EXACT same configuration and seed
    const THRESHOLD: u16 = 3;
    const TOTAL: u16 = 4;
    const MESSAGE_COUNT: u32 = 5;
    const BATCH_SIZE: u32 = 1;
    const BASE_OT_KEY_SIZE: u16 = 128;
    const KAPPA: u16 = 256;
    const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
    const SEED: u64 = 42;

    // Test 1: Direct execution (should work)
    println!("📘 TEST 1: Direct Execution (Reference Implementation)");
    println!("{}", "=".repeat(50));
    
    let mut rng1 = StdRng::seed_from_u64(SEED);
    let params1 = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng1, MESSAGE_COUNT);
    
    let (secret_key1, key_shares1) = {
        let (secret, shares, _) = deal_random_secret(&mut rng1, THRESHOLD, TOTAL)
            .map_err(|e| anyhow::anyhow!("Failed to deal secret: {:?}", e))?;
        (secret, shares.0.into_iter().map(|s| s.share).collect::<Vec<_>>())
    };
    
    let public_key1 = PublicKeyG2::generate_using_secret_key(&SecretKey(secret_key1), &params1);
    
    println!("Secret key: {:?}", secret_key1);
    println!("Public key W: {:?}", public_key1.0);
    for (i, share) in key_shares1.iter().enumerate() {
        println!("Share[{}]: {:?}", i + 1, share);
    }

    let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
    let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<Blake2b512>(
        ote_params, 
        b"test-gadget-vector"
    );

    let total_party_set = (1..=TOTAL).collect::<BTreeSet<_>>();
    let threshold_party_set = (1..=THRESHOLD).collect::<BTreeSet<_>>();
    
    let base_ot_outputs1 = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
        &mut rng1,
        ote_params.num_base_ot(),
        TOTAL,
        total_party_set.clone(),
    );

    let messages1: Vec<Fr> = (0..MESSAGE_COUNT)
        .map(|i| Fr::from(100 + i as u64))
        .collect();

    // Direct Phase 1
    println!("\n🔸 Phase 1 - Direct");
    let protocol_id = b"threshold-bbs-plus-demo".to_vec();
    
    let mut round1s = Vec::new();
    let mut commitments = Vec::new();
    let mut commitments_zero_share = Vec::new();

    for i in 1..=THRESHOLD {
        let mut others = threshold_party_set.clone();
        others.remove(&i);
        
        let (round1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs_plus::<_, Blake2b512>(
            &mut rng1,
            BATCH_SIZE,
            i,
            others.clone(),
            protocol_id.clone(),
        ).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        
        println!("  Participant {} others: {:?}", i, others);
        
        round1s.push(round1);
        commitments.push(comm);
        commitments_zero_share.push(comm_zero);
    }

    // Exchange commitments
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
                    ).map_err(|e| anyhow::anyhow!("{:?}", e))?;
            }
        }
    }

    // Exchange shares
    for i in 1..=THRESHOLD {
        for j in 1..=THRESHOLD {
            if i != j {
                let share = round1s[j as usize - 1].get_comm_shares_and_salts();
                let zero_share = round1s[j as usize - 1]
                    .get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i);
                
                round1s[i as usize - 1]
                    .receive_shares::<Blake2b512>(j, share, zero_share)
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            }
        }
    }

    // Finish Phase 1
    let mut round1_outputs = Vec::new();
    for (i, round1) in round1s.into_iter().enumerate() {
        let output = round1
            .finish_for_bbs_plus::<Blake2b512>(&key_shares1[i])
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        
        println!("  P{} Phase1 output:", i + 1);
        println!("    e[0]: {:?}", output.e[0]);
        println!("    s[0]: {:?}", output.s[0]);
        println!("    r[0]: {:?}", output.r[0]);
        println!("    masked_sk[0]: {:?}", output.masked_signing_key_shares[0]);
        println!("    masked_r[0]: {:?}", output.masked_rs[0]);
        println!("    others: {:?}", output.others);
        
        round1_outputs.push(output);
    }

    // Direct Phase 2
    println!("\n🔸 Phase 2 - Direct");
    let mut round2s = Vec::new();
    let mut all_msg_1s = Vec::new();

    for i in 1..=THRESHOLD {
        let mut others = threshold_party_set.clone();
        others.remove(&i);
        
        let (phase, msg1s) = Phase2::init::<_, Shake256>(
            &mut rng1,
            i,
            round1_outputs[i as usize - 1].masked_signing_key_shares.clone(),
            round1_outputs[i as usize - 1].masked_rs.clone(),
            base_ot_outputs1[i as usize - 1].clone(),
            others,
            ote_params,
            &gadget_vector,
        ).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        
        round2s.push(phase);
        all_msg_1s.push((i, msg1s));
    }

    let mut all_msg_2s = Vec::new();
    for (sender_id, msg_1s) in all_msg_1s {
        for (receiver_id, m) in msg_1s {
            let m2 = round2s[receiver_id as usize - 1]
                .receive_message1::<Blake2b512, Shake256>(sender_id, m, &gadget_vector)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            all_msg_2s.push((receiver_id, sender_id, m2));
        }
    }

    for (sender_id, receiver_id, m2) in all_msg_2s {
        round2s[receiver_id as usize - 1]
            .receive_message2::<Blake2b512>(sender_id, m2, &gadget_vector)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    let round2_outputs: Vec<_> = round2s
        .into_iter()
        .map(|p| p.finish())
        .collect();

    // Generate signature shares
    println!("\n🔸 Signature Shares - Direct");
    let mut signature_shares1 = Vec::new();
    
    for i in 0..THRESHOLD as usize {
        let share = BBSPlusSignatureShare::new(
            &messages1,
            0,
            &round1_outputs[i],
            &round2_outputs[i],
            &params1,
        ).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        
        println!("  Share[{}]:", i + 1);
        println!("    e: {:?}", share.e);
        println!("    s: {:?}", share.s);
        println!("    u: {:?}", share.u);
        println!("    R: {:?}", share.R);
        
        signature_shares1.push(share);
    }

    let signature1 = BBSPlusSignatureShare::aggregate(signature_shares1.clone())
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    
    println!("\n📊 Final Signature - Direct:");
    println!("  A: {:?}", signature1.A);
    println!("  e: {:?}", signature1.e);
    println!("  s: {:?}", signature1.s);

    match signature1.verify(&messages1, public_key1.clone(), params1.clone()) {
        Ok(_) => println!("  ✅ Direct verification: SUCCESS"),
        Err(e) => println!("  ❌ Direct verification: FAILED - {:?}", e),
    }

    // Test 2: Now test with mesh simulation (serialization/deserialization)
    println!("\n\n📙 TEST 2: With Serialization (Simulating Mesh)");
    println!("{}", "=".repeat(50));
    
    // Use same seed to get identical setup
    let mut rng2 = StdRng::seed_from_u64(SEED);
    let params2 = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng2, MESSAGE_COUNT);
    
    let (secret_key2, key_shares2) = {
        let (secret, shares, _) = deal_random_secret(&mut rng2, THRESHOLD, TOTAL)
            .map_err(|e| anyhow::anyhow!("Failed to deal secret: {:?}", e))?;
        (secret, shares.0.into_iter().map(|s| s.share).collect::<Vec<_>>())
    };
    
    let public_key2 = PublicKeyG2::generate_using_secret_key(&SecretKey(secret_key2), &params2);
    
    // Verify setup is identical
    assert_eq!(secret_key1, secret_key2, "Secret keys must match!");
    assert_eq!(public_key1, public_key2, "Public keys must match!");
    assert_eq!(params1.h, params2.h, "Params must match!");
    
    println!("✓ Setup verified identical to direct test");
    
    // Now run the mesh version using our orchestration code
    use tbbsplus_rust::orchestration::threshold_phases::{
        Phase1Coordinator, Phase2Coordinator,
        Phase1Message, Phase2Message,
    };
    use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

    let base_ot_outputs2 = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
        &mut rng2,
        ote_params.num_base_ot(),
        TOTAL,
        total_party_set.clone(),
    );

    println!("\n🔸 Phase 1 - With Serialization");
    
    // Create coordinators
    let mut phase1_coordinators = Vec::new();
    for i in 1..=THRESHOLD {
        let coordinator = Phase1Coordinator::new(
            i,
            THRESHOLD,
            TOTAL,
            BATCH_SIZE,
            protocol_id.clone(),
        );
        phase1_coordinators.push(coordinator);
    }

    // Initialize and collect messages
    let mut all_phase1_messages = Vec::new();
    
    for (i, coord) in phase1_coordinators.iter_mut().enumerate() {
        let participant_id = (i + 1) as ParticipantId;
        
        // Initialize Phase 1
        let others: BTreeSet<ParticipantId> = (1..=THRESHOLD)
            .filter(|&p| p != participant_id)
            .collect();
        
        println!("  P{} initializing with others: {:?}", participant_id, others);
        
        // Call initialize directly without async
        let (phase1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs_plus::<_, Blake2b512>(
            &mut rng2,
            BATCH_SIZE,
            participant_id,
            others,
            protocol_id.clone(),
        ).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        
        coord.phase1 = Some(phase1);
        
        // Serialize commitments (simulating network)
        let mut commitment_bytes = Vec::new();
        comm.serialize_compressed(&mut commitment_bytes)?;
        
        let mut zero_commitments_map = std::collections::BTreeMap::new();
        for (pid, zc) in comm_zero {
            let mut zc_bytes = Vec::new();
            zc.serialize_compressed(&mut zc_bytes)?;
            zero_commitments_map.insert(pid, zc_bytes);
        }
        
        let msg = Phase1Message::Commitment {
            from: participant_id,
            commitment: commitment_bytes,
            zero_share_commitments: zero_commitments_map,
        };
        
        all_phase1_messages.push(msg);
    }

    // Process commitment messages
    for msg in &all_phase1_messages {
        for coord in &mut phase1_coordinators {
            coord.process_commitment(msg.clone())?;
        }
    }

    // Generate and exchange shares
    let mut all_share_messages = Vec::new();
    for (i, coord) in phase1_coordinators.iter_mut().enumerate() {
        let participant_id = (i + 1) as ParticipantId;
        let phase1 = coord.phase1.as_ref().unwrap();
        
        for pid in 1..=THRESHOLD {
            if pid != participant_id {
                let shares = phase1.get_comm_shares_and_salts();
                let zero_shares = phase1.get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&pid);
                
                let mut shares_bytes = Vec::new();
                shares.serialize_compressed(&mut shares_bytes)?;
                
                let mut zero_shares_bytes = Vec::new();
                zero_shares.serialize_compressed(&mut zero_shares_bytes)?;
                
                let msg = Phase1Message::ShareExchange {
                    from: participant_id,
                    to: pid,
                    shares: shares_bytes,
                    zero_shares: zero_shares_bytes,
                };
                
                all_share_messages.push(msg);
            }
        }
    }

    // Process share messages
    for msg in &all_share_messages {
        for coord in &mut phase1_coordinators {
            coord.process_share_exchange(msg.clone())?;
        }
    }

    // Complete Phase 1
    let mut phase1_outputs2 = Vec::new();
    for (i, coord) in phase1_coordinators.iter_mut().enumerate() {
        let output = coord.finalize(&key_shares2[i])?;
        
        println!("  P{} Phase1 output (serialized):", i + 1);
        println!("    e[0]: {:?}", output.e[0]);
        println!("    s[0]: {:?}", output.s[0]);
        println!("    r[0]: {:?}", output.r[0]);
        println!("    masked_sk[0]: {:?}", output.masked_signing_key_shares[0]);
        println!("    masked_r[0]: {:?}", output.masked_rs[0]);
        println!("    others: {:?}", output.others);
        
        phase1_outputs2.push(output);
    }

    // Compare Phase 1 outputs
    println!("\n📈 Comparing Phase 1 Outputs:");
    for i in 0..THRESHOLD as usize {
        let matches = 
            round1_outputs[i].e == phase1_outputs2[i].e &&
            round1_outputs[i].s == phase1_outputs2[i].s &&
            round1_outputs[i].r == phase1_outputs2[i].r &&
            round1_outputs[i].masked_signing_key_shares == phase1_outputs2[i].masked_signing_key_shares &&
            round1_outputs[i].masked_rs == phase1_outputs2[i].masked_rs;
        
        if matches {
            println!("  P{}: ✅ Outputs match", i + 1);
        } else {
            println!("  P{}: ❌ Outputs DIFFER!", i + 1);
            if round1_outputs[i].e != phase1_outputs2[i].e {
                println!("    e differs!");
            }
            if round1_outputs[i].s != phase1_outputs2[i].s {
                println!("    s differs!");
            }
            if round1_outputs[i].r != phase1_outputs2[i].r {
                println!("    r differs!");
            }
        }
    }

    // Phase 2 with serialization
    println!("\n🔸 Phase 2 - With Serialization");
    
    let mut phase2_coordinators = Vec::new();
    for i in 1..=THRESHOLD {
        let coordinator = Phase2Coordinator::new(i, THRESHOLD);
        phase2_coordinators.push(coordinator);
    }

    // Initialize Phase 2 and collect round 1 messages
    let mut all_round1_messages = Vec::new();
    
    for (i, coord) in phase2_coordinators.iter_mut().enumerate() {
        let participant_id = (i + 1) as ParticipantId;
        
        // Use the same set of others from Phase 1 output
        let others: BTreeSet<ParticipantId> = phase1_outputs2[i].others.iter().cloned().collect();
        
        let (phase2, messages) = Phase2::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::init::<_, Shake256>(
            &mut rng2,
            participant_id,
            phase1_outputs2[i].masked_signing_key_shares.clone(),
            phase1_outputs2[i].masked_rs.clone(),
            base_ot_outputs2[i].clone(),
            others,
            ote_params,
            &gadget_vector,
        ).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        
        coord.phase2 = Some(phase2);
        
        // Serialize messages
        for (to, msg) in messages {
            let mut msg_bytes = Vec::new();
            msg.serialize_compressed(&mut msg_bytes)?;
            
            let phase2_msg = Phase2Message::Round1 {
                from: participant_id,
                to,
                message: msg_bytes,
            };
            
            all_round1_messages.push(phase2_msg);
        }
    }

    // Process round 1 and generate round 2
    let mut all_round2_messages = Vec::new();
    
    for msg in &all_round1_messages {
        if let Phase2Message::Round1 { from, to, message } = msg {
            let coord_idx = (*to as usize) - 1;
            if coord_idx < phase2_coordinators.len() {
                let phase2 = phase2_coordinators[coord_idx].phase2.as_mut().unwrap();
                
                let msg1 = CanonicalDeserialize::deserialize_compressed(&message[..])?;
                let msg2 = phase2.receive_message1::<Blake2b512, Shake256>(
                    *from,
                    msg1,
                    &gadget_vector,
                ).map_err(|e| anyhow::anyhow!("{:?}", e))?;
                
                let mut msg2_bytes = Vec::new();
                msg2.serialize_compressed(&mut msg2_bytes)?;
                
                let phase2_msg = Phase2Message::Round2 {
                    from: *to,
                    to: *from,
                    message: msg2_bytes,
                };
                
                all_round2_messages.push(phase2_msg);
            }
        }
    }

    // Process round 2 messages
    for msg in &all_round2_messages {
        if let Phase2Message::Round2 { from, to, message } = msg {
            let coord_idx = (*to as usize) - 1;
            if coord_idx < phase2_coordinators.len() {
                let phase2 = phase2_coordinators[coord_idx].phase2.as_mut().unwrap();
                
                let msg2 = CanonicalDeserialize::deserialize_compressed(&message[..])?;
                phase2.receive_message2::<Blake2b512>(*from, msg2, &gadget_vector)
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            }
        }
    }

    // Complete Phase 2
    let mut phase2_outputs2 = Vec::new();
    for coord in &mut phase2_coordinators {
        let phase2 = coord.phase2.take().unwrap();
        let output = phase2.finish();
        phase2_outputs2.push(output);
    }

    // Generate signature shares with serialization
    println!("\n🔸 Signature Shares - With Serialization");
    let messages2 = messages1.clone();
    let mut signature_shares2 = Vec::new();
    
    for i in 0..THRESHOLD as usize {
        let share = BBSPlusSignatureShare::new(
            &messages2,
            0,
            &phase1_outputs2[i],
            &phase2_outputs2[i],
            &params2,
        ).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        
        println!("  Share[{}] (serialized):", i + 1);
        println!("    e: {:?}", share.e);
        println!("    s: {:?}", share.s);
        println!("    u: {:?}", share.u);
        println!("    R: {:?}", share.R);
        
        signature_shares2.push(share);
    }

    // Compare signature shares
    println!("\n📈 Comparing Signature Shares:");
    for i in 0..THRESHOLD as usize {
        let matches = 
            signature_shares1[i].e == signature_shares2[i].e &&
            signature_shares1[i].s == signature_shares2[i].s &&
            signature_shares1[i].u == signature_shares2[i].u &&
            signature_shares1[i].R == signature_shares2[i].R;
        
        if matches {
            println!("  Share {}: ✅ Identical", i + 1);
        } else {
            println!("  Share {}: ❌ DIFFERENT!", i + 1);
            if signature_shares1[i].e != signature_shares2[i].e {
                println!("    e: {:?} vs {:?}", signature_shares1[i].e, signature_shares2[i].e);
            }
            if signature_shares1[i].s != signature_shares2[i].s {
                println!("    s: {:?} vs {:?}", signature_shares1[i].s, signature_shares2[i].s);
            }
            if signature_shares1[i].u != signature_shares2[i].u {
                println!("    u: {:?} vs {:?}", signature_shares1[i].u, signature_shares2[i].u);
            }
            if signature_shares1[i].R != signature_shares2[i].R {
                println!("    R: {:?} vs {:?}", signature_shares1[i].R, signature_shares2[i].R);
            }
        }
    }

    let signature2 = BBSPlusSignatureShare::aggregate(signature_shares2)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    
    println!("\n📊 Final Signature - With Serialization:");
    println!("  A: {:?}", signature2.A);
    println!("  e: {:?}", signature2.e);
    println!("  s: {:?}", signature2.s);

    println!("\n📈 Comparing Final Signatures:");
    if signature1.A == signature2.A && signature1.e == signature2.e && signature1.s == signature2.s {
        println!("  ✅ Signatures are IDENTICAL");
    } else {
        println!("  ❌ Signatures DIFFER!");
        if signature1.A != signature2.A {
            println!("    A: {:?} vs {:?}", signature1.A, signature2.A);
        }
        if signature1.e != signature2.e {
            println!("    e: {:?} vs {:?}", signature1.e, signature2.e);
        }
        if signature1.s != signature2.s {
            println!("    s: {:?} vs {:?}", signature1.s, signature2.s);
        }
    }

    match signature2.verify(&messages2, public_key2, params2) {
        Ok(_) => println!("  ✅ Serialized verification: SUCCESS"),
        Err(e) => println!("  ❌ Serialized verification: FAILED - {:?}", e),
    }

    println!("\n🎯 Diagnosis Complete!");
    
    Ok(())
}

#[cfg(not(feature = "mpc"))]
fn main() {
    eprintln!("This debug tool requires the 'mpc' feature to be enabled.");
    eprintln!("Try: cargo run --features mpc --bin threshold_debug_compare");
}
