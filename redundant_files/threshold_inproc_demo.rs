#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use bbs_plus::prelude::*;
    use bbs_plus::threshold::randomness_generation_phase::Phase1;
    use bbs_plus::threshold::threshold_bbs_plus::{BBSPlusSignatureShare, Phase1Output as BBSPhase1Output};
    use bbs_plus::threshold::multiplication_phase::{Phase2, Phase2Output};
    use blake2::Blake2b512;
    use oblivious_transfer_protocols::ot_based_multiplication::{
        base_ot_multi_party_pairwise::BaseOTOutput,
        dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::GadgetVector,
    };
    use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
    use serde::{Serialize, Deserialize};
    use sha3::Shake256;
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};

    println!("Threshold BBS+ in-proc demo (no libp2p)");

    const THRESHOLD: u16 = 3; // quorum
    const TOTAL: u16 = 4;     // total signers
    const MESSAGE_COUNT: u32 = 5;
    const BATCH_SIZE: u32 = 1;
    const BASE_OT_KEY_SIZE: u16 = 128;
    const KAPPA: u16 = 256;
    const SSP: u16 = 80;

    // Setup params and keys
    println!("[main] generating params and secret shares...");
    let mut rng = StdRng::seed_from_u64(42);
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, MESSAGE_COUNT);
    let (secret_key, key_shares) = {
        let (secret, shares, _) = deal_random_secret(&mut rng, THRESHOLD, TOTAL)
            .map_err(|e| anyhow::anyhow!("deal_random_secret failed: {:?}", e))?;
        (secret, shares.0.into_iter().map(|s| s.share).collect::<Vec<_>>())
    };
    let public_key = PublicKeyG2::generate_using_secret_key(&SecretKey(secret_key), &params);
    println!("[main] params and shares ready");

    // One-time base OT setup
    let party_set: BTreeSet<_> = (1..=TOTAL).collect();
    let ote_params = MultiplicationOTEParams::<KAPPA, SSP> {};
    let gadget_vector = GadgetVector::<Fr, KAPPA, SSP>::new::<Blake2b512>(ote_params, b"threshold-bbs-plus-gadget");
    println!("[main] running pairwise base OT for {} parties ({} base OTs)...", TOTAL, ote_params.num_base_ot());
    let base_ot_outputs = test_utils::ot::do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
        &mut rng,
        ote_params.num_base_ot(),
        TOTAL,
        party_set,
    );
    println!("[main] base OT complete");

    // In-proc message types
    #[derive(Debug, Clone, Serialize, Deserialize)]
    enum Msg {
        P1Commit { from: u16, comm: Vec<u8>, comm_zero_map: BTreeMap<u16, Vec<u8>> },
        P1Shares { from: u16, to: u16, shares: Vec<u8>, zero_shares: Vec<u8> },
        P2R1 { from: u16, to: u16, data: Vec<u8> },
        P2R2 { from: u16, to: u16, data: Vec<u8> },
    }

    // Per-participant inbox
    let mut inboxes = Vec::new();
    let mut senders = Vec::new();
    for _ in 1..=TOTAL { let (tx, rx) = mpsc::channel::<Msg>(128); senders.push(tx); inboxes.push(rx); }
    let mut tasks = Vec::new();

    // Share params across tasks
    let params = Arc::new(params);

    // Run first THRESHOLD participants
    for pid in 1..=THRESHOLD {
    let mut rng = StdRng::seed_from_u64(1000 + pid as u64);
    let mut rx = inboxes.remove(0);
    let mut buf: VecDeque<Msg> = VecDeque::new();
    let txs = senders.clone();
        let sk_share = key_shares[(pid - 1) as usize];
        let base_ot = base_ot_outputs[(pid - 1) as usize].clone();
    let params = params.clone();
    let gadget_vector = gadget_vector.clone();

    tasks.push(tokio::spawn(async move {
            println!("[P{}] starting", pid);
            // Phase 1 init
            let others: BTreeSet<u16> = (1..=THRESHOLD).filter(|&x| x != pid).collect();
            let protocol_id = b"threshold-bbs-demo".to_vec();
            let (mut p1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs_plus::<_, Blake2b512>(
                &mut rng, BATCH_SIZE, pid, others.clone(), protocol_id.clone()
            ).map_err(|e| anyhow::anyhow!("p1 init: {:?}", e))?;

            // Broadcast commitments
            let mut comm_bytes = Vec::new(); comm.serialize_compressed(&mut comm_bytes)?;
            let mut comm_zero_map_bytes = BTreeMap::new();
            for (k, v) in comm_zero.iter() { let mut b = Vec::new(); v.serialize_compressed(&mut b)?; comm_zero_map_bytes.insert(*k, b); }
            for other in 1..=THRESHOLD { if other != pid { let m = Msg::P1Commit { from: pid, comm: comm_bytes.clone(), comm_zero_map: comm_zero_map_bytes.clone() }; let _ = txs[(other - 1) as usize].send(m).await; } }
            println!("[P{}] broadcasted commitments", pid);

            // Receive commitments (buffer unrelated messages)
            let mut got_from = BTreeSet::new();
            while got_from.len() < (THRESHOLD as usize - 1) {
                // Try buffered commits first
                if let Some(idx) = buf.iter().position(|m| matches!(m, Msg::P1Commit { .. })) {
                    if let Some(Msg::P1Commit { from, comm, comm_zero_map }) = buf.remove(idx) {
                        let their_comm = CanonicalDeserialize::deserialize_compressed(&comm[..])?;
                        let zc_bytes = comm_zero_map.get(&pid).context("missing zc for me")?;
                        let their_zc = CanonicalDeserialize::deserialize_compressed(&zc_bytes[..])?;
                        p1.receive_commitment(from, their_comm, their_zc)
                            .map_err(|e| anyhow::anyhow!("recv commit: {:?}", e))?;
                        got_from.insert(from);
                        continue;
                    }
                }
                if let Some(m) = timeout(Duration::from_secs(10), rx.recv()).await.map_err(|_| anyhow::anyhow!("[P{}] timeout waiting for P1Commit", pid))? {
                    match m {
                        Msg::P1Commit { from, comm, comm_zero_map } => {
                            let their_comm = CanonicalDeserialize::deserialize_compressed(&comm[..])?;
                            let zc_bytes = comm_zero_map.get(&pid).context("missing zc for me")?;
                            let their_zc = CanonicalDeserialize::deserialize_compressed(&zc_bytes[..])?;
                            p1.receive_commitment(from, their_comm, their_zc)
                                .map_err(|e| anyhow::anyhow!("recv commit: {:?}", e))?;
                            got_from.insert(from);
                            println!("[P{}] received commitment from {}", pid, from);
                        }
                        other => buf.push_back(other),
                    }
                }
            }
            println!("[P{}] received all commitments", pid);

            // Send shares to others
            for other in 1..=THRESHOLD { if other != pid {
                let shares = p1.get_comm_shares_and_salts();
                let zero_shares = p1.get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&other);
                let mut s1 = Vec::new(); shares.serialize_compressed(&mut s1)?;
                let mut s2 = Vec::new(); zero_shares.serialize_compressed(&mut s2)?;
                let m = Msg::P1Shares { from: pid, to: other, shares: s1, zero_shares: s2 };
                let _ = txs[(other - 1) as usize].send(m).await;
            }}

            // Receive shares (buffer unrelated messages)
            let mut got_shares = BTreeSet::new();
            while got_shares.len() < (THRESHOLD as usize - 1) {
                // Try buffered target shares first
                if let Some(idx) = buf.iter().position(|m| matches!(m, Msg::P1Shares { to, .. } if *to == pid)) {
                    if let Some(Msg::P1Shares { from, to: _, shares, zero_shares }) = buf.remove(idx) {
                        let s1: Vec<(Fr, [u8; 256])> = CanonicalDeserialize::deserialize_compressed(&shares[..])?;
                        let s2: Vec<(Fr, [u8; 256])> = CanonicalDeserialize::deserialize_compressed(&zero_shares[..])?;
                        p1.receive_shares::<Blake2b512>(from, s1, s2)
                            .map_err(|e| anyhow::anyhow!("recv shares: {:?}", e))?;
                        got_shares.insert(from);
                        continue;
                    }
                }
                if let Some(m) = timeout(Duration::from_secs(10), rx.recv()).await.map_err(|_| anyhow::anyhow!("[P{}] timeout waiting for P1Shares", pid))? {
                    match m {
                        Msg::P1Shares { from, to, shares, zero_shares } if to == pid => {
                            let s1: Vec<(Fr, [u8; 256])> = CanonicalDeserialize::deserialize_compressed(&shares[..])?;
                            let s2: Vec<(Fr, [u8; 256])> = CanonicalDeserialize::deserialize_compressed(&zero_shares[..])?;
                            p1.receive_shares::<Blake2b512>(from, s1, s2)
                                .map_err(|e| anyhow::anyhow!("recv shares: {:?}", e))?;
                            got_shares.insert(from);
                            println!("[P{}] received shares from {}", pid, from);
                        }
                        other => buf.push_back(other),
                    }
                }
            }
            println!("[P{}] received all shares", pid);

            // Finalize Phase 1
            let p1_out: BBSPhase1Output<Fr> = p1
                .finish_for_bbs_plus::<Blake2b512>(&sk_share)
                .map_err(|e| anyhow::anyhow!("p1 finish: {:?}", e))?;

            // Phase 2
            let (mut p2, msgs1) = Phase2::<Fr, KAPPA, SSP>::init::<_, Shake256>(
                &mut rng,
                pid,
                p1_out.masked_signing_key_shares.clone(),
                p1_out.masked_rs.clone(),
                base_ot.clone(),
                others.clone(),
                ote_params,
                &gadget_vector,
            ).map_err(|e| anyhow::anyhow!("p2 init: {:?}", e))?;
            println!("[P{}] phase 2 initialized", pid);

            // Send round1 messages
            for (to, m1) in msgs1.into_iter() {
                let mut bytes = Vec::new(); m1.serialize_compressed(&mut bytes)?;
                let _ = txs[(to - 1) as usize]
                    .send(Msg::P2R1 { from: pid, to, data: bytes })
                    .await;
            }
            println!("[P{}] sent phase2 round1 to peers", pid);

            // Receive r1 and reply with r2 (buffer unrelated messages)
            let mut pending_r2 = BTreeMap::new();
            let mut r1_from = BTreeSet::new();
            let mut r2_from = BTreeSet::new();
            // Expect Round1 only from peers where I am Party1 (i.e., my id > other id)
            let expected_r1 = others.iter().filter(|&&o| pid > o).count();
            // Expect Round2 only from peers where I am Party2 (i.e., my id < other id)
            let expected_r2 = others.iter().filter(|&&o| pid < o).count();
            while r1_from.len() < expected_r1 || r2_from.len() < expected_r2 || !pending_r2.is_empty() {
                // Drain any buffered r1/r2 for me
                loop {
                    let maybe_idx = buf.iter().position(|m| match m { Msg::P2R1 { to, .. } | Msg::P2R2 { to, .. } => *to == pid, _ => false });
                    if let Some(idx) = maybe_idx {
                        let m = buf.remove(idx).unwrap();
                        match m {
                            Msg::P2R1 { from, to: _, data } => {
                                let m1 = CanonicalDeserialize::deserialize_compressed(&data[..])?;
                                let m2 = p2.receive_message1::<Blake2b512, Shake256>(from, m1, &gadget_vector)
                                    .map_err(|e| anyhow::anyhow!("p2 recv1: {:?}", e))?;
                                let mut bytes = Vec::new(); m2.serialize_compressed(&mut bytes)?;
                                let _ = txs[(from - 1) as usize]
                                    .send(Msg::P2R2 { from: pid, to: from, data: bytes })
                                    .await;
                                r1_from.insert(from);
                            }
                            Msg::P2R2 { from, to: _, data } => {
                                pending_r2.insert(from, data);
                            }
                            _ => {}
                        }
                    } else { break; }
                }

        if let Some(m) = timeout(Duration::from_secs(15), rx.recv()).await.map_err(|_| anyhow::anyhow!("[P{}] timeout waiting for Phase2 messages", pid))? {
                    match m {
                        Msg::P2R1 { from, to, data } if to == pid => {
                            let m1 = CanonicalDeserialize::deserialize_compressed(&data[..])?;
                            let m2 = p2.receive_message1::<Blake2b512, Shake256>(from, m1, &gadget_vector)
                                .map_err(|e| anyhow::anyhow!("p2 recv1: {:?}", e))?;
                            let mut bytes = Vec::new(); m2.serialize_compressed(&mut bytes)?;
                            let _ = txs[(from - 1) as usize]
                                .send(Msg::P2R2 { from: pid, to: from, data: bytes })
                                .await;
                            r1_from.insert(from);
                println!("[P{}] processed P2R1 from {} and sent P2R2", pid, from);
                        }
                        Msg::P2R2 { from, to, data } if to == pid => {
                            // Process immediately
                            let m2 = CanonicalDeserialize::deserialize_compressed(&data[..])?;
                            p2.receive_message2::<Blake2b512>(from, m2, &gadget_vector)
                                .map_err(|e| anyhow::anyhow!("p2 recv2: {:?}", e))?;
                            r2_from.insert(from);
                            println!("[P{}] processed P2R2 from {}", pid, from);
                        }
                        other => buf.push_back(other),
                    }
                }
                while let Some((from, data)) = pending_r2.iter().next().map(|(k, v)| (*k, v.clone())) {
                    pending_r2.remove(&from);
                    let m2 = CanonicalDeserialize::deserialize_compressed(&data[..])?;
                    p2.receive_message2::<Blake2b512>(from, m2, &gadget_vector)
                        .map_err(|e| anyhow::anyhow!("p2 recv2: {:?}", e))?;
                    r2_from.insert(from);
                    println!("[P{}] processed queued P2R2 from {}", pid, from);
                }
                if r1_from.len() >= expected_r1 && r2_from.len() >= expected_r2 && pending_r2.is_empty() { break; }
            }

            let p2_out: Phase2Output<Fr> = p2.finish();
        println!("[P{}] phase 2 completed", pid);

            // Messages to sign
            let messages: Vec<Fr> = (0..MESSAGE_COUNT).map(|i| Fr::from(100 + i as u64)).collect();
            let share = BBSPlusSignatureShare::<Bls12_381>::new(
                &messages, 0, &p1_out, &p2_out, &params
            ).map_err(|e| anyhow::anyhow!("make share: {:?}", e))?;
            println!("[P{}] produced signature share", pid);

            anyhow::Ok(share)
        }));
    }

    println!("[main] spawned {} signer tasks; awaiting shares...", THRESHOLD);
    // Wait for shares
    let mut shares = Vec::new();
    for t in tasks { shares.push(t.await??); }

    // Aggregate and verify
    println!("Aggregating {} shares...", shares.len());
    let sig = BBSPlusSignatureShare::aggregate(shares)
        .map_err(|e| anyhow::anyhow!("aggregate: {:?}", e))?;
    let messages: Vec<Fr> = (0..MESSAGE_COUNT).map(|i| Fr::from(100 + i as u64)).collect();
    sig.verify(&messages, public_key, (*params).clone())
        .map_err(|e| anyhow::anyhow!("verify failed: {:?}", e))?;
    println!("OK: threshold signature verified");
    Ok(())
}
