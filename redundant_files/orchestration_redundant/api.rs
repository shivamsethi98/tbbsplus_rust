use std::collections::BTreeSet;

use anyhow::Result;
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use blake2::Blake2b512;
use sha3::Shake256;

use bbs_plus::{
    prelude::*,
    threshold::{
        threshold_bbs_plus::BBSPlusSignatureShare,
        multiplication_phase::Phase2,
        randomness_generation_phase::Phase1,
    },
};
use oblivious_transfer_protocols::ot_based_multiplication::{
    dkls18_mul_2p::MultiplicationOTEParams,
    dkls19_batch_mul_2p::GadgetVector,
};
use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
use test_utils::ot::do_pairwise_base_ot;

// Public contract for an in-proc threshold signing run
pub struct InprocSignInput {
    pub threshold: u16,
    pub total: u16,
    pub messages: Vec<Fr>,
    pub seed: u64,
}

pub struct InprocSignOutput {
    pub signature: SignatureG1<Bls12_381>,
    pub public_key: PublicKeyG2<Bls12_381>,
    pub params: SignatureParamsG1<Bls12_381>,
    pub verified: bool,
}

// Helper: run a single-process threshold signing for the first `threshold` participants out of `total` and verify
pub fn sign_inproc(input: InprocSignInput) -> Result<InprocSignOutput> {
    let InprocSignInput { threshold, total, messages, seed } = input;

    // Parameters
    let mut rng = StdRng::seed_from_u64(seed);
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, messages.len() as u32);

    // Secret shares
    let (secret_key, key_shares) = {
        let (secret, shares, _) = deal_random_secret(&mut rng, threshold, total)
            .map_err(|e| anyhow::anyhow!("deal_random_secret failed: {:?}", e))?;
        (secret, shares.0.into_iter().map(|s| s.share).collect::<Vec<_>>())
    };
    let public_key = PublicKeyG2::generate_using_secret_key(&SecretKey(secret_key), &params);

    // OTE params
    const KAPPA: u16 = 256;
    const SSP: u16 = 80;
    const BASE_OT_KEY_SIZE: u16 = 128;
    let ote_params = MultiplicationOTEParams::<KAPPA, SSP> {};
    let gadget_vector = GadgetVector::<Fr, KAPPA, SSP>::new::<Blake2b512>(ote_params, b"threshold-bbs-plus-gadget");

    // Base OT
    let total_party_set = (1..=total).collect::<BTreeSet<_>>();
    let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
        &mut rng,
        ote_params.num_base_ot(),
        total,
        total_party_set,
    );

    // Phase 1 for first `threshold` participants
    let thresh_set = (1..=threshold).collect::<BTreeSet<_>>();
    let protocol_id = b"threshold-bbs-plus-demo".to_vec();

    let mut p1s = Vec::new();
    let mut comms = Vec::new();
    let mut comms_zero = Vec::new();

    for i in 1..=threshold {
        let mut others = thresh_set.clone();
        others.remove(&i);
        let (p1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs_plus::<_, Blake2b512>(
            &mut rng,
            1,
            i,
            others,
            protocol_id.clone(),
        ).map_err(|e| anyhow::anyhow!("phase1 init failed: {:?}", e))?;
        p1s.push(p1);
        comms.push(comm);
        comms_zero.push(comm_zero);
    }

    // Exchange commitments
    for i in 1..=threshold {
        for j in 1..=threshold {
            if i == j { continue; }
            p1s[i as usize - 1].receive_commitment(
                j,
                comms[j as usize - 1].clone(),
                comms_zero[j as usize - 1].get(&i).unwrap().clone(),
            ).map_err(|e| anyhow::anyhow!("receive_commitment failed: {:?}", e))?;
        }
    }

    // Exchange shares
    for i in 1..=threshold {
        for j in 1..=threshold {
            if i == j { continue; }
            let share = p1s[j as usize - 1].get_comm_shares_and_salts();
            let zero_share = p1s[j as usize - 1].get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i);
            p1s[i as usize - 1].receive_shares::<Blake2b512>(j, share, zero_share)
                .map_err(|e| anyhow::anyhow!("receive_shares failed: {:?}", e))?;
        }
    }

    // Finish Phase 1
    let mut p1_out = Vec::new();
    for (idx, p1) in p1s.into_iter().enumerate() {
        let out = p1.finish_for_bbs_plus::<Blake2b512>(&key_shares[idx])
            .map_err(|e| anyhow::anyhow!("phase1 finalize failed: {:?}", e))?;
        p1_out.push(out);
    }

    // Phase 2 init and exchange
    let mut p2s = Vec::new();
    let mut all_msg1 = Vec::new();
    for i in 1..=threshold {
        let mut others = thresh_set.clone();
        others.remove(&i);
        let (p2, msg1s) = Phase2::init::<_, Shake256>(
            &mut rng,
            i,
            p1_out[i as usize - 1].masked_signing_key_shares.clone(),
            p1_out[i as usize - 1].masked_rs.clone(),
            base_ot_outputs[i as usize - 1].clone(),
            others,
            ote_params,
            &gadget_vector,
        ).map_err(|e| anyhow::anyhow!("phase2 init failed: {:?}", e))?;
        p2s.push(p2);
        all_msg1.push((i, msg1s));
    }

    // Round 1
    let mut all_msg2 = Vec::new();
    for (sender, msgs) in all_msg1 {
        for (receiver, m1) in msgs {
            let m2 = p2s[receiver as usize - 1]
                .receive_message1::<Blake2b512, Shake256>(sender, m1, &gadget_vector)
                .map_err(|e| anyhow::anyhow!("receive_message1 failed: {:?}", e))?;
            all_msg2.push((receiver, sender, m2));
        }
    }

    // Round 2
    for (receiver, sender, m2) in all_msg2 {
        p2s[receiver as usize - 1]
            .receive_message2::<Blake2b512>(sender, m2, &gadget_vector)
            .map_err(|e| anyhow::anyhow!("receive_message2 failed: {:?}", e))?;
    }

    // Finish Phase 2
    let p2_out: Vec<_> = p2s.into_iter().map(|p| p.finish()).collect();

    // Signature shares
    let mut sig_shares = Vec::new();
    for i in 0..threshold as usize {
        let share = BBSPlusSignatureShare::new(&messages, 0, &p1_out[i], &p2_out[i], &params)
            .map_err(|e| anyhow::anyhow!("create signature share failed: {:?}", e))?;
        sig_shares.push(share);
    }

    // Aggregate and verify
    let signature = BBSPlusSignatureShare::aggregate(sig_shares)
        .map_err(|e| anyhow::anyhow!("aggregate failed: {:?}", e))?;
    let verified = signature.verify(&messages, public_key.clone(), params.clone()).is_ok();

    Ok(InprocSignOutput { signature, public_key, params, verified })
}

// Helper to serialize a signature to bytes
pub fn serialize_signature(sig: &SignatureG1<Bls12_381>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    sig.serialize_compressed(&mut bytes)
        .map_err(|e| anyhow::anyhow!("serialize signature failed: {:?}", e))?;
    Ok(bytes)
}
