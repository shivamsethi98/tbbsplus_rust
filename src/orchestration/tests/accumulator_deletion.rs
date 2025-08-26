#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{PrimeField, Zero};
    use ark_serialize::CanonicalSerialize;
    use ark_std::{collections::BTreeSet, rand::RngCore, vec::Vec};
    use blake2::Blake2b512;
    use oblivious_transfer_protocols::ot_based_multiplication::{
        base_ot_multi_party_pairwise::BaseOTOutput, dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::GadgetVector,
    };
    use oblivious_transfer_protocols::ParticipantId;
    use secret_sharing_and_dkg::shamir_ss::{deal_random_secret, deal_secret};
    use sha3::Shake256;
    use short_group_sig::threshold_weak_bb_sig::{Phase2, SigShare};
    use vb_accumulator::persistence::test::InMemoryState;
    use vb_accumulator::positive::{Accumulator as _, PositiveAccumulator};
    use vb_accumulator::prelude::SetupParams;
    use vb_accumulator::setup::{PublicKey, SecretKey};
    use ark_std::{rand::{rngs::StdRng, SeedableRng}, UniformRand};
    use test_utils::ot::do_pairwise_base_ot;

    const BASE_OT_KEY_SIZE: u16 = 128;
    const KAPPA: u16 = 256;
    const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
    const OTE_PARAMS: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER> =
        MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};

    fn trusted_party_keygen<R: RngCore, F: PrimeField>(
        rng: &mut R,
        threshold: ParticipantId,
        total: ParticipantId,
    ) -> (F, Vec<F>) {
        let (secret, shares, _) = deal_random_secret(rng, threshold, total).unwrap();
        (secret, shares.0.into_iter().map(|s| s.share).collect())
    }

    fn do_phase1(
        rng: &mut StdRng,
        threshold_signers: ParticipantId,
        protocol_id: Vec<u8>,
    ) -> Vec<short_group_sig::threshold_weak_bb_sig::Phase1Output<Fr>> {
        let threshold_party_set = (1..=threshold_signers).into_iter().collect::<BTreeSet<_>>();
        let mut phase1s = vec![];
        let mut commitments_zero_share = vec![];

        for i in 1..=threshold_signers {
            let mut others = threshold_party_set.clone();
            others.remove(&i);
            let (round1, comm_zero) =
                short_group_sig::threshold_weak_bb_sig::Phase1::<Fr, 256>::init::<_, Blake2b512>(
                    rng,
                    i,
                    others,
                    protocol_id.clone(),
                )
                .unwrap();
            phase1s.push(round1);
            commitments_zero_share.push(comm_zero);
        }

        for i in 1..=threshold_signers {
            for j in 1..=threshold_signers {
                if i != j {
                    phase1s[i as usize - 1]
                        .receive_commitment(
                            j,
                            commitments_zero_share[j as usize - 1]
                                .get(&i)
                                .unwrap()
                                .clone(),
                        )
                        .unwrap();
                }
            }
        }

        for i in 1..=threshold_signers {
            for j in 1..=threshold_signers {
                if i != j {
                    let zero_share = phase1s[j as usize - 1]
                        .get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i);
                    phase1s[i as usize - 1]
                        .receive_shares::<Blake2b512>(j, zero_share)
                        .unwrap();
                }
            }
        }

        phase1s
            .into_iter()
            .map(|p| p.finish::<Blake2b512>().unwrap())
            .collect::<Vec<_>>()
    }

    fn do_phase2(
        rng: &mut StdRng,
        threshold_signers: ParticipantId,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        pk_gen: &G1Affine,
        base_ot_outputs: &[BaseOTOutput],
        phase1_outs: &[short_group_sig::threshold_weak_bb_sig::Phase1Output<Fr>],
        expected_sk_term: Fr,
        secret_key_shares: &[Fr],
        full_element: Option<Fr>,
    ) -> Vec<SigShare<G1Affine>> {
        let mut phase2s = vec![];
        let mut all_msg_1s = vec![];

        let label = b"test";
        let known_element = full_element.is_some();
        let full_element = full_element.unwrap_or_default();

        for i in 1..=threshold_signers {
            let (phase, msgs) = if known_element {
                Phase2::init_for_known_message::<_, Shake256>(
                    rng,
                    i,
                    secret_key_shares[i as usize - 1],
                    full_element,
                    phase1_outs[i as usize - 1].clone(),
                    base_ot_outputs[i as usize - 1].clone(),
                    OTE_PARAMS,
                    &gadget_vector,
                    label,
                )
                .unwrap()
            } else {
                unreachable!()
            };
            phase2s.push(phase);
            all_msg_1s.push((i, msgs));
        }

        let mut sk_term = Fr::zero();
        for p in &phase2s { sk_term += p.masked_sk_term_share }
        assert_eq!(expected_sk_term, sk_term);

        let mut all_msg_2s = vec![];
        for (sender_id, msg_1s) in all_msg_1s {
            for (receiver_id, m) in msg_1s {
                let m2 = phase2s[receiver_id as usize - 1]
                    .receive_message1::<Blake2b512, Shake256>(sender_id, m, &gadget_vector)
                    .unwrap();
                all_msg_2s.push((receiver_id, sender_id, m2));
            }
        }

        for (sender_id, receiver_id, m2) in all_msg_2s {
            phase2s[receiver_id as usize - 1]
                .receive_message2::<Blake2b512>(sender_id, m2, &gadget_vector)
                .unwrap();
        }

        phase2s
            .into_iter()
            .map(|p| p.finish(pk_gen))
            .collect::<Vec<_>>()
    }

    #[test]
    fn accumulator_on_deletion_threshold() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(OTE_PARAMS, b"test-gadget-vector");

        let threshold_signers = 3;
        let total_signers = 5;

        let (sk, sk_shares) = trusted_party_keygen::<_, Fr>(&mut rng, threshold_signers, total_signers);

        let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
        let mut accumulator = PositiveAccumulator::<G1Affine>::initialize(&params);
        let mut state = InMemoryState::new();
        let secret_key = SecretKey(sk);

        let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
            &mut rng,
            OTE_PARAMS.num_base_ot(),
            total_signers,
            (1..=total_signers).collect::<BTreeSet<_>>(),
        );

        let count = 8;
        let mut elems = vec![];
        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            accumulator = accumulator.add(elem, &secret_key, &mut state).unwrap();
            elems.push(elem);
        }

        let remove_element = &elems[2];
        let expected_new = accumulator.compute_new_post_remove(remove_element, &secret_key);

        let protocol_id = b"test-acc-del".to_vec();

        let phase1_outs = do_phase1(&mut rng, threshold_signers, protocol_id.clone());
        let shares = do_phase2(
            &mut rng,
            threshold_signers,
            &gadget_vector,
            &accumulator.value(),
            &base_ot_outputs,
            &phase1_outs,
            sk + remove_element,
            &sk_shares,
            Some(remove_element.clone()),
        );

        let updated_accum = SigShare::aggregate(shares);
        assert_eq!(updated_accum, expected_new);
    }
}


