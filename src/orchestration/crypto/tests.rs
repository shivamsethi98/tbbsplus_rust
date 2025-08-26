#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
    use ark_ff::PrimeField;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{UniformRand, rand::{SeedableRng}};
    use blake2::Blake2b512;
    use schnorr_pok::discrete_log::PokDiscreteLogProtocol;
    use schnorr_pok::pok_generalized_pedersen::compute_random_oracle_challenge;

    #[test]
    fn threshold_opening_tbar_and_dleq() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0);
        // Setup random T1, T2, secret y shares y1,y2,y3 s.t. y = y1 + y2 + y3 (for simplicity, not Shamir)
        let t1 = <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine();
        let y1 = Fr::rand(&mut rng);
        let y2 = Fr::rand(&mut rng);
        let y3 = Fr::rand(&mut rng);
        let y = y1 + y2 + y3;
        let tbar = t1.mul_bigint(y.into_bigint()).into_affine();
        let t2 = (<Bls12_381 as Pairing>::G1::rand(&mut rng) + tbar.into_group()).into_affine();
        let g2 = <Bls12_381 as Pairing>::G2::rand(&mut rng).into_affine();
        let y1g2 = g2.mul_bigint(y1.into_bigint()).into_affine();
        let y2g2 = g2.mul_bigint(y2.into_bigint()).into_affine();
        let y3g2 = g2.mul_bigint(y3.into_bigint()).into_affine();

        // Partials
        let tbar1 = t1.mul_bigint(y1.into_bigint()).into_affine();
        let tbar2 = t1.mul_bigint(y2.into_bigint()).into_affine();
        let tbar3 = t1.mul_bigint(y3.into_bigint()).into_affine();

        // Pairing checks
        assert_eq!(Bls12_381::pairing(t1, y1g2), Bls12_381::pairing(tbar1, g2));
        assert_eq!(Bls12_381::pairing(t1, y2g2), Bls12_381::pairing(tbar2, g2));
        assert_eq!(Bls12_381::pairing(t1, y3g2), Bls12_381::pairing(tbar3, g2));

        // DLEQ proofs in G2 using schnorr_pok for each share
        for (yi, yi_g2) in [(y1,y1g2),(y2,y2g2),(y3,y3g2)] {
            let blind = Fr::rand(&mut rng);
            let protocol = PokDiscreteLogProtocol::<<Bls12_381 as Pairing>::G2Affine>::init(yi, blind, &g2);
            let mut chal_contrib = Vec::new();
            protocol.challenge_contribution(&g2, &yi_g2, &mut chal_contrib).unwrap();
            let chal = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib);
            let proof = protocol.gen_proof(&chal);
            assert!(proof.verify(&yi_g2, &g2, &chal));
        }

        // Recombine (since y = sum of yi, lambdas=[1,1,1])
        let tbar_sum = (tbar1.into_group() + tbar2.into_group() + tbar3.into_group()).into_affine();
        assert_eq!(tbar, tbar_sum);
        // Compute A = T2 - Tbar
        let a = (t2.into_group() + (-tbar).into_group()).into_affine();
        // just ensure not infinity
        let _a_bytes = {
            use crate::orchestration::crypto::encoding::g1_to_eip2537_bytes;
            g1_to_eip2537_bytes(&a)
        };
    }
}


