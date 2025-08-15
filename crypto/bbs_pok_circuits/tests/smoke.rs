use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use bbs_pok_circuits::{setup, prove, verify, PublicInputs, expected_public_inputs_len, Fr};

#[test]
fn groth16_smoke() {
    let (pk, vk) = setup(8, 4).expect("setup");
    let pi = PublicInputs {
        message_count: 3,
        revealed_idx: vec![1, 2],
        revealed_vals: vec![
            <Bls12_381 as ark_ec::pairing::Pairing>::ScalarField::from(42u64),
            <Bls12_381 as ark_ec::pairing::Pairing>::ScalarField::from(7u64),
        ],
        sid_opt: Some(5),
        ..Default::default()
    };
    // Build messages where m[1]=42 and m[2]=7 to satisfy constraints
    let mut messages = vec![Fr::from(0u64); 8];
    messages[1] = Fr::from(42u64);
    messages[2] = Fr::from(7u64);
    let (proof, publics) = prove(&pk, &pi, &messages, 8, 4).expect("prove");
    let ok = verify(&vk, &proof, &publics).expect("verify");
    assert!(ok);
    assert_eq!(publics.len(), expected_public_inputs_len(4));
    // spot-check first element (params_hash -> 0)
    assert_eq!(publics[0], Fr::from(0u64));
}
