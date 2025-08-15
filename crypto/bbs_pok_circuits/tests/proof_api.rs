use ark_bls12_381::Bls12_381;
use bbs_pok_circuits::{self as circuits, Fr, PublicInputs};

#[test]
fn offchain_proof_api_roundtrip() {
    let max_messages = 8;
    let max_revealed = 4;
    let (pk, vk) = circuits::setup(max_messages, max_revealed).expect("setup");

    // a minimal instance: reveal one value m[1] = 42
    let mut messages = vec![Fr::from(0u64); max_messages as usize];
    messages[1] = Fr::from(42u64);
    let pi = PublicInputs { message_count: 3, revealed_idx: vec![1], revealed_vals: vec![messages[1]], ..Default::default() };

    let snark = circuits::proof::create_proof(&pk, &pi, &messages, max_messages, max_revealed).expect("prove");
    let ok = circuits::proof::verify_proof(&vk, &snark).expect("verify call");
    assert!(ok);

    // serialization
    let bytes = snark.to_bytes();
    let snark2 = circuits::proof::SnarkProof::from_bytes(&bytes, circuits::proof::pi_len(max_revealed)).expect("from_bytes");
    let ok2 = circuits::proof::verify_proof(&vk, &snark2).expect("verify call 2");
    assert!(ok2);
}
