use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use bbs_pok_circuits::{PublicInputs, encode_public_inputs, blake2b512_first32, blake2b512_to_fr};

fn main() {
    // Demo inputs
    let params_label = b"bbs+ params v1";
    let pk_bytes = b"dummy-pk";
    let context = b"demo-context";
    let sid = 9u32;

    let params_hash = blake2b512_first32(params_label);
    let pk_hash = blake2b512_first32(pk_bytes);
    let context_hash = blake2b512_first32(context);

    let msg_count = 3u32;
    let revealed_idx = vec![1u32];
    let revealed_vals = vec![
        blake2b512_to_fr(b"m1"),
    ];

    let pi = PublicInputs {
        params_hash,
        pk_hash,
        message_count: msg_count,
        revealed_idx,
        revealed_vals,
        context_hash,
        sid_opt: Some(sid),
    };

    let publics = encode_public_inputs(&pi, 4);
    println!("encoded_public_inputs_len={} first={}", publics.len(), publics[0]);
}
