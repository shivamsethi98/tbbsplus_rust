use ark_bls12_381::Fr;
use tbbsplus_rust::orchestration::api::{InprocSignInput, sign_inproc};

#[test]
fn inproc_threshold_3_of_4_verifies() {
    let messages: Vec<Fr> = (0..5).map(|i| Fr::from(100 + i as u64)).collect();
    let out = sign_inproc(InprocSignInput { threshold: 3, total: 4, messages: messages.clone(), seed: 42 }).unwrap();
    assert!(out.verified, "signature should verify");
}

#[test]
fn inproc_threshold_2_of_3_verifies() {
    let messages: Vec<Fr> = (0..3).map(|i| Fr::from(7 + i as u64)).collect();
    let out = sign_inproc(InprocSignInput { threshold: 2, total: 3, messages: messages.clone(), seed: 1337 }).unwrap();
    assert!(out.verified, "signature should verify");
}

#[test]
fn inproc_threshold_3_of_4_meshlike_verifies() {
    // Same as first test but distinct seed to simulate another session
    let messages: Vec<Fr> = (0..5).map(|i| Fr::from(200 + i as u64)).collect();
    let out = sign_inproc(InprocSignInput { threshold: 3, total: 4, messages: messages.clone(), seed: 4242 }).unwrap();
    assert!(out.verified, "signature should verify (mesh-like)");
}
