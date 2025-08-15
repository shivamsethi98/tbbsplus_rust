use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_groth16::{VerifyingKey};
use bbs_pok_circuits::{setup, PublicInputs};
use serde::Serialize;

#[derive(Serialize)]
struct G1Point { x: String, y: String }
#[derive(Serialize)]
struct G2Point { x: [String; 2], y: [String; 2] }
#[derive(Serialize)]
struct VkJson {
    alpha_g1: G1Point,
    beta_g2: G2Point,
    gamma_g2: G2Point,
    delta_g2: G2Point,
    gamma_abc_g1: Vec<G1Point>,
}

fn fr_to_hex<F: ark_ff::PrimeField>(f: F) -> String {
    let mut bytes = Vec::new();
    f.serialize_uncompressed(&mut bytes).unwrap();
    format!("0x{}", hex::encode(bytes))
}

fn g1_to_json(p: G1Affine) -> G1Point {
    let x = fr_to_hex(p.x);
    let y = fr_to_hex(p.y);
    G1Point { x, y }
}

fn g2_to_json(p: G2Affine) -> G2Point {
    let x0 = fr_to_hex(p.x.c0);
    let x1 = fr_to_hex(p.x.c1);
    let y0 = fr_to_hex(p.y.c0);
    let y1 = fr_to_hex(p.y.c1);
    G2Point { x: [x0, x1], y: [y0, y1] }
}

fn vk_to_json(vk: &VerifyingKey<Bls12_381>) -> VkJson {
    let alpha = g1_to_json(vk.alpha_g1);
    let beta = g2_to_json(vk.beta_g2);
    let gamma = g2_to_json(vk.gamma_g2);
    let delta = g2_to_json(vk.delta_g2);
    let gamma_abc = vk.gamma_abc_g1.iter().map(|p| g1_to_json(*p)).collect();
    VkJson { alpha_g1: alpha, beta_g2: beta, gamma_g2: gamma, delta_g2: delta, gamma_abc_g1: gamma_abc }
}

fn main() {
    let (_pk, vk) = setup(8, 4).expect("setup");
    let vk_json = vk_to_json(&vk);
    let s = serde_json::to_string_pretty(&vk_json).unwrap();
    println!("{}", s);
}
