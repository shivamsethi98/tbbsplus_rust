use eyre::Result;
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use bbs_plus::{
    proof::PoKOfSignatureG1Protocol,
    setup::{KeypairG2, SignatureParamsG1},
    signature::SignatureG1,
};
use blake2::Blake2b512;
use dock_crypto_utils::signature::MessageOrBlinding;
use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use rand::{rngs::StdRng, SeedableRng};
use sha3::{Digest, Keccak256};
use std::{collections::BTreeMap, env};

abigen!(
    PokWrap,
    r#"[
        function cRaw(bytes transcript) external pure returns (uint256)
    ]"#,
);

type E = Bls12_381;

fn keccak_to_fr(bytes: &[u8]) -> Fr {
    let mut h = Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    // Interpret as BE and reduce mod r via PrimeField
    Fr::from_be_bytes_mod_order(&out)
}

fn _fr_to_u256(x: &Fr) -> U256 {
    let mut bytes = vec![];
    x.serialize_compressed(&mut bytes).unwrap(); // 32 bytes canonical
    U256::from_big_endian(&bytes)
}

#[tokio::main]
async fn main() -> Result<()> {
    // 1) Setup demo params/keys/messages
    let mut rng = StdRng::seed_from_u64(23);
    let m: u32 = 5;
    let params = SignatureParamsG1::<E>::new::<Blake2b512>(b"demo-pok", m);
    let keypair = KeypairG2::<E>::generate_using_rng(&mut rng, &params);
    let mut msgs: Vec<Fr> = (0..m).map(|i| Fr::from((i as u64) + 5)).collect();
    // sign
    let sig = SignatureG1::<E>::new(&mut rng, &msgs, &keypair.secret_key, &params).expect("sign");

    // 2) Build PoK protocol with a revealed set
    let mut revealed = BTreeMap::<usize, Fr>::new();
    revealed.insert(1, msgs[1]);
    let message_iter = msgs
        .iter()
        .enumerate()
        .map(|(i, m)| if revealed.contains_key(&i) { MessageOrBlinding::RevealMessage(m) } else { MessageOrBlinding::BlindMessageRandomly(m) });
    let pok = PoKOfSignatureG1Protocol::<E>::init(
        &mut rng,
        &sig,
        &params,
        message_iter,
    ).expect("pok init");

    // 3) Get transcript bytes from the protocol
    let mut transcript = vec![];
    pok.challenge_contribution(&revealed, &params, &mut transcript).expect("contrib");

    // 4) Compute c = keccak256(transcript) mod Fr
    let c_off = keccak_to_fr(&transcript);
    let _proof = pok.gen_proof(&c_off).expect("gen proof");

    // 5) Call Solidity wrapper on local fork to recompute challenge
    let rpc = env::var("ETH_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8555".to_string());
    let provider = Provider::<Http>::try_from(rpc)?;

    // Address: deploy BbsPlusPokTranscriptWrapper beforehand, then set env WRAP_ADDR
    let addr_hex = match env::var("WRAP_ADDR") { Ok(v) => v, Err(_) => {
        println!("WRAP_ADDR not set; computed off-chain c only: {:?}", c_off);
        return Ok(());
    }};
    let addr: Address = addr_hex.parse().expect("WRAP_ADDR parse");
    let client = PokWrap::new(addr, std::sync::Arc::new(provider));

    // Compute via structured input OR raw transcript; use raw for exact match
    let c_on_raw: U256 = client.c_raw(Bytes::from(transcript.clone())).call().await?;
    let mut be = [0u8; 32];
    c_on_raw.to_big_endian(&mut be);
    let c_on_raw_fr = Fr::from_be_bytes_mod_order(&be);

    if c_on_raw_fr == c_off { println!("OK: on-chain raw challenge matches off-chain"); }
    else { println!("MISMATCH raw: on={:?} off={:?}", c_on_raw_fr, c_off); }

    Ok(())
}
