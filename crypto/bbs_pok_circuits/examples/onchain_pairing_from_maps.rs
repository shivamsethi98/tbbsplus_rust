// Query MAP precompiles to get P in G1 and Q in G2, then craft pairing inputs
// e(P, Q) * e(-P, Q) == 1, or e(P, Q) * e(P, -Q) == 1, depending on encoding order.
// This mirrors test/eip2537.precompiles.spec.ts logic.

use dotenvy::dotenv;
use ethers::providers::{Http, Provider};
use ethers::providers::Middleware;
use ethers::types::{Bytes, TransactionRequest, H160};
use ethers::types::transaction::eip2718::TypedTransaction;
use num_bigint::BigUint;
use num_traits::Zero;
use std::env;

const ADDR_PAIR: &str = "000000000000000000000000000000000000000f";
const ADDR_MAP1: &str = "0000000000000000000000000000000000000010";
const ADDR_MAP2: &str = "0000000000000000000000000000000000000011";

// bls12-381 Fp modulus as 64-byte big-endian hex (no 0x)
const FP_MODULUS_HEX_64: &str = concat!(
    "00000000000000000000000000000000",
    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624",
    "1eabfffeb153ffffb9feffffffffaaab",
);

fn hex_to_h160(s: &str) -> H160 { H160::from_slice(&hex::decode(s).unwrap()) }

fn be_hex_to_biguint(hex_no_0x: &str) -> BigUint { BigUint::parse_bytes(hex_no_0x.as_bytes(), 16).unwrap() }

fn biguint_to_hex_be(n: &BigUint, bytes: usize) -> String {
    let mut h = n.to_str_radix(16);
    if h.len() > bytes * 2 { panic!("overflow"); }
    while h.len() < bytes * 2 { h.insert(0, '0'); }
    h
}

fn neg_fp64(hex64: &str) -> String {
    let p = be_hex_to_biguint(FP_MODULUS_HEX_64);
    let a = be_hex_to_biguint(hex64);
    let mut neg = if a.is_zero() { BigUint::zero() } else { &p - (a % &p) };
    // ensure < p
    neg %= &p;
    biguint_to_hex_be(&neg, 64)
}

fn neg_g1_uncompressed_128(g1_0x: &str) -> String {
    let s = &g1_0x[2..];
    let x = &s[0..128];
    let y = &s[128..256];
    let y_neg = neg_fp64(y);
    format!("0x{}{}", x, y_neg)
}

fn split_g2_xy(g2_0x: &str) -> (String, String, String, String) {
    let s = &g2_0x[2..];
    let x0 = s[0..128].to_string();
    let x1 = s[128..256].to_string();
    let y0 = s[256..384].to_string();
    let y1 = s[384..512].to_string();
    (x0, x1, y0, y1)
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv().ok();
    let rpc = env::var("ETH_RPC_URL")
        .or_else(|_| env::var("SEPOLIA_URL"))
        .or_else(|_| env::var("HOODI_URL"))
        .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let provider = Provider::<Http>::try_from(rpc)?;

    // Query MAP precompiles
    let to_map1 = hex_to_h160(ADDR_MAP1);
    let to_map2 = hex_to_h160(ADDR_MAP2);
    let map1_tx: TypedTransaction = TransactionRequest::new().to(to_map1).data(Bytes::from(vec![0u8;64])).into();
    let map2_tx: TypedTransaction = TransactionRequest::new().to(to_map2).data(Bytes::from(vec![0u8;128])).into();

    let P_bytes: Bytes = match provider.call(&map1_tx, None).await {
        Ok(b) if b.0.len() == 128 => b,
        Ok(b) => {
            println!("MAP1 absent or unexpected len: {} bytes", b.0.len());
            return Ok(());
        }
        Err(_) => { println!("MAP1 call failed (likely precompile absent)"); return Ok(()); }
    };
    let Q_bytes: Bytes = match provider.call(&map2_tx, None).await {
        Ok(b) if b.0.len() == 256 => b,
        Ok(b) => { println!("MAP2 absent or unexpected len: {} bytes", b.0.len()); return Ok(()); }
        Err(_) => { println!("MAP2 call failed (likely precompile absent)"); return Ok(()); }
    };

    let P = format!("0x{}", hex::encode(P_bytes.to_vec()));
    let Q = format!("0x{}", hex::encode(Q_bytes.to_vec()));

    // Build candidate pairing inputs (two possible Fp2 limb orders)
    let (x0, x1, y0, y1) = split_g2_xy(&Q);
    let order_a_x = format!("{}{}", x0, x1);
    let order_a_y = format!("{}{}", y0, y1);
    let order_b_x = format!("{}{}", x1, x0);
    let order_b_y = format!("{}{}", y1, y0);

    let nP = neg_g1_uncompressed_128(&P);
    let nY0 = neg_fp64(&y0);
    let nY1 = neg_fp64(&y1);
    let nY_a = format!("{}{}", nY0, nY1);
    let nY_b = format!("{}{}", nY1, nY0);

    let p_no = &P[2..];
    let np_no = &nP[2..];
    let cand = vec![
        // order A: e(P,Q)*e(-P,Q)
        [p_no, &order_a_x, &order_a_y, np_no, &order_a_x, &order_a_y].concat(),
        // order A: e(P,Q)*e(P,-Q)
        [p_no, &order_a_x, &order_a_y, p_no, &order_a_x, &nY_a].concat(),
        // order B: e(P,Q)*e(-P,Q)
        [p_no, &order_b_x, &order_b_y, np_no, &order_b_x, &order_b_y].concat(),
        // order B: e(P,Q)*e(P,-Q)
        [p_no, &order_b_x, &order_b_y, p_no, &order_b_x, &nY_b].concat(),
    ];

    let to_pair = hex_to_h160(ADDR_PAIR);
    for (i, data_no0x) in cand.iter().enumerate() {
        let data_bytes = Bytes::from(hex::decode(data_no0x).unwrap());
        let tx: TypedTransaction = TransactionRequest::new().to(to_pair).data(data_bytes).into();
        match provider.call(&tx, None).await {
            Ok(res) => {
                let hexres = hex::encode(res.to_vec());
                println!("candidate {} -> len={} bytes, res=0x{}", i, res.0.len(), hexres);
                if res.0.len() == 32 && hexres.ends_with("01") {
                    println!("PAIR success for candidate {} (ends with 01)", i);
                    break;
                }
            }
            Err(e) => {
                println!("candidate {} errored: {}", i, e);
            }
        }
    }

    Ok(())
}
