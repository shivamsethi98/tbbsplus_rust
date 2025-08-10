use std::net::SocketAddr;

use ark_bls12_381::{Bls12_381, Fr};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use dotenvy::dotenv;

use bbs_plus::prelude::*;
use tbbsplus_rust::orchestration::{config::Stage1Config, net::{connect, send_json, recv_json}, types::{fr_to_hex, Msg}};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    let cfg = Stage1Config::default();

    // Prepare params and messages
    let mut rng = StdRng::seed_from_u64(7);
    let _params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, cfg.message_count);
    let messages: Vec<Fr> = (0..cfg.message_count).map(|i| Fr::from(100 + i as u64)).collect();

    // Connect to N issuers sequentially, request shares
    let mut shares = Vec::new();

    for k in 0..cfg.threshold { // request from threshold issuers for demo
        let issuer_port = 9200 + (k as u16);
        let addr: SocketAddr = format!("127.0.0.1:{}", issuer_port).parse()?;
        if let Ok(mut stream) = connect(addr).await {
            send_json(&mut stream, &Msg::SignReq { messages: messages.iter().map(fr_to_hex).collect() }).await?;
            if let Ok(Msg::SigShare { id, share }) = recv_json(&mut stream).await {
                shares.push((id, share));
            }
        }
    }

    // Demo aggregation: ensure we have at least threshold shares and print them
    if shares.len() as u16 >= cfg.threshold {
        println!("[User] collected {} shares (>= threshold {})", shares.len(), cfg.threshold);
        for (id, s) in &shares { println!("  share from {}: {}..", id, &s[..16]); }
        println!("[User] Stage-1 demo complete (aggregation placeholder)");
    } else {
        anyhow::bail!("insufficient shares: {} < {}", shares.len(), cfg.threshold);
    }

    Ok(())
}
