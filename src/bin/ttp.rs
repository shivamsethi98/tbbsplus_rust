use std::{collections::BTreeSet, net::SocketAddr};

use ark_bls12_381::Fr;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use dotenvy::dotenv;
use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
use tokio::{net::TcpListener, task::JoinSet};

use tbbsplus_rust::orchestration::{config::Stage1Config, net::{listen, send_json}, types::{fr_to_hex, Msg}};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    let cfg = Stage1Config::default();
    let threshold = cfg.threshold;
    let total = cfg.total;

    println!("[TTP] threshold {} of {}, listening at {}", threshold, total, cfg.ttp_addr);

    // Deal secret and shares (demo only)
    let mut rng = StdRng::seed_from_u64(42);
    let (_secret, shares, _) = deal_random_secret(&mut rng, threshold, total)
        .map_err(|e| anyhow::anyhow!("deal_random_secret failed: {e:?}"))?;
    let shares: Vec<Fr> = shares.0.into_iter().map(|s| s.share).collect();

    // Accept connections from issuers and assign ids sequentially
    let listener: TcpListener = listen(cfg.ttp_addr).await?;
    let mut set = JoinSet::new();
    let mut next_id: u16 = 1;
    let mut assigned: BTreeSet<u16> = BTreeSet::new();

    loop {
    let (mut stream, addr) = listener.accept().await?;
        if (next_id as usize) > shares.len() { continue; }
        let id = next_id; next_id += 1; assigned.insert(id);
        let sk_share = shares[(id - 1) as usize].clone();
        println!("[TTP] issuer {} connected from {}", id, addr);
        set.spawn(async move {
            let payload = Msg::Assign { id, sk_share: fr_to_hex(&sk_share) };
            let _ = send_json(&mut stream, &payload).await;
        });
    }
}
