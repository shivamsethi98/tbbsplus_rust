// no_std imports

use ark_bls12_381::Bls12_381;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use dotenvy::dotenv;
use tokio::net::TcpListener;

use bbs_plus::prelude::*;
use tbbsplus_rust::orchestration::{
    config::Stage1Config,
    net::{connect, listen, recv_json, send_json},
    types::{fr_from_hex, Msg},
};
use blake2::{Blake2b512, Digest};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    let cfg = Stage1Config::default();

    // Connect to TTP to get id and key share
    let mut ttp = connect(cfg.ttp_addr).await?;
    let assign: Msg = recv_json(&mut ttp).await?;
    let (id, _sk_share) = match assign { Msg::Assign { id, sk_share } => (id, fr_from_hex(&sk_share)?), _ => anyhow::bail!("unexpected msg") };
    println!("[Issuer {}] received key share", id);

    // Generate params locally (demo). In a real setup, broadcast params or fetch from contract
    let mut rng = StdRng::seed_from_u64(100 + id as u64);
    let _params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, cfg.message_count);

    // Determine bind address: if not provided or OS-assigned, default to 127.0.0.1:9200+(id-1)
    let effective_bind = if cfg.issuer_bind.ip().is_loopback() && cfg.issuer_bind.port() == 0 {
        let port: u16 = 9200 + (id - 1);
        format!("127.0.0.1:{}", port).parse::<std::net::SocketAddr>()?
    } else {
        cfg.issuer_bind
    };
    let listener: TcpListener = listen(effective_bind).await?;
    println!("[Issuer {}] listening at {}", id, listener.local_addr()?);
    let (mut user, _addr) = listener.accept().await?;

    // Receive sign request
    let req: Msg = recv_json(&mut user).await?;
    let messages = match req {
        Msg::SignReq { messages } => {
            messages.iter().map(|s| fr_from_hex(s)).collect::<Result<Vec<_>, _>>()?
        },
        _ => anyhow::bail!("unexpected msg")
    };

    // Produce demo signature share: hash(id || messages) as hex string
    let mut hasher = Blake2b512::new();
    hasher.update(&id.to_be_bytes());
    for m in &messages {
        let mut bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(m, &mut bytes)?;
        hasher.update(&bytes);
    }
    let share_hex = hex::encode(hasher.finalize());

    send_json(&mut user, &Msg::SigShare { id, share: share_hex }).await?;
    println!("[Issuer {}] sent signature share", id);

    Ok(())
}
