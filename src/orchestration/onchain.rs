//! Shared on-chain helpers. Phase 0 stub for params fetching and ABI utilities.
use ark_bls12_381::Bls12_381;
use bbs_plus::prelude::SignatureParamsG1;
use ethers::contract::abigen;
use ethers::providers::Middleware;
use ethers::types::Bytes as EthBytes;

use crate::orchestration::crypto::encoding::{eip2537_g1_to_affine, eip2537_g2_to_affine};

#[derive(Clone)]
pub struct ParamsBundle {
    pub params_bbs: SignatureParamsG1<Bls12_381>,
    pub mcount: u32,
    pub t: u16,
    pub n: u16,
}

abigen!(
    ParamsContract,
    "artifacts/contracts/Params.sol/Params.json"
);

pub async fn fetch_params_bundle<M: Middleware + 'static>(
    params_contract: &ParamsContract<M>,
    cred_name: &str,
) -> anyhow::Result<ParamsBundle> {
    // Use typed abigen methods that match Params.sol
    let pc = params_contract
        .get_params_by_name(cred_name.to_string())
        .call()
        .await?;
    let mcount = pc.message_count.as_u64();
    let t = pc.t.as_u64();
    let n = pc.n.as_u64();
    let (g1_b, h0_b, g2_b): (EthBytes, EthBytes, EthBytes) = params_contract
        .get_g1h0g2_by_name(cred_name.to_string())
        .call()
        .await?;
    let h_bytes: Vec<EthBytes> = params_contract
        .get_h_by_name(cred_name.to_string())
        .call()
        .await?;

    let g1 = eip2537_g1_to_affine(&g1_b.0[..])?;
    let h0 = eip2537_g1_to_affine(&h0_b.0[..])?;
    let g2 = eip2537_g2_to_affine(&g2_b.0[..])?;
    let mut h = Vec::with_capacity(h_bytes.len());
    for hb in h_bytes { h.push(eip2537_g1_to_affine(&hb.0[..])?); }
    let params_bbs = SignatureParamsG1::<Bls12_381> { g1, g2, h_0: h0, h };

    Ok(ParamsBundle { params_bbs, mcount: mcount as u32, t: t as u16, n: n as u16 })
}
