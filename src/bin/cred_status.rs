use std::env;
use std::time::Duration;

use anyhow::Context;
use sha3::Digest as _;
use ethers::abi::Abi;
use ethers::contract::Contract;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::{Bytes as EthBytes, U256, Address};
use tokio::time::sleep;
use ark_bls12_381::Fr;
use ark_serialize::CanonicalDeserialize;
use ark_ff::PrimeField;

fn decode_status(s: u8) -> &'static str {
    match s {
        0 => "None",
        1 => "Unverified",
        2 => "Verified",
        3 => "Revoked",
        _ => "Unknown",
    }
}

fn parse_args() -> anyhow::Result<(String, u64, bool, bool, bool)> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let mut name = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
    let mut sid: Option<u64> = env::var("SID").ok().and_then(|v| v.parse().ok());
    let mut watch = env::var("WATCH").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let mut confirm = env::var("CONFIRM").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let mut debug = env::var("DEBUG").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                if i + 1 >= args.len() { anyhow::bail!("--name requires value"); }
                name = args[i + 1].clone();
                i += 2;
            }
            "--sid" => {
                if i + 1 >= args.len() { anyhow::bail!("--sid requires value"); }
                sid = Some(args[i + 1].parse()?);
                i += 2;
            }
            "--watch" => {
                watch = true;
                i += 1;
            }
            "--confirm" => {
                confirm = true;
                i += 1;
            }
            "--debug" => {
                debug = true;
                i += 1;
            }
            v if sid.is_none() && v.chars().all(|c| c.is_ascii_digit()) => {
                sid = Some(v.parse()?);
                i += 1;
            }
            _ => {
                eprintln!("unknown arg: {}", args[i]);
                i += 1;
            }
        }
    }

    let sid = sid.ok_or_else(|| anyhow::anyhow!("sid not provided (use --sid <n> or SID env)"))?;
    Ok((name, sid, watch, confirm, debug))
}

async fn load_registry_contract<M: Middleware>(
    provider: std::sync::Arc<M>,
) -> anyhow::Result<(Contract<M>, Address)> {
    let registry_addr: Address = env::var("REGISTRY_CONTRACT")
        .context("REGISTRY_CONTRACT env missing")?
        .parse()
        .context("bad REGISTRY_CONTRACT address")?;

    let art_path = "artifacts/contracts/CredentialRegistry.sol/CredentialRegistry.json";
    let art_json = std::fs::read_to_string(art_path)
        .with_context(|| format!("failed reading {}", art_path))?;
    let v: serde_json::Value = serde_json::from_str(&art_json).context("parse artifact JSON")?;
    let abi_val = v.get("abi").ok_or_else(|| anyhow::anyhow!("abi missing in artifact"))?.clone();
    let abi: Abi = serde_json::from_value(abi_val).context("abi decode")?;

    let contract = Contract::new(registry_addr, abi, provider);
    Ok((contract, registry_addr))
}

// --- Helpers using precompiles ---
async fn g1add_call(provider: &std::sync::Arc<Provider<Ws>>, a128: &EthBytes, b128: &EthBytes) -> anyhow::Result<EthBytes> {
    let precompile: Address = "0x000000000000000000000000000000000000000b".parse()?;
    let data = [&a128.0[..], &b128.0[..]].concat();
    let req = serde_json::json!([{ "to": format!("0x{:040x}", precompile), "data": format!("0x{}", hex::encode(&data)) }, "latest"]);
    let out_hex: String = provider.request("eth_call", req).await?;
    let out_bytes = hex::decode(out_hex.trim_start_matches("0x"))?;
    Ok(EthBytes::from(out_bytes))
}

async fn g1msm_call(provider: &std::sync::Arc<Provider<Ws>>, p128: &EthBytes, scalars: &[U256]) -> anyhow::Result<EthBytes> {
    let precompile: Address = "0x000000000000000000000000000000000000000c".parse()?;
    let mut input = Vec::with_capacity(160 * scalars.len());
    for s in scalars.iter() {
        input.extend_from_slice(&p128.0);
        let mut be = [0u8; 32];
        s.to_big_endian(&mut be);
        input.extend_from_slice(&be);
    }
    let req = serde_json::json!([{ "to": format!("0x{:040x}", precompile), "data": format!("0x{}", hex::encode(&input)) }, "latest"]);
    let out_hex: String = provider.request("eth_call", req).await?;
    let out_bytes = hex::decode(out_hex.trim_start_matches("0x"))?;
    Ok(EthBytes::from(out_bytes))
}

async fn g1msm_many_call(provider: &std::sync::Arc<Provider<Ws>>, pts: &[&[u8]], scs: &[U256]) -> anyhow::Result<EthBytes> {
    let precompile: Address = "0x000000000000000000000000000000000000000c".parse()?;
    let mut input = Vec::with_capacity(160 * scs.len());
    for i in 0..scs.len() {
        input.extend_from_slice(pts[i]);
        let mut be = [0u8; 32];
        scs[i].to_big_endian(&mut be);
        input.extend_from_slice(&be);
    }
    let req = serde_json::json!([{ "to": format!("0x{:040x}", precompile), "data": format!("0x{}", hex::encode(&input)) }, "latest"]);
    let out_hex: String = provider.request("eth_call", req).await?;
    let out_bytes = hex::decode(out_hex.trim_start_matches("0x"))?;
    Ok(EthBytes::from(out_bytes))
}

async fn g2add_call(provider: &std::sync::Arc<Provider<Ws>>, a256: &EthBytes, b256: &EthBytes) -> anyhow::Result<EthBytes> {
    let precompile: Address = "0x000000000000000000000000000000000000000d".parse()?;
    let data = [&a256.0[..], &b256.0[..]].concat();
    let req = serde_json::json!([{ "to": format!("0x{:040x}", precompile), "data": format!("0x{}", hex::encode(&data)) }, "latest"]);
    let out_hex: String = provider.request("eth_call", req).await?;
    let out_bytes = hex::decode(out_hex.trim_start_matches("0x"))?;
    Ok(EthBytes::from(out_bytes))
}

async fn g2msm_call(provider: &std::sync::Arc<Provider<Ws>>, p256: &EthBytes, scalars: &[U256]) -> anyhow::Result<EthBytes> {
    let precompile: Address = "0x000000000000000000000000000000000000000e".parse()?;
    let mut input = Vec::with_capacity(288 * scalars.len());
    for s in scalars.iter() {
        input.extend_from_slice(&p256.0);
        let mut be = [0u8; 32];
        s.to_big_endian(&mut be);
        input.extend_from_slice(&be);
    }
    let req = serde_json::json!([{ "to": format!("0x{:040x}", precompile), "data": format!("0x{}", hex::encode(&input)) }, "latest"]);
    let out_hex: String = provider.request("eth_call", req).await?;
    let out_bytes = hex::decode(out_hex.trim_start_matches("0x"))?;
    Ok(EthBytes::from(out_bytes))
}

fn g1neg_eip(p128: &[u8]) -> EthBytes {
    if p128.len() != 128 { return EthBytes::from_static(&[]); }
    // yNeg = (modulus - y) mod modulus; leave x unchanged; zero-pad 16 bytes
    // BLS12-381 Fq modulus (BE 48 bytes)
    let fq_mod_vec = hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab").unwrap_or_else(|_| vec![0u8;48]);
    let mut out = vec![0u8; 128];
    out[..64].copy_from_slice(&p128[..64]);
    let y = &p128[80..128];
    let mut yneg = [0u8; 48];
    if y.iter().any(|&b| b != 0) {
        let mut borrow = 0i32;
        for i in (0..48).rev() {
            let m = fq_mod_vec[i] as i32;
            let yi = y[i] as i32;
            let mut diff = m - yi - borrow;
            if diff < 0 { diff += 256; borrow = 1; } else { borrow = 0; }
            yneg[i] = diff as u8;
        }
    }
    // write zero pad (64..79) then yneg
    for i in 64..80 { out[i] = 0; }
    out[80..128].copy_from_slice(&yneg);
    EthBytes::from(out)
}

async fn pairing_call(provider: &std::sync::Arc<Provider<Ws>>, g1_1: &[u8], g2_1: &[u8], g1_2: &[u8], g2_2: &[u8]) -> anyhow::Result<bool> {
    let pair: Address = "0x000000000000000000000000000000000000000f".parse()?;
    let mut input = Vec::with_capacity(128+256+128+256);
    input.extend_from_slice(g1_1);
    input.extend_from_slice(g2_1);
    input.extend_from_slice(g1_2);
    input.extend_from_slice(g2_2);
    let req = serde_json::json!([{ "to": format!("0x{:040x}", pair), "data": format!("0x{}", hex::encode(&input)) }, "latest"]);
    let out_hex: String = provider.request("eth_call", req).await?;
    let out_bytes = hex::decode(out_hex.trim_start_matches("0x"))?;
    Ok(out_bytes.len() == 32 && out_bytes[31] == 1)
}

fn fr_to_u256(fr: &Fr) -> U256 {
    use ark_ff::BigInteger;
    let bi = fr.into_bigint();
    let limbs: [u64; 4] = bi.0;
    let mut le32 = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        le32[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    let mut be32 = [0u8; 32];
    for i in 0..32 { be32[i] = le32[31 - i]; }
    U256::from_big_endian(&be32)
}

fn read_user_blinding(name: &str, sid: u64) -> Option<Fr> {
    // Prefer CLIENT_PK-derived address, else USER_ID env, else default
    let addr_hex_opt = env::var("CLIENT_PK").ok().and_then(|pk| pk.parse::<LocalWallet>().ok()).map(|w| format!("{:x}", w.address()));
    let id = addr_hex_opt.or_else(|| env::var("USER_ID").ok()).unwrap_or_else(|| "default".into());
    let p1 = format!(".runtime/users/{}/{}/sid_{}/blinding.hex", id, name, sid);
    let p2 = format!(".runtime/users/default/{}/sid_{}/blinding.hex", name, sid);
    let data = std::fs::read_to_string(&p1).ok().or_else(|| std::fs::read_to_string(&p2).ok())?;
    let s = data.trim();
    let hexstr = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hexstr).ok()?;
    let fr: Fr = CanonicalDeserialize::deserialize_compressed(&bytes[..]).ok()?;
    Some(fr)
}

fn read_local_signature(name: &str, sid: u64) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let addr_hex_opt = env::var("CLIENT_PK").ok().and_then(|pk| pk.parse::<LocalWallet>().ok()).map(|w| format!("{:x}", w.address()));
    let id = addr_hex_opt.or_else(|| env::var("USER_ID").ok()).unwrap_or_else(|| "default".into());
    let p = format!(".runtime/users/{}/{}/sid_{}/agg_signature.json", id, name, sid);
    let data = std::fs::read(&p).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let a_hex = v.get("A")?.as_str()?; let e_hex = v.get("e")?.as_str()?; let s_hex = v.get("s")?.as_str()?;
    let a = hex::decode(a_hex.trim_start_matches("0x")).ok()?;
    let e = hex::decode(e_hex.trim_start_matches("0x")).ok()?;
    let s = hex::decode(s_hex.trim_start_matches("0x")).ok()?;
    Some((a, e, s))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let (name, sid, watch, confirm, debug) = parse_args()?;

    let provider = Provider::<Ws>::connect(ws_url.clone()).await?;
    let provider = std::sync::Arc::new(provider);
    let (registry, _addr) = load_registry_contract(provider.clone()).await?;

    // Optional VerifyWrapper
    let verify_contract_opt: Option<Contract<_>> = env::var("VERIFY_CONTRACT")
        .ok()
        .and_then(|s| s.parse::<Address>().ok())
        .and_then(|addr| {
            let art_path = "artifacts/contracts/Verify.sol/VerifyWrapper.json";
            let art_json = std::fs::read_to_string(art_path).ok()?;
            let v: serde_json::Value = serde_json::from_str(&art_json).ok()?;
            let abi_val = v.get("abi")?.clone();
            let abi: Abi = serde_json::from_value(abi_val).ok()?;
            Some(Contract::new(addr, abi, provider.clone()))
        });
    // Params contract (for g1/h0/H/g2 base and pkG2)
    let params_contract_opt: Option<Contract<_>> = env::var("PARAMS_CONTRACT")
        .ok()
        .and_then(|s| s.parse::<Address>().ok())
        .and_then(|addr| {
            let art_path = "artifacts/contracts/Params.sol/Params.json";
            let art_json = std::fs::read_to_string(art_path).ok()?;
            let v: serde_json::Value = serde_json::from_str(&art_json).ok()?;
            let abi_val = v.get("abi")?.clone();
            let abi: Abi = serde_json::from_value(abi_val).ok()?;
            Some(Contract::new(addr, abi, provider.clone()))
        });

    // One-shot read
    let read_once = || async {
        let (a, e_u, s_u, st): (EthBytes, U256, U256, u8) = registry
            .method("getSignature", (name.clone(), U256::from(sid)))?
            .call()
            .await?;
        let status = decode_status(st);
        println!(
            "getSignature(name='{}', sid={}): A.len={}, e=0x{:x}, s=0x{:x}, Status={}",
            name,
            sid,
            a.0.len(),
            e_u,
            s_u,
            status
        );
        Ok::<u8, anyhow::Error>(st)
    };

    let mut last = read_once().await?;

    // Debug: reconstruct B'' off-chain using precompiles and verify pairing
    if debug {
        if let (Some(params), Some(verify_opt)) = (params_contract_opt.as_ref(), verify_contract_opt.as_ref()) {
            // Load params and request data
            let (g1_b, h0_b, g2_base): (EthBytes, EthBytes, EthBytes) = params
                .method("getG1H0G2ByName", (name.clone(),))?
                .call()
                .await?;
            let pk_g2: EthBytes = params
                .method("getPkG2ByName", (name.clone(),))?
                .call()
                .await?;
            let H: Vec<EthBytes> = params
                .method("getHByName", (name.clone(),))?
                .call()
                .await?;
            let (bprime, ridx, rvals): (EthBytes, Vec<U256>, Vec<U256>) = registry
                .method("getRequestData", (name.clone(), U256::from(sid)))?
                .call()
                .await?;
            let (A_b, e_u, s_u, _st): (EthBytes, U256, U256, u8) = registry
                .method("getSignature", (name.clone(), U256::from(sid)))?
                .call()
                .await?;

            // Build h0^s and sum revealed via G1MSM precompile
            let h0s = g1msm_call(&provider, &h0_b, &[s_u]).await.unwrap_or_else(|_| EthBytes::from_static(&[]));
            let mut bpp = g1add_call(&provider, &bprime, &h0s).await.unwrap_or_else(|_| EthBytes::from_static(&[]));
            // Debug hashes
            let mut keccak = sha3::Keccak256::new();
            keccak.update(&bprime.0); let bprime_h = keccak.finalize_reset();
            keccak.update(&h0s.0); let h0s_h = keccak.finalize_reset();
            if !ridx.is_empty() {
                let mut pts: Vec<&[u8]> = Vec::with_capacity(ridx.len());
                let mut scs: Vec<U256> = Vec::with_capacity(ridx.len());
                for i in 0..ridx.len() {
                    let j = ridx[i].as_usize();
                    if j < H.len() { pts.push(&H[j].0); scs.push(rvals[i]); }
                }
                let sum_rev = g1msm_many_call(&provider, &pts, &scs).await.unwrap_or_else(|_| EthBytes::from_static(&[]));
                bpp = g1add_call(&provider, &bpp, &sum_rev).await.unwrap_or(bpp);
                keccak.update(&sum_rev.0); let sum_rev_h = keccak.finalize_reset();
                println!("[debug] hashes: B'={}, h0^s={}, sumRevealed={}", hex::encode(bprime_h), hex::encode(h0s_h), hex::encode(sum_rev_h));
            } else {
                println!("[debug] hashes: B'={}, h0^s={}, sumRevealed=<none>", hex::encode(bprime_h), hex::encode(h0s_h));
            }
            let g1_plus_bpp = g1add_call(&provider, &g1_b, &bpp).await.unwrap_or_else(|_| EthBytes::from_static(&[]));
            keccak.update(&g1_plus_bpp.0); let g1bpp_h = keccak.finalize_reset();
            keccak.update(&A_b.0); let A_h = keccak.finalize_reset();
            keccak.update(&pk_g2.0); let pk_h = keccak.finalize_reset();
            println!("[debug] hashes: g1+Bpp={}, A={}, pkG2={}", hex::encode(g1bpp_h), hex::encode(A_h), hex::encode(pk_h));

            // Recompute B' locally from user blinding and on-chain H for hidden set, compare to registry B'
            if let Some(r_fr) = read_user_blinding(&name, sid) {
                // Hidden set = all indices except revealed
                // fetch messageCount by counting H length
                let mc = H.len();
                // Build MSM input: include h0^r and all hidden H[i]^m[i] with m[i] default 100+i, or sid for i=0 if hidden
                // Start with h0^r
                let r_u = fr_to_u256(&r_fr);
                let mut pts: Vec<&[u8]> = vec![&h0_b.0];
                let mut scs: Vec<U256> = vec![r_u];
                // Prepare revealed set lookup
                let mut is_revealed = vec![false; mc];
                for i in 0..ridx.len() { let j = ridx[i].as_usize(); if j < mc { is_revealed[j] = true; } }
                for i in 0..mc {
                    if i==0 { continue; }
                    if is_revealed[i] { continue; }
                    // hidden index i
                    pts.push(&H[i].0);
                    let m_val = U256::from(100u64 + i as u64);
                    scs.push(m_val);
                }
                let bprime_local = g1msm_many_call(&provider, &pts, &scs).await.unwrap_or_else(|_| EthBytes::from_static(&[]));
                keccak.update(&bprime_local.0); let bpl_h = keccak.finalize_reset();
                println!("[debug] B'local hash={} (should equal registry B'={})", hex::encode(bpl_h), hex::encode(bprime_h));
            } else {
                println!("[debug] skipped B'local: blinding not found");
            }

            // Negate g1_plus_bpp
            let neg_g1_plus_bpp = if let Some(verify) = verify_contract_opt.as_ref() {
                verify.method::<_, EthBytes>("g1neg", (g1_plus_bpp.clone(),))?.call().await.unwrap_or_else(|_| EthBytes::from_static(&[]))
            } else {
                g1neg_eip(&g1_plus_bpp.0)
            };

            // Compute pkG2 + e*g2base
            let eg2 = g2msm_call(&provider, &g2_base, &[e_u]).await.unwrap_or_else(|_| EthBytes::from_static(&[]));
            let pk_plus_eg2 = g2add_call(&provider, &pk_g2, &eg2).await.unwrap_or_else(|_| EthBytes::from_static(&[]));

            // Pairing via VerifyWrapper or precompile 0x0f (with pk+e*g2base)
            let ok_with_e = if let Some(verify) = verify_contract_opt.as_ref() {
                verify
                    .method::<_, bool>("verifyPairing", (A_b.clone(), pk_plus_eg2.clone(), neg_g1_plus_bpp.clone(), g2_base.clone()))?
                    .call()
                    .await
                    .unwrap_or(false)
            } else {
                pairing_call(&provider, &A_b.0, &pk_plus_eg2.0, &neg_g1_plus_bpp.0, &g2_base.0).await.unwrap_or(false)
            };
            // Also check without the e term for comparison
            let ok_pk_only = if let Some(verify) = verify_contract_opt.as_ref() {
                verify
                    .method::<_, bool>("verifyPairing", (A_b.clone(), pk_g2.clone(), neg_g1_plus_bpp.clone(), g2_base.clone()))?
                    .call()
                    .await
                    .unwrap_or(false)
            } else {
                pairing_call(&provider, &A_b.0, &pk_g2.0, &neg_g1_plus_bpp.0, &g2_base.0).await.unwrap_or(false)
            };
            println!("[debug] off-chain reconstructed pairing -> with_e={} pk_only={}", ok_with_e, ok_pk_only);

            // Diagnostics: try alternative constructions to identify source of mismatch
            // 1) No h0^s term
            let g1_plus_bpp_noh0s = {
                let sum_rev_only = if !ridx.is_empty() {
                    let mut pts: Vec<&[u8]> = Vec::with_capacity(ridx.len());
                    let mut scs: Vec<U256> = Vec::with_capacity(ridx.len());
                    for i in 0..ridx.len() { let j = ridx[i].as_usize(); if j < H.len() { pts.push(&H[j].0); scs.push(rvals[i]); } }
                    g1msm_many_call(&provider, &pts, &scs).await.unwrap_or_else(|_| EthBytes::from_static(&[]))
                } else { EthBytes::from_static(&[0u8;128]) };
                let bpp_noh0s = if sum_rev_only.0.is_empty() || sum_rev_only.0.len()!=128 { bprime.clone() } else { g1add_call(&provider, &bprime, &sum_rev_only).await.unwrap_or(bprime.clone()) };
                g1add_call(&provider, &g1_b, &bpp_noh0s).await.unwrap_or_else(|_| EthBytes::from_static(&[]))
            };
            let neg_noh0s = if let Some(verify) = verify_contract_opt.as_ref() { verify.method::<_, EthBytes>("g1neg", (g1_plus_bpp_noh0s.clone(),))?.call().await.unwrap_or_else(|_| EthBytes::from_static(&[])) } else { g1neg_eip(&g1_plus_bpp_noh0s.0) };
            let ok_noh0s = if let Some(verify) = verify_contract_opt.as_ref() { verify.method::<_, bool>("verifyPairing", (A_b.clone(), pk_plus_eg2.clone(), neg_noh0s.clone(), g2_base.clone()))?.call().await.unwrap_or(false) } else { pairing_call(&provider, &A_b.0, &pk_plus_eg2.0, &neg_noh0s.0, &g2_base.0).await.unwrap_or(false) };

            // 2) Treat B' as hidden-only: subtract h0^r if we can read r, then add h0^s
            let mut ok_hidden = false;
            if let Some(r_fr) = read_user_blinding(&name, sid) {
                let r_u = fr_to_u256(&r_fr);
                let h0r = g1msm_call(&provider, &h0_b, &[r_u]).await.unwrap_or_else(|_| EthBytes::from_static(&[]));
                let neg_h0r = if let Some(verify) = verify_contract_opt.as_ref() { verify.method::<_, EthBytes>("g1neg", (h0r.clone(),))?.call().await.unwrap_or_else(|_| EthBytes::from_static(&[])) } else { g1neg_eip(&h0r.0) };
                let bprime_hidden = g1add_call(&provider, &bprime, &neg_h0r).await.unwrap_or_else(|_| bprime.clone());
                let bpp_hidden = g1add_call(&provider, &bprime_hidden, &h0s).await.unwrap_or_else(|_| bprime_hidden.clone());
                let bpp_hidden_plus_rev = if !ridx.is_empty() {
                    let mut pts: Vec<&[u8]> = Vec::with_capacity(ridx.len());
                    let mut scs: Vec<U256> = Vec::with_capacity(ridx.len());
                    for i in 0..ridx.len() { let j = ridx[i].as_usize(); if j < H.len() { pts.push(&H[j].0); scs.push(rvals[i]); } }
                    let sum_rev = g1msm_many_call(&provider, &pts, &scs).await.unwrap_or_else(|_| EthBytes::from_static(&[]));
                    g1add_call(&provider, &bpp_hidden, &sum_rev).await.unwrap_or(bpp_hidden)
                } else { bpp_hidden };
                let g1_plus_bpp_hidden = g1add_call(&provider, &g1_b, &bpp_hidden_plus_rev).await.unwrap_or_else(|_| EthBytes::from_static(&[]));
                let neg_hidden = if let Some(verify) = verify_contract_opt.as_ref() { verify.method::<_, EthBytes>("g1neg", (g1_plus_bpp_hidden.clone(),))?.call().await.unwrap_or_else(|_| EthBytes::from_static(&[])) } else { g1neg_eip(&g1_plus_bpp_hidden.0) };
                ok_hidden = if let Some(verify) = verify_contract_opt.as_ref() { verify.method::<_, bool>("verifyPairing", (A_b.clone(), pk_plus_eg2.clone(), neg_hidden.clone(), g2_base.clone()))?.call().await.unwrap_or(false) } else { pairing_call(&provider, &A_b.0, &pk_plus_eg2.0, &neg_hidden.0, &g2_base.0).await.unwrap_or(false) };
            }
            println!("[debug] pairing variants: with_e={} no_h0s={} hidden_only+add_h0s={}", ok_with_e, ok_noh0s, ok_hidden);
            // Optional: could decode full CredParams here to cross-check messageCount; skipped for brevity
        }
    }

    // If --confirm provided, try to call confirmCredential when status is Unverified and data is present
    if confirm && last == 1 {
        // We need a signer: use CLIENT_PK or OWNER_PK from env
        let ws_url2 = ws_url.clone();
        let chain_id: u64 = env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse().unwrap_or(31337);
        let pk_env = env::var("CLIENT_PK").or_else(|_| env::var("OWNER_PK"))
            .context("CLIENT_PK or OWNER_PK required for --confirm")?;
        let wallet: LocalWallet = pk_env.parse::<LocalWallet>()?.with_chain_id(chain_id);
        let provider2 = Provider::<Ws>::connect(ws_url2).await?;
        let client = std::sync::Arc::new(SignerMiddleware::new(provider2, wallet));
        let (reg2, _addr2) = load_registry_contract(client.clone()).await?;
        // Send confirmCredential(name, sid)
        match reg2.method::<_, ()>("confirmCredential", (name.clone(), U256::from(sid)))?.send().await {
            Ok(pending) => {
                let _ = pending.await?; // wait mined
                println!("confirmCredential sent and mined");
                // Re-read status once
                last = read_once().await?;
            }
            Err(e) => eprintln!("confirmCredential error: {:?}", e),
        }
    }
    if watch {
        let interval_ms: u64 = env::var("POLL_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
        let exit_on_verified = env::var("EXIT_ON_VERIFIED").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(true);
        loop {
            sleep(Duration::from_millis(interval_ms)).await;
            match read_once().await {
                Ok(cur) => {
                    if cur != last {
                        println!("Status changed: {} -> {}", decode_status(last), decode_status(cur));
                        last = cur;
                    }
                    if exit_on_verified && cur == 2 {
                        println!("Verified reached; exiting.");
                        break;
                    }
                }
                Err(e) => eprintln!("poll error: {:?}", e),
            }
        }
    }

    Ok(())
}
