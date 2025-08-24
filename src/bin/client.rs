// (removed older duplicate helpers; see implementations below)
// Interactive CLI client: create a credential request or verify by session id.
// Usage:
//   cargo run --bin client --features mpc               # interactive prompts
//   cargo run --bin client --features mpc -- 5          # request sid=5 (non-interactive legacy mode)
//   cargo run --bin client --features mpc -- verify 5   # verify existing sid=5 by fetching on-chain shares
use std::env;
use std::io::{self, Write};

use ark_bls12_381::{Bls12_381, Fr, Fq};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::{rngs::StdRng, SeedableRng}, UniformRand};
use bbs_plus::prelude::*;
use blake2::Blake2b512;
use ark_ff::PrimeField;
use schnorr_pok::{SchnorrChallengeContributor, pok_generalized_pedersen::{SchnorrCommitment, compute_random_oracle_challenge}};
use ethers::contract::abigen;
use ethers::prelude::*;
use ethers::contract::Contract;
use ethers::abi::Abi;
use ethers::types::Bytes as EthBytes;
use ethers::providers::{Provider, Ws};
use ethers::types::TxHash;
use ethers::types::H256;
use futures::StreamExt;

// Bring solidity helpers into scope directly
use tbbsplus_rust::orchestration::helpers::{
    decode_commitment_pok_for_onchain,
    persist_share,
    load_persisted_shares,
    persist_request_meta,
    u256_to_fr,
    build_commitment_pok,
    fr_to_u256,
    keccak_to_fr,
    fq_to_be64,
    g1_to_eip2537_bytes,
    fq2_to_be64_pair,
    g2_to_eip2537_bytes,
    eip2537_g1_to_affine,
    eip2537_g2_to_affine,
};

abigen!(
    RequestCredential,
    "artifacts/contracts/RequestCredential.sol/RequestCredential.json"
);
abigen!(
    Params,
    "artifacts/contracts/Params.sol/Params.json"
);

// Note: we avoid abigen! for VerifyWrapper and instead use a dynamic Contract with ABI loaded at runtime,
// to prevent duplicate error type collisions when multiple contracts define the same error names.

// Local credential helpers
fn local_credential_present(user_id: &str, cred_name: &str, sid: u64) -> bool {
    use std::path::PathBuf;
    let base: PathBuf = [".runtime", "users", user_id, cred_name, &format!("sid_{}", sid)].iter().collect();
    base.join("agg_signature.json").exists()
}

async fn interactive_local_actions(
    user_id: &str,
    client: &std::sync::Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    params_contract: &Params<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    cred_name: &str,
    sid: u64,
) -> anyhow::Result<()> {
    // Delegate to common action loop using on-disk artifacts
    persist_and_optionally_present(user_id, client, params_contract, cred_name, 0, sid, Vec::new()).await
}

fn persist_revealed_pairs(
    user_id: &str,
    cred_name: &str,
    sid: u64,
    revealed_idx: &Vec<u32>,
    revealed_vals: &Vec<U256>,
) -> anyhow::Result<()> {
    use std::fs;
    use std::path::PathBuf;
    let dir: PathBuf = [".runtime", "users", user_id, cred_name, &format!("sid_{}", sid)].iter().collect();
    fs::create_dir_all(&dir)?;
    let vals_hex: Vec<String> = revealed_vals.iter().map(|v| {
        let mut be = [0u8; 32];
        v.to_big_endian(&mut be);
        format!("0x{}", hex::encode(be))
    }).collect();
    let obj = serde_json::json!({
        "idx": revealed_idx,
        "vals": vals_hex,
    });
    fs::write(dir.join("revealed.json"), serde_json::to_vec_pretty(&obj)?)?;
    Ok(())
}

pub fn load_revealed_pairs(
    user_id: &str,
    cred_name: &str,
    sid: u64,
) -> anyhow::Result<Option<Vec<(u32, Fr)>>> {
    use std::fs;
    use std::path::PathBuf;
    let p: PathBuf = [".runtime", "users", user_id, cred_name, &format!("sid_{}", sid), "revealed.json"].iter().collect();
    if !p.exists() { return Ok(None); }
    let v: serde_json::Value = serde_json::from_slice(&fs::read(p)?)?;
    let idx_arr = v.get("idx").and_then(|x| x.as_array()).ok_or_else(|| anyhow::anyhow!("bad revealed.idx"))?;
    let vals_arr = v.get("vals").and_then(|x| x.as_array()).ok_or_else(|| anyhow::anyhow!("bad revealed.vals"))?;
    if idx_arr.len() != vals_arr.len() { return Ok(None); }
    let mut out = Vec::with_capacity(idx_arr.len());
    for (i_v, s_v) in idx_arr.iter().zip(vals_arr.iter()) {
        let i_u32 = i_v.as_u64().ok_or_else(|| anyhow::anyhow!("idx not u64"))? as u32;
        let s = s_v.as_str().ok_or_else(|| anyhow::anyhow!("val not string"))?;
        let u = if s.starts_with("0x") { U256::from_str_radix(&s[2..], 16)? } else { U256::from_dec_str(s)? };
        let fr: Fr = u256_to_fr(&u);
        out.push((i_u32, fr));
    }
    Ok(Some(out))
}

fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    if !prompt.is_empty() { print!("{}: ", prompt); io::stdout().flush()?; }
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s.trim_end().to_string())
}

fn prompt_parse_u64(prompt: &str, default: u64) -> anyhow::Result<u64> {
    let l = prompt_line(&format!("{} [default: {}]", prompt, default))?;
    if l.trim().is_empty() { return Ok(default); }
    Ok(l.trim().parse()?)
}

fn parse_revealed(line: &str) -> anyhow::Result<(Vec<u32>, Vec<U256>)> {
    let mut idx = Vec::new();
    let mut vals = Vec::new();
    for part in line.split(',') {
        let p = part.trim();
        if p.is_empty() { continue; }
        let mut it = p.split('=');
        let i: u32 = it.next().ok_or_else(|| anyhow::anyhow!("bad pair"))?.trim().parse()?;
        let v_str = it.next().ok_or_else(|| anyhow::anyhow!("bad pair"))?.trim();
        let v = if v_str.starts_with("0x") { U256::from_str_radix(&v_str[2..], 16)? } else { U256::from_dec_str(v_str)? };
        idx.push(i); vals.push(v);
    }
    Ok((idx, vals))
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let chain_id: u64 = env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse()?;
    let req_addr: Address = env::var("REQ_CONTRACT").expect("REQ_CONTRACT").parse()?;
    // Note: RELAY_CONTRACT deprecated; using CredentialRegistry events and getters
    let params_addr: Address = env::var("PARAMS_CONTRACT").expect("PARAMS_CONTRACT").parse()?;
    let cred_name = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
    let t: u16 = env::var("THRESHOLD").unwrap_or_else(|_| "3".into()).parse()?;
    let mcount: u32 = env::var("MESSAGE_COUNT").unwrap_or_else(|_| "5".into()).parse()?;
    // Parse mode/args
    enum Mode {
        Request { sid: u64, revealed_idx: Vec<u32>, revealed_vals: Vec<U256>, context: Vec<u8>, wait_and_verify: bool },
        Verify { sid: u64 },
        DebugG2,
    }

    let args = env::args().skip(1).collect::<Vec<_>>();
    let mode: Mode = if args.is_empty() {
        // Interactive
        println!("Client interactive mode");
        // sid
        let sid = prompt_parse_u64("Enter session id (sid)", 1)?;
        // If credential already exists locally, enter local action loop and do not request on-chain
        let user_id_preview = env::var("USER_ID").unwrap_or_else(|_| "unknown".into());
        if local_credential_present(&user_id_preview, &cred_name, sid) {
            // We need an initialized client to run actions; fall through and handle after client init
            // For now, select Verify mode and the code below will handle the local-actions once client is ready
            Mode::Verify { sid }
        } else {
        // choose mode
        let m = prompt_line("Choose mode: [r]equest or [v]erify (default: request)")?;
        if m.trim().eq_ignore_ascii_case("v") || m.trim().eq_ignore_ascii_case("verify") {
            Mode::Verify { sid }
        } else {
            // revealed pairs
            println!("Enter revealed pairs as idx=value comma-separated (default: 0 only; 0 will be set to sid)");
            let line = prompt_line("")?;
            let (revealed_idx, revealed_vals) = if line.trim().is_empty() {
                (vec![0u32], vec![U256::zero()])
            } else {
                parse_revealed(&line)?
            };
            // context
            let ctxs = prompt_line("Optional context (ascii, default: client-demo)")?;
            let context = if ctxs.trim().is_empty() { b"client-demo".to_vec() } else { ctxs.into_bytes() };
            // wait/verify
            let w = prompt_line("Wait for shares and verify now? [y/N]")?;
            let wait_and_verify = matches!(w.trim(), "y"|"Y"|"yes"|"YES");
            Mode::Request { sid, revealed_idx, revealed_vals, context, wait_and_verify }
        }
        }
    } else if args[0] == "verify" {
        if args.len() < 2 { anyhow::bail!("usage: client verify <sid>"); }
        let sid: u64 = args[1].parse()?;
        Mode::Verify { sid }
    } else if args[0] == "debug" && args.get(1).map(|s| s.as_str()) == Some("g2") {
        // Usage: client debug g2
        Mode::DebugG2
    } else if args[0] == "present" {
        if args.len() < 2 { anyhow::bail!("usage: client present <sid>"); }
        let sid: u64 = args[1].parse()?;
        // Reuse Verify path to aggregate shares from chain and then present credential on-chain
        Mode::Verify { sid }
    } else if let Ok(sid) = args[0].parse::<u64>() {
        // Legacy: client <sid> acts like request with defaults and waits/verify
        Mode::Request { sid, revealed_idx: vec![0,2], revealed_vals: vec![U256::from(123u64), U256::from(456u64)], context: b"client-demo".to_vec(), wait_and_verify: true }
    } else {
        anyhow::bail!("unrecognized args; use 'verify <sid>' or numeric sid, or run without args for interactive mode")
    };

    let ws = Provider::<Ws>::connect(ws_url.clone()).await?;
    // Use provided CLIENT_PK or OWNER_PK if set; else fallback to a known local dev key.
    let wallet: LocalWallet = if let Ok(pk) = env::var("CLIENT_PK").or_else(|_| env::var("OWNER_PK")) {
        pk.parse::<LocalWallet>()?
    } else {
        // Hardhat/Anvil well-known dev key mapping to 0x7099... account
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".parse::<LocalWallet>()?
    }.with_chain_id(chain_id);
    let client = std::sync::Arc::new(SignerMiddleware::new(ws, wallet));
    // User namespace: prefer explicit USER_ID, else signer address
    let user_id = env::var("USER_ID").unwrap_or_else(|_| format!("{:x}", client.address()));
    // If credential already exists locally (for interactive runs), we can offer local actions later after we have contracts
    // Top-up balance on local anvil if needed
    if ws_url.contains("127.0.0.1") || ws_url.contains("localhost") {
        let addr = client.address();
        let _ : () = client
            .provider()
            .request("anvil_setBalance", serde_json::json!([addr, "0x1BC16D674EC8000000"]))
            .await
            .unwrap_or(());
    }

    let req = RequestCredential::new(req_addr, client.clone());
    // Optional CredentialRegistry for on-chain aggregation
    // Dynamic Contract for CredentialRegistry (avoid abigen error type collisions)
    let registry_opt: Option<Contract<SignerMiddleware<Provider<Ws>, LocalWallet>>> = env::var("REGISTRY_CONTRACT")
        .ok()
        .and_then(|s| s.parse::<Address>().ok())
        .and_then(|addr| {
            let art_path = "artifacts/contracts/CredentialRegistry.sol/CredentialRegistry.json";
            let art_str = std::fs::read_to_string(art_path).ok()?;
            let v: serde_json::Value = serde_json::from_str(&art_str).ok()?;
            let abi_val = v.get("abi")?.clone();
            let abi: Abi = serde_json::from_value(abi_val).ok()?;
            Some(Contract::new(addr, abi, client.clone()))
        });
    let params_contract = Params::new(params_addr, client.clone());

    // Handle debug command early and exit
    if let Mode::DebugG2 = mode {
        // Fetch g2 base from Params and print
        let g1h0g2 = params_contract.get_g1h0g2_by_name(cred_name.to_string()).call().await?;
        let g2_bytes: ethers::types::Bytes = g1h0g2.2;
        let g2_hex = format!("0x{}", hex::encode(&g2_bytes.0));
        println!("G2_BASE_256={}", g2_hex);
        let _ = std::fs::write(".runtime.g2_base.hex", &g2_hex);
        return Ok(());
    }

    match mode {
        Mode::Request { sid, mut revealed_idx, mut revealed_vals, context, wait_and_verify } => {
            // If a local credential already exists for this sid, offer local actions instead of sending a new request
            if local_credential_present(&user_id, &cred_name, sid) {
                println!("[local] credential already present for sid {}; skipping on-chain request", sid);
                interactive_local_actions(&user_id, &client, &params_contract, &cred_name, sid).await?;
                return Ok(());
            }
            // Fetch on-chain params to know message_count and match params generation
            let pc = params_contract.get_params_by_name(cred_name.clone()).call().await?;
            let mcount_onchain: u32 = pc.message_count.as_u64() as u32;
            // Rebuild BBS+ params from on-chain values
            let (g1_b, h0_b, g2_b) = params_contract.get_g1h0g2_by_name(cred_name.clone()).call().await?;
            let g1 = eip2537_g1_to_affine(&g1_b.0[..])?;
            let h0 = eip2537_g1_to_affine(&h0_b.0[..])?;
            let g2 = eip2537_g2_to_affine(&g2_b.0[..])?;
            let h_bytes: Vec<ethers::types::Bytes> = params_contract.get_h_by_name(cred_name.clone()).call().await?;
            let mut H: Vec<<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine> = Vec::with_capacity(h_bytes.len());
            for hb in h_bytes { H.push(eip2537_g1_to_affine(&hb.0[..])?); }
            let params_bbs = SignatureParamsG1::<Bls12_381> { g1, g2, h_0: h0, h: H };

            // Ensure index 0 is revealed and equals sid
            if let Some(pos) = revealed_idx.iter().position(|&i| i == 0) {
                revealed_vals[pos] = U256::from(sid);
            } else {
                revealed_idx.insert(0, 0);
                revealed_vals.insert(0, U256::from(sid));
            }

            // Build hidden map as complement of revealed (excluding 0), defaulting to 100+i values
            use std::collections::BTreeMap;
            let mut hidden_u256: BTreeMap<u32, U256> = BTreeMap::new();
            for i in 0..mcount_onchain {
                if i == 0 { continue; }
                if !revealed_idx.contains(&i) {
                    hidden_u256.insert(i, U256::from(100u64 + i as u64));
                }
            }
            // Convert to Fr map (sorted by index)
            let hidden_msgs_fr: BTreeMap<usize, Fr> = hidden_u256
                .iter()
                .map(|(i, v)| (*i as usize, u256_to_fr::<Fr>(v)))
                .collect();

            // Sample user blinding for commitment
            let mut rng = StdRng::seed_from_u64(rand::random::<u64>());
            let blinding = Fr::rand(&mut rng);
            // Persist blinding so we can unblind the final signature at presentation time
            // Path: .runtime/users/<addr>/<cred_name>/sid_<sid>/blinding.hex
            {
                use std::fs;
                use std::path::PathBuf;
                let user_id = format!("{:x}", client.address());
                let base: PathBuf = [".runtime", "users", &user_id, &cred_name, &format!("sid_{}", sid)].iter().collect();
                let _ = fs::create_dir_all(&base);
                let mut be = Vec::new();
                ark_serialize::CanonicalSerialize::serialize_compressed(&blinding, &mut be).ok();
                let _ = fs::write(base.join("blinding.hex"), format!("0x{}", hex::encode(be)));
            }
            // Commitment B'
            let commitment = params_bbs
                .commit_to_messages(hidden_msgs_fr.iter().map(|(i, fr)| (*i, fr)), &blinding)
                .map_err(|e| anyhow::anyhow!("commit_to_messages failed: {:?}", e))?;
            let mut commitment_bytes = Vec::new();
            commitment.serialize_compressed(&mut commitment_bytes)?;

            // Persist revealed pairs for this sid so later verification uses exact signed values
            persist_revealed_pairs(&user_id, &cred_name, sid, &revealed_idx, &revealed_vals).ok();

            // Build Schnorr-style PoK bound to transcript and serialize proof bytes
            let proof_bytes = build_commitment_pok(&params_bbs, &commitment, &hidden_msgs_fr, &blinding, mcount_onchain, sid, &cred_name, &revealed_idx, &revealed_vals, &context)?;

            let commitment_b = EthBytes::from(g1_to_eip2537_bytes(&commitment).to_vec());
            let commitment_u = EthBytes::from(g1_to_eip2537_bytes(&commitment).to_vec());
            let context_bytes = ethers::types::Bytes::from(context.clone());
            // Prepare on-chain inputs for verified request call
            let h0_b = EthBytes::from(g1_to_eip2537_bytes(&params_bbs.h_0).to_vec());
            let h_b: Vec<EthBytes> = params_bbs
                .h
                .iter()
                .map(|h| EthBytes::from(g1_to_eip2537_bytes(h).to_vec()))
                .collect();
            let (hidden_idx_vec, t_b, c_u256, resp_vec_u256) = decode_commitment_pok_for_onchain(&proof_bytes)?;

            if wait_and_verify {
                // Require registry; subscribe to Aggregated(name,sid,...) before broadcasting
                if registry_opt.is_none() { anyhow::bail!("REGISTRY_CONTRACT missing; cannot wait for Aggregated event"); }
                use ethers::types::{BlockNumber, Filter, ValueOrArray};
                let registry = registry_opt.as_ref().unwrap();
                let event_sig = H256::from(ethers::utils::keccak256(b"Aggregated(string,uint256,bytes,uint256,uint256)"));
                let name_topic = H256::from(ethers::utils::keccak256(cred_name.as_bytes()));
                let mut sid_be = [0u8; 32];
                U256::from(sid).to_big_endian(&mut sid_be);
                let sid_topic = H256::from(sid_be);
                let filter = Filter::new()
                    .address(ValueOrArray::Value(registry.address()))
                    .topic0(ValueOrArray::Value(event_sig))
                    .topic1(ValueOrArray::Value(name_topic))
                    .topic2(ValueOrArray::Value(sid_topic))
                    .from_block(BlockNumber::Latest);
                let mut agg_stream = client.provider().subscribe_logs(&filter).await?;

                // Broadcast verified request
                let try_verified_call = req.broadcast_sig_req_bbs_plus_verified(
                    U256::from(sid),
                    cred_name.clone(),
                    commitment_u.clone(),
                    commitment_b.clone(),
                    revealed_idx.clone(),
                    revealed_vals.clone(),
                    h0_b.clone(),
                    h_b.clone(),
                    hidden_idx_vec.clone(),
                    t_b.clone(),
                    c_u256,
                    resp_vec_u256.clone(),
                    context_bytes.clone(),
                );
                let rcpt_opt = match try_verified_call.send().await { Ok(p) => p.await?, Err(e) => return Err(anyhow::anyhow!("verified request failed: {:?}", e)) };
                println!("Client: sent cred request sid={}", sid);
                if let Some(rcpt) = rcpt_opt.as_ref() {
                    let topic_sig = H256::from(ethers::utils::keccak256(b"SigReqBBSPlusVerified(address,uint256,string,bytes,uint32[],uint256[],uint32[],bytes,uint256,uint256[],bytes)"));
                    let mut found = false;
                    for lg in rcpt.logs.iter() {
                        if lg.address == req_addr && !lg.topics.is_empty() && lg.topics[0] == topic_sig { found = true; break; }
                    }
                    println!("[on-chain] commitment PoK verified: {}", if found { "OK" } else { "UNKNOWN" });
                }
                // Persist request metadata for this sid to help later lookups
                if let Some(rcpt) = rcpt_opt.clone() {
                    let txh = rcpt.transaction_hash;
                    if let Some(bn) = rcpt.block_number {
                        persist_request_meta(&user_id, &cred_name, sid, txh, bn.as_u64()).ok();
                    }
                }
                // Wait for Aggregated log and then fetch signature
                loop {
                    if let Some(_log) = agg_stream.next().await {
                        // Fetch aggregated signature from registry
                        let (abytes, e_u, s_u, _status): (ethers::types::Bytes, U256, U256, u8) = registry
                            .method("getSignature", (cred_name.clone(), U256::from(sid)))
                            .unwrap()
                            .call()
                            .await?;
                        if abytes.0.len() != 128 { anyhow::bail!("registry returned bad A len: {}", abytes.0.len()); }
                        // Build messages and persist artifacts
                        let pc = params_contract.get_params_by_name(cred_name.clone()).call().await?;
                        let onchain_mcount: u32 = pc.message_count.as_u64() as u32;
                        let onchain_t: u16 = pc.t.as_u64() as u16;
                        let onchain_n: u16 = pc.n.as_u64() as u16;

                        let mut messages: Vec<Fr> = (0..onchain_mcount).map(|i| Fr::from(100 + i as u64)).collect();
                        if !messages.is_empty() { messages[0] = Fr::from(sid); }
                        if let Ok(Some(rev)) = load_revealed_pairs(&user_id, &cred_name, sid) {
                            for (i, fr_val) in rev {
                                if i != 0 && (i as usize) < messages.len() { messages[i as usize] = fr_val; }
                            }
                        }

                        use std::fs;
                        use std::path::PathBuf;
                        use ark_ec::AffineRepr;
                        let base: PathBuf = [".runtime", "users", &user_id, &cred_name, &format!("sid_{}", sid)].iter().collect();
                        let _ = fs::create_dir_all(&base);

                        let msgs_hex: Vec<String> = messages.iter().map(|f| {
                            let mut be = Vec::new();
                            ark_serialize::CanonicalSerialize::serialize_compressed(f, &mut be).unwrap();
                            format!("0x{}", hex::encode(be))
                        }).collect();
                        fs::write(base.join("messages.json"), serde_json::to_vec_pretty(&msgs_hex)?)?;
                        let params_obj = serde_json::json!({
                            "cred_name": cred_name,
                            "messageCount": onchain_mcount,
                            "t": onchain_t,
                            "n": onchain_n,
                        });
                        fs::write(base.join("params.json"), serde_json::to_vec_pretty(&params_obj)?)?;

                        // Persist aggregated signature from registry
                        let A = eip2537_g1_to_affine(&abytes.0[..])?;
                        let e = u256_to_fr::<Fr>(&e_u);
                        let s = u256_to_fr::<Fr>(&s_u);
                        let signature = bbs_plus::signature::SignatureG1::<Bls12_381> { A, e, s };
                        let mut a_bytes = Vec::new(); signature.A.serialize_compressed(&mut a_bytes)?;
                        let mut e_bytes = Vec::new(); signature.e.serialize_compressed(&mut e_bytes)?;
                        let mut s_bytes = Vec::new(); signature.s.serialize_compressed(&mut s_bytes)?;
                        let sig_obj = serde_json::json!({
                            "A": format!("0x{}", hex::encode(a_bytes)),
                            "e": format!("0x{}", hex::encode(e_bytes)),
                            "s": format!("0x{}", hex::encode(s_bytes)),
                        });
                        fs::write(base.join("agg_signature.json"), serde_json::to_vec_pretty(&sig_obj)?)?;

                        // Enter action loop
                        persist_and_optionally_present(&user_id, &client, &params_contract, &cred_name, mcount, sid, Vec::new()).await?;
                        break;
                    }
                }
            } else {
                // Send request only (verified path preferred)
                let try_verified_call = req.broadcast_sig_req_bbs_plus_verified(
                    U256::from(sid),
                    cred_name.clone(),
                    commitment_u.clone(),
                    commitment_b.clone(),
                    revealed_idx.clone(),
                    revealed_vals.clone(),
                    h0_b.clone(),
                    h_b.clone(),
                    hidden_idx_vec.clone(),
                    t_b.clone(),
                    c_u256,
                    resp_vec_u256.clone(),
                    context_bytes.clone(),
                );
                let rcpt_opt = match try_verified_call.send().await { Ok(p) => p.await?, Err(e) => return Err(anyhow::anyhow!("verified request failed: {:?}", e)) };
                println!("Client: sent cred request sid={}", sid);
                if let Some(rcpt) = rcpt_opt.as_ref() {
                    let topic_sig = H256::from(ethers::utils::keccak256(b"SigReqBBSPlusVerified(address,uint256,string,bytes,uint32[],uint256[],uint32[],bytes,uint256,uint256[],bytes)"));
                    let mut found = false;
                    for lg in rcpt.logs.iter() {
                        if lg.address == req_addr && !lg.topics.is_empty() && lg.topics[0] == topic_sig { found = true; break; }
                    }
                    println!("[on-chain] commitment PoK verified: {}", if found { "OK" } else { "UNKNOWN" });
                }
                if let Some(rcpt) = rcpt_opt.clone() {
                    let txh = rcpt.transaction_hash;
                    if let Some(bn) = rcpt.block_number {
                        persist_request_meta(&user_id, &cred_name, sid, txh, bn.as_u64()).ok();
                    }
                }
            }
    }
    Mode::Verify { sid } => {
            // Prefer registry aggregation: fetch signature directly; else try to find Aggregated event
            if let Some(registry) = registry_opt.as_ref() {
                // Try to fetch signature via dynamic call
                let res: (ethers::types::Bytes, U256, U256, u8) = registry
                    .method("getSignature", (cred_name.clone(), U256::from(sid)))
                    .unwrap()
                    .call()
                    .await?;
                let (abytes, e_u, s_u, _status_raw) = res;
                if abytes.0.len() == 128 {
                    // Persist artifacts and enter action loop
                    let pc = params_contract.get_params_by_name(cred_name.clone()).call().await?;
                    let onchain_mcount: u32 = pc.message_count.as_u64() as u32;
                    let onchain_t: u16 = pc.t.as_u64() as u16;
                    let onchain_n: u16 = pc.n.as_u64() as u16;

                    let mut messages: Vec<Fr> = (0..onchain_mcount).map(|i| Fr::from(100 + i as u64)).collect();
                    if !messages.is_empty() { messages[0] = Fr::from(sid); }
                    if let Ok(Some(rev)) = load_revealed_pairs(&user_id, &cred_name, sid) {
                        for (i, fr_val) in rev {
                            if i != 0 && (i as usize) < messages.len() { messages[i as usize] = fr_val; }
                        }
                    }

                    use std::fs;
                    use std::path::PathBuf;
                    use ark_ec::AffineRepr;
                    let base: PathBuf = [".runtime", "users", &user_id, &cred_name, &format!("sid_{}", sid)].iter().collect();
                    let _ = fs::create_dir_all(&base);

                    let msgs_hex: Vec<String> = messages.iter().map(|f| {
                        let mut be = Vec::new();
                        ark_serialize::CanonicalSerialize::serialize_compressed(f, &mut be).unwrap();
                        format!("0x{}", hex::encode(be))
                    }).collect();
                    fs::write(base.join("messages.json"), serde_json::to_vec_pretty(&msgs_hex)?)?;
                    let params_obj = serde_json::json!({ "cred_name": cred_name, "messageCount": onchain_mcount, "t": onchain_t, "n": onchain_n });
                    fs::write(base.join("params.json"), serde_json::to_vec_pretty(&params_obj)?)?;

                    let A = eip2537_g1_to_affine(&abytes.0[..])?;
                    let e = u256_to_fr::<Fr>(&e_u);
                    let s = u256_to_fr::<Fr>(&s_u);
                    let signature = bbs_plus::signature::SignatureG1::<Bls12_381> { A, e, s };
                    let mut a_bytes = Vec::new(); signature.A.serialize_compressed(&mut a_bytes)?;
                    let mut e_bytes = Vec::new(); signature.e.serialize_compressed(&mut e_bytes)?;
                    let mut s_bytes = Vec::new(); signature.s.serialize_compressed(&mut s_bytes)?;
                    let sig_obj = serde_json::json!({
                        "A": format!("0x{}", hex::encode(a_bytes)),
                        "e": format!("0x{}", hex::encode(e_bytes)),
                        "s": format!("0x{}", hex::encode(s_bytes)),
                    });
                    fs::write(base.join("agg_signature.json"), serde_json::to_vec_pretty(&sig_obj)?)?;

                    persist_and_optionally_present(&user_id, &client, &params_contract, &cred_name, mcount, sid, Vec::new()).await?;
                    return Ok(());
                } else {
                    // Try to find Aggregated event and then fetch signature
                    // Query past logs via provider filter
                    use ethers::types::{Filter, ValueOrArray};
                    let event_sig = H256::from(ethers::utils::keccak256(b"Aggregated(string,uint256,bytes,uint256,uint256)"));
                    let name_topic = H256::from(ethers::utils::keccak256(cred_name.as_bytes()));
                    let mut sid_be = [0u8; 32];
                    U256::from(sid).to_big_endian(&mut sid_be);
                    let sid_topic = H256::from(sid_be);
                    let filter = Filter::new()
                        .address(ValueOrArray::Value(registry.address()))
                        .topic0(ValueOrArray::Value(event_sig))
                        .topic1(ValueOrArray::Value(name_topic))
                        .topic2(ValueOrArray::Value(sid_topic))
                        .from_block(0u64);
                    let logs = client.provider().get_logs(&filter).await?;
                    let found = !logs.is_empty();
                    if found {
                        let (abytes2, e_u2, s_u2, _status2): (ethers::types::Bytes, U256, U256, u8) = registry
                            .method("getSignature", (cred_name.clone(), U256::from(sid)))
                            .unwrap()
                            .call()
                    .await?;
                        if abytes2.0.len() == 128 {
                            // Recurse into same logic by resetting variables
                            let abytes = abytes2; let e_u = e_u2; let s_u = s_u2;
                            // Persist and continue
                            let pc = params_contract.get_params_by_name(cred_name.clone()).call().await?;
                            let onchain_mcount: u32 = pc.message_count.as_u64() as u32;
                            let onchain_t: u16 = pc.t.as_u64() as u16;
                            let onchain_n: u16 = pc.n.as_u64() as u16;
                            let mut messages: Vec<Fr> = (0..onchain_mcount).map(|i| Fr::from(100 + i as u64)).collect();
                            if !messages.is_empty() { messages[0] = Fr::from(sid); }
                            if let Ok(Some(rev)) = load_revealed_pairs(&user_id, &cred_name, sid) {
                                for (i, fr_val) in rev {
                                    if i != 0 && (i as usize) < messages.len() { messages[i as usize] = fr_val; }
                                }
                            }
                            use std::fs; use std::path::PathBuf; use ark_ec::AffineRepr;
                            let base: PathBuf = [".runtime", "users", &user_id, &cred_name, &format!("sid_{}", sid)].iter().collect();
                            let _ = fs::create_dir_all(&base);
                            let msgs_hex: Vec<String> = messages.iter().map(|f| { let mut be = Vec::new(); ark_serialize::CanonicalSerialize::serialize_compressed(f, &mut be).unwrap(); format!("0x{}", hex::encode(be)) }).collect();
                            fs::write(base.join("messages.json"), serde_json::to_vec_pretty(&msgs_hex)?)?;
                            let params_obj = serde_json::json!({ "cred_name": cred_name, "messageCount": onchain_mcount, "t": onchain_t, "n": onchain_n });
                            fs::write(base.join("params.json"), serde_json::to_vec_pretty(&params_obj)?)?;
                            let A = eip2537_g1_to_affine(&abytes.0[..])?;
                            let e = u256_to_fr::<Fr>(&e_u);
                            let s = u256_to_fr::<Fr>(&s_u);
                            let signature = bbs_plus::signature::SignatureG1::<Bls12_381> { A, e, s };
                            let mut a_bytes = Vec::new(); signature.A.serialize_compressed(&mut a_bytes)?;
                            let mut e_bytes = Vec::new(); signature.e.serialize_compressed(&mut e_bytes)?;
                            let mut s_bytes = Vec::new(); signature.s.serialize_compressed(&mut s_bytes)?;
                            let sig_obj = serde_json::json!({ "A": format!("0x{}", hex::encode(a_bytes)), "e": format!("0x{}", hex::encode(e_bytes)), "s": format!("0x{}", hex::encode(s_bytes)) });
                            fs::write(base.join("agg_signature.json"), serde_json::to_vec_pretty(&sig_obj)?)?;
                            persist_and_optionally_present(&user_id, &client, &params_contract, &cred_name, mcount, sid, Vec::new()).await?;
                            return Ok(());
                        }
                    }
                }
            }

            anyhow::bail!("Aggregated signature not found in registry for sid {}", sid);
        }
        Mode::DebugG2 => {
            // Already handled above; this is here to make the match exhaustive.
            return Ok(());
        }
    }

    Ok(())
}

async fn verify_with_shares(
    params_contract: &Params<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    cred_name: &str,
    mcount: u32,
    sid: u64,
    shares: Vec<Vec<u8>>,
    blinding: Option<Fr>,
) -> anyhow::Result<()> {
    // Aggregate
    // Reconstruct params, counts from chain and then build message vector accordingly
    let pc = params_contract.get_params_by_name(cred_name.to_string()).call().await?;
    let onchain_mcount: u32 = pc.message_count.as_u64() as u32;
    let onchain_t: u16 = pc.t.as_u64() as u16;
    let onchain_n: u16 = pc.n.as_u64() as u16;
    let mut messages: Vec<Fr> = (0..onchain_mcount).map(|i| Fr::from(100 + i as u64)).collect();
    if !messages.is_empty() { messages[0] = Fr::from(sid); }
    let mut sig_shares = Vec::new();
    for b in shares {
        let share: bbs_plus::threshold::threshold_bbs_plus::BBSPlusSignatureShare<Bls12_381> =
            CanonicalDeserialize::deserialize_compressed(&b[..])?;
        sig_shares.push(share);
    }
    match bbs_plus::threshold::threshold_bbs_plus::BBSPlusSignatureShare::aggregate(sig_shares) {
        Ok(signature) => {
            println!("Client: aggregated signature: A={:?} e={:?} s={:?}", signature.A, signature.e, signature.s);
            // Reconstruct public key deterministically
            // Params must match issuers (label-derived from cred_name and message_count), not RNG-generated.
            let params_bbs = SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(cred_name.as_bytes(), onchain_mcount);
            // Match TTP: secret is generated from StdRng seeded with 42 with no prior RNG usage here.
            let mut rng_sk = StdRng::seed_from_u64(42);
            let (secret, _shares, _poly) = secret_sharing_and_dkg::shamir_ss::deal_random_secret(&mut rng_sk, onchain_t, onchain_n)
                .map_err(|e| anyhow::anyhow!("deal_random_secret failed: {:?}", e))?;
            let pk = PublicKeyG2::generate_using_secret_key(&SecretKey(secret), &params_bbs);
            // Blind signatures must be unblinded before verification if blinding was used
            let sig_to_verify = if let Some(b) = blinding { signature.unblind(&b) } else { signature };
            match sig_to_verify.verify(&messages, pk, params_bbs) {
                Ok(()) => println!("Client: signature verification: OK"),
                Err(e) => {
                    eprintln!("Client: signature verification FAILED: {:?}", e);
                    if blinding.is_none() {
                        eprintln!("Hint: This is a blind issuance. Run in request mode with wait-and-verify, or provide the blinding for sid {} to unblind before verifying.", sid);
                    }
                },
            }
        }
        Err(e) => {
            eprintln!("Client: aggregation failed: {:?}", e);
        }
    }
    Ok(())
}

async fn persist_and_optionally_present(
    user_id: &str,
    client: &std::sync::Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    params_contract: &Params<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    cred_name: &str,
    mcount: u32,
    sid: u64,
    shares: Vec<Vec<u8>>,
) -> anyhow::Result<()> {
    use std::fs;
    use std::path::PathBuf;
    use ark_ec::AffineRepr;
    let pc = params_contract.get_params_by_name(cred_name.to_string()).call().await?;
    let onchain_mcount: u32 = pc.message_count.as_u64() as u32;
    let onchain_t: u16 = pc.t.as_u64() as u16;
    let onchain_n: u16 = pc.n.as_u64() as u16;
    let base: PathBuf = [".runtime", "users", user_id, cred_name, &format!("sid_{}", sid)].iter().collect();
    fs::create_dir_all(&base)?;

    // Build messages and signature: aggregate if shares provided, else load existing
    let (messages, signature) = if !shares.is_empty() {
        let mut messages: Vec<Fr> = (0..onchain_mcount).map(|i| Fr::from(100 + i as u64)).collect();
        if !messages.is_empty() { messages[0] = Fr::from(sid); }
        // Override with any persisted revealed pairs (index 0 stays bound to sid)
        if let Ok(Some(rev)) = load_revealed_pairs(user_id, cred_name, sid) {
            for (i, fr_val) in rev {
                if i != 0 && (i as usize) < messages.len() { messages[i as usize] = fr_val; }
            }
        }
        let mut sig_shares = Vec::new();
        for b in shares {
            let share: bbs_plus::threshold::threshold_bbs_plus::BBSPlusSignatureShare<Bls12_381> =
                CanonicalDeserialize::deserialize_compressed(&b[..])?;
            sig_shares.push(share);
        }
        let signature = bbs_plus::threshold::threshold_bbs_plus::BBSPlusSignatureShare::aggregate(sig_shares)
            .map_err(|e| anyhow::anyhow!("aggregate failed: {:?}", e))?;
        // Persist artifacts
        let msgs_hex: Vec<String> = messages.iter().map(|f| {
            let mut be = Vec::new();
            ark_serialize::CanonicalSerialize::serialize_compressed(f, &mut be).unwrap();
            format!("0x{}", hex::encode(be))
        }).collect();
        fs::write(base.join("messages.json"), serde_json::to_vec_pretty(&msgs_hex)?)?;
        let params_obj = serde_json::json!({
            "cred_name": cred_name,
            "messageCount": onchain_mcount,
            "t": onchain_t,
            "n": onchain_n,
        });
        fs::write(base.join("params.json"), serde_json::to_vec_pretty(&params_obj)?)?;
        let mut a_bytes = Vec::new(); signature.A.serialize_compressed(&mut a_bytes)?;
        let mut e_bytes = Vec::new(); signature.e.serialize_compressed(&mut e_bytes)?;
        let mut s_bytes = Vec::new(); signature.s.serialize_compressed(&mut s_bytes)?;
        let sig_obj = serde_json::json!({
            "A": format!("0x{}", hex::encode(a_bytes)),
            "e": format!("0x{}", hex::encode(e_bytes)),
            "s": format!("0x{}", hex::encode(s_bytes)),
        });
        fs::write(base.join("agg_signature.json"), serde_json::to_vec_pretty(&sig_obj)?)?;
        (messages, signature)
    } else {
        // Load from disk
        let msgs_hex: Vec<String> = serde_json::from_slice(&fs::read(base.join("messages.json"))?)?;
        let mut messages: Vec<Fr> = Vec::with_capacity(msgs_hex.len());
        for h in msgs_hex {
            let bytes = hex::decode(h.trim_start_matches("0x"))?;
            messages.push(Fr::deserialize_compressed(&bytes[..])?);
        }
        let v: serde_json::Value = serde_json::from_slice(&fs::read(base.join("agg_signature.json"))?)?;
        let a_hex = v.get("A").and_then(|x| x.as_str()).ok_or_else(|| anyhow::anyhow!("sig.A missing"))?;
        let e_hex = v.get("e").and_then(|x| x.as_str()).ok_or_else(|| anyhow::anyhow!("sig.e missing"))?;
        let s_hex = v.get("s").and_then(|x| x.as_str()).ok_or_else(|| anyhow::anyhow!("sig.s missing"))?;
        let A = <Bls12_381 as ark_ec::pairing::Pairing>::G1Affine::deserialize_compressed(&hex::decode(a_hex.trim_start_matches("0x"))?[..])?;
        let e = Fr::deserialize_compressed(&hex::decode(e_hex.trim_start_matches("0x"))?[..])?;
        let s = Fr::deserialize_compressed(&hex::decode(s_hex.trim_start_matches("0x"))?[..])?;
        let signature = bbs_plus::signature::SignatureG1::<Bls12_381> { A, e, s };
        (messages, signature)
    };

    // Action loop: verify off-chain, present on-chain, fetch-witness, or exit
    loop {
        println!("Choose action: [v]erify off-chain, [p]resent on-chain, [w]itness check, [e]xit (default: verify)");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let choice = line.trim().to_lowercase();
        if choice.is_empty() || choice == "v" || choice == "verify" {
            let params_bbs = SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(cred_name.as_bytes(), onchain_mcount);
            let mut rng_sk = StdRng::seed_from_u64(42);
            let (secret, _shares, _poly) = secret_sharing_and_dkg::shamir_ss::deal_random_secret::<_, Fr>(&mut rng_sk, onchain_t, onchain_n)
                .map_err(|e| anyhow::anyhow!("deal_random_secret failed: {:?}", e))?;
            let pk = PublicKeyG2::generate_using_secret_key(&SecretKey(secret), &params_bbs);
            let sig_for_verify = {
                let bpath = base.join("blinding.hex");
                if let Ok(s) = fs::read_to_string(&bpath) {
                    if let Some(stripped) = s.strip_prefix("0x") {
                        if let Ok(bytes) = hex::decode(stripped) {
                            if let Ok(b) = Fr::deserialize_compressed(&bytes[..]) {
                                println!("[local] found blinding; unblinding before verification");
                                signature.clone().unblind(&b)
                            } else { signature.clone() }
                        } else { signature.clone() }
                    } else { signature.clone() }
                } else { signature.clone() }
            };
            match sig_for_verify.verify(&messages, pk, params_bbs) {
                Ok(()) => println!("[local] aggregated signature verification: OK"),
                Err(e) => println!("[local] aggregated signature verification FAILED: {:?}", e),
            }
            continue;
        } else if choice == "w" || choice == "witness" {
            // Fetch witness and verify membership off-chain
            let acc_addr: Address = env::var("ACC_CONTRACT").expect("ACC_CONTRACT").parse()?;
            let art = std::fs::read("artifacts/contracts/Accumulator.sol/Accumulator.json")?;
            let v: serde_json::Value = serde_json::from_slice(&art)?;
            let abi: Abi = serde_json::from_value(v.get("abi").cloned().ok_or_else(|| anyhow::anyhow!("abi missing"))?)?;
            let acc = Contract::new(acc_addr, abi, client.clone());
            // Load signature e and Delta
            let sig_v: serde_json::Value = serde_json::from_slice(&std::fs::read(base.join("agg_signature.json"))?)?;
            let e_hex = sig_v.get("e").and_then(|x| x.as_str()).ok_or_else(|| anyhow::anyhow!("sig.e missing"))?;
            let e_fr = Fr::deserialize_compressed(&hex::decode(e_hex.trim_start_matches("0x"))?[..])?;
            let e_u = fr_to_u256(&e_fr);
            let wit: ethers::types::Bytes = acc.method("getWitness", (cred_name.to_string(), e_u))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
            if wit.0.is_empty() { println!("[witness] not available yet"); continue; }
            // Rebuild accumulator params and pkAcc
            let (g1_b, _h0_b, g2_b) = params_contract.get_g1h0g2_by_name(cred_name.to_string()).call().await?;
            let g1 = eip2537_g1_to_affine(&g1_b.0[..])?;
            let g2 = eip2537_g2_to_affine(&g2_b.0[..])?;
            let vb_params = vb_accumulator::setup::SetupParams::<Bls12_381> { P: g1, P_tilde: g2 };
            let pkG2_b = params_contract.get_opener_pk_g2_by_name(cred_name.to_string()).call().await?;
            let pk_acc = vb_accumulator::setup::PublicKey::<Bls12_381>(eip2537_g2_to_affine(&pkG2_b.0[..])?);
            // Verify membership off-chain
            let delta_b: ethers::types::Bytes = acc.method("getDelta", (cred_name.to_string(),))?.call().await?;
            if delta_b.0.len() != 128 { println!("[witness] no Delta on-chain"); continue; }
            let V = eip2537_g1_to_affine(&delta_b.0[..])?;
            use vb_accumulator::positive::Accumulator as _;
            let acc_view = vb_accumulator::positive::PositiveAccumulator::<ark_bls12_381::G1Affine>::from_accumulated(V);
            let wit_aff = eip2537_g1_to_affine(&wit.0[..])?;
            let mw = vb_accumulator::witness::MembershipWitness::<ark_bls12_381::G1Affine>(wit_aff);
            let ok = vb_accumulator::positive::Accumulator::verify_membership::<Bls12_381>(&acc_view, &e_fr, &mw, &pk_acc, &vb_params);
            println!("[witness] membership {}", if ok { "OK" } else { "FAIL" });
            continue;
        } else if choice == "p" || choice == "present" {
        // Resolve VerifyWrapper address: prefer VERIFY_CONTRACT env; prompt if missing/invalid.
        // Also ensure the address has deployed code on the connected chain.
        let verify_addr: Address = {
            // Try env first
            let from_env = std::env::var("VERIFY_CONTRACT").ok();
            let maybe_valid_env = if let Some(s) = from_env.clone() {
                match s.parse::<Address>() {
                    Ok(addr) => {
                        let code = client.provider().get_code(addr, None).await?;
                        if code.0.is_empty() {
                            eprintln!("VERIFY_CONTRACT {} has no code on this network; will prompt.", s);
                            None
                        } else { Some(addr) }
                    }
                    Err(_) => {
                        eprintln!("VERIFY_CONTRACT is set but invalid; will prompt.");
                        None
                    }
                }
            } else { None };

            if let Some(addr) = maybe_valid_env { addr } else {
                println!("Enter VerifyWrapper address (0x...), or leave blank to skip:");
                let mut addr_in = String::new();
                std::io::stdin().read_line(&mut addr_in)?;
                let a = addr_in.trim();
                if a.is_empty() { continue; }
                let addr: Address = a.parse()?;
                let code = client.provider().get_code(addr, None).await?;
                if code.0.is_empty() {
                    anyhow::bail!("No contract code at {} on this network", a);
                }
                addr
            }
        };
        // Use dynamic Contract method to avoid struct type names from abigen
        let art_path = "artifacts/contracts/Verify.sol/VerifyWrapper.json";
        let art_str = std::fs::read_to_string(art_path)
            .map_err(|e| anyhow::anyhow!("read {} failed: {:?}", art_path, e))?;
        let v: serde_json::Value = serde_json::from_str(&art_str)?;
        let abi_val = v.get("abi").ok_or_else(|| anyhow::anyhow!("abi missing in artifact"))?.clone();
        let abi: Abi = serde_json::from_value(abi_val)?;
        let contract = Contract::new(verify_addr, abi, client.clone());
        // Build PoK for selective disclosure like exporter
        // Prompt for revealed set
        println!("Enter revealed indices for presentation (comma-separated, e.g., 0,2). Leave blank for 0 only:");
        let mut rset = String::new();
        std::io::stdin().read_line(&mut rset)?;
        let revealed_idx: Vec<u32> = if rset.trim().is_empty() {
            vec![0u32]
        } else {
            rset.split(',').filter_map(|s| s.trim().parse::<u32>().ok()).collect()
        };

        // Rebuild params and signature types
        // Rebuild BBS+ params from Params
        let (g1_b, h0_b, g2_b) = params_contract.get_g1h0g2_by_name(cred_name.to_string()).call().await?;
        let g1 = eip2537_g1_to_affine(&g1_b.0[..])?;
        let h0 = eip2537_g1_to_affine(&h0_b.0[..])?;
        let g2 = eip2537_g2_to_affine(&g2_b.0[..])?;
        let h_bytes: Vec<ethers::types::Bytes> = params_contract.get_h_by_name(cred_name.to_string()).call().await?;
        let mut H: Vec<<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine> = Vec::with_capacity(h_bytes.len());
        for hb in h_bytes { H.push(eip2537_g1_to_affine(&hb.0[..])?); }
        let params_bbs = SignatureParamsG1::<Bls12_381> { g1, g2, h_0: h0, h: H };
        // Use in-memory aggregated signature; try to unblind using persisted blinding if available
        let sig_struct = {
            // Attempt to read blinding from known locations
            // Preferred path: by user address
            let user_id = format!("{:x}", client.address());
            let by_user = [".runtime", "users", &user_id, cred_name, &format!("sid_{}", sid), "blinding.hex"].join("/");
            let generic = [".runtime", "users", "default", cred_name, &format!("sid_{}", sid), "blinding.hex"].join("/");
            let bhex = std::fs::read_to_string(&by_user)
                .ok()
                .or_else(|| std::fs::read_to_string(&generic).ok());
            if let Some(s) = bhex {
                if s.starts_with("0x") {
                    if let Ok(bytes) = hex::decode(&s[2..]) {
                        if let Ok(b) = Fr::deserialize_compressed(&bytes[..]) {
                            println!("[present debug] found blinding; unblinding signature before PoK");
                            signature.clone().unblind(&b)
                        } else { signature.clone() }
                    } else { signature.clone() }
                } else { signature.clone() }
            } else {
                println!("[present debug] blinding not found; using blinded signature (pairing may fail)");
                signature.clone()
            }
        };

        // Build revealed messages map
        let mut revealed_msgs = std::collections::BTreeMap::<usize, Fr>::new();
        for &ix in &revealed_idx { let i = ix as usize; if i < messages.len() { revealed_msgs.insert(i, messages[i]); } }
        // Build message iterator: reveal or blind randomly
        let mut rng = StdRng::seed_from_u64(99);
        use dock_crypto_utils::signature::MessageOrBlinding;
        let message_iter = messages.iter().enumerate().map(|(i, m)| {
            if revealed_msgs.contains_key(&i) { MessageOrBlinding::RevealMessage(m) } else { MessageOrBlinding::BlindMessageRandomly(m) }
        });
        // Fetch opener Ybar and use init_with_encryption for strict binding with enc relation
        let ybar_bytes = params_contract.get_opener_ybar_by_name(cred_name.to_string()).call().await?;
        if ybar_bytes.0.len() != 128 { anyhow::bail!("opener Ybar missing or wrong length"); }
        let ybar_aff = eip2537_g1_to_affine(&ybar_bytes.0[..])?;
        let pok = bbs_plus::proof::PoKOfSignatureG1Protocol::<Bls12_381>::init_with_encryption(&mut rng, &sig_struct, &params_bbs, message_iter, &ybar_aff)
            .map_err(|e| anyhow::anyhow!("pok init_with_encryption failed: {:?}", e))?;
        // Transcript and challenge (keccak to Fr)
        let mut transcript = Vec::new();
        pok.challenge_contribution(&revealed_msgs, &params_bbs, &mut transcript)
            .map_err(|e| anyhow::anyhow!("challenge contrib failed: {:?}", e))?;
        let c_fr = keccak_to_fr(&transcript);
        let proof = pok.gen_proof(&c_fr).map_err(|e| anyhow::anyhow!("gen_proof failed: {:?}", e))?;

        // Pack inputs for VerifyWrapper.verifyPok
        // Build tuple-shaped args matching ABI
        let ctx_g1 = EthBytes::from(g1_to_eip2537_bytes(&params_bbs.g1).to_vec());
        let ctx_h0 = EthBytes::from(g1_to_eip2537_bytes(&params_bbs.h_0).to_vec());
        let ctx_h: Vec<EthBytes> = params_bbs.h.iter().map(|h| EthBytes::from(g1_to_eip2537_bytes(h).to_vec())).collect();
        let ctx_h_len_dbg = ctx_h.len();
        let sig_ap = EthBytes::from(g1_to_eip2537_bytes(&proof.A_prime).to_vec());
        let sig_ab = EthBytes::from(g1_to_eip2537_bytes(&proof.A_bar).to_vec());
        let sig_d  = EthBytes::from(g1_to_eip2537_bytes(&proof.d).to_vec());
        // Preflight length checks (must be 128 bytes each)
        fn check_len(label: &str, b: &EthBytes, exp: usize) -> anyhow::Result<()> {
            if b.len() != exp { anyhow::bail!("{}: expected {} bytes, got {}", label, exp, b.len()); }
            Ok(())
        }
        check_len("ctx.g1", &ctx_g1, 128)?;
        check_len("ctx.h0", &ctx_h0, 128)?;
        for (i, hh) in ctx_h.iter().enumerate() { check_len(&format!("ctx.H[{}]", i), hh, 128)?; }
        check_len("sig.APrime", &sig_ap, 128)?;
        check_len("sig.ABar", &sig_ab, 128)?;
        check_len("sig.d", &sig_d, 128)?;
        let ctx_t = (onchain_mcount, ctx_g1, ctx_h0, ctx_h);
    let sig_t = (sig_ap.clone(), sig_ab.clone(), sig_d);
        let mut revealed_vals_u256: Vec<U256> = revealed_idx.iter().map(|ix| {
            let v = messages[*ix as usize];
            fr_to_u256(&v)
        }).collect();
        // Optional debug tamper for verifyPok: set VERIFYPOK_TAMPER=1 and optionally VERIFYPOK_TAMPER_IDX=<u32>
        if let Ok(tamper) = std::env::var("VERIFYPOK_TAMPER") {
            let t = tamper.to_ascii_lowercase();
            if !(t.is_empty() || t == "0" || t == "false") {
                let idx_to_tamper = std::env::var("VERIFYPOK_TAMPER_IDX").ok().and_then(|s| s.parse::<u32>().ok());
                let pos_opt = if let Some(ix) = idx_to_tamper {
                    revealed_idx.iter().position(|i| *i == ix)
                } else if !revealed_idx.is_empty() { Some(0usize) } else { None };
                if let Some(pos) = pos_opt {
                    let old = revealed_vals_u256[pos];
                    let mut be = [0u8; 32];
                    old.to_big_endian(&mut be);
                    be[31] ^= 1; // flip low bit
                    let new = U256::from_big_endian(&be);
                    revealed_vals_u256[pos] = new;
                    println!(
                        "[present debug] VERIFYPOK_TAMPER: changed revealed value at idx {} from {} to {}",
                        revealed_idx[pos], old, new
                    );
                } else {
                    println!("[present debug] VERIFYPOK_TAMPER set but no revealed indices to tamper");
                }
            }
        }
        let revealed_t = (revealed_idx.clone(), revealed_vals_u256);
        let p1_t_t1 = EthBytes::from(g1_to_eip2537_bytes(&proof.sc_resp_1.t).to_vec());
        check_len("p1.T1", &p1_t_t1, 128)?;
        let p1_t = (p1_t_t1, fr_to_u256(&proof.sc_resp_1.response1), fr_to_u256(&proof.sc_resp_1.response2));
        // responses for undisclosed messages then r3 then s'
        let sc2 = proof.sc_resp_2.as_ref().ok_or_else(|| anyhow::anyhow!("missing sc_resp_2"))?;
        let undis_count = (onchain_mcount as usize) - revealed_idx.len();
        let resp_msgs: Vec<U256> = sc2.0.iter().take(undis_count).map(fr_to_u256).collect();
        let resp_msgs_len_dbg = resp_msgs.len();
        let resp_r3 = fr_to_u256(&sc2.0[undis_count]);
        let resp_sprime = fr_to_u256(&sc2.0[undis_count + 1]);
        if resp_msgs.len() != undis_count { anyhow::bail!("respMsgs length {} != undisclosed count {}", resp_msgs.len(), undis_count); }
        let p2_t_t2 = EthBytes::from(g1_to_eip2537_bytes(&proof.T2).to_vec());
        check_len("p2.T2", &p2_t_t2, 128)?;
        let p2_t = (p2_t_t2, resp_msgs, resp_r3, resp_sprime);
        let challenge_u256 = fr_to_u256(&c_fr);



        // Encryption extras from proof
        let t1_b = EthBytes::from(g1_to_eip2537_bytes(&proof.sc_resp_1.t).to_vec());
        let t2enc_b = EthBytes::from(g1_to_eip2537_bytes(proof.T2_enc.as_ref().ok_or_else(|| anyhow::anyhow!("missing T2_enc"))?).to_vec());
        let t_enc_b = EthBytes::from(g1_to_eip2537_bytes(&proof.sc_resp_enc.as_ref().ok_or_else(|| anyhow::anyhow!("missing sc_resp_enc"))?.t).to_vec());
        let resp_a3_u = fr_to_u256(&proof.sc_resp_enc.as_ref().unwrap().response1);
        let resp_k_u = fr_to_u256(&proof.sc_resp_enc.as_ref().unwrap().response2);
        let params_addr_u8: [u8; 20] = params_contract.address().into();
        let params_addr_eth: Address = Address::from(params_addr_u8);
        // Single call that does full verification and emits PresentationVerified(T1,T2)
        let call = contract
            .method::<_, bool>(
                "verifyPokEncWithPairingFromParamsEmit",
                    (
                        sig_t,
                        ctx_t,
                        revealed_t,
                        challenge_u256,
                        p1_t,
                        p2_t,
                    t1_b,
                    t2enc_b,
                    t_enc_b,
                    resp_a3_u,
                    resp_k_u,
                    cred_name.to_string(),
                    params_addr_eth,
                ),
            )?;
        let pending_tx = call.send().await?;
        let rcpt = pending_tx.await?;
        let topic = H256::from(ethers::utils::keccak256(b"PresentationVerified(string,address,bytes,bytes)"));
        let mut ok = false;
        if let Some(r) = rcpt.as_ref() {
            for lg in &r.logs {
                if lg.address == verify_addr && !lg.topics.is_empty() && lg.topics[0] == topic { ok = true; break; }
            }
        }
        println!("Client: presentation {}", if ok { "succeeded" } else { "failed (no event)" });
    } else if choice == "e" || choice == "exit" {
        break;
    } else {
        continue;
    }
}
    Ok(())
}




