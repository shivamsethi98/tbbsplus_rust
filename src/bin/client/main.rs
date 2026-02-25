// Thin client entrypoint, delegating to orchestration modules and cli helpers
use std::env;
use std::sync::Arc;
use ark_bls12_381::{Bls12_381, Fr};
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::{Bytes as EthBytes, H256, U256};
use std::time::Instant;
use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use serde_json::json;

use tbbsplus_rust::orchestration::onchain::{ParamsContract, fetch_params_bundle};
use tbbsplus_rust::orchestration::persistence::{persist_request_meta, persist_revealed_pairs, load_revealed_pairs, CredentialsStore, MessagesFile, SignatureFile, RevealedFile};
use tbbsplus_rust::orchestration::crypto::encoding::{
    u256_to_fr, g1_to_eip2537_bytes, eip2537_g1_to_affine,
};
use tbbsplus_rust::orchestration::crypto::pok::{build_commitment_pok, decode_commitment_pok_for_onchain};
use tbbsplus_rust::orchestration::chain::clients::RegistryClient;

mod cli;
use cli::{prompt_line, parse_revealed};
mod args;
use args as clap_args;
#[cfg(feature = "interactive")]
mod ui;
mod session;

// Keep abigen bindings here (unchanged behavior)
ethers::contract::abigen!(
    RequestCredential,
    "artifacts/contracts/RequestCredential.sol/RequestCredential.json"
);
ethers::contract::abigen!(
    Params,
    "artifacts/contracts/Params.sol/Params.json"
);

// Small helper to check if local credential exists (flat path, no sid)
fn local_credential_present(user_id: &str, cred_name: &str) -> bool {
    use std::path::PathBuf;
    let base: PathBuf = [".runtime", "users", user_id, cred_name].iter().collect();
    base.join("agg_signature.json").exists()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let chain_id: u64 = env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse()?;
    let req_addr: Address = env::var("REQ_CONTRACT").expect("REQ_CONTRACT").parse()?;
    let params_addr: Address = env::var("PARAMS_CONTRACT").expect("PARAMS_CONTRACT").parse()?;
    let cred_name = env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
    let mcount: u32 = env::var("MESSAGE_COUNT").unwrap_or_else(|_| "5".into()).parse()?;

    enum Mode { Request { revealed_idx: Vec<u32>, revealed_vals: Vec<U256>, context: Vec<u8>, wait_and_verify: bool }, Verify, Present }
    // Parse args with clap first; fall back to legacy interactive prompts when none supplied
    let clap_mode = clap_args::parse_mode();
    let is_interactive = matches!(clap_mode, clap_args::Mode::Interactive);

    'MAIN_LOOP: loop {
        let mode: Mode = if is_interactive {
            let user_id_preview = env::var("USER_ID").unwrap_or_else(|_| "unknown".into());
            if local_credential_present(&user_id_preview, &cred_name) {
                Mode::Verify
            } else {
                let m = prompt_line("Choose mode: [r]equest or [v]erify (default: request)")?;
                if m.trim().eq_ignore_ascii_case("v") || m.trim().eq_ignore_ascii_case("verify") { Mode::Verify } else {
                    println!("Enter revealed pairs as idx=value comma-separated (default: 0 only; 0 will be set to userId)");
                    let line = prompt_line("")?;
                    let (revealed_idx, revealed_vals) = if line.trim().is_empty() { (vec![0u32], vec![U256::zero()]) } else { parse_revealed(&line)? };
                    let ctxs = prompt_line("Optional context (ascii, default: client-demo)")?;
                    let context = if ctxs.trim().is_empty() { b"client-demo".to_vec() } else { ctxs.into_bytes() };
                    let w = prompt_line("Wait for shares and verify now? [y/N]")?;
                    let wait_and_verify = matches!(w.trim(), "y"|"Y"|"yes"|"YES");
                    Mode::Request { revealed_idx, revealed_vals, context, wait_and_verify }
                }
            }
        } else {
            match clap_mode {
                clap_args::Mode::Interactive => unreachable!(),
                clap_args::Mode::Verify => Mode::Verify,
                clap_args::Mode::Present => Mode::Present,
                clap_args::Mode::Request { wait_and_verify } => {
                    // Non-interactive defaults for revealed/context
                    Mode::Request { revealed_idx: vec![0u32], revealed_vals: vec![U256::zero()], context: b"client-demo".to_vec(), wait_and_verify }
                }
            }
        };

    let ws = Provider::<Ws>::connect(ws_url.clone()).await?;
    let wallet: LocalWallet = if let Ok(pk) = env::var("CLIENT_PK").or_else(|_| env::var("OWNER_PK")) { pk.parse::<LocalWallet>()? } else { "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".parse::<LocalWallet>()? }.with_chain_id(chain_id);
    let client = Arc::new(SignerMiddleware::new(ws, wallet));
    let user_id = env::var("USER_ID").unwrap_or_else(|_| format!("{:x}", client.address()));

    // Derive userId = uint256(uint160(msg.sender)) — matches on-chain derivation
    let user_id_u256 = {
        let mut be = [0u8; 32];
        be[12..].copy_from_slice(client.address().as_bytes());
        U256::from_big_endian(&be)
    };
    let user_id_fr: Fr = u256_to_fr::<Fr>(&user_id_u256);

    if ws_url.contains("127.0.0.1") || ws_url.contains("localhost") {
        let addr = client.address();
        let _ : () = client.provider().request("anvil_setBalance", serde_json::json!([addr, "0x1BC16D674EC8000000"]))
            .await.unwrap_or(());
    }

    let req = RequestCredential::new(req_addr, client.clone());
    let store = CredentialsStore::new(&user_id, &cred_name);
    let registry_addr_env = env::var("REGISTRY_CONTRACT").ok().or_else(|| env::var("RELAY_CONTRACT").ok());
    let metrics = env::var("METRICS").map(|v| v=="1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let metrics_file = env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/client.ndjson".into());
    let registry_opt: Option<RegistryClient<SignerMiddleware<Provider<Ws>, LocalWallet>>> = registry_addr_env
        .and_then(|s| s.parse::<Address>().ok())
        .and_then(|addr| RegistryClient::new(addr, client.clone()).ok());
    let params_contract = ParamsContract::new(params_addr, client.clone());

    fn metrics_append(enabled: bool, path: &str, value: serde_json::Value) {
        if !enabled { return; }
        let _ = (|| -> Result<(), Box<dyn std::error::Error>> {
            if let Some(dir) = std::path::Path::new(path).parent() { let _ = std::fs::create_dir_all(dir); }
            let mut f = OpenOptions::new().create(true).append(true).open(path)?;
            let s = serde_json::to_string(&value)?;
            writeln!(f, "{}", s)?;
            Ok(())
        })();
    }



    match mode {
        Mode::Request { mut revealed_idx, mut revealed_vals, context, wait_and_verify } => {
            if local_credential_present(&user_id, &cred_name) {
                println!("[local] credential already present for user");
                #[cfg(feature = "interactive")]
                {
                    println!("entering actions");
                    let sess = session::Session::load(&user_id, &cred_name, &params_contract).await?;
                    ui::run_action_loop(client.clone(), &params_contract, &sess).await?;
                }
                if is_interactive { continue 'MAIN_LOOP; } else { return Ok(()); }
            }
            // Chain check: if Confirmed was missed locally but signature exists on-chain, pull it and persist
            if let Some(registry) = registry_opt.as_ref() {
                let (abytes, e_u, s_u, _status) = registry.get_signature(cred_name.clone(), user_id_u256).await?;
                if abytes.0.len() == 128 {
                    println!("[chain] aggregated signature found; persisting locally");
                    // Persist params/messages/signature like in post-Confirmed branch
                    let pb2 = fetch_params_bundle(&params_contract, &cred_name).await?;
                    let onchain_mcount = pb2.mcount;
                    let mut messages: Vec<Fr> = (0..onchain_mcount).map(|i| Fr::from(100 + i as u64)).collect();
                    if !messages.is_empty() { messages[0] = user_id_fr; }
                    if let Ok(Some(rev)) = load_revealed_pairs(&user_id, &cred_name) {
                        for (i, fr_val) in rev { if i != 0 && (i as usize) < messages.len() { messages[i as usize] = fr_val; } }
                    }
                    use ark_serialize::CanonicalSerialize;
                    let msgs_hex: Vec<String> = messages.iter().map(|f| {
                        let mut be = Vec::new(); ark_serialize::CanonicalSerialize::serialize_compressed(f, &mut be).unwrap();
                        format!("0x{}", hex::encode(be))
                    }).collect();
                    store.save_messages(&MessagesFile(msgs_hex))?;
                    // Persist aggregated signature from registry
                    let a = eip2537_g1_to_affine(&abytes.0[..])?; let e = u256_to_fr::<Fr>(&e_u); let s = u256_to_fr::<Fr>(&s_u);
                    let signature = bbs_plus::signature::SignatureG1::<Bls12_381> { A: a, e, s };
                    let mut a_bytes = Vec::new(); signature.A.serialize_compressed(&mut a_bytes)?;
                    let mut e_bytes = Vec::new(); signature.e.serialize_compressed(&mut e_bytes)?;
                    let mut s_bytes = Vec::new(); signature.s.serialize_compressed(&mut s_bytes)?;
                    store.save_signature(&SignatureFile { a: format!("0x{}", hex::encode(a_bytes)), e: format!("0x{}", hex::encode(e_bytes)), s: format!("0x{}", hex::encode(s_bytes)) })?;
                    #[cfg(feature = "interactive")]
                    {
                        let sess = session::Session::load(&user_id, &cred_name, &params_contract).await?;
                        ui::run_action_loop(client.clone(), &params_contract, &sess).await?;
                    }
                    if is_interactive { continue 'MAIN_LOOP; } else { return Ok(()); }
                }
            }
            let pb = fetch_params_bundle(&params_contract, &cred_name).await?;
            let mcount_onchain = pb.mcount; let params_bbs = pb.params_bbs.clone();
            if let Some(pos) = revealed_idx.iter().position(|&i| i == 0) { revealed_vals[pos] = user_id_u256; }
            else { revealed_idx.insert(0, 0); revealed_vals.insert(0, user_id_u256); }

            use std::collections::BTreeMap; use ark_serialize::CanonicalSerialize; use ark_std::rand::{rngs::StdRng, SeedableRng}; use ark_std::UniformRand;
            let mut hidden_u256: BTreeMap<u32, U256> = BTreeMap::new();
            for i in 0..mcount_onchain { if i == 0 { continue; } if !revealed_idx.contains(&i) { hidden_u256.insert(i, U256::from(100u64 + i as u64)); } }
            let hidden_msgs_fr: BTreeMap<usize, Fr> = hidden_u256.iter().map(|(i, v)| (*i as usize, u256_to_fr::<Fr>(v))).collect();
            let mut rng = StdRng::seed_from_u64(rand::random::<u64>()); let blinding = Fr::rand(&mut rng);
            {
                use std::fs; use std::path::PathBuf; let base: PathBuf = [".runtime","users", &format!("{:x}", client.address()), &cred_name].iter().collect();
                let _ = fs::create_dir_all(&base); let mut be = Vec::new(); let _ = ark_serialize::CanonicalSerialize::serialize_compressed(&blinding, &mut be); let _ = fs::write(base.join("blinding.hex"), format!("0x{}", hex::encode(be)));
            }
            let commitment = params_bbs.commit_to_messages(hidden_msgs_fr.iter().map(|(i, fr)| (*i, fr)), &blinding)
                .map_err(|e| anyhow::anyhow!("commit_to_messages failed: {:?}", e))?;
            // Persist revealed pairs now so downstream flows use exact values
            let _ = persist_revealed_pairs(&user_id, &cred_name, &revealed_idx, &revealed_vals);
            let _ = store.save_revealed(&RevealedFile { idx: revealed_idx.clone(), vals: revealed_vals.iter().map(|v| { let mut be=[0u8;32]; v.to_big_endian(&mut be); format!("0x{}", hex::encode(be)) }).collect() });
            let t0_pok = Instant::now();
            let proof_bytes = build_commitment_pok(&params_bbs, &commitment, &hidden_msgs_fr, &blinding, mcount_onchain, &user_id_u256, &cred_name, &revealed_idx, &revealed_vals, &context)?;
            metrics_append(metrics, &metrics_file, json!({"scenario":"issuance_timer_start","userId": format!("0x{:x}", user_id_u256)}));
            let commitment_b = EthBytes::from(g1_to_eip2537_bytes(&commitment).to_vec());
            let commitment_u = EthBytes::from(g1_to_eip2537_bytes(&commitment).to_vec());
            let context_bytes = ethers::types::Bytes::from(context.clone());
            let h0_b = EthBytes::from(g1_to_eip2537_bytes(&params_bbs.h_0).to_vec());
            let h_b: Vec<EthBytes> = params_bbs.h.iter().map(|h| EthBytes::from(g1_to_eip2537_bytes(h).to_vec())).collect();
            let (hidden_idx_vec, t_b, c_u256, resp_vec_u256) = decode_commitment_pok_for_onchain(&proof_bytes)?;
            // Ephemeral request session (no secrets like blinding/hidden scalars inside)
            let req_session = session::RequestSession::new(
                &user_id, &cred_name, pb.clone(),
                revealed_idx.clone(), revealed_vals.clone(),
                commitment_u.clone(), commitment_b.clone(),
                h0_b.clone(), h_b.clone(),
                hidden_idx_vec.clone(), t_b.clone(), c_u256, resp_vec_u256.clone(),
                context_bytes.clone(),
            );

            // ── Batch request export mode ──
            // When BATCH_REQUEST_EXPORT is set, serialize the proof data to a JSON file
            // and skip on-chain submission. The request_aggregator binary collects
            // multiple exported files and submits a single batched tx.
            if std::env::var("BATCH_REQUEST_EXPORT").is_ok() {
                use tbbsplus_rust::orchestration::batching::RequestData;
                let out_path = std::env::var("BATCH_REQUEST_FILE")
                    .unwrap_or_else(|_| "batch_request.json".into());
                let req_data = RequestData {
                    user_addr: format!("{:?}", client.address()),
                    commitment_u: commitment_u.to_vec(),
                    commitment_b: commitment_b.to_vec(),
                    h0: h0_b.to_vec(),
                    h: h_b.iter().map(|hb| hb.to_vec()).collect(),
                    revealed_idx: revealed_idx.clone(),
                    revealed_vals: revealed_vals.clone(),
                    hidden_idx: hidden_idx_vec.clone(),
                    t: t_b.to_vec(),
                    challenge: c_u256,
                    responses: resp_vec_u256.clone(),
                    context: context_bytes.to_vec(),
                    cred_name: cred_name.clone(),
                };
                // File-locked append for concurrent-safe batch writes
                {
                    use fs2::FileExt;
                    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).open(&out_path)?;
                    file.lock_exclusive()?;
                    let existing = std::fs::read_to_string(&out_path).unwrap_or_default();
                    let mut req_vec: Vec<RequestData> = if existing.trim().is_empty() {
                        Vec::new()
                    } else {
                        serde_json::from_str(&existing).unwrap_or_default()
                    };
                    req_vec.push(req_data);
                    let count = req_vec.len();
                    std::fs::write(&out_path, serde_json::to_string_pretty(&req_vec)?)?;
                    file.unlock()?;
                    println!("[batch-export] request #{} written to {} ({} total)", count, out_path, count);
                }
                if is_interactive { continue 'MAIN_LOOP; } else { return Ok(()); }
            }

            if wait_and_verify {
                if registry_opt.is_none() { anyhow::bail!("REGISTRY_CONTRACT/RELAY_CONTRACT missing; cannot wait for Aggregated event"); }
                let registry = registry_opt.as_ref().unwrap();
                // Build Aggregated and Confirmed streams
                use ethers::types::{Filter, ValueOrArray, BlockNumber};
                let topic_agg = H256::from(ethers::utils::keccak256(b"Aggregated(string,uint256,bytes,uint256,uint256)"));
                let name_topic = H256::from(ethers::utils::keccak256(cred_name.as_bytes()));
                let mut uid_be = [0u8; 32];
                user_id_u256.to_big_endian(&mut uid_be);
                let uid_topic = H256::from(uid_be);
                let filter_agg = Filter::new()
                    .address(ValueOrArray::Value(registry.address()))
                    .topic0(ValueOrArray::Value(topic_agg))
                    .topic1(ValueOrArray::Value(name_topic))
                    .topic2(ValueOrArray::Value(uid_topic))
                    .from_block(BlockNumber::Latest);
                let mut agg_stream = client.provider().subscribe_logs(&filter_agg).await?;
                let topic_conf = H256::from(ethers::utils::keccak256(b"Confirmed(string,uint256)"));
                let filter_conf = Filter::new()
                    .address(ValueOrArray::Value(registry.address()))
                    .topic0(ValueOrArray::Value(topic_conf))
                    .topic1(ValueOrArray::Value(name_topic))
                    .topic2(ValueOrArray::Value(uid_topic))
                    .from_block(BlockNumber::Latest);
                let mut conf_stream = client.provider().subscribe_logs(&filter_conf).await?;
                let try_verified_call = req.broadcast_sig_req_bbs_plus_verified(
                    req_session.cred_name.clone(),
                    req_session.commitment_u.clone(), req_session.commitment_b.clone(),
                    req_session.revealed_idx.clone(), req_session.revealed_vals.clone(),
                    req_session.h0_b.clone(), req_session.h_b.clone(),
                    req_session.hidden_idx_vec.clone(), req_session.t_b.clone(),
                    req_session.c_u256, req_session.resp_vec_u256.clone(),
                    req_session.context_bytes.clone(),
                );
                let t0_total = t0_pok;
                let t0_send = Instant::now();
                let rcpt_opt = match try_verified_call.send().await { Ok(p) => p.await?, Err(e) => return Err(anyhow::anyhow!("verified request failed: {:?}", e)) };
                if let Some(rcpt) = rcpt_opt.as_ref() {
                    let gas_used = rcpt.gas_used.unwrap_or_default();
                    let eff_price = rcpt.effective_gas_price.unwrap_or_default();
                    let cost = gas_used * eff_price;
                    metrics_append(metrics, &metrics_file, json!({
                        "scenario":"requestCredential",
                        "userId": format!("0x{:x}", user_id_u256),
                        "gasUsed": gas_used.to_string(),
                        "effectiveGasPrice": eff_price.to_string(),
                        "costWei": cost.to_string()
                    }));
                    let topic_sig = H256::from(ethers::utils::keccak256(b"SigReqBBSPlusVerified(address,uint256,string,bytes,uint32[],uint256[],uint32[],bytes,uint256,uint256[],bytes)")); let mut found = false; for lg in rcpt.logs.iter() { if lg.address == req_addr && !lg.topics.is_empty() && lg.topics[0] == topic_sig { found = true; break; } } println!("[on-chain] commitment PoK verified: {}", if found { "OK" } else { "UNKNOWN" });
                }
                if let Some(rcpt) = rcpt_opt.clone() { let txh = rcpt.transaction_hash; if let Some(bn) = rcpt.block_number { persist_request_meta(&user_id, &cred_name, txh, bn.as_u64()).ok(); } }
                // Wait for Confirmed and then fetch signature; persist artifacts; enter action loop
                if let Ok(Some(_lg)) = tokio::time::timeout(std::time::Duration::from_secs(60), conf_stream.next()).await {
                    metrics_append(metrics, &metrics_file, json!({"scenario":"issuance_e2e_confirmed","userId": format!("0x{:x}", user_id_u256),"ms": t0_total.elapsed().as_millis() as u64}));
                    // Fetch aggregated signature from registry
                    let (abytes, e_u, s_u, _status) = registry.get_signature(cred_name.clone(), user_id_u256).await?;
                    if abytes.0.len() != 128 { anyhow::bail!("registry returned bad A len: {}", abytes.0.len()); }
                    // Build messages and persist artifacts similar to Verify path
                    let pb2 = fetch_params_bundle(&params_contract, &cred_name).await?;
                    let onchain_mcount = pb2.mcount;
                    let mut messages: Vec<Fr> = (0..onchain_mcount).map(|i| Fr::from(100 + i as u64)).collect();
                    if !messages.is_empty() { messages[0] = user_id_fr; }
                    if let Ok(Some(rev)) = load_revealed_pairs(&user_id, &cred_name) {
                        for (i, fr_val) in rev { if i != 0 && (i as usize) < messages.len() { messages[i as usize] = fr_val; } }
                    }
                    use ark_serialize::CanonicalSerialize;
                    let msgs_hex: Vec<String> = messages.iter().map(|f| { let mut be = Vec::new(); ark_serialize::CanonicalSerialize::serialize_compressed(f, &mut be).unwrap(); format!("0x{}", hex::encode(be)) }).collect();
                    store.save_messages(&MessagesFile(msgs_hex))?;
                    let a = eip2537_g1_to_affine(&abytes.0[..])?; let e = u256_to_fr::<Fr>(&e_u); let s = u256_to_fr::<Fr>(&s_u);
                    let signature = bbs_plus::signature::SignatureG1::<Bls12_381> { A: a, e, s };
                    let mut a_bytes = Vec::new(); signature.A.serialize_compressed(&mut a_bytes)?;
                    let mut e_bytes = Vec::new(); signature.e.serialize_compressed(&mut e_bytes)?;
                    let mut s_bytes = Vec::new(); signature.s.serialize_compressed(&mut s_bytes)?;
                    store.save_signature(&SignatureFile { a: format!("0x{}", hex::encode(a_bytes)), e: format!("0x{}", hex::encode(e_bytes)), s: format!("0x{}", hex::encode(s_bytes)) })?;
                    // ── Auto witness sync + batch presentation export (non-interactive) ──
                    #[cfg(feature = "interactive")]
                    if std::env::var("AUTO_WITNESS_SYNC").is_ok() || std::env::var("BATCH_PRESENTATION_EXPORT").is_ok() {
                        let sess = session::Session::load(&user_id, &cred_name, &params_contract).await?;
                        println!("[auto] credential confirmed — running witness sync...");
                        ui::auto_witness_sync(client.clone(), &params_contract, &sess).await?;
                        if std::env::var("BATCH_PRESENTATION_EXPORT").is_ok() {
                            let out_path = std::env::var("BATCH_PRESENTATION_FILE")
                                .unwrap_or_else(|_| "batch_presentation.json".into());
                            let revealed_idx_str = std::env::var("AUTO_REVEALED_IDX")
                                .unwrap_or_else(|_| "0".into());
                            let auto_revealed: Vec<u32> = revealed_idx_str
                                .split(',')
                                .filter_map(|s| s.trim().parse().ok())
                                .collect();
                            println!("[auto] exporting batch presentation to {}...", out_path);
                            ui::auto_batch_export(client.clone(), &params_contract, &sess, &auto_revealed, &out_path).await?;
                        }
                        if is_interactive { continue 'MAIN_LOOP; } else { return Ok(()); }
                    }
                    #[cfg(feature = "interactive")]
                    {
                        let sess = session::Session::load(&user_id, &cred_name, &params_contract).await?;
                        ui::run_action_loop(client.clone(), &params_contract, &sess).await?;
                    }
                    if is_interactive { continue 'MAIN_LOOP; } else { return Ok(()); }
                }
            } else {
                let try_verified_call = req.broadcast_sig_req_bbs_plus_verified(
                    req_session.cred_name.clone(),
                    req_session.commitment_u.clone(), req_session.commitment_b.clone(),
                    req_session.revealed_idx.clone(), req_session.revealed_vals.clone(),
                    req_session.h0_b.clone(), req_session.h_b.clone(),
                    req_session.hidden_idx_vec.clone(), req_session.t_b.clone(),
                    req_session.c_u256, req_session.resp_vec_u256.clone(),
                    req_session.context_bytes.clone(),
                );
                let rcpt_opt = match try_verified_call.send().await { Ok(p) => p.await?, Err(e) => return Err(anyhow::anyhow!("verified request failed: {:?}", e)) };
                if let Some(rcpt) = rcpt_opt.clone() { let txh = rcpt.transaction_hash; if let Some(bn) = rcpt.block_number { persist_request_meta(&user_id, &cred_name, txh, bn.as_u64()).ok(); } }
                if is_interactive { continue 'MAIN_LOOP; }
            }
        }
        Mode::Verify => {
            if let Some(registry) = registry_opt.as_ref() {
                let (abytes, e_u, s_u, _status_raw) = registry.get_signature(cred_name.clone(), user_id_u256).await?;
                if abytes.0.len() == 128 {
                    // Persist params and messages
                    let pb = fetch_params_bundle(&params_contract, &cred_name).await?;
                    let onchain_mcount = pb.mcount;
                    let mut messages: Vec<Fr> = (0..onchain_mcount).map(|i| Fr::from(100 + i as u64)).collect();
                    if !messages.is_empty() { messages[0] = user_id_fr; }
                    if let Ok(Some(rev)) = load_revealed_pairs(&user_id, &cred_name) {
                        for (i, fr_val) in rev { if i != 0 && (i as usize) < messages.len() { messages[i as usize] = fr_val; } }
                    }
                    use ark_serialize::CanonicalSerialize;
                    let msgs_hex: Vec<String> = messages.iter().map(|f| { let mut be = Vec::new(); ark_serialize::CanonicalSerialize::serialize_compressed(f, &mut be).unwrap(); format!("0x{}", hex::encode(be)) }).collect();
                    store.save_messages(&MessagesFile(msgs_hex))?;
                    // Persist signature
                    let a = eip2537_g1_to_affine(&abytes.0[..])?; let e = u256_to_fr::<Fr>(&e_u); let s = u256_to_fr::<Fr>(&s_u);
                    let signature = bbs_plus::signature::SignatureG1::<Bls12_381> { A: a, e, s };
                    let mut a_bytes = Vec::new(); signature.A.serialize_compressed(&mut a_bytes)?;
                    let mut e_bytes = Vec::new(); signature.e.serialize_compressed(&mut e_bytes)?;
                    let mut s_bytes = Vec::new(); signature.s.serialize_compressed(&mut s_bytes)?;
                    store.save_signature(&SignatureFile { a: format!("0x{}", hex::encode(a_bytes)), e: format!("0x{}", hex::encode(e_bytes)), s: format!("0x{}", hex::encode(s_bytes)) })?;
                    println!("[verify] artifacts written to {}", store.base().display());
                    // Enter interactive action loop (off-chain verify, witness, present)
                    #[cfg(feature = "interactive")]
                    {
                        let sess = session::Session::load(&user_id, &cred_name, &params_contract).await?;
                        ui::run_action_loop(client.clone(), &params_contract, &sess).await?;
                    }
                    if is_interactive { continue 'MAIN_LOOP; } else { return Ok(()); }
                }
            }
            anyhow::bail!("Aggregated signature not found in registry for user");
        }
        Mode::Present => {
            #[cfg(feature = "interactive")]
            {
                let sess = session::Session::load(&user_id, &cred_name, &params_contract).await?;
                return ui::run_action_loop(client.clone(), &params_contract, &sess).await;
            }
            if is_interactive { continue 'MAIN_LOOP; } else { return Ok(()); }
        }
        
    }
        if !is_interactive { break 'MAIN_LOOP; }
    }
    Ok(())
}
