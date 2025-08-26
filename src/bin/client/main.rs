// Thin client entrypoint, delegating to orchestration modules and cli helpers
use std::env;
use std::sync::Arc;
use ark_bls12_381::{Bls12_381, Fr};
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::contract::Contract;
use ethers::abi::Abi;
use ethers::types::{Bytes as EthBytes, H256, U256};

use tbbsplus_rust::orchestration::onchain::{ParamsContract, fetch_params_bundle};
use tbbsplus_rust::orchestration::persistence::{persist_request_meta, persist_revealed_pairs, load_revealed_pairs, CredentialsStore, MessagesFile, SignatureFile, RevealedFile};




use tbbsplus_rust::orchestration::crypto::encoding::{
    fr_to_u256, u256_to_fr, g1_to_eip2537_bytes, eip2537_g1_to_affine, eip2537_g2_to_affine,
};
use tbbsplus_rust::orchestration::crypto::pok::{build_pok_and_proof, build_presentation_tuples, build_commitment_pok, decode_commitment_pok_for_onchain};
use tbbsplus_rust::orchestration::chain::abi::load_abi_from_artifact;
use tbbsplus_rust::orchestration::chain::clients::RegistryClient;

mod cli;
use cli::{prompt_line, prompt_parse_u64, parse_revealed};
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

// Small helper to check if local credential exists
fn local_credential_present(user_id: &str, cred_name: &str, sid: u64) -> bool {
    use std::path::PathBuf;
    let base: PathBuf = [".runtime", "users", user_id, cred_name, &format!("sid_{}", sid)].iter().collect();
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

    enum Mode { Request { sid: u64, revealed_idx: Vec<u32>, revealed_vals: Vec<U256>, context: Vec<u8>, wait_and_verify: bool }, Verify { sid: u64 }, Present { sid: u64 } }
    // Parse args with clap first; fall back to legacy interactive prompts when none supplied
    let clap_mode = clap_args::parse_mode();
    let mode: Mode = if matches!(clap_mode, clap_args::Mode::Interactive) {
        let sid = prompt_parse_u64("Enter session id (sid)", 1)?;
        let user_id_preview = env::var("USER_ID").unwrap_or_else(|_| "unknown".into());
        if local_credential_present(&user_id_preview, &cred_name, sid) {
            Mode::Verify { sid }
        } else {
            let m = prompt_line("Choose mode: [r]equest or [v]erify (default: request)")?;
            if m.trim().eq_ignore_ascii_case("v") || m.trim().eq_ignore_ascii_case("verify") { Mode::Verify { sid } } else {
                println!("Enter revealed pairs as idx=value comma-separated (default: 0 only; 0 will be set to sid)");
                let line = prompt_line("")?;
                let (revealed_idx, revealed_vals) = if line.trim().is_empty() { (vec![0u32], vec![U256::zero()]) } else { parse_revealed(&line)? };
                let ctxs = prompt_line("Optional context (ascii, default: client-demo)")?;
                let context = if ctxs.trim().is_empty() { b"client-demo".to_vec() } else { ctxs.into_bytes() };
                let w = prompt_line("Wait for shares and verify now? [y/N]")?;
                let wait_and_verify = matches!(w.trim(), "y"|"Y"|"yes"|"YES");
                Mode::Request { sid, revealed_idx, revealed_vals, context, wait_and_verify }
            }
        }
    } else {
        match clap_mode {
            clap_args::Mode::Interactive => unreachable!(),
            clap_args::Mode::Verify { sid } => Mode::Verify { sid },
            clap_args::Mode::Present { sid } => Mode::Present { sid },
            clap_args::Mode::Request { sid, wait_and_verify } => {
                // Non-interactive defaults for revealed/context
                Mode::Request { sid, revealed_idx: vec![0u32], revealed_vals: vec![U256::zero()], context: b"client-demo".to_vec(), wait_and_verify }
            }
        }
    };

    let ws = Provider::<Ws>::connect(ws_url.clone()).await?;
    let wallet: LocalWallet = if let Ok(pk) = env::var("CLIENT_PK").or_else(|_| env::var("OWNER_PK")) { pk.parse::<LocalWallet>()? } else { "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".parse::<LocalWallet>()? }.with_chain_id(chain_id);
    let client = Arc::new(SignerMiddleware::new(ws, wallet));
    let user_id = env::var("USER_ID").unwrap_or_else(|_| format!("{:x}", client.address()));

    if ws_url.contains("127.0.0.1") || ws_url.contains("localhost") {
        let addr = client.address();
        let _ : () = client.provider().request("anvil_setBalance", serde_json::json!([addr, "0x1BC16D674EC8000000"]))
            .await.unwrap_or(());
    }

    let req = RequestCredential::new(req_addr, client.clone());
    let store = CredentialsStore::new(&user_id, &cred_name);
    let registry_addr_env = env::var("REGISTRY_CONTRACT").ok().or_else(|| env::var("RELAY_CONTRACT").ok());
    let registry_opt: Option<RegistryClient<SignerMiddleware<Provider<Ws>, LocalWallet>>> = registry_addr_env
        .and_then(|s| s.parse::<Address>().ok())
        .and_then(|addr| RegistryClient::new(addr, client.clone()).ok());
    let params_contract = ParamsContract::new(params_addr, client.clone());



    match mode {
        Mode::Request { sid, mut revealed_idx, mut revealed_vals, context, wait_and_verify } => {
            if local_credential_present(&user_id, &cred_name, sid) {
                println!("[local] credential already present for sid {}", sid);
                #[cfg(feature = "interactive")]
                {
                    println!("entering actions");
                    let sess = session::Session::load(&user_id, &cred_name, sid, &params_contract).await?;
                    return ui::run_action_loop(client.clone(), &params_contract, &sess).await;
                }
                return Ok(());
            }
            let pb = fetch_params_bundle(&params_contract, &cred_name).await?;
            let mcount_onchain = pb.mcount; let params_bbs = pb.params_bbs.clone();
            if let Some(pos) = revealed_idx.iter().position(|&i| i == 0) { revealed_vals[pos] = U256::from(sid); }
            else { revealed_idx.insert(0, 0); revealed_vals.insert(0, U256::from(sid)); }

            use std::collections::BTreeMap; use ark_serialize::CanonicalSerialize; use ark_std::rand::{rngs::StdRng, SeedableRng}; use ark_std::UniformRand;
            let mut hidden_u256: BTreeMap<u32, U256> = BTreeMap::new();
            for i in 0..mcount_onchain { if i == 0 { continue; } if !revealed_idx.contains(&i) { hidden_u256.insert(i, U256::from(100u64 + i as u64)); } }
            let hidden_msgs_fr: BTreeMap<usize, Fr> = hidden_u256.iter().map(|(i, v)| (*i as usize, u256_to_fr::<Fr>(v))).collect();
            let mut rng = StdRng::seed_from_u64(rand::random::<u64>()); let blinding = Fr::rand(&mut rng);
            {
                use std::fs; use std::path::PathBuf; let base: PathBuf = [".runtime","users", &format!("{:x}", client.address()), &cred_name, &format!("sid_{}", sid)].iter().collect();
                let _ = fs::create_dir_all(&base); let mut be = Vec::new(); let _ = ark_serialize::CanonicalSerialize::serialize_compressed(&blinding, &mut be); let _ = fs::write(base.join("blinding.hex"), format!("0x{}", hex::encode(be)));
            }
            let commitment = params_bbs.commit_to_messages(hidden_msgs_fr.iter().map(|(i, fr)| (*i, fr)), &blinding)
                .map_err(|e| anyhow::anyhow!("commit_to_messages failed: {:?}", e))?;
            // Persist revealed pairs now so downstream flows use exact values
            let _ = persist_revealed_pairs(&user_id, &cred_name, sid, &revealed_idx, &revealed_vals);
            let _ = store.save_revealed(sid, &RevealedFile { idx: revealed_idx.clone(), vals: revealed_vals.iter().map(|v| { let mut be=[0u8;32]; v.to_big_endian(&mut be); format!("0x{}", hex::encode(be)) }).collect() });
            let proof_bytes = build_commitment_pok(&params_bbs, &commitment, &hidden_msgs_fr, &blinding, mcount_onchain, sid, &cred_name, &revealed_idx, &revealed_vals, &context)?;
            let commitment_b = EthBytes::from(g1_to_eip2537_bytes(&commitment).to_vec());
            let commitment_u = EthBytes::from(g1_to_eip2537_bytes(&commitment).to_vec());
            let context_bytes = ethers::types::Bytes::from(context.clone());
            let h0_b = EthBytes::from(g1_to_eip2537_bytes(&params_bbs.h_0).to_vec());
            let h_b: Vec<EthBytes> = params_bbs.h.iter().map(|h| EthBytes::from(g1_to_eip2537_bytes(h).to_vec())).collect();
            let (hidden_idx_vec, t_b, c_u256, resp_vec_u256) = decode_commitment_pok_for_onchain(&proof_bytes)?;
            // Ephemeral request session (no secrets like blinding/hidden scalars inside)
            let req_session = session::RequestSession::new(
                &user_id, &cred_name, sid, pb.clone(),
                revealed_idx.clone(), revealed_vals.clone(),
                commitment_u.clone(), commitment_b.clone(),
                h0_b.clone(), h_b.clone(),
                hidden_idx_vec.clone(), t_b.clone(), c_u256, resp_vec_u256.clone(),
                context_bytes.clone(),
            );

            if wait_and_verify {
                if registry_opt.is_none() { anyhow::bail!("REGISTRY_CONTRACT/RELAY_CONTRACT missing; cannot wait for Aggregated event"); }
                let registry = registry_opt.as_ref().unwrap();
                let filter = registry.aggregated_filter(&cred_name, sid);
                let mut agg_stream = client.provider().subscribe_logs(&filter).await?;
                let try_verified_call = req.broadcast_sig_req_bbs_plus_verified(
                    U256::from(req_session.sid), req_session.cred_name.clone(),
                    req_session.commitment_u.clone(), req_session.commitment_b.clone(),
                    req_session.revealed_idx.clone(), req_session.revealed_vals.clone(),
                    req_session.h0_b.clone(), req_session.h_b.clone(),
                    req_session.hidden_idx_vec.clone(), req_session.t_b.clone(),
                    req_session.c_u256, req_session.resp_vec_u256.clone(),
                    req_session.context_bytes.clone(),
                );
                let rcpt_opt = match try_verified_call.send().await { Ok(p) => p.await?, Err(e) => return Err(anyhow::anyhow!("verified request failed: {:?}", e)) };
                if let Some(rcpt) = rcpt_opt.as_ref() { let topic_sig = H256::from(ethers::utils::keccak256(b"SigReqBBSPlusVerified(address,uint256,string,bytes,uint32[],uint256[],uint32[],bytes,uint256,uint256[],bytes)")); let mut found = false; for lg in rcpt.logs.iter() { if lg.address == req_addr && !lg.topics.is_empty() && lg.topics[0] == topic_sig { found = true; break; } } println!("[on-chain] commitment PoK verified: {}", if found { "OK" } else { "UNKNOWN" }); }
                if let Some(rcpt) = rcpt_opt.clone() { let txh = rcpt.transaction_hash; if let Some(bn) = rcpt.block_number { persist_request_meta(&user_id, &cred_name, sid, txh, bn.as_u64()).ok(); } }
                // Wait for Aggregated and then fetch signature; persist artifacts; enter action loop
                loop {
                    if let Some(_log) = agg_stream.next().await {
                        // Fetch aggregated signature from registry
                        let (abytes, e_u, s_u, _status) = registry.get_signature(cred_name.clone(), U256::from(sid)).await?;
                        if abytes.0.len() != 128 { anyhow::bail!("registry returned bad A len: {}", abytes.0.len()); }
                        // Build messages and persist artifacts similar to Verify path
                        let pb2 = fetch_params_bundle(&params_contract, &cred_name).await?;
                        let onchain_mcount = pb2.mcount; let onchain_t = pb2.t; let onchain_n = pb2.n;
                        let mut messages: Vec<Fr> = (0..onchain_mcount).map(|i| Fr::from(100 + i as u64)).collect();
                        if !messages.is_empty() { messages[0] = Fr::from(sid); }
                        if let Ok(Some(rev)) = load_revealed_pairs(&user_id, &cred_name, sid) {
                            for (i, fr_val) in rev { if i != 0 && (i as usize) < messages.len() { messages[i as usize] = fr_val; } }
                        }
                        use ark_serialize::CanonicalSerialize;
                        let msgs_hex: Vec<String> = messages.iter().map(|f| { let mut be = Vec::new(); ark_serialize::CanonicalSerialize::serialize_compressed(f, &mut be).unwrap(); format!("0x{}", hex::encode(be)) }).collect();
                        store.save_messages(sid, &MessagesFile(msgs_hex))?;
                        // params.json left as-is for now
                        // Persist aggregated signature from registry
                        let a = eip2537_g1_to_affine(&abytes.0[..])?; let e = u256_to_fr::<Fr>(&e_u); let s = u256_to_fr::<Fr>(&s_u);
                        let signature = bbs_plus::signature::SignatureG1::<Bls12_381> { A: a, e, s };
                        let mut a_bytes = Vec::new(); signature.A.serialize_compressed(&mut a_bytes)?;
                        let mut e_bytes = Vec::new(); signature.e.serialize_compressed(&mut e_bytes)?;
                        let mut s_bytes = Vec::new(); signature.s.serialize_compressed(&mut s_bytes)?;
                        store.save_signature(sid, &SignatureFile { a: format!("0x{}", hex::encode(a_bytes)), e: format!("0x{}", hex::encode(e_bytes)), s: format!("0x{}", hex::encode(s_bytes)) })?;
                        // Enter interactive loop and then return
                        #[cfg(feature = "interactive")]
                        {
                            let sess = session::Session::load(&user_id, &cred_name, sid, &params_contract).await?;
                            return ui::run_action_loop(client.clone(), &params_contract, &sess).await;
                        }
                        return Ok(());
                    }
                }
            } else {
                let try_verified_call = req.broadcast_sig_req_bbs_plus_verified(
                    U256::from(req_session.sid), req_session.cred_name.clone(),
                    req_session.commitment_u.clone(), req_session.commitment_b.clone(),
                    req_session.revealed_idx.clone(), req_session.revealed_vals.clone(),
                    req_session.h0_b.clone(), req_session.h_b.clone(),
                    req_session.hidden_idx_vec.clone(), req_session.t_b.clone(),
                    req_session.c_u256, req_session.resp_vec_u256.clone(),
                    req_session.context_bytes.clone(),
                );
                let rcpt_opt = match try_verified_call.send().await { Ok(p) => p.await?, Err(e) => return Err(anyhow::anyhow!("verified request failed: {:?}", e)) };
                if let Some(rcpt) = rcpt_opt.clone() { let txh = rcpt.transaction_hash; if let Some(bn) = rcpt.block_number { persist_request_meta(&user_id, &cred_name, sid, txh, bn.as_u64()).ok(); } }
            }
        }
        Mode::Verify { sid } => {
            if let Some(registry) = registry_opt.as_ref() {
                let (abytes, e_u, s_u, _status_raw) = registry.get_signature(cred_name.clone(), U256::from(sid)).await?;
                if abytes.0.len() == 128 {
                    // Persist params and messages
                    let pb = fetch_params_bundle(&params_contract, &cred_name).await?;
                    let onchain_mcount = pb.mcount; let onchain_t = pb.t; let onchain_n = pb.n;
                    let mut messages: Vec<Fr> = (0..onchain_mcount).map(|i| Fr::from(100 + i as u64)).collect();
                    if !messages.is_empty() { messages[0] = Fr::from(sid); }
                    if let Ok(Some(rev)) = load_revealed_pairs(&user_id, &cred_name, sid) {
                        for (i, fr_val) in rev { if i != 0 && (i as usize) < messages.len() { messages[i as usize] = fr_val; } }
                    }
                    use ark_serialize::CanonicalSerialize;
                    let msgs_hex: Vec<String> = messages.iter().map(|f| { let mut be = Vec::new(); ark_serialize::CanonicalSerialize::serialize_compressed(f, &mut be).unwrap(); format!("0x{}", hex::encode(be)) }).collect();
                    store.save_messages(sid, &MessagesFile(msgs_hex))?;
                    // params.json left as-is for now
                    // Persist signature
                    let a = eip2537_g1_to_affine(&abytes.0[..])?; let e = u256_to_fr::<Fr>(&e_u); let s = u256_to_fr::<Fr>(&s_u);
                    let signature = bbs_plus::signature::SignatureG1::<Bls12_381> { A: a, e, s };
                    let mut a_bytes = Vec::new(); signature.A.serialize_compressed(&mut a_bytes)?;
                    let mut e_bytes = Vec::new(); signature.e.serialize_compressed(&mut e_bytes)?;
                    let mut s_bytes = Vec::new(); signature.s.serialize_compressed(&mut s_bytes)?;
                    store.save_signature(sid, &SignatureFile { a: format!("0x{}", hex::encode(a_bytes)), e: format!("0x{}", hex::encode(e_bytes)), s: format!("0x{}", hex::encode(s_bytes)) })?;
                    println!("[verify] artifacts written to {}", store.base(sid).display());
                    // Enter interactive action loop (off-chain verify, witness, present)
                    #[cfg(feature = "interactive")]
                    {
                        let sess = session::Session::load(&user_id, &cred_name, sid, &params_contract).await?;
                        return ui::run_action_loop(client.clone(), &params_contract, &sess).await;
                    }
                    return Ok(());
                }
            }
            anyhow::bail!("Aggregated signature not found in registry for sid {}", sid);
        }
        Mode::Present { sid } => {
            #[cfg(feature = "interactive")]
            {
                let sess = session::Session::load(&user_id, &cred_name, sid, &params_contract).await?;
                return ui::run_action_loop(client.clone(), &params_contract, &sess).await;
            }
            return Ok(());
        }
        
    }

    Ok(())
}
