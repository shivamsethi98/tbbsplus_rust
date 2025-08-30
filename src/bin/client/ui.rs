use std::sync::Arc;
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::{rngs::StdRng, SeedableRng}, UniformRand};
use bbs_plus::prelude::*;
use blake2::Blake2b512;
use ethers::contract::Contract;
use ethers::providers::{Provider, Ws};
use ethers::middleware::SignerMiddleware;
use ethers::signers::LocalWallet;
use ethers::types::{Address, Bytes as EthBytes, H256, U256};

use tbbsplus_rust::orchestration::onchain::ParamsContract;
use tbbsplus_rust::orchestration::onchain;
use tbbsplus_rust::orchestration::persistence::{load_revealed_pairs, CredentialsStore, MessagesFile, SignatureFile};
use tbbsplus_rust::orchestration::crypto::encoding::{
    fr_to_u256, g1_to_eip2537_bytes, eip2537_g1_to_affine, eip2537_g2_to_affine,
};
use tbbsplus_rust::orchestration::crypto::pok::{build_pok_and_proof, build_presentation_tuples, EncExtras};
use vb_accumulator::proofs_cdh::MembershipProofProtocol as AccMemPokProtocol;
use vb_accumulator::witness::MembershipWitness as AccMembershipWitness;
use schnorr_pok::compute_random_oracle_challenge;
use tbbsplus_rust::orchestration::chain::clients::{VerifyClient, AccumulatorClient};

use super::session::Session;
fn metrics_append(enabled: bool, path: &str, value: serde_json::Value) {
    if !enabled { return; }
    let _ = (|| -> Result<(), Box<dyn std::error::Error>> {
        if let Some(dir) = std::path::Path::new(path).parent() { let _ = std::fs::create_dir_all(dir); }
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        let s = serde_json::to_string(&value)?;
        use std::io::Write; writeln!(f, "{}", s)?;
        Ok(())
    })();
}

pub async fn run_action_loop(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    params_contract: &ParamsContract<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    session: &Session,
) -> anyhow::Result<()> {
    use std::fs;
    // Fetch params and counts via shared helper
    let pb = onchain::fetch_params_bundle(params_contract, &session.cred_name).await?;
    let onchain_mcount: u32 = pb.mcount;
    let onchain_t: u16 = pb.t;
    let onchain_n: u16 = pb.n;

    let store = CredentialsStore::new(&session.user_id, &session.cred_name);
    // Load messages and aggregated signature
    let msgs_hex: Vec<String> = match store.load_messages(session.sid)? { Some(MessagesFile(v)) => v, None => anyhow::bail!("messages.json missing") };
    let mut messages: Vec<Fr> = Vec::with_capacity(msgs_hex.len());
    for h in msgs_hex { let bytes = hex::decode(h.trim_start_matches("0x"))?; messages.push(Fr::deserialize_compressed(&bytes[..])?); }
    let sig_file = store.load_signature(session.sid)?.ok_or_else(|| anyhow::anyhow!("agg_signature.json missing"))?;
    let a_hex = sig_file.a.as_str();
    let e_hex = sig_file.e.as_str();
    let s_hex = sig_file.s.as_str();
    let a = <Bls12_381 as ark_ec::pairing::Pairing>::G1Affine::deserialize_compressed(&hex::decode(a_hex.trim_start_matches("0x"))?[..])?;
    let e = Fr::deserialize_compressed(&hex::decode(e_hex.trim_start_matches("0x"))?[..])?;
    let s = Fr::deserialize_compressed(&hex::decode(s_hex.trim_start_matches("0x"))?[..])?;
    let signature = bbs_plus::signature::SignatureG1::<Bls12_381> { A: a, e, s };

    let metrics = std::env::var("METRICS").map(|v| v=="1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let metrics_file = std::env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/client.ndjson".into());
    loop {
        println!("Choose action: [v]erify off-chain, [p]resent on-chain, [w]itness check, [e]xit (default: verify)");
        let mut line = String::new(); std::io::stdin().read_line(&mut line)?; let choice = line.trim().to_lowercase();
    if choice.is_empty() || choice == "v" || choice == "verify" {
            // Build params and public key (mirrors issuer setup)
            let params_bbs = SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(session.cred_name.as_bytes(), onchain_mcount);
            let mut rng_sk = StdRng::seed_from_u64(42);
            let (secret, _shares, _poly) = secret_sharing_and_dkg::shamir_ss::deal_random_secret::<_, Fr>(&mut rng_sk, onchain_t, onchain_n)
                .map_err(|e| anyhow::anyhow!("deal_random_secret failed: {:?}", e))?;
            let pk = PublicKeyG2::generate_using_secret_key(&SecretKey(secret), &params_bbs);
            let sig_for_verify = {
                let bpath = store.base(session.sid).join("blinding.hex");
                if let Ok(s) = fs::read_to_string(&bpath) {
                    if let Some(stripped) = s.strip_prefix("0x") { if let Ok(bytes) = hex::decode(stripped) { if let Ok(b) = Fr::deserialize_compressed(&bytes[..]) { println!("[local] found blinding; unblinding before verification"); signature.clone().unblind(&b) } else { signature.clone() } } else { signature.clone() } }
                    else { signature.clone() }
                } else { signature.clone() }
            };
            match sig_for_verify.verify(&messages, pk, params_bbs) {
                Ok(()) => println!("[local] aggregated signature verification: OK"),
                Err(e) => println!("[local] aggregated signature verification FAILED: {:?}", e),
            }
            continue;
        } else if choice == "w" || choice == "witness" {
            // Accumulator membership check
            let acc_addr: Address = std::env::var("ACC_CONTRACT").expect("ACC_CONTRACT").parse()?;
            let acc = AccumulatorClient::new(acc_addr, client.clone())?;
            let e_u = fr_to_u256(&signature.e);
            let wit: ethers::types::Bytes = acc.contract.method("getWitness", (session.cred_name.to_string(), e_u))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
            if wit.0.is_empty() { println!("[witness] not available yet"); continue; }
            // Rebuild accumulator params and pkAcc
            let (g1_b, _h0_b, g2_b): (EthBytes, EthBytes, EthBytes) = params_contract.method("getG1H0G2ByName", session.cred_name.to_string())?.call().await?;
            let g1 = eip2537_g1_to_affine(&g1_b.0[..])?; let g2 = eip2537_g2_to_affine(&g2_b.0[..])?;
            let vb_params = vb_accumulator::setup::SetupParams::<Bls12_381> { P: g1, P_tilde: g2 };
            let pk_g2_b: EthBytes = params_contract.method("getOpenerPkG2ByName", session.cred_name.to_string())?.call().await?;
            let pk_acc = vb_accumulator::setup::PublicKey::<Bls12_381>(eip2537_g2_to_affine(&pk_g2_b.0[..])?);
            let delta_b: ethers::types::Bytes = acc.contract.method("getDelta", (session.cred_name.to_string(),))?.call().await?;
            if delta_b.0.len() != 128 { println!("[witness] no Delta on-chain"); continue; }
            let v = eip2537_g1_to_affine(&delta_b.0[..])?;
            use vb_accumulator::positive::Accumulator as _;
            let acc_view = vb_accumulator::positive::PositiveAccumulator::<ark_bls12_381::G1Affine>::from_accumulated(v);
            let wit_aff = eip2537_g1_to_affine(&wit.0[..])?;
            let mw = vb_accumulator::witness::MembershipWitness::<ark_bls12_381::G1Affine>(wit_aff);
            let ok = vb_accumulator::positive::Accumulator::verify_membership::<Bls12_381>(&acc_view, &signature.e, &mw, &pk_acc, &vb_params);
            println!("[witness] membership {}", if ok { "OK" } else { "FAIL" });
            continue;
        } else if choice == "p" || choice == "present" {
            // On-chain presentation via VerifyWrapper
            let t0_prove = std::time::Instant::now();
            let pb = onchain::fetch_params_bundle(params_contract, &session.cred_name).await?;
            let params_bbs = pb.params_bbs.clone();
            // Prompt revealed indices
            println!("Enter revealed indices for presentation (comma-separated, e.g., 0,2). Leave blank for 0 only:");
            let mut rset = String::new(); std::io::stdin().read_line(&mut rset)?;
            let revealed_idx: Vec<u32> = if rset.trim().is_empty() { vec![0u32] } else { rset.split(',').filter_map(|s| s.trim().parse::<u32>().ok()).collect() };
            // Fetch Ybar
            let ybar_bytes: EthBytes = params_contract.method("getOpenerYbarByName", session.cred_name.to_string())?.call().await?;
            if ybar_bytes.0.len() != 128 { anyhow::bail!("opener Ybar missing or wrong length"); }
            let ybar_aff = eip2537_g1_to_affine(&ybar_bytes.0[..])?;
            // Unblind signature if blinding exists, else use as-is
            let sig_struct = {
                let bpath = store.base(session.sid).join("blinding.hex");
                if let Ok(s) = std::fs::read_to_string(&bpath) {
                    if let Some(stripped) = s.strip_prefix("0x") {
                        if let Ok(bytes) = hex::decode(stripped) {
                            if let Ok(b) = Fr::deserialize_compressed(&bytes[..]) {
                                println!("[present] found blinding; unblinding signature before PoK");
                                signature.clone().unblind(&b)
                            } else { signature.clone() }
                        } else { signature.clone() }
                    } else { signature.clone() }
                } else { signature.clone() }
            };
            let (proof, c_fr, revealed_idx2) = build_pok_and_proof(&params_bbs, &sig_struct, &messages, &ybar_aff, &revealed_idx)?;
            let prove_ms = t0_prove.elapsed().as_millis() as u64;
            metrics_append(metrics, &metrics_file, serde_json::json!({"scenario":"off_chain_proof_gen","sid":session.sid,"ms": prove_ms}));
            let (sig_t, ctx_t, revealed_t, challenge_u256, p1_t, p2_t, enc_extras) = build_presentation_tuples(&params_bbs, &proof, &revealed_idx2, &messages, pb.mcount, &c_fr)?;
            let EncExtras { t1_b, t2enc_b, t_enc_b, resp_a3_u, resp_k_u } = enc_extras;
            let verify_addr: Address = std::env::var("VERIFY_CONTRACT").expect("VERIFY_CONTRACT").parse()?;
            let acc_addr: Address = std::env::var("ACC_CONTRACT").expect("ACC_CONTRACT").parse()?;
            let verify = VerifyClient::new(verify_addr, client.clone())?;
            let acc = AccumulatorClient::new(acc_addr, client.clone())?;
            let e_u = fr_to_u256(&signature.e);
            let witness_b: ethers::types::Bytes = acc.contract.method("getWitness", (session.cred_name.to_string(), e_u))?.call().await.unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
            if witness_b.0.is_empty() { println!("[present] membership witness missing on-chain"); continue; }
            // Fetch current accumulator anchor Delta
            let delta_b: ethers::types::Bytes = acc.contract.method("getDelta", (session.cred_name.to_string(),))?.call().await?;
            if delta_b.0.len() != 128 { println!("[present] missing Delta on-chain"); continue; }
            let delta_aff = eip2537_g1_to_affine(&delta_b.0[..])?;
            let params_addr_eth: Address = params_contract.address();
            // Build accumulator membership PoK
            let wit_aff = eip2537_g1_to_affine(&witness_b.0[..])?;
            let mw = AccMembershipWitness::<ark_bls12_381::G1Affine>(wit_aff);
            let mut rng_acc = StdRng::seed_from_u64(0xacc_u64);
            let protocol = AccMemPokProtocol::<Bls12_381>::init(&mut rng_acc, signature.e, None, &delta_aff, &mw);
            let mut chal_acc_bytes = Vec::new();
            protocol
                .challenge_contribution(&delta_aff, &mut chal_acc_bytes)
                .map_err(|e| anyhow::anyhow!("accumulator pok challenge_contribution failed: {:?}", e))?;
            let c_acc = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_acc_bytes);
            let proof_acc = protocol
                .gen_proof(&c_acc)
                .map_err(|e| anyhow::anyhow!("accumulator pok gen_proof failed: {:?}", e))?;
            let a_prime_b = EthBytes::from(g1_to_eip2537_bytes(&proof_acc.0.A_prime).to_vec());
            let a_bar_b   = EthBytes::from(g1_to_eip2537_bytes(&proof_acc.0.A_bar).to_vec());
            let t_b       = EthBytes::from(g1_to_eip2537_bytes(&proof_acc.0.sc.as_ref().ok_or_else(|| anyhow::anyhow!("acc sc missing"))?.t).to_vec());
            let resp_r_u  = fr_to_u256(&proof_acc.0.sc.as_ref().unwrap().response1);
            let resp_e_u  = fr_to_u256(&proof_acc.0.sc.as_ref().unwrap().response2);
            let challenge_acc_u256 = fr_to_u256(&c_acc);
            let mp_tuple = (a_prime_b, a_bar_b, t_b, resp_r_u, resp_e_u);

            let call = verify.contract.method::<_, bool>(
                "verifyPokEncWithPairingAndMembershipPokFromParamsEmit",
                (
                    sig_t, ctx_t, revealed_t, challenge_u256, challenge_acc_u256, p1_t, p2_t,
                    t1_b, t2enc_b, t_enc_b, resp_a3_u, resp_k_u,
                    session.cred_name.to_string(), params_addr_eth, acc_addr,
                    mp_tuple,
                ),
            )?;
            let topic = H256::from(ethers::utils::keccak256(b"PresentationVerified(string,address,bytes,bytes)"));
            let mut ok = false;
            let t0_send = std::time::Instant::now();
            match call.send().await {
                Ok(pending_tx) => {
                    match pending_tx.await {
                        Ok(rcpt_opt) => {
                            if let Some(r) = rcpt_opt.as_ref() { for lg in &r.logs { if lg.address == verify_addr && !lg.topics.is_empty() && lg.topics[0] == topic { ok = true; break; } } }
                            // Emit metrics with gas if available
                            if let Some(r) = rcpt_opt.as_ref() {
                                let gas_used = r.gas_used.unwrap_or_default();
                                let eff_price = r.effective_gas_price.unwrap_or_default();
                                let cost = gas_used * eff_price;
                                let blk = r.block_number.unwrap_or_default();
                                metrics_append(metrics, &metrics_file, serde_json::json!({
                                    "scenario":"on_chain_verify_time",
                                    "sid": session.sid,
                                    "ms": t0_send.elapsed().as_millis() as u64,
                                    "hash": format!("0x{:x}", r.transaction_hash),
                                    "blockNumber": blk.as_u64(),
                                    "gasUsed": gas_used.to_string(),
                                    "effectiveGasPrice": eff_price.to_string(),
                                    "costWei": cost.to_string()
                                }));
                                // Presentation E2E from proof construction start to tx mined
                                metrics_append(metrics, &metrics_file, serde_json::json!({
                                    "scenario":"presentation_e2e",
                                    "sid": session.sid,
                                    "ms": t0_prove.elapsed().as_millis() as u64
                                }));
                                // Off-chain verification (BBS+ PoK incl. pairing and optional enc relation; and accumulator membership PoK)
                                let mut revealed_map = std::collections::BTreeMap::<usize, Fr>::new();
                                for &ix in revealed_idx.iter() { revealed_map.insert(ix as usize, messages[ix as usize]); }
                                let t0_off = std::time::Instant::now();
                                // BBS+ PoK verify using issuer pk from Params
                                let pk_g2_b: EthBytes = params_contract
                                    .method("getPkG2ByName", (session.cred_name.to_string(),))?
                                    .call()
                                    .await?;
                                let pk_g2_aff = eip2537_g2_to_affine(&pk_g2_b.0[..])?;
                                let bbs_pk = bbs_plus::setup::PublicKeyG2::<Bls12_381>(pk_g2_aff);
                                let prepared_bbs_pk = bbs_plus::setup::PreparedPublicKeyG2::<Bls12_381>::from(bbs_pk);
                                let prepared_bbs_params = bbs_plus::setup::PreparedSignatureParamsG1::<Bls12_381>::from(params_bbs.clone());
                                let mut bbs_ok = proof.verify(&revealed_map, &c_fr, prepared_bbs_pk, prepared_bbs_params).is_ok();
                                // Explicit encryption relation check if present
                                if bbs_ok {
                                    if let (Some(_ybar), Some(_t2e), Some(enc)) = (proof.Y_bar.as_ref(), proof.T2_enc.as_ref(), proof.sc_resp_enc.as_ref()) {
                                        bbs_ok = enc.verify(_t2e, &proof.A_prime, _ybar, &c_fr);
                                    }
                                }
                                // Accumulator membership verify off-chain
                                {
                                    use vb_accumulator::setup::{PreparedPublicKey, PreparedSetupParams, PublicKey, SetupParams};
                                    let acc_params = SetupParams::<Bls12_381> { P: params_bbs.g1, P_tilde: params_bbs.g2 };
                                    let prepared_params = PreparedSetupParams::<Bls12_381>::from(acc_params);
                                    let opener_pk_b: EthBytes = params_contract
                                        .method("getOpenerPkG2ByName", (session.cred_name.to_string(),))?
                                        .call()
                                        .await?;
                                    let opener_pk_aff = eip2537_g2_to_affine(&opener_pk_b.0[..])?;
                                    let acc_pk = PublicKey::<Bls12_381>(opener_pk_aff);
                                    let prepared_pk = PreparedPublicKey::<Bls12_381>::from(acc_pk);
                                    let acc_ok = proof_acc.verify(&delta_aff, &c_acc, prepared_pk, prepared_params).is_ok();
                                    let off_ms = t0_off.elapsed().as_millis() as u64;
                                    metrics_append(metrics, &metrics_file, serde_json::json!({
                                        "scenario":"off-chain_verify_time",
                                        "sid": session.sid,
                                        "ms": off_ms,
                                        "bbs_ok": bbs_ok,
                                        "acc_ok": acc_ok
                                    }));
                                }
                            } else {
                                metrics_append(metrics, &metrics_file, serde_json::json!({
                                    "scenario":"on_chain_verify_time",
                                    "sid": session.sid,
                                    "ms": t0_send.elapsed().as_millis() as u64,
                                    "hash": rcpt_opt.as_ref().map(|r| format!("0x{:x}", r.transaction_hash))
                                }));
                            }
                        }
                        Err(e) => { eprintln!("[present] tx await error: {:?}", e); }
                    }
                }
                Err(e) => { eprintln!("[present] call reverted: {:?}", e); }
            }
            println!("Client: presentation {}", if ok { "succeeded" } else { "failed" });
            continue;
        } else if choice == "e" || choice == "exit" { break; } else { continue; }
    }
    Ok(())
}
