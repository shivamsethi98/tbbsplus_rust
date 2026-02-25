use std::sync::Arc;
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::{rngs::StdRng, SeedableRng}, UniformRand};
use bbs_plus::prelude::*;
use blake2::Blake2b512;
use ethers::contract::Contract;
use ethers::providers::{Provider, Ws, Middleware};
use ethers::middleware::SignerMiddleware;
use ethers::signers::LocalWallet;
use ethers::types::{Address, Bytes as EthBytes, H256, U256};

use tbbsplus_rust::orchestration::onchain::ParamsContract;
use tbbsplus_rust::orchestration::onchain;
use tbbsplus_rust::orchestration::persistence::{load_revealed_pairs, CredentialsStore, MessagesFile, SignatureFile};
use tbbsplus_rust::orchestration::crypto::encoding::{
    fr_to_u256, u256_to_fr, g1_to_eip2537_bytes, eip2537_g1_to_affine, eip2537_g2_to_affine,
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
    let msgs_hex: Vec<String> = match store.load_messages()? { Some(MessagesFile(v)) => v, None => anyhow::bail!("messages.json missing") };
    let mut messages: Vec<Fr> = Vec::with_capacity(msgs_hex.len());
    for h in msgs_hex { let bytes = hex::decode(h.trim_start_matches("0x"))?; messages.push(Fr::deserialize_compressed(&bytes[..])?); }
    let sig_file = store.load_signature()?.ok_or_else(|| anyhow::anyhow!("agg_signature.json missing"))?;
    let a_hex = sig_file.a.as_str();
    let e_hex = sig_file.e.as_str();
    let s_hex = sig_file.s.as_str();
    let a = <Bls12_381 as ark_ec::pairing::Pairing>::G1Affine::deserialize_compressed(&hex::decode(a_hex.trim_start_matches("0x"))?[..])?;
    let e = Fr::deserialize_compressed(&hex::decode(e_hex.trim_start_matches("0x"))?[..])?;
    let s = Fr::deserialize_compressed(&hex::decode(s_hex.trim_start_matches("0x"))?[..])?;
    let signature = bbs_plus::signature::SignatureG1::<Bls12_381> { A: a, e, s };

    let metrics = std::env::var("METRICS").map(|v| v=="1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let metrics_file = std::env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/client.ndjson".into());
    'action: loop {
        println!("Choose action: [v]erify off-chain, [p]resent on-chain, [b]atch export, [w]itness check, [e]xit (default: verify)");
        let mut line = String::new(); std::io::stdin().read_line(&mut line)?; let choice = line.trim().to_lowercase();
    if choice.is_empty() || choice == "v" || choice == "verify" {
            // Build params and issuer public key from on-chain Params
            let params_bbs = pb.params_bbs.clone();
            let pk_g2_b: EthBytes = params_contract
                .method("getPkG2ByName", (session.cred_name.to_string(),))?
                .call()
                .await?;
            let pk_g2_aff = eip2537_g2_to_affine(&pk_g2_b.0[..])?;
            let pk = bbs_plus::setup::PublicKeyG2::<Bls12_381>(pk_g2_aff);
            // Try unblinded first if blinding exists; if that fails, try as-is
            let bpath = store.base().join("blinding.hex");
            let maybe_blinding = if let Ok(s) = fs::read_to_string(&bpath) {
                if let Some(stripped) = s.strip_prefix("0x") {
                    if let Ok(bytes) = hex::decode(stripped) {
                        Fr::deserialize_compressed(&bytes[..]).ok()
                    } else { None }
                } else { None }
            } else { None };
            let try_unblinded_first = if let Some(b) = maybe_blinding.as_ref() {
                println!("[local] found blinding; unblinding before verification");
                let sig_unblinded = signature.clone().unblind(b);
                match sig_unblinded.verify(&messages, pk.clone(), params_bbs.clone()) {
                    Ok(()) => { println!("[local] aggregated signature verification: OK (unblinded)"); true }
                    Err(e) => { println!("[local] unblinded verify FAILED: {:?}; retrying with blinded signature", e); false }
                }
            } else { false };
            if !try_unblinded_first {
                match signature.clone().verify(&messages, pk, params_bbs) {
                    Ok(()) => println!("[local] aggregated signature verification: OK (as-is)"),
                    Err(e) => println!("[local] aggregated signature verification FAILED (as-is): {:?}", e),
                }
            }
            continue;
        } else if choice == "w" || choice == "witness" {
            // Accumulator membership: sync witness from event logs, then verify
            let acc_addr: Address = std::env::var("ACC_CONTRACT").expect("ACC_CONTRACT").parse()?;
            let acc = AccumulatorClient::new(acc_addr, client.clone())?;
            let my_e_u256 = fr_to_u256(&signature.e);

            // Rebuild accumulator params and pkAcc
            let (g1_b, _h0_b, g2_b): (EthBytes, EthBytes, EthBytes) = params_contract.method("getG1H0G2ByName", session.cred_name.to_string())?.call().await?;
            let g1 = eip2537_g1_to_affine(&g1_b.0[..])?; let g2 = eip2537_g2_to_affine(&g2_b.0[..])?;
            let vb_params = vb_accumulator::setup::SetupParams::<Bls12_381> { P: g1, P_tilde: g2 };
            let pk_g2_b: EthBytes = params_contract.method("getOpenerPkG2ByName", session.cred_name.to_string())?.call().await?;
            let pk_acc = vb_accumulator::setup::PublicKey::<Bls12_381>(eip2537_g2_to_affine(&pk_g2_b.0[..])?);

            // Current on-chain delta
            let delta_b: ethers::types::Bytes = acc.contract.method("getDelta", (session.cred_name.to_string(),))?.call().await?;
            if delta_b.0.len() != 128 { println!("[witness] no Delta on-chain yet"); continue; }
            let v_current = eip2537_g1_to_affine(&delta_b.0[..])?;

            // Try cached witness first
            let wit_path = store.base().join("witness.bin");
            let witness_aff: Option<ark_bls12_381::G1Affine> = if let Ok(raw) = std::fs::read(&wit_path) {
                if raw.len() == 128 {
                    let cached = eip2537_g1_to_affine(&raw[..])?;
                    let mw = vb_accumulator::witness::MembershipWitness::<ark_bls12_381::G1Affine>(cached);
                    use vb_accumulator::positive::Accumulator as _;
                    let ok = vb_accumulator::positive::Accumulator::verify_membership::<Bls12_381>(
                        &vb_accumulator::positive::PositiveAccumulator::from_accumulated(v_current), &signature.e, &mw, &pk_acc, &vb_params);
                    if ok {
                        println!("[witness] cached witness still valid");
                        println!("[witness] membership OK");
                        continue;
                    }
                    println!("[witness] cached witness stale — re-syncing from event logs");
                    None
                } else { None }
            } else {
                println!("[witness] syncing witness from event logs...");
                None
            };

            // --- Event-log witness sync ---
            use ethers::types::{Filter, ValueOrArray, BlockNumber};
            let name_topic = H256::from(ethers::utils::keccak256(session.cred_name.as_bytes()));

            // 1. Find MemberAdded(name, e) where e == my element
            let topic_added = H256::from(ethers::utils::keccak256(b"MemberAdded(string,uint256)"));
            let mut my_e_be = [0u8; 32]; my_e_u256.to_big_endian(&mut my_e_be);
            let my_e_topic = H256::from(my_e_be);
            let filter_my_add = Filter::new()
                .address(ValueOrArray::Value(acc_addr))
                .topic0(ValueOrArray::Value(topic_added))
                .topic1(ValueOrArray::Value(name_topic))
                .topic2(ValueOrArray::Value(my_e_topic))
                .from_block(BlockNumber::Earliest);
            let my_add_logs = client.provider().get_logs(&filter_my_add).await?;
            if my_add_logs.is_empty() { println!("[witness] MemberAdded event not found for this credential"); continue; }
            let my_add_block = my_add_logs[0].block_number.ok_or_else(|| anyhow::anyhow!("MemberAdded log missing block_number"))?.as_u64();
            println!("[witness] MemberAdded found at block {}", my_add_block);

            // 2. Initial witness = Delta at block before our addition
            let prev_delta_b: ethers::types::Bytes = acc.contract
                .method("getDelta", (session.cred_name.to_string(),))?
                .block(ethers::types::BlockId::Number(BlockNumber::Number((my_add_block - 1).into())))
                .call().await?;
            let initial_witness = if prev_delta_b.0.len() == 128 {
                eip2537_g1_to_affine(&prev_delta_b.0[..])?
            } else {
                // If no delta existed before, the initial accumulator was g1 (generator)
                println!("[witness] no Delta before addition; using g1 as initial witness");
                g1
            };
            let mut wit = vb_accumulator::witness::MembershipWitness::<ark_bls12_381::G1Affine>(initial_witness);

            // 3. Replay subsequent MemberAdded / MemberRevoked events
            // Query ALL AccumulatorUpdated events from our block onwards to track delta changes
            let filter_added_after = Filter::new()
                .address(ValueOrArray::Value(acc_addr))
                .topic0(ValueOrArray::Value(topic_added))
                .topic1(ValueOrArray::Value(name_topic))
                .from_block(BlockNumber::Number(my_add_block.into()));
            let all_adds = client.provider().get_logs(&filter_added_after).await?;

            let topic_revoked = H256::from(ethers::utils::keccak256(b"MemberRevoked(string,uint256,bytes)"));
            let filter_revoked_after = Filter::new()
                .address(ValueOrArray::Value(acc_addr))
                .topic0(ValueOrArray::Value(topic_revoked))
                .topic1(ValueOrArray::Value(name_topic))
                .from_block(BlockNumber::Number(my_add_block.into()));
            let all_revs = client.provider().get_logs(&filter_revoked_after).await?;

            // Merge events by (block, log_index) to process in order
            #[derive(Debug)]
            enum AccEvent { Add(U256), Revoke(U256, Vec<u8>) }
            let mut events: Vec<(u64, u64, AccEvent)> = Vec::new();
            for lg in &all_adds {
                let bn = lg.block_number.map(|b| b.as_u64()).unwrap_or(0);
                let li = lg.log_index.map(|i| i.as_u64()).unwrap_or(0);
                // topic2 = indexed e
                if lg.topics.len() >= 3 {
                    let e_val = U256::from_big_endian(lg.topics[2].as_bytes());
                    if e_val == my_e_u256 { continue; } // skip our own addition
                    events.push((bn, li, AccEvent::Add(e_val)));
                }
            }
            for lg in &all_revs {
                let bn = lg.block_number.map(|b| b.as_u64()).unwrap_or(0);
                let li = lg.log_index.map(|i| i.as_u64()).unwrap_or(0);
                if lg.topics.len() >= 3 {
                    let e_val = U256::from_big_endian(lg.topics[2].as_bytes());
                    // data contains newDelta bytes
                    let new_delta_bytes = lg.data.0.to_vec();
                    events.push((bn, li, AccEvent::Revoke(e_val, new_delta_bytes)));
                }
            }
            events.sort_by_key(|(bn, li, _)| (*bn, *li));

            // Track the accumulator value as we replay updates
            // After our own addition, V = delta at my_add_block (the new delta)
            let post_add_delta_b: ethers::types::Bytes = acc.contract
                .method("getDelta", (session.cred_name.to_string(),))?
                .block(ethers::types::BlockId::Number(BlockNumber::Number(my_add_block.into())))
                .call().await?;
            let mut v_tracking = if post_add_delta_b.0.len() == 128 {
                eip2537_g1_to_affine(&post_add_delta_b.0[..])?
            } else { v_current };

            let mut updates_applied = 0u64;
            for (_bn, _li, ev) in &events {
                match ev {
                    AccEvent::Add(e_other) => {
                        let e_other_fr: Fr = u256_to_fr::<Fr>(e_other);
                        wit = wit.update_after_addition(&signature.e, &e_other_fr, &v_tracking);
                        // After this addition, V becomes V' = (e_other + sk) * V
                        // We don't have sk, but we can query delta at this block
                        // For efficiency, we track by querying the delta at each block
                        // But that's expensive. Instead we look for an AccumulatorUpdated
                        // in the same tx. Since addMember emits AccumulatorUpdated right after
                        // MemberAdded, we need the new delta. Query it at that block.
                        // For now, we query getDelta at the block of this event.
                        let delta_at: ethers::types::Bytes = acc.contract
                            .method("getDelta", (session.cred_name.to_string(),))?
                            .block(ethers::types::BlockId::Number(BlockNumber::Number((*_bn).into())))
                            .call().await?;
                        if delta_at.0.len() == 128 { v_tracking = eip2537_g1_to_affine(&delta_at.0[..])?; }
                        updates_applied += 1;
                    }
                    AccEvent::Revoke(e_other, new_delta_data) => {
                        let e_other_fr: Fr = u256_to_fr::<Fr>(e_other);
                        // newDelta is ABI-encoded in log data, extract 128-byte point
                        // For MemberRevoked the data layout is: offset(32) + length(32) + newDelta128
                        // Actually the event is: MemberRevoked(string indexed name, uint256 indexed e, bytes newDelta)
                        // non-indexed: newDelta (dynamic bytes) => offset(32) + length(32) + data
                        let new_v = if new_delta_data.len() >= 192 {
                            // ABI: 32 offset + 32 length + 128 bytes
                            eip2537_g1_to_affine(&new_delta_data[64..192])?
                        } else if new_delta_data.len() == 128 {
                            eip2537_g1_to_affine(&new_delta_data[..])?
                        } else {
                            println!("[witness] unexpected MemberRevoked data length {}, skipping", new_delta_data.len());
                            continue;
                        };
                        if *e_other == my_e_u256 {
                            println!("[witness] own element was revoked — membership is no longer valid");
                            // Persist stale witness anyway so user can see status
                            let wit_bytes = g1_to_eip2537_bytes(&wit.0);
                            let _ = std::fs::write(&wit_path, &wit_bytes);
                            println!("[witness] you have been revoked from the accumulator");
                            continue 'action;
                        }
                        match wit.update_after_removal(&signature.e, &e_other_fr, &new_v) {
                            Ok(w) => { wit = w; v_tracking = new_v; updates_applied += 1; }
                            Err(e) => { println!("[witness] update_after_removal failed: {:?}", e); continue; }
                        }
                    }
                }
            }
            println!("[witness] replayed {} accumulator updates", updates_applied);

            // 4. Persist witness.bin (128-byte EIP-2537 G1 encoding)
            let wit_bytes = g1_to_eip2537_bytes(&wit.0);
            std::fs::write(&wit_path, &wit_bytes)?;
            println!("[witness] witness.bin written to {}", wit_path.display());

            // 5. Verify membership against current on-chain delta
            use vb_accumulator::positive::Accumulator as _;
            let acc_view = vb_accumulator::positive::PositiveAccumulator::<ark_bls12_381::G1Affine>::from_accumulated(v_current);
            let ok = vb_accumulator::positive::Accumulator::verify_membership::<Bls12_381>(&acc_view, &signature.e, &wit, &pk_acc, &vb_params);
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
                let bpath = store.base().join("blinding.hex");
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
            metrics_append(metrics, &metrics_file, serde_json::json!({"scenario":"off_chain_proof_gen","user_id":&session.user_id,"ms": prove_ms}));
            let (sig_t, ctx_t, revealed_t, challenge_u256, p1_t, p2_t, enc_extras) = build_presentation_tuples(&params_bbs, &proof, &revealed_idx2, &messages, pb.mcount, &c_fr)?;
            let EncExtras { t1_b, t2enc_b, t_enc_b, resp_a3_u, resp_k_u } = enc_extras;
            let verify_addr: Address = std::env::var("VERIFY_CONTRACT").expect("VERIFY_CONTRACT").parse()?;
            let acc_addr: Address = std::env::var("ACC_CONTRACT").expect("ACC_CONTRACT").parse()?;
            let verify = VerifyClient::new(verify_addr, client.clone())?;
            let acc = AccumulatorClient::new(acc_addr, client.clone())?;
            let e_u = fr_to_u256(&signature.e);
            // Load witness from witness.bin (produced by event-log sync)
            let wit_path = store.base().join("witness.bin");
            let witness_raw = match std::fs::read(&wit_path) {
                Ok(b) => b,
                Err(_) => { println!("[present] witness.bin not found — run 'w' first to sync witness"); continue; }
            };
            if witness_raw.len() != 128 { println!("[present] witness.bin has unexpected length {}", witness_raw.len()); continue; }
            // Fetch current accumulator anchor Delta
            let delta_b: ethers::types::Bytes = acc.contract.method("getDelta", (session.cred_name.to_string(),))?.call().await?;
            if delta_b.0.len() != 128 { println!("[present] missing Delta on-chain"); continue; }
            let delta_aff = eip2537_g1_to_affine(&delta_b.0[..])?;
            let params_addr_eth: Address = params_contract.address();
            // Build accumulator membership PoK
            let wit_aff = eip2537_g1_to_affine(&witness_raw[..])?;
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
                                    "user_id": &session.user_id,
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
                                    "user_id": &session.user_id,
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
                                        "user_id": &session.user_id,
                                        "ms": off_ms,
                                        "bbs_ok": bbs_ok,
                                        "acc_ok": acc_ok
                                    }));
                                }
                            } else {
                                metrics_append(metrics, &metrics_file, serde_json::json!({
                                    "scenario":"on_chain_verify_time",
                                    "user_id": &session.user_id,
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
        } else if choice == "b" || choice == "batch" {
            // Export PresentationData as JSON for batch aggregator
            use tbbsplus_rust::orchestration::batching::PresentationData;
            let pb = onchain::fetch_params_bundle(params_contract, &session.cred_name).await?;
            let params_bbs = pb.params_bbs.clone();
            println!("Enter revealed indices for batch export (comma-separated, e.g., 0,2). Leave blank for 0 only:");
            let mut rset = String::new(); std::io::stdin().read_line(&mut rset)?;
            let revealed_idx: Vec<u32> = if rset.trim().is_empty() { vec![0u32] } else { rset.split(',').filter_map(|s| s.trim().parse::<u32>().ok()).collect() };
            // Fetch Ybar
            let ybar_bytes: EthBytes = params_contract.method("getOpenerYbarByName", session.cred_name.to_string())?.call().await?;
            if ybar_bytes.0.len() != 128 { anyhow::bail!("opener Ybar missing or wrong length"); }
            let ybar_aff = eip2537_g1_to_affine(&ybar_bytes.0[..])?;
            // Unblind signature
            let sig_struct = {
                let bpath = store.base().join("blinding.hex");
                if let Ok(s) = std::fs::read_to_string(&bpath) {
                    if let Some(stripped) = s.strip_prefix("0x") {
                        if let Ok(bytes) = hex::decode(stripped) {
                            if let Ok(b) = Fr::deserialize_compressed(&bytes[..]) {
                                signature.clone().unblind(&b)
                            } else { signature.clone() }
                        } else { signature.clone() }
                    } else { signature.clone() }
                } else { signature.clone() }
            };
            let (proof, c_fr, revealed_idx2) = build_pok_and_proof(&params_bbs, &sig_struct, &messages, &ybar_aff, &revealed_idx)?;
            let (sig_t, _ctx_t, _revealed_t, challenge_u256, p1_t, p2_t, enc_extras) = build_presentation_tuples(&params_bbs, &proof, &revealed_idx2, &messages, pb.mcount, &c_fr)?;
            let EncExtras { t1_b, t2enc_b, t_enc_b, resp_a3_u, resp_k_u } = enc_extras;
            // Build accumulator membership PoK
            let acc_addr: Address = std::env::var("ACC_CONTRACT").expect("ACC_CONTRACT").parse()?;
            let acc = AccumulatorClient::new(acc_addr, client.clone())?;
            let wit_path = store.base().join("witness.bin");
            let witness_raw = match std::fs::read(&wit_path) {
                Ok(b) => b,
                Err(_) => { println!("[batch] witness.bin not found — run 'w' first to sync witness"); continue; }
            };
            if witness_raw.len() != 128 { println!("[batch] witness.bin has unexpected length {}", witness_raw.len()); continue; }
            let delta_b: ethers::types::Bytes = acc.contract.method("getDelta", (session.cred_name.to_string(),))?.call().await?;
            if delta_b.0.len() != 128 { println!("[batch] missing Delta on-chain"); continue; }
            let delta_aff = eip2537_g1_to_affine(&delta_b.0[..])?;
            let wit_aff = eip2537_g1_to_affine(&witness_raw[..])?;
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
            let a_prime_acc = g1_to_eip2537_bytes(&proof_acc.0.A_prime).to_vec();
            let a_bar_acc   = g1_to_eip2537_bytes(&proof_acc.0.A_bar).to_vec();
            let t_acc       = g1_to_eip2537_bytes(&proof_acc.0.sc.as_ref().ok_or_else(|| anyhow::anyhow!("acc sc missing"))?.t).to_vec();
            let resp_r_acc  = fr_to_u256(&proof_acc.0.sc.as_ref().unwrap().response1);
            let resp_e_acc  = fr_to_u256(&proof_acc.0.sc.as_ref().unwrap().response2);
            let challenge_acc_u256 = fr_to_u256(&c_acc);
            // Build revealed_vals from messages at revealed_idx
            let revealed_vals: Vec<U256> = revealed_idx.iter().map(|&i| fr_to_u256(&messages[i as usize])).collect();
            // Extract resp_msgs from p2_t
            let resp_msgs = p2_t.1.clone();
            let pres_data = PresentationData {
                a_prime: sig_t.0.to_vec(),
                a_bar: sig_t.1.to_vec(),
                d: sig_t.2.to_vec(),
                t1_bbs: p1_t.0.to_vec(),
                t2_bbs: p2_t.0.to_vec(),
                bbs_challenge: challenge_u256,
                resp_a: p1_t.1,
                resp_h0: p1_t.2,
                resp_r3: p2_t.2,
                resp_sprime: p2_t.3,
                resp_msgs,
                t1_enc: t1_b.to_vec(),
                t2_enc: t2enc_b.to_vec(),
                t_enc: t_enc_b.to_vec(),
                resp_a3: resp_a3_u,
                resp_k: resp_k_u,
                a_prime_acc,
                a_bar_acc,
                t_acc,
                acc_challenge: challenge_acc_u256,
                resp_r_acc,
                resp_e_acc,
                revealed_idx: revealed_idx.clone(),
                revealed_vals,
            };
            // Prompt output file
            println!("Enter output file path (default: batch_presentation.json):");
            let mut out_line = String::new(); std::io::stdin().read_line(&mut out_line)?;
            let out_path = if out_line.trim().is_empty() { "batch_presentation.json".to_string() } else { out_line.trim().to_string() };
            // File-locked append for concurrent-safe batch writes
            append_to_batch_json(&out_path, &pres_data)?;
            continue;
        } else if choice == "e" || choice == "exit" { break; } else { continue; }
    }
    Ok(())
}

/// Non-interactive witness sync — equivalent to the [w] action in run_action_loop.
/// Syncs accumulator membership witness from on-chain event logs.
pub async fn auto_witness_sync(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    params_contract: &ParamsContract<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    session: &Session,
) -> anyhow::Result<()> {
    use ethers::types::{Filter, ValueOrArray, BlockNumber};

    let store = CredentialsStore::new(&session.user_id, &session.cred_name);
    // Load signature to get e value
    let sig_file = store.load_signature()?.ok_or_else(|| anyhow::anyhow!("agg_signature.json missing for witness sync"))?;
    let e = Fr::deserialize_compressed(&hex::decode(sig_file.e.trim_start_matches("0x"))?[..])?;
    let signature_e = e;
    let my_e_u256 = fr_to_u256(&signature_e);

    let acc_addr: Address = std::env::var("ACC_CONTRACT").expect("ACC_CONTRACT").parse()?;
    let acc = AccumulatorClient::new(acc_addr, client.clone())?;

    // Rebuild accumulator params and pkAcc
    let (g1_b, _h0_b, g2_b): (EthBytes, EthBytes, EthBytes) = params_contract.method("getG1H0G2ByName", session.cred_name.to_string())?.call().await?;
    let g1 = eip2537_g1_to_affine(&g1_b.0[..])?;
    let g2 = eip2537_g2_to_affine(&g2_b.0[..])?;
    let vb_params = vb_accumulator::setup::SetupParams::<Bls12_381> { P: g1, P_tilde: g2 };
    let pk_g2_b: EthBytes = params_contract.method("getOpenerPkG2ByName", session.cred_name.to_string())?.call().await?;
    let pk_acc = vb_accumulator::setup::PublicKey::<Bls12_381>(eip2537_g2_to_affine(&pk_g2_b.0[..])?);

    // Current on-chain delta
    let delta_b: ethers::types::Bytes = acc.contract.method("getDelta", (session.cred_name.to_string(),))?.call().await?;
    if delta_b.0.len() != 128 { anyhow::bail!("[auto-witness] no Delta on-chain yet"); }
    let v_current = eip2537_g1_to_affine(&delta_b.0[..])?;

    // Check cached witness first
    let wit_path = store.base().join("witness.bin");
    if let Ok(raw) = std::fs::read(&wit_path) {
        if raw.len() == 128 {
            let cached = eip2537_g1_to_affine(&raw[..])?;
            let mw = vb_accumulator::witness::MembershipWitness::<ark_bls12_381::G1Affine>(cached);
            use vb_accumulator::positive::Accumulator as _;
            let ok = vb_accumulator::positive::Accumulator::verify_membership::<Bls12_381>(
                &vb_accumulator::positive::PositiveAccumulator::from_accumulated(v_current), &signature_e, &mw, &pk_acc, &vb_params);
            if ok {
                println!("[auto-witness] cached witness still valid");
                return Ok(());
            }
            println!("[auto-witness] cached witness stale — re-syncing from event logs");
        }
    } else {
        println!("[auto-witness] syncing witness from event logs...");
    }

    // --- Event-log witness sync ---
    let name_topic = H256::from(ethers::utils::keccak256(session.cred_name.as_bytes()));

    // 1. Find MemberAdded(name, e) where e == my element
    let topic_added = H256::from(ethers::utils::keccak256(b"MemberAdded(string,uint256)"));
    let mut my_e_be = [0u8; 32]; my_e_u256.to_big_endian(&mut my_e_be);
    let my_e_topic = H256::from(my_e_be);
    let filter_my_add = Filter::new()
        .address(ValueOrArray::Value(acc_addr))
        .topic0(ValueOrArray::Value(topic_added))
        .topic1(ValueOrArray::Value(name_topic))
        .topic2(ValueOrArray::Value(my_e_topic))
        .from_block(BlockNumber::Earliest);
    let my_add_logs = client.provider().get_logs(&filter_my_add).await?;
    if my_add_logs.is_empty() { anyhow::bail!("[auto-witness] MemberAdded event not found for this credential"); }
    let my_add_block = my_add_logs[0].block_number.ok_or_else(|| anyhow::anyhow!("MemberAdded log missing block_number"))?.as_u64();
    println!("[auto-witness] MemberAdded found at block {}", my_add_block);

    // 2. Initial witness = Delta at block before our addition
    let prev_delta_b: ethers::types::Bytes = acc.contract
        .method("getDelta", (session.cred_name.to_string(),))?
        .block(ethers::types::BlockId::Number(BlockNumber::Number((my_add_block - 1).into())))
        .call().await?;
    let initial_witness = if prev_delta_b.0.len() == 128 {
        eip2537_g1_to_affine(&prev_delta_b.0[..])?
    } else {
        println!("[auto-witness] no Delta before addition; using g1 as initial witness");
        g1
    };
    let mut wit = vb_accumulator::witness::MembershipWitness::<ark_bls12_381::G1Affine>(initial_witness);

    // 3. Replay subsequent MemberAdded / MemberRevoked events
    let filter_added_after = Filter::new()
        .address(ValueOrArray::Value(acc_addr))
        .topic0(ValueOrArray::Value(topic_added))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Number(my_add_block.into()));
    let all_adds = client.provider().get_logs(&filter_added_after).await?;

    let topic_revoked = H256::from(ethers::utils::keccak256(b"MemberRevoked(string,uint256,bytes)"));
    let filter_revoked_after = Filter::new()
        .address(ValueOrArray::Value(acc_addr))
        .topic0(ValueOrArray::Value(topic_revoked))
        .topic1(ValueOrArray::Value(name_topic))
        .from_block(BlockNumber::Number(my_add_block.into()));
    let all_revs = client.provider().get_logs(&filter_revoked_after).await?;

    // Merge events by (block, log_index) to process in order
    #[derive(Debug)]
    enum AccEvent { Add(U256), Revoke(U256, Vec<u8>) }
    let mut events: Vec<(u64, u64, AccEvent)> = Vec::new();
    for lg in &all_adds {
        let bn = lg.block_number.map(|b| b.as_u64()).unwrap_or(0);
        let li = lg.log_index.map(|i| i.as_u64()).unwrap_or(0);
        if lg.topics.len() >= 3 {
            let e_val = U256::from_big_endian(lg.topics[2].as_bytes());
            if e_val == my_e_u256 { continue; } // skip our own addition
            events.push((bn, li, AccEvent::Add(e_val)));
        }
    }
    for lg in &all_revs {
        let bn = lg.block_number.map(|b| b.as_u64()).unwrap_or(0);
        let li = lg.log_index.map(|i| i.as_u64()).unwrap_or(0);
        if lg.topics.len() >= 3 {
            let e_val = U256::from_big_endian(lg.topics[2].as_bytes());
            let new_delta_bytes = lg.data.0.to_vec();
            events.push((bn, li, AccEvent::Revoke(e_val, new_delta_bytes)));
        }
    }
    events.sort_by_key(|(bn, li, _)| (*bn, *li));

    let post_add_delta_b: ethers::types::Bytes = acc.contract
        .method("getDelta", (session.cred_name.to_string(),))?
        .block(ethers::types::BlockId::Number(BlockNumber::Number(my_add_block.into())))
        .call().await?;
    let mut v_tracking = if post_add_delta_b.0.len() == 128 {
        eip2537_g1_to_affine(&post_add_delta_b.0[..])?
    } else { v_current };

    let mut updates_applied = 0u64;
    for (_bn, _li, ev) in &events {
        match ev {
            AccEvent::Add(e_other) => {
                let e_other_fr: Fr = u256_to_fr::<Fr>(e_other);
                wit = wit.update_after_addition(&signature_e, &e_other_fr, &v_tracking);
                let delta_at: ethers::types::Bytes = acc.contract
                    .method("getDelta", (session.cred_name.to_string(),))?
                    .block(ethers::types::BlockId::Number(BlockNumber::Number((*_bn).into())))
                    .call().await?;
                if delta_at.0.len() == 128 { v_tracking = eip2537_g1_to_affine(&delta_at.0[..])?; }
                updates_applied += 1;
            }
            AccEvent::Revoke(e_other, new_delta_data) => {
                let e_other_fr: Fr = u256_to_fr::<Fr>(e_other);
                if *e_other == my_e_u256 {
                    println!("[auto-witness] own element was revoked — membership is no longer valid");
                    let wit_bytes = g1_to_eip2537_bytes(&wit.0);
                    let _ = std::fs::write(&wit_path, &wit_bytes);
                    anyhow::bail!("credential revoked");
                }
                let new_v = if new_delta_data.len() >= 192 {
                    eip2537_g1_to_affine(&new_delta_data[64..192])?
                } else if new_delta_data.len() == 128 {
                    eip2537_g1_to_affine(&new_delta_data[..])?
                } else {
                    println!("[auto-witness] unexpected MemberRevoked data length {}, skipping", new_delta_data.len());
                    continue;
                };
                match wit.update_after_removal(&signature_e, &e_other_fr, &new_v) {
                    Ok(w) => { wit = w; v_tracking = new_v; updates_applied += 1; }
                    Err(e) => { println!("[auto-witness] update_after_removal failed: {:?}", e); }
                }
            }
        }
    }
    println!("[auto-witness] replayed {} accumulator updates", updates_applied);

    // 4. Persist witness.bin
    let wit_bytes = g1_to_eip2537_bytes(&wit.0);
    std::fs::write(&wit_path, &wit_bytes)?;
    println!("[auto-witness] witness.bin written to {}", wit_path.display());

    // 5. Verify membership
    use vb_accumulator::positive::Accumulator as _;
    let acc_view = vb_accumulator::positive::PositiveAccumulator::<ark_bls12_381::G1Affine>::from_accumulated(v_current);
    let ok = vb_accumulator::positive::Accumulator::verify_membership::<Bls12_381>(&acc_view, &signature_e, &wit, &pk_acc, &vb_params);
    println!("[auto-witness] membership {}", if ok { "OK" } else { "FAIL" });
    if !ok { anyhow::bail!("[auto-witness] membership verification failed"); }
    Ok(())
}

/// Non-interactive batch presentation export — equivalent to the [b] action.
/// Builds BBS+ PoK + accumulator membership PoK and writes PresentationData to JSON file.
pub async fn auto_batch_export(
    client: Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    params_contract: &ParamsContract<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    session: &Session,
    revealed_idx: &[u32],
    out_path: &str,
) -> anyhow::Result<()> {
    use tbbsplus_rust::orchestration::batching::PresentationData;

    let store = CredentialsStore::new(&session.user_id, &session.cred_name);
    let pb = onchain::fetch_params_bundle(params_contract, &session.cred_name).await?;
    let params_bbs = pb.params_bbs.clone();

    // Load messages and signature
    let msgs_hex: Vec<String> = match store.load_messages()? { Some(MessagesFile(v)) => v, None => anyhow::bail!("messages.json missing") };
    let mut messages: Vec<Fr> = Vec::with_capacity(msgs_hex.len());
    for h in msgs_hex { let bytes = hex::decode(h.trim_start_matches("0x"))?; messages.push(Fr::deserialize_compressed(&bytes[..])?); }
    let sig_file = store.load_signature()?.ok_or_else(|| anyhow::anyhow!("agg_signature.json missing"))?;
    let a = <Bls12_381 as ark_ec::pairing::Pairing>::G1Affine::deserialize_compressed(&hex::decode(sig_file.a.trim_start_matches("0x"))?[..])?;
    let e = Fr::deserialize_compressed(&hex::decode(sig_file.e.trim_start_matches("0x"))?[..])?;
    let s = Fr::deserialize_compressed(&hex::decode(sig_file.s.trim_start_matches("0x"))?[..])?;
    let signature = bbs_plus::signature::SignatureG1::<Bls12_381> { A: a, e, s };

    // Fetch Ybar
    let ybar_bytes: EthBytes = params_contract.method("getOpenerYbarByName", session.cred_name.to_string())?.call().await?;
    if ybar_bytes.0.len() != 128 { anyhow::bail!("opener Ybar missing or wrong length"); }
    let ybar_aff = eip2537_g1_to_affine(&ybar_bytes.0[..])?;

    // Unblind signature if blinding exists
    let sig_struct = {
        let bpath = store.base().join("blinding.hex");
        if let Ok(s) = std::fs::read_to_string(&bpath) {
            if let Some(stripped) = s.strip_prefix("0x") {
                if let Ok(bytes) = hex::decode(stripped) {
                    if let Ok(b) = Fr::deserialize_compressed(&bytes[..]) {
                        signature.clone().unblind(&b)
                    } else { signature.clone() }
                } else { signature.clone() }
            } else { signature.clone() }
        } else { signature.clone() }
    };

    let revealed_idx_vec: Vec<u32> = revealed_idx.to_vec();
    let (proof, c_fr, revealed_idx2) = build_pok_and_proof(&params_bbs, &sig_struct, &messages, &ybar_aff, &revealed_idx_vec)?;
    let (sig_t, _ctx_t, _revealed_t, challenge_u256, p1_t, p2_t, enc_extras) = build_presentation_tuples(&params_bbs, &proof, &revealed_idx2, &messages, pb.mcount, &c_fr)?;
    let EncExtras { t1_b, t2enc_b, t_enc_b, resp_a3_u, resp_k_u } = enc_extras;

    // Build accumulator membership PoK
    let acc_addr: Address = std::env::var("ACC_CONTRACT").expect("ACC_CONTRACT").parse()?;
    let acc = AccumulatorClient::new(acc_addr, client.clone())?;
    let wit_path = store.base().join("witness.bin");
    let witness_raw = std::fs::read(&wit_path)
        .map_err(|_| anyhow::anyhow!("[auto-batch] witness.bin not found — run witness sync first"))?;
    if witness_raw.len() != 128 { anyhow::bail!("[auto-batch] witness.bin has unexpected length {}", witness_raw.len()); }
    let delta_b: ethers::types::Bytes = acc.contract.method("getDelta", (session.cred_name.to_string(),))?.call().await?;
    if delta_b.0.len() != 128 { anyhow::bail!("[auto-batch] missing Delta on-chain"); }
    let delta_aff = eip2537_g1_to_affine(&delta_b.0[..])?;
    let wit_aff = eip2537_g1_to_affine(&witness_raw[..])?;
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
    let a_prime_acc = g1_to_eip2537_bytes(&proof_acc.0.A_prime).to_vec();
    let a_bar_acc   = g1_to_eip2537_bytes(&proof_acc.0.A_bar).to_vec();
    let t_acc       = g1_to_eip2537_bytes(&proof_acc.0.sc.as_ref().ok_or_else(|| anyhow::anyhow!("acc sc missing"))?.t).to_vec();
    let resp_r_acc  = fr_to_u256(&proof_acc.0.sc.as_ref().unwrap().response1);
    let resp_e_acc  = fr_to_u256(&proof_acc.0.sc.as_ref().unwrap().response2);
    let challenge_acc_u256 = fr_to_u256(&c_acc);

    let revealed_vals: Vec<U256> = revealed_idx_vec.iter().map(|&i| fr_to_u256(&messages[i as usize])).collect();
    let resp_msgs = p2_t.1.clone();
    let pres_data = PresentationData {
        a_prime: sig_t.0.to_vec(),
        a_bar: sig_t.1.to_vec(),
        d: sig_t.2.to_vec(),
        t1_bbs: p1_t.0.to_vec(),
        t2_bbs: p2_t.0.to_vec(),
        bbs_challenge: challenge_u256,
        resp_a: p1_t.1,
        resp_h0: p1_t.2,
        resp_r3: p2_t.2,
        resp_sprime: p2_t.3,
        resp_msgs,
        t1_enc: t1_b.to_vec(),
        t2_enc: t2enc_b.to_vec(),
        t_enc: t_enc_b.to_vec(),
        resp_a3: resp_a3_u,
        resp_k: resp_k_u,
        a_prime_acc,
        a_bar_acc,
        t_acc,
        acc_challenge: challenge_acc_u256,
        resp_r_acc,
        resp_e_acc,
        revealed_idx: revealed_idx_vec,
        revealed_vals,
    };

    // File-locked append to batch JSON
    append_to_batch_json(out_path, &pres_data)?;
    println!("[auto-batch] presentation exported to {}", out_path);
    Ok(())
}

/// File-locked append for concurrent-safe batch JSON writes.
pub fn append_to_batch_json<T: serde::Serialize + serde::de::DeserializeOwned>(
    path: &str, item: &T,
) -> anyhow::Result<usize> {
    use std::fs::OpenOptions;
    use fs2::FileExt;
    let file = OpenOptions::new().read(true).write(true).create(true).open(path)?;
    file.lock_exclusive()?;
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut vec: Vec<T> = if existing.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&existing)?
    };
    vec.push(serde_json::from_value(serde_json::to_value(item)?)?);
    let count = vec.len();
    std::fs::write(path, serde_json::to_string_pretty(&vec)?)?;
    file.unlock()?;
    println!("[batch-json] entry #{} written to {} ({} total)", count, path, count);
    Ok(count)
}
