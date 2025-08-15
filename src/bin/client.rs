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

abigen!(
    RequestCredential,
    "artifacts/contracts/RequestCredential.sol/RequestCredential.json"
);
abigen!(
    PartialSignatureRelay,
    "artifacts/contracts/PartialSignatureRelay.sol/PartialSignatureRelay.json"
);
abigen!(
    Params,
    "artifacts/contracts/Params.sol/Params.json"
);

abigen!(
    VerifyWrapper,
    "artifacts/contracts/Verify.sol/VerifyWrapper.json"
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let ws_url = env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
    let chain_id: u64 = env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse()?;
    let req_addr: Address = env::var("REQ_CONTRACT").expect("REQ_CONTRACT").parse()?;
    let relay_addr: Address = env::var("RELAY_CONTRACT").expect("RELAY_CONTRACT").parse()?;
    let params_addr: Address = env::var("PARAMS_CONTRACT").expect("PARAMS_CONTRACT").parse()?;
    let cred_name = env::var("CRED_NAME").unwrap_or_else(|_| "IITH_UG_AC".into());
    let t: u16 = env::var("THRESHOLD").unwrap_or_else(|_| "3".into()).parse()?;
    let mcount: u32 = env::var("MESSAGE_COUNT").unwrap_or_else(|_| "5".into()).parse()?;
    // Parse mode/args
    enum Mode { Request { sid: u64, revealed_idx: Vec<u32>, revealed_vals: Vec<U256>, context: Vec<u8>, wait_and_verify: bool }, Verify { sid: u64 } }

    let args = env::args().skip(1).collect::<Vec<_>>();
    let mode: Mode = if args.is_empty() {
        // Interactive
        println!("Client interactive mode");
        // sid
        let sid = prompt_parse_u64("Enter session id (sid)", 1)?;
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
    } else if args[0] == "verify" {
        if args.len() < 2 { anyhow::bail!("usage: client verify <sid>"); }
        let sid: u64 = args[1].parse()?;
        Mode::Verify { sid }
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
    let relay = PartialSignatureRelay::new(relay_addr, client.clone());
    let params_contract = Params::new(params_addr, client.clone());

    match mode {
        Mode::Request { sid, mut revealed_idx, mut revealed_vals, context, wait_and_verify } => {
            // Fetch on-chain params to know message_count and match params generation
            let pc = params_contract.get_params_by_name(cred_name.clone()).call().await?;
            let mcount_onchain: u32 = pc.message_count.as_u64() as u32;
            // Deterministic params generation (must match issuers/TTP demo)
            let params_bbs = SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(cred_name.as_bytes(), mcount_onchain);

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
            // Commitment B'
            let commitment = params_bbs
                .commit_to_messages(hidden_msgs_fr.iter().map(|(i, fr)| (*i, fr)), &blinding)
                .map_err(|e| anyhow::anyhow!("commit_to_messages failed: {:?}", e))?;
            let mut commitment_bytes = Vec::new();
            commitment.serialize_compressed(&mut commitment_bytes)?;

            // Build Schnorr-style PoK bound to transcript and serialize proof bytes
            let proof_bytes = build_commitment_pok(&params_bbs, &commitment, &hidden_msgs_fr, &blinding, mcount_onchain, sid, &cred_name, &revealed_idx, &revealed_vals, &context)?;

            let commitment_b = ethers::types::Bytes::from(commitment_bytes);
            let proof = ethers::types::Bytes::from(proof_bytes);
            let context = ethers::types::Bytes::from(context);

            if wait_and_verify {
                // Create event stream first to avoid missing early shares, keep builder alive in this scope
                use ethers::types::BlockNumber;
                let eb = relay
                    .event::<partial_signature_relay::PartialShareFilter>()
                    .from_block(BlockNumber::Latest);
                let mut stream = eb.stream().await?;

                // Send request
                let mb = req.broadcast_sig_req_bbs_plus(
                    U256::from(sid),
                    cred_name.clone(),
                    commitment_b.clone(),
                    revealed_idx.clone(),
                    revealed_vals.clone(),
                    proof.clone(),
                    context,
                );
                let tx = mb.send().await?;
                let _rcpt = tx.await?;
                println!("Client: sent cred request sid={}", sid);

                // Collect shares
                let mut shares: Vec<Vec<u8>> = Vec::new();
                while shares.len() < t as usize {
                    if let Some(ev) = stream.next().await { if let Ok(ev) = ev {
                        if ev.sid.as_u64() == sid { shares.push(ev.payload.to_vec()); println!("Client: got share {} from idx {}", shares.len(), ev.idx); }
                    }}
                }
                verify_with_shares(&params_contract, &cred_name, mcount, sid, shares, Some(blinding)).await?;
            } else {
                // Send request only
                let mb = req.broadcast_sig_req_bbs_plus(
                    U256::from(sid),
                    cred_name.clone(),
                    commitment_b,
                    revealed_idx.clone(),
                    revealed_vals.clone(),
                    proof,
                    context,
                );
                let tx = mb.send().await?;
                let _rcpt = tx.await?;
                println!("Client: sent cred request sid={}", sid);
            }
        }
    Mode::Verify { sid } => {
            // Fetch past PartialShare events and filter by sid
            let events = relay
                .event::<partial_signature_relay::PartialShareFilter>()
                .from_block(0u64)
                .query()
                .await?;
            let mut shares: Vec<Vec<u8>> = Vec::new();
            for ev in events.into_iter().filter(|e| e.sid.as_u64() == sid) {
                shares.push(ev.payload.to_vec());
                println!("Client: found past share from idx {}", ev.idx);
            }
            if shares.len() < t as usize {
                eprintln!("Client: not enough shares for sid {}: got {}, need {}", sid, shares.len(), t);
            }
            // Persist credential and optionally present
            persist_and_optionally_present(&client, &params_contract, &cred_name, mcount, sid, shares).await?;
        }
    }

    Ok(())
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
    // Aggregate signature like verify_with_shares does, then persist basic artifacts
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
    let signature = bbs_plus::threshold::threshold_bbs_plus::BBSPlusSignatureShare::aggregate(sig_shares)
        .map_err(|e| anyhow::anyhow!("aggregate failed: {:?}", e))?;
    // Persist to .runtime/users/<user>/<cred>
    let user_id = format!("{:x}", client.address());
    let base: PathBuf = [".runtime", "users", &user_id, cred_name].iter().collect();
    fs::create_dir_all(&base)?;
    // messages.json
    let msgs_hex: Vec<String> = messages.iter().map(|f| {
        let mut be = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(f, &mut be).unwrap();
        format!("0x{}", hex::encode(be))
    }).collect();
    fs::write(base.join("messages.json"), serde_json::to_vec_pretty(&msgs_hex)?)?;
    // params.json
    let params_obj = serde_json::json!({
        "cred_name": cred_name,
        "messageCount": onchain_mcount,
        "t": onchain_t,
        "n": onchain_n,
    });
    fs::write(base.join("params.json"), serde_json::to_vec_pretty(&params_obj)?)?;
    // signature.json
    let mut a_bytes = Vec::new(); signature.A.serialize_compressed(&mut a_bytes)?;
    let mut e_bytes = Vec::new(); signature.e.serialize_compressed(&mut e_bytes)?;
    let mut s_bytes = Vec::new(); signature.s.serialize_compressed(&mut s_bytes)?;
    let sig_obj = serde_json::json!({
        "A": format!("0x{}", hex::encode(a_bytes)),
        "e": format!("0x{}", hex::encode(e_bytes)),
        "s": format!("0x{}", hex::encode(s_bytes)),
    });
    fs::write(base.join("agg_signature.json"), serde_json::to_vec_pretty(&sig_obj)?)?;

    // Interactive: ask if user wants to present now
    println!("Present credential on-chain now? [y/N]");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if matches!(line.trim(), "y"|"Y"|"yes"|"YES") {
        // Ask for VerifyWrapper address if not set in env
        let verify_addr: Address = match std::env::var("VERIFY_CONTRACT") {
            Ok(s) => s.parse()?,
            Err(_) => {
                println!("Enter VerifyWrapper address (0x...), or leave blank to skip:");
                let mut addr_in = String::new();
                std::io::stdin().read_line(&mut addr_in)?;
                let a = addr_in.trim();
                if a.is_empty() { return Ok(()); }
                a.parse()?
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
        let params_bbs = SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(cred_name.as_bytes(), onchain_mcount);
        // Use in-memory 'signature' built above
        let sig_struct = signature; // already aggregated

        // Build revealed messages map
        let mut revealed_msgs = std::collections::BTreeMap::<usize, Fr>::new();
        for &ix in &revealed_idx { let i = ix as usize; if i < messages.len() { revealed_msgs.insert(i, messages[i]); } }
        // Build message iterator: reveal or blind randomly
        let mut rng = StdRng::seed_from_u64(99);
        use dock_crypto_utils::signature::MessageOrBlinding;
        let message_iter = messages.iter().enumerate().map(|(i, m)| {
            if revealed_msgs.contains_key(&i) { MessageOrBlinding::RevealMessage(m) } else { MessageOrBlinding::BlindMessageRandomly(m) }
        });
        let pok = bbs_plus::proof::PoKOfSignatureG1Protocol::<Bls12_381>::init(&mut rng, &sig_struct, &params_bbs, message_iter)
            .map_err(|e| anyhow::anyhow!("pok init failed: {:?}", e))?;
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
        let ctx_H: Vec<EthBytes> = params_bbs.h.iter().map(|h| EthBytes::from(g1_to_eip2537_bytes(h).to_vec())).collect();
        let ctx_H_len_dbg = ctx_H.len();
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
        for (i, hh) in ctx_H.iter().enumerate() { check_len(&format!("ctx.H[{}]", i), hh, 128)?; }
        check_len("sig.APrime", &sig_ap, 128)?;
        check_len("sig.ABar", &sig_ab, 128)?;
        check_len("sig.d", &sig_d, 128)?;
        let ctx_t = (onchain_mcount, ctx_g1, ctx_h0, ctx_H);
        let sig_t = (sig_ap, sig_ab, sig_d);
        let revealed_vals_u256: Vec<U256> = revealed_idx.iter().map(|ix| {
            let v = messages[*ix as usize];
            fr_to_u256(&v)
        }).collect();
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

        // Unconditional debug: print sizes of all G1 byte inputs and counts
        println!(
            "[present debug] lens: g1={}, h0={}, H[0..]={:?}, A'={}, Ā={}, d={}, T1={}, T2={}, respMsgs={}, undisclosed={}",
            128,
            128,
            ctx_H_len_dbg,
            128,
            128,
            128,
            128,
            128,
            resp_msgs_len_dbg,
            undis_count
        );

        let call = contract.method::<_, bool>(
            "verifyPok",
            (sig_t, ctx_t, revealed_t, challenge_u256, p1_t, p2_t)
        )?;
        match call.call().await {
            Ok(ok) => {
                if ok { println!("Presentation verify: OK"); } else { println!("Presentation verify: FAILED (returned false)"); }
            }
            Err(e) => {
                let dbg = format!(
                    "verifyPok call error: {:?}\n[debug] ctx.H len={}, revealedIdx len={}, respMsgs len={} (expected undisclosed={})\n",
                    e, ctx_H_len_dbg, revealed_idx.len(), resp_msgs_len_dbg, undis_count
                );
                print!("{}", dbg);
                let _ = std::fs::write("client.log", dbg);
            }
        }
    }
    Ok(())
}

fn fq_to_be64(x: &Fq) -> [u8; 64] {
    let bi = x.into_bigint();
    let limbs: [u64; 6] = bi.0;
    let mut le48 = [0u8; 48];
    for (i, limb) in limbs.iter().enumerate() {
        le48[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    let mut be48 = [0u8; 48];
    for i in 0..48 { be48[i] = le48[47 - i]; }
    let mut out = [0u8; 64];
    out[16..].copy_from_slice(&be48);
    out
}

fn g1_to_eip2537_bytes(p: &<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine) -> [u8; 128] {
    let (x, y) = (p.x, p.y);
    let xb = fq_to_be64(&x);
    let yb = fq_to_be64(&y);
    let mut out = [0u8; 128];
    out[..64].copy_from_slice(&xb);
    out[64..].copy_from_slice(&yb);
    out
}

fn fr_to_u256(fr: &Fr) -> U256 {
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

fn keccak_to_fr(bytes: &[u8]) -> Fr {
    use sha3::Digest;
    let mut h = sha3::Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    Fr::from_be_bytes_mod_order(&out)
}

async fn probe_msm_precompiles(
    client: &std::sync::Arc<SignerMiddleware<Provider<Ws>, LocalWallet>>,
    params: &SignatureParamsG1<Bls12_381>,
    proof: &bbs_plus::proof::PoKOfSignatureG1Proof<Bls12_381>,
    revealed_idx: &Vec<u32>,
    messages: &Vec<Fr>,
    c_fr: &Fr,
) -> anyhow::Result<()> {
    use ethers::types::Address;
    let g1add: Address = "0x000000000000000000000000000000000000000b".parse()?;
    let g1msm: Address = "0x000000000000000000000000000000000000000c".parse()?;
    // Check one MSM input shape: g1*1
    let g1 = EthBytes::from(g1_to_eip2537_bytes(&params.g1).to_vec());
    if g1.len() != 128 { eprintln!("[debug] ctx.g1 not 128 bytes: {}", g1.len()); }
    let mut data = Vec::with_capacity(160);
    data.extend_from_slice(&g1);
    data.extend_from_slice(&[0u8; 31]);
    data.push(1u8); // scalar 1
    let call_req = serde_json::json!([{ "to": format!("0x{:040x}", g1msm), "data": format!("0x{}", hex::encode(&data)) }, "latest"]);
    match client.provider().request::<serde_json::Value, String>("eth_call", call_req).await {
        Ok(s) => {
            let out_bytes = hex::decode(s.trim_start_matches("0x")).unwrap_or_default();
            if out_bytes.len() != 128 { eprintln!("[debug] g1msm(g1*1) returned {} bytes", out_bytes.len()); }
        }
        Err(e) => {
            eprintln!("[debug] eth_call g1msm probe error: {:?}", e);
        }
    }
    // Check T1 size
    let t1 = EthBytes::from(g1_to_eip2537_bytes(&proof.sc_resp_1.t).to_vec());
    if t1.len() != 128 { eprintln!("[debug] p1.T1 not 128 bytes: {}", t1.len()); }
    // Check T2 size
    let t2 = EthBytes::from(g1_to_eip2537_bytes(&proof.T2).to_vec());
    if t2.len() != 128 { eprintln!("[debug] p2.T2 not 128 bytes: {}", t2.len()); }
    // Check respMsgs count
    let undis = (params.h.len() as usize) - revealed_idx.len();
    if let Some(sc2) = &proof.sc_resp_2 { if sc2.0.len() != undis + 2 { eprintln!("[debug] responses count {} != expected {} (undis+2)", sc2.0.len(), undis+2); } }
    Ok(())
}

fn u256_to_fr<F: PrimeField>(v: &U256) -> F {
    let mut be = [0u8; 32];
    v.to_big_endian(&mut be);
    F::from_be_bytes_mod_order(&be)
}

fn build_commitment_pok(
    params: &SignatureParamsG1<Bls12_381>,
    commitment: &<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine,
    hidden_msgs: &std::collections::BTreeMap<usize, Fr>,
    blinding: &Fr,
    mcount: u32,
    sid: u64,
    cred_name: &str,
    revealed_idx: &Vec<u32>,
    revealed_vals: &Vec<U256>,
    context: &Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    use ark_ec::AffineRepr;
    use std::collections::BTreeMap;

    // Bases for Schnorr: [h_0] for blinding, and [h_i] for each hidden i
    let mut bases = Vec::with_capacity(1 + hidden_msgs.len());
    bases.push(params.h_0);
    let mut witnesses = Vec::with_capacity(1 + hidden_msgs.len());
    witnesses.push(*blinding);
    let mut hidden_indices_sorted: Vec<usize> = hidden_msgs.keys().copied().collect();
    hidden_indices_sorted.sort_unstable();
    for i in hidden_indices_sorted.iter() {
        bases.push(params.h[*i]);
        witnesses.push(*hidden_msgs.get(i).unwrap());
    }
    // y is the commitment; not used directly here as we serialize t and verify at issuers
    // Random blindings for Schnorr
    let mut rng = StdRng::seed_from_u64(rand::random::<u64>());
    let blindings = (0..witnesses.len()).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let comm = SchnorrCommitment::new(&bases, blindings);

    // Transcript for challenge: domain separator + sid + name + mcount + revealed pairs sorted + hidden idx set + commitment + t + context
    let mut chal_bytes = Vec::new();
    chal_bytes.extend_from_slice(b"TBBS+_Blind_PoK_v1");
    chal_bytes.extend_from_slice(&sid.to_be_bytes());
    chal_bytes.extend_from_slice(&(mcount as u64).to_be_bytes());
    chal_bytes.extend_from_slice(cred_name.as_bytes());
    // revealed pairs sorted by idx
    let mut pairs: Vec<(u32, &U256)> = revealed_idx.iter().cloned().zip(revealed_vals.iter()).collect();
    pairs.sort_by_key(|(i, _)| *i);
    for (i, v) in pairs.into_iter() {
        chal_bytes.extend_from_slice(&i.to_be_bytes());
        let mut be = [0u8; 32];
        v.to_big_endian(&mut be);
        chal_bytes.extend_from_slice(&be);
    }
    // hidden indices
    for i in hidden_indices_sorted.iter() {
        let i_u32 = *i as u32;
        chal_bytes.extend_from_slice(&i_u32.to_be_bytes());
    }
    // commitment and Schnorr t contribution
    commitment.serialize_compressed(&mut chal_bytes)?;
    SchnorrChallengeContributor::challenge_contribution(&comm, &mut chal_bytes)
        .map_err(|e| anyhow::anyhow!("challenge_contribution failed: {:?}", e))?;
    // context
    chal_bytes.extend_from_slice(context);

    // Compute challenge using Blake2b512
    let c: Fr = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
    let resp = comm.response(&witnesses, &c)
        .map_err(|e| anyhow::anyhow!("Schnorr response failed: {:?}", e))?;

    // Serialize proof bytes: hidden_len || hidden_indices || t || c || rlen || responses
    let mut out = Vec::new();
    // encode hidden count and indices
    let hidden_len = hidden_indices_sorted.len() as u32;
    out.extend_from_slice(&hidden_len.to_be_bytes());
    for i in hidden_indices_sorted.iter() {
        let i_u32 = *i as u32;
        out.extend_from_slice(&i_u32.to_be_bytes());
    }
    // encode t (commitment to randomness)
    comm.t.serialize_compressed(&mut out)?;
    // encode challenge c
    c.serialize_compressed(&mut out)?;
    // encode responses count and values
    let rlen = resp.len() as u32;
    out.extend_from_slice(&rlen.to_be_bytes());
    for j in 0..resp.len() {
        let rj = resp.get_response(j)
            .map_err(|e| anyhow::anyhow!("get_response failed: {:?}", e))?;
        rj.serialize_compressed(&mut out)?;
    }
    Ok(out)
}
