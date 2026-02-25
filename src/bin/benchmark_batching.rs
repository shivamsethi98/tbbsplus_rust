/// Benchmark harness for batched vs single credential operations.
///
/// Generates valid BBS+ signatures using the Dock crypto library and measures
/// gas costs for single vs batched on-chain operations across batch sizes {1,2,4,8,16,32,64,128}.
///
/// Operations benchmarked:
///   1. submitShare × N  vs  submitShareBatch(N)
///   2. confirmCredential × N  vs  confirmBatchRandomized(N)
///   3. addMember × N  vs  addMembers(N)
///   4. verifyPairing × N  vs  verifyBbsPairingBatch(N)
///
/// Requires: Anvil running on ws://127.0.0.1:8545 with BLS12-381 precompiles (--hardfork PragueEOF)
///
/// Usage: cargo run --bin benchmark_batching [-- --batch-sizes 1,2,4,8,16,32,64,128]

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use bbs_plus::prelude::*;
use ethers::abi::{Abi, Token, Tokenize};
use ethers::contract::Contract;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::signers::{coins_bip39::English, MnemonicBuilder};
use ethers::types::{Bytes as EthBytes, U256};
use serde_json::json;

use tbbsplus_rust::orchestration::crypto::encoding::{
    fr_to_u256, g1_to_eip2537_bytes, g2_to_eip2537_bytes,
};

type Client = SignerMiddleware<Provider<Http>, LocalWallet>;
type ArcClient = Arc<Client>;

const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128];
const MESSAGE_COUNT: usize = 5;
const THRESHOLD: u16 = 3;
const TOTAL: u16 = 4;

fn metrics_append(path: &str, value: serde_json::Value) {
    let _ = (|| -> Result<(), Box<dyn std::error::Error>> {
        if let Some(dir) = std::path::Path::new(path).parent() {
            fs::create_dir_all(dir)?;
        }
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(f, "{}", serde_json::to_string(&value)?)?;
        Ok(())
    })();
}

fn load_abi(name: &str) -> Abi {
    // Try exact match first, then common patterns
    let candidates = vec![
        format!("artifacts/contracts/{}.sol/{}.json", name, name),
        format!("artifacts/contracts/Verify.sol/{}.json", name),
        format!("artifacts/contracts/lib/{}.sol/{}.json", name, name),
    ];
    for path in &candidates {
        if let Ok(data) = fs::read_to_string(path) {
            let v: serde_json::Value = serde_json::from_str(&data).unwrap();
            return serde_json::from_value(v["abi"].clone()).unwrap();
        }
    }
    panic!("ABI not found for {}: tried {:?}", name, candidates);
}

fn load_bytecode(name: &str) -> EthBytes {
    let candidates = vec![
        format!("artifacts/contracts/{}.sol/{}.json", name, name),
        format!("artifacts/contracts/Verify.sol/{}.json", name),
        format!("artifacts/contracts/lib/{}.sol/{}.json", name, name),
    ];
    for path in &candidates {
        if let Ok(data) = fs::read_to_string(path) {
            let v: serde_json::Value = serde_json::from_str(&data).unwrap();
            let bc_str = v["bytecode"]
                .as_str()
                .or_else(|| v["bytecode"]["object"].as_str())
                .unwrap_or_else(|| panic!("no bytecode in {}", path));
            return EthBytes::from(hex::decode(bc_str.strip_prefix("0x").unwrap_or(bc_str)).unwrap());
        }
    }
    panic!("bytecode not found for {}: tried {:?}", name, candidates);
}

/// Generate BBS+ signature params, keypair, and N valid signatures
fn generate_test_data(
    n: usize,
) -> (
    SignatureParamsG1<Bls12_381>,
    PublicKeyG2<Bls12_381>,
    Vec<(SignatureG1<Bls12_381>, Vec<Fr>)>, // (sig, messages) for each credential
) {
    let mut rng = StdRng::seed_from_u64(0xBEEF);
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, MESSAGE_COUNT as u32);
    let keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &params);

    let mut credentials = Vec::with_capacity(n);
    for i in 0..n {
        let mut rng_i = StdRng::seed_from_u64(0xCAFE + i as u64);
        let messages: Vec<Fr> = (0..MESSAGE_COUNT).map(|_| Fr::rand(&mut rng_i)).collect();
        let sig =
            SignatureG1::<Bls12_381>::new(&mut rng_i, &messages, &keypair.secret_key, &params)
                .expect("sign failed");
        // Verify locally
        sig.verify(&messages, keypair.public_key.clone(), params.clone())
            .expect("local verify failed");
        credentials.push((sig, messages));
    }

    (params, keypair.public_key.clone(), credentials)
}

async fn deploy_contract(client: ArcClient, name: &str, args: Vec<Token>) -> Contract<Client> {
    let artifact_path = format!(
        "artifacts/contracts/{}.sol/{}.json",
        name, name
    );
    let data = fs::read_to_string(&artifact_path).expect(&format!("artifact not found: {}", artifact_path));
    let v: serde_json::Value = serde_json::from_str(&data).unwrap();
    let abi: Abi = serde_json::from_value(v["abi"].clone()).unwrap();
    let bytecode = v["bytecode"]["object"]
        .as_str()
        .expect("no bytecode");
    let bytecode = ethers::types::Bytes::from(hex::decode(bytecode.strip_prefix("0x").unwrap_or(bytecode)).unwrap());

    let factory = ethers::contract::ContractFactory::new(abi.clone(), bytecode, client.clone());
    let deployer = if args.is_empty() {
        factory.deploy(()).expect("deploy encode failed")
    } else {
        factory.deploy(Token::Tuple(args)).expect("deploy encode failed")
    };
    let contract = deployer.send().await.expect(&format!("deploy {} failed", name));
    contract
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    dotenvy::dotenv().ok();

    let rpc_url = env::var("ETH_RPC").unwrap_or_else(|_| "http://127.0.0.1:8545".into());
    let metrics_file =
        env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/batching_benchmark.ndjson".into());

    // Parse batch sizes from args or use defaults
    let batch_sizes: Vec<usize> = env::args()
        .skip_while(|a| a != "--batch-sizes")
        .nth(1)
        .map(|s| s.split(',').map(|x| x.parse().unwrap()).collect())
        .unwrap_or_else(|| BATCH_SIZES.to_vec());

    println!("=== Batching Benchmark ===");
    println!("Batch sizes: {:?}", batch_sizes);
    println!("Message count: {}", MESSAGE_COUNT);
    println!("Threshold: {}/{}", THRESHOLD, TOTAL);
    println!();

    // Connect to Anvil via HTTP (stateless, no WS subscription issues with evm_revert)
    let provider = Provider::<Http>::try_from(&rpc_url)?;
    let phrase = "test test test test test test test test test test test junk";
    let wallet: LocalWallet = MnemonicBuilder::<English>::default()
        .phrase(phrase)
        .index(0u32)?
        .build()?
        .with_chain_id(31337u64);
    let client = Arc::new(SignerMiddleware::new(provider, wallet));

    // Fund the account
    let addr = client.address();
    let _ = client
        .provider()
        .request::<_, ()>("anvil_setBalance", (addr, "0x56BC75E2D63100000"))
        .await;

    // Create issuer wallets (indices 1..=THRESHOLD)
    let mut issuers = Vec::new();
    for i in 1..=THRESHOLD {
        let w: LocalWallet = MnemonicBuilder::<English>::default()
            .phrase(phrase)
            .index(i as u32)?
            .build()?
            .with_chain_id(31337u64);
        let a = w.address();
        let _ = client
            .provider()
            .request::<_, ()>("anvil_setBalance", (a, "0x56BC75E2D63100000"))
            .await;
        let c = Arc::new(SignerMiddleware::new(
            Provider::<Http>::try_from(&rpc_url)?,
            w,
        ));
        issuers.push(c);
    }

    // ===================== DEPLOY CONTRACTS =====================
    println!("[deploy] Deploying contracts...");

    // Params
    let params_abi = load_abi("Params");
    let params_factory = ethers::contract::ContractFactory::new(params_abi.clone(), load_bytecode("Params"), client.clone());
    let params_contract = params_factory.deploy(())?.send().await?;
    let params_addr = params_contract.address();
    println!("[deploy] Params: {:?}", params_addr);

    // CredentialRegistry
    let reg_abi = load_abi("CredentialRegistry");
    let reg_factory = ethers::contract::ContractFactory::new(reg_abi.clone(), load_bytecode("CredentialRegistry"), client.clone());
    let reg_contract = reg_factory.deploy(Token::Address(params_addr))?.send().await?;
    let reg_addr = reg_contract.address();
    println!("[deploy] CredentialRegistry: {:?}", reg_addr);

    // RequestCredential
    let req_abi = load_abi("RequestCredential");
    let req_factory = ethers::contract::ContractFactory::new(req_abi.clone(), load_bytecode("RequestCredential"), client.clone());
    let req_contract = req_factory.deploy(())?.send().await?;
    let req_addr = req_contract.address();
    println!("[deploy] RequestCredential: {:?}", req_addr);

    // Accumulator
    let acc_abi = load_abi("Accumulator");
    let acc_factory = ethers::contract::ContractFactory::new(acc_abi.clone(), load_bytecode("Accumulator"), client.clone());
    let acc_contract = acc_factory.deploy((Token::Address(params_addr), Token::Address(reg_addr)))?.send().await?;
    let acc_addr = acc_contract.address();
    println!("[deploy] Accumulator: {:?}", acc_addr);

    // VerifyWrapper
    let verify_abi = load_abi("VerifyWrapper");
    let verify_factory = ethers::contract::ContractFactory::new(verify_abi.clone(), load_bytecode("VerifyWrapper"), client.clone());
    let verify_contract = verify_factory.deploy(())?.send().await?;
    let verify_addr = verify_contract.address();
    println!("[deploy] VerifyWrapper: {:?}", verify_addr);

    // Wire contracts
    // BENCHMARK SHORTCUT: Set deployer as requestContract so we can directly call
    // noteRequest/recordBprime/recordRevealed without impersonation.
    let _ = reg_contract.method::<_, H256>("setRequestContract", addr)?.send().await?.await?;
    let _ = req_contract.method::<_, H256>("setRegistry", reg_addr)?.send().await?.await?;
    let _ = reg_contract.method::<_, H256>("setAccumulator", acc_addr)?.send().await?.await?;
    // Owner as accumulator manager
    let _ = reg_contract.method::<_, H256>("setAccumulatorManager", (addr, true))?.send().await?.await?;
    println!("[deploy] Contracts wired");

    // ===================== SETUP BBS+ PARAMS ON-CHAIN =====================
    println!("[setup] Generating BBS+ params...");

    let max_n = *batch_sizes.iter().max().unwrap();
    let (bbs_params, pk, creds) = generate_test_data(max_n);

    // Encode params to EIP-2537 format
    let g1_bytes = g1_to_eip2537_bytes(&bbs_params.g1);
    let h0_bytes = g1_to_eip2537_bytes(&bbs_params.h_0);
    let g2_bytes = g2_to_eip2537_bytes(&bbs_params.g2);
    let pk_g2_bytes = g2_to_eip2537_bytes(&pk.0);

    // Build blob for setupAll: g1(128) + h0(128) + g2Base(256) + pkG2(256) + openerYbarG1(128) + openerPkG2(256) = 1152
    // For benchmark, use zero opener keys (not needed for issuance/confirm benchmark)
    let mut blob = Vec::with_capacity(1152);
    blob.extend_from_slice(&g1_bytes);    // 0..128
    blob.extend_from_slice(&h0_bytes);    // 128..256
    blob.extend_from_slice(&g2_bytes);    // 256..512
    blob.extend_from_slice(&pk_g2_bytes); // 512..768
    // Opener ybar G1 (128 zeros) and opener pkG2 (256 zeros) — not needed for confirm benchmark
    // Actually we need valid G1/G2 points or the contract may reject. Use g1 and g2.
    blob.extend_from_slice(&g1_bytes);    // 768..896 openerYbarG1
    blob.extend_from_slice(&g2_bytes);    // 896..1152 openerPkG2

    let cred_name = "BENCH_CRED".to_string();

    // Register issuers on Params before setupAll
    for i in 1..=THRESHOLD {
        let issuer_addr = issuers[(i - 1) as usize].address();
        let _ = params_contract
            .method::<_, H256>("setIssuer", (issuer_addr, i, true))?
            .send().await?.await?;
    }

    // setupAll
    let public_m_encoding: Vec<U256> = vec![];
    let indices: Vec<u16> = vec![];
    let commitments_g2: Vec<EthBytes> = vec![];
    let _ = params_contract
        .method::<_, H256>(
            "setupAll",
            (
                cred_name.clone(),
                U256::from(MESSAGE_COUNT),
                U256::from(THRESHOLD),
                U256::from(TOTAL),
                public_m_encoding,
                EthBytes::from(blob),
                indices,
                commitments_g2,
            ),
        )?
        .send()
        .await?
        .await?;

    // Set H vector
    let h_bytes_vec: Vec<EthBytes> = bbs_params
        .h
        .iter()
        .map(|h| EthBytes::from(g1_to_eip2537_bytes(h).to_vec()))
        .collect();
    let _ = params_contract
        .method::<_, H256>("setHByName", (cred_name.clone(), h_bytes_vec))?
        .send()
        .await?
        .await?;

    println!("[setup] BBS+ params set on-chain");

    // ===================== BENCHMARK LOOP =====================
    // Clear metrics file
    let _ = fs::remove_file(&metrics_file);
    fs::create_dir_all("metrics/results")?;

    println!();
    println!("{:<10} {:>18} {:>18} {:>18} {:>18}", "BatchSize", "submitShare×N", "submitShareBatch", "confirmCred×N", "confirmBatch");
    println!("{}", "-".repeat(90));

    for &batch_size in &batch_sizes {
        // Snapshot Anvil state for rollback (each benchmark iteration starts clean)
        let snapshot_id: U256 = client.provider().request("evm_snapshot", ()).await?;

        // ---- Generate synthetic data for this batch ----
        // We need: for each user j in 0..batch_size:
        //   - userId (derived from address)
        //   - commitment B' (h0^s' where s' is random)
        //   - revealed messages
        //   - BBS+ signature (A, e, s) — pre-generated from generate_test_data
        //
        // For the benchmark, we simulate the full submitShare flow:
        //   - Each issuer submits (R_j, u_j, e, s) for each user
        //   - We use the actual BBS+ signature (A, e, s) and reverse-engineer R and u:
        //     A = g1^(1/(e + sk)) * ... etc. For simplicity, we'll create dummy shares
        //     whose R accumulates to A*u and u sums to a known value.

        // Simpler approach: We'll use the actual BBS+ signature components directly.
        // For threshold aggregation benchmark, we construct shares such that:
        //   sum_R = A * sum_u  (so that A = sum_R * inv(sum_u) holds)
        // Each issuer i contributes: R_i is a fraction of A*sum_u, and u_i is a fraction of sum_u.

        let mut rng = StdRng::seed_from_u64(0xBE0C0 + batch_size as u64);

        // For each credential j, we need (A_j, e_j, s_j) and B'_j
        struct CredData {
            user_id: U256,
            a_bytes: [u8; 128],
            e_val: U256,
            s_val: U256,
            bprime_bytes: [u8; 128],
            messages: Vec<Fr>,
        }

        let mut cred_data: Vec<CredData> = Vec::with_capacity(batch_size);
        for j in 0..batch_size {
            let (sig, msgs) = &creds[j];
            let user_id = U256::from(1000 + j);

            let a_bytes = g1_to_eip2537_bytes(&sig.A);
            let e_val = fr_to_u256(&sig.e);
            let s_val = fr_to_u256(&sig.s);

            // B' = commitment = h0^s' + sum(h_i^m_i for hidden messages)
            // For the benchmark, compute B' = h0^s + sum(h_i^m_i) (the actual commitment part without g1)
            // Actually in the real protocol, B' = h0*blinding + sum(h_i * m_i for hidden)
            // For the confirm benchmark, we need:
            //   verify: e(A, pk + e*g2) = e(g1 + B'', g2)
            //   where B'' = B' + h0^s + sum(H[i]^m[i] for revealed)
            //   and B' is the user's commitment to hidden messages
            // 
            // Full B computation: B = g1 + h0*s + sum(h_i * m_i)  =  g1 + B''
            // So B'' = h0*s + sum(h_i * m_i)
            // B' (stored) = sum(h_i * m_i for HIDDEN) (user's blind commitment)
            // Then contract adds h0*s + sum(H[i]*m[i] for REVEALED) to get B''
            //
            // For simplicity, all messages are revealed in the benchmark:
            // B' = 0 (identity), and contract computes B'' = h0*s + sum(H[i]*m[i])
            // But B' must be a valid 128-byte G1 point. Use generator * 0 = identity...
            // Actually, let's make msg[0] hidden and the rest revealed.
            // B' = h_0 * m[0] (hidden message commitment without h0*s)
            // Wait, in the actual protocol B' = h_1^m1 * h_2^m2 ... for hidden messages
            // And the contract adds h0^s + sum(H[i]^m[i] for revealed)
            //
            // For the benchmark, let's just reveal ALL messages (simplest):
            // B' would be the identity point. But G1 identity isn't a standard 128-byte point.
            // Actually, let's reveal messages 0..MESSAGE_COUNT-1 and have B' be a dummy
            // that makes the pairing check pass.
            //
            // Cleanest approach: compute B'' directly in Rust, then set B' = B'' - h0*s - sum(H_i*m_i for revealed)
            // where B'' = h0*s + sum(h_i * m_i for ALL)
            // So B' = sum(h_i * m_i for HIDDEN) = 0 if all revealed.
            // But we need B' to be 0 (identity). Identity in G1 is (0, 1, 0) in projective.
            // EIP-2537 uses point-at-infinity as all zeros? Actually no.
            // 
            // Let's just hide message 0 and reveal messages 1..MESSAGE_COUNT-1.
            // B' = h[0] * m[0]

            use ark_ec::CurveGroup;
            let bprime: G1Affine = (bbs_params.h[0] * msgs[0]).into_affine();
            let bprime_bytes = g1_to_eip2537_bytes(&bprime);

            cred_data.push(CredData {
                user_id,
                a_bytes,
                e_val,
                s_val,
                bprime_bytes,
                messages: msgs.clone(),
            });
        }

        // ---- Pre-register requests: noteRequest + recordBprime + recordRevealed ----
        // We set deployer as requestContract, so we can call directly without impersonation.
        eprintln!("[debug] Pre-registering {} users...", batch_size);
        for j in 0..batch_size {
            let cd = &cred_data[j];

            // noteRequest
            eprintln!("[debug]   noteRequest user {}...", j);
            let _ = reg_contract
                .method::<_, H256>(
                    "noteRequest",
                    (cred_name.clone(), cd.user_id, addr), // owner = deployer
                )?
                .send().await?.await?;

            // recordBprime
            let _ = reg_contract
                .method::<_, H256>(
                    "recordBprime",
                    (cred_name.clone(), cd.user_id, EthBytes::from(cd.bprime_bytes.to_vec())),
                )?
                .send().await?.await?;

            // recordRevealed — reveal messages 1..MESSAGE_COUNT-1 (msg 0 is hidden)
            let revealed_idx: Vec<u32> = (1..MESSAGE_COUNT as u32).collect();
            let revealed_vals: Vec<U256> = cd.messages[1..]
                .iter()
                .map(|m| fr_to_u256(m))
                .collect();
            let _ = reg_contract
                .method::<_, H256>(
                    "recordRevealed",
                    (cred_name.clone(), cd.user_id, revealed_idx, revealed_vals),
                )?
                .send().await?.await?;
        }
        eprintln!("[debug] Pre-registration done.");

        // ---- BENCHMARK 1: submitShare (single) vs submitShareBatch ----
        // For each credential, we need THRESHOLD issuers to submit shares.
        // We construct dummy shares where:
        //   For issuer i, user j: R_ij and u_ij such that sum_i(R_ij) = A_j * sum_i(u_ij)
        // Simple construction: u_i = 1 for all i, R_i = A / threshold for i < threshold, R_last = A - sum(R_i)
        // Actually: u_1=u_2=...=u_{t-1}= 0, u_t = 1. Then R_1=R_2=...=R_{t-1}= identity, R_t = A.
        // But identity isn't a valid 128-byte point for G1ADD.
        //
        // Better: u_i = random, R_i = A * u_i. Then sum_R = A * sum_u, and A = sum_R / sum_u. ✓
        // But each R_i needs to be computed as A_j * u_ij via G1 scalar mul.

        use ark_ec::CurveGroup;

        struct ShareData {
            r_bytes: [u8; 128],
            u_val: U256,
            e_val: U256,
            s_val: U256,
        }

        // Generate per-issuer per-user shares
        let mut all_shares: Vec<Vec<ShareData>> = Vec::new(); // [issuer][user] -> ShareData
        for issuer_idx in 0..THRESHOLD as usize {
            let mut issuer_shares: Vec<ShareData> = Vec::new();
            for j in 0..batch_size {
                let a_affine: G1Affine = creds[j].0.A;
                let u_scalar = Fr::rand(&mut rng);
                let r_point: G1Affine = (a_affine * u_scalar).into_affine();
                issuer_shares.push(ShareData {
                    r_bytes: g1_to_eip2537_bytes(&r_point),
                    u_val: fr_to_u256(&u_scalar),
                    e_val: cred_data[j].e_val,
                    s_val: cred_data[j].s_val,
                });
            }
            all_shares.push(issuer_shares);
        }

        // --- Benchmark single submitShare ×N (for each issuer) ---
        eprintln!("[debug] Starting single submitShare benchmark...");
        let snapshot_before_submit: U256 = client.provider().request("evm_snapshot", ()).await?;

        let mut total_gas_single_submit = U256::zero();
        let start_single_submit = Instant::now();

        for issuer_idx in 0..THRESHOLD as usize {
            let issuer_client = &issuers[issuer_idx];
            let issuer_reg = Contract::new(reg_addr, reg_abi.clone(), issuer_client.clone());

            for j in 0..batch_size {
                let sd = &all_shares[issuer_idx][j];
                let tx = issuer_reg
                    .method::<_, ()>(
                        "submitShare",
                        (
                            cred_name.clone(),
                            cred_data[j].user_id,
                            (issuer_idx + 1) as u16,
                            EthBytes::from(sd.r_bytes.to_vec()),
                            sd.u_val,
                            sd.e_val,
                            sd.s_val,
                            THRESHOLD,
                        ),
                    )?
                    .gas_price(U256::from(1_000_000_000u64));
                let rcpt = tx.send().await?.await?.ok_or(anyhow::anyhow!("no receipt"))?;
                total_gas_single_submit += rcpt.gas_used.unwrap_or_default();
            }
        }
        let elapsed_single_submit = start_single_submit.elapsed();

        // Revert to before submit
        let _: serde_json::Value = client.provider().request("evm_revert", [snapshot_before_submit]).await?;

        // Re-register request data after revert (no impersonation needed)
        for j in 0..batch_size {
            let cd = &cred_data[j];
            let _ = reg_contract.method::<_, H256>("noteRequest", (cred_name.clone(), cd.user_id, addr))?.send().await?.await?;
            let _ = reg_contract.method::<_, H256>("recordBprime", (cred_name.clone(), cd.user_id, EthBytes::from(cd.bprime_bytes.to_vec())))?.send().await?.await?;
            let revealed_idx: Vec<u32> = (1..MESSAGE_COUNT as u32).collect();
            let revealed_vals: Vec<U256> = cd.messages[1..].iter().map(|m| fr_to_u256(m)).collect();
            let _ = reg_contract.method::<_, H256>("recordRevealed", (cred_name.clone(), cd.user_id, revealed_idx, revealed_vals))?.send().await?.await?;
        }

        // --- Benchmark batch submitShareBatch ---
        eprintln!("[debug] Starting batch submitShareBatch...");
        let mut total_gas_batch_submit = U256::zero();
        let start_batch_submit = Instant::now();

        for issuer_idx in 0..THRESHOLD as usize {
            let issuer_client = &issuers[issuer_idx];
            let issuer_reg = Contract::new(reg_addr, reg_abi.clone(), issuer_client.clone());

            // Build batch arrays
            let user_ids: Vec<U256> = (0..batch_size).map(|j| cred_data[j].user_id).collect();
            let mut r_concat = Vec::with_capacity(batch_size * 128);
            let mut us = Vec::with_capacity(batch_size);
            let mut es = Vec::with_capacity(batch_size);
            let mut ss = Vec::with_capacity(batch_size);
            for j in 0..batch_size {
                let sd = &all_shares[issuer_idx][j];
                r_concat.extend_from_slice(&sd.r_bytes);
                us.push(sd.u_val);
                es.push(sd.e_val);
                ss.push(sd.s_val);
            }

            let tx = issuer_reg
                .method::<_, ()>(
                    "submitShareBatch",
                    (
                        cred_name.clone(),
                        user_ids,
                        (issuer_idx + 1) as u16,
                        EthBytes::from(r_concat),
                        us,
                        es,
                        ss,
                    ),
                )?
                .gas_price(U256::from(1_000_000_000u64))
                .gas(30_000_000u64); // high gas limit for large batches
            let rcpt = tx.send().await?.await?.ok_or(anyhow::anyhow!("no receipt"))?;
            total_gas_batch_submit += rcpt.gas_used.unwrap_or_default();
        }
        let elapsed_batch_submit = start_batch_submit.elapsed();

        // ---- BENCHMARK 2: confirmCredential (single) vs confirmBatchRandomized ----
        eprintln!("[debug] Starting confirmCredential benchmark...");
        // After submitShareBatch, all credentials should be in Unverified state.
        // Test single confirm:
        let snapshot_before_confirm: U256 = client.provider().request("evm_snapshot", ()).await?;

        let mut total_gas_single_confirm = U256::zero();
        let start_single_confirm = Instant::now();
        for j in 0..batch_size {
            let tx = reg_contract
                .method::<_, ()>(
                    "confirmCredential",
                    (cred_name.clone(), cred_data[j].user_id),
                )?
                .gas_price(U256::from(1_000_000_000u64));
            let rcpt = tx.send().await?.await?.ok_or(anyhow::anyhow!("confirmCred receipt"))?;
            total_gas_single_confirm += rcpt.gas_used.unwrap_or_default();
        }
        let elapsed_single_confirm = start_single_confirm.elapsed();

        // Revert
        let _: serde_json::Value = client.provider().request("evm_revert", [snapshot_before_confirm]).await?;

        // Batch confirm
        let start_batch_confirm = Instant::now();
        let user_ids_confirm: Vec<U256> = (0..batch_size).map(|j| cred_data[j].user_id).collect();
        let tx = reg_contract
            .method::<_, ()>(
                "confirmBatchRandomized",
                (cred_name.clone(), user_ids_confirm),
            )?
            .gas_price(U256::from(1_000_000_000u64))
            .gas(100_000_000u64);
        let rcpt = tx.send().await?.await?.ok_or(anyhow::anyhow!("confirmBatch receipt"))?;
        let gas_batch_confirm = rcpt.gas_used.unwrap_or_default();
        let elapsed_batch_confirm = start_batch_confirm.elapsed();

        // ---- BENCHMARK 3: addMember (single) vs addMembers ----
        eprintln!("[debug] Starting addMember benchmark...");
        // Generate dummy accumulator deltas (use g1 * random scalar as delta)
        let snapshot_before_acc: U256 = client.provider().request("evm_snapshot", ()).await?;

        // Set deployer as opener (accumulatorManager on registry, and opener on accumulator)
        // Actually deployer is already accumulatorManager. But accumulator.addMember requires onlyOpener.
        // onlyOpener checks registry.accumulatorManagers(msg.sender).
        // We already set addr as accumulatorManager on the registry. Good.

        // Set initial delta
        let init_delta = g1_to_eip2537_bytes(&bbs_params.g1);
        let tx = acc_contract
            .method::<_, ()>("setDelta", (cred_name.clone(), EthBytes::from(init_delta.to_vec())))?
            .send().await?.await?;

        // Single addMember × N
        let mut total_gas_single_add = U256::zero();
        let start_single_add = Instant::now();
        for j in 0..batch_size {
            let e_val = U256::from(2000 + j);
            let delta = g1_to_eip2537_bytes(&(bbs_params.g1 * Fr::from((j + 1) as u64)).into_affine());
            let tx = acc_contract
                .method::<_, ()>(
                    "addMember",
                    (cred_name.clone(), e_val, EthBytes::from(delta.to_vec())),
                )?
                .gas_price(U256::from(1_000_000_000u64));
            let rcpt = tx.send().await?.await?.ok_or(anyhow::anyhow!("addMember receipt"))?;
            total_gas_single_add += rcpt.gas_used.unwrap_or_default();
        }
        let elapsed_single_add = start_single_add.elapsed();

        // Revert
        let _: serde_json::Value = client.provider().request("evm_revert", [snapshot_before_acc]).await?;

        // Re-set delta after revert
        let _ = acc_contract
            .method::<_, ()>("setDelta", (cred_name.clone(), EthBytes::from(init_delta.to_vec())))?
            .send().await?.await?;

        // Batch addMembers
        let start_batch_add = Instant::now();
        let member_es: Vec<U256> = (0..batch_size).map(|j| U256::from(2000 + j)).collect();
        let final_delta = g1_to_eip2537_bytes(&(bbs_params.g1 * Fr::from(batch_size as u64)).into_affine());
        let tx = acc_contract
            .method::<_, ()>(
                "addMembers",
                (cred_name.clone(), member_es, EthBytes::from(final_delta.to_vec())),
            )?
            .gas_price(U256::from(1_000_000_000u64))
            .gas(30_000_000u64);
        let rcpt = tx.send().await?.await?.ok_or(anyhow::anyhow!("addMembers receipt"))?;
        let gas_batch_add = rcpt.gas_used.unwrap_or_default();
        let elapsed_batch_add = start_batch_add.elapsed();

        // ---- BENCHMARK 4: verifyPairing (single) vs verifyBbsPairingBatch ----
        eprintln!("[debug] Starting verifyPairing benchmark...");
        // Generate N random (A', Abar) pairs.
        // For the batch pairing benchmark, we need pairs where e(A', pk) * e(-Abar, g2) = 1.
        // i.e., A' and Abar satisfy e(A', pk) = e(Abar, g2).
        // Construct: A' = random G1, Abar = A' * sk (where sk is the BBS+ secret key)
        // Actually e(A', pk) = e(A', sk*g2) and e(Abar, g2). So Abar = sk * A' satisfies it.
        // But we don't have sk directly. We have the signatures though.
        //
        // For a valid BBS+ presentation: A' = A * r, Abar = A' * sk = A * r * sk
        // Actually, Abar = A' * (-e) + B'' * r where B'' = g1 + h0*s + sum(h_i*m_i)
        // The pairing check is e(A', pk + e*g2) = e(Abar, g2), not e(A', pk) = e(Abar, g2).
        //
        // For a clean benchmark of the batch pairing primitive, let's just create pairs
        // where e(A'_j, Q) * e(negB_j, g2) = 1 for some shared G2 point Q.
        // Construction: Choose random r, set A' = g1*r, B = g1*r*sk... too complex.
        //
        // Simplest: use the actual BBS+ signature. For each sig (A, e, s):
        //   e(A, pk + e*g2) = e(g1 + B'', g2)
        //   Rewrite: e(A, pk + e*g2) * e(-(g1+B''), g2) = 1
        //   i.e., e(A, pk+e*g2) * e(-C, g2) = 1 where C = g1 + B''
        //
        // For batch: e(∑δ_j*A_j, pk+e_j*g2) doesn't factor nicely because e_j varies.
        // The standard BBS+ PoK presentation: Prover re-randomizes:
        //   A' = A * r, Abar = A' * (-e) + (g1+B'') * r
        //   Check: e(A', pk) * e(-Abar, g2) == 1
        // This IS the factored form we want! Let's compute these.

        let snapshot_before_pair: U256 = client.provider().request("evm_snapshot", ()).await?;

        struct PairData {
            a_prime: [u8; 128],
            a_bar: [u8; 128],
        }

        let mut pair_data: Vec<PairData> = Vec::new();
        for j in 0..batch_size {
            let sig = &creds[j].0;
            let msgs = &creds[j].1;

            // Compute B'' = h0*s + sum(h_i * m_i)
            let mut bpp = bbs_params.h_0 * sig.s;
            for (i, m) in msgs.iter().enumerate() {
                bpp += bbs_params.h[i] * m;
            }
            let g1_plus_bpp = (bbs_params.g1 + bpp).into_affine();

            // Re-randomize for PoK
            let r = Fr::rand(&mut rng);
            let a_prime: G1Affine = (sig.A * r).into_affine();
            // Abar = A' * (-e) + (g1 + B'') * r
            let neg_e = -sig.e;
            let a_bar: G1Affine =
                (a_prime * neg_e + g1_plus_bpp * r).into_affine();

            // Verify locally: e(A', pk) * e(-Abar, g2) should = 1
            // (We trust this from BBS+ math)

            pair_data.push(PairData {
                a_prime: g1_to_eip2537_bytes(&a_prime),
                a_bar: g1_to_eip2537_bytes(&a_bar),
            });
        }

        // Single verifyPairing × N
        let verify_wrapper = Contract::new(verify_addr, verify_abi.clone(), client.clone());
        let mut total_gas_single_pair = U256::zero();
        let start_single_pair = Instant::now();
        for j in 0..batch_size {
            let pd = &pair_data[j];
            // Call verifyPairing(A', pk, -Abar, g2)
            use tbbsplus_rust::orchestration::crypto::encoding::eip2537_g1_to_affine;
            // Negate Abar for the pairing (library expects -Abar as second G1)
            let neg_abar_affine = -eip2537_g1_to_affine(&pd.a_bar)?;
            let neg_abar_bytes = g1_to_eip2537_bytes(&neg_abar_affine);

            let result: bool = verify_wrapper
                .method(
                    "verifyPairing",
                    (
                        EthBytes::from(pd.a_prime.to_vec()),
                        EthBytes::from(pk_g2_bytes.to_vec()),
                        EthBytes::from(neg_abar_bytes.to_vec()),
                        EthBytes::from(g2_bytes.to_vec()),
                    ),
                )?
                .call()
                .await?;
            assert!(result, "single pairing check failed for j={}", j);

            // Estimate gas via eth_estimateGas
            let est = verify_wrapper
                .method::<_, bool>(
                    "verifyPairing",
                    (
                        EthBytes::from(pd.a_prime.to_vec()),
                        EthBytes::from(pk_g2_bytes.to_vec()),
                        EthBytes::from(neg_abar_bytes.to_vec()),
                        EthBytes::from(g2_bytes.to_vec()),
                    ),
                )?
                .estimate_gas()
                .await?;
            total_gas_single_pair += est;
        }
        let elapsed_single_pair = start_single_pair.elapsed();

        // Batch verifyBbsPairingBatch
        let start_batch_pair = Instant::now();
        let mut a_primes_concat = Vec::with_capacity(batch_size * 128);
        let mut a_bars_concat = Vec::with_capacity(batch_size * 128);
        for j in 0..batch_size {
            a_primes_concat.extend_from_slice(&pair_data[j].a_prime);
            a_bars_concat.extend_from_slice(&pair_data[j].a_bar);
        }
        let gas_batch_pair = verify_wrapper
            .method::<_, bool>(
                "verifyBbsPairingBatch",
                (
                    EthBytes::from(a_primes_concat),
                    EthBytes::from(a_bars_concat),
                    EthBytes::from(pk_g2_bytes.to_vec()),
                    EthBytes::from(g2_bytes.to_vec()),
                ),
            )?
            .gas(100_000_000u64)
            .estimate_gas()
            .await?;
        let elapsed_batch_pair = start_batch_pair.elapsed();

        // Revert
        let _: serde_json::Value = client.provider().request("evm_revert", [snapshot_before_pair]).await?;

        // ---- Print results ----
        let n = batch_size;
        println!(
            "{:<10} {:>18} {:>18} {:>18} {:>18}",
            n,
            total_gas_single_submit,
            total_gas_batch_submit,
            total_gas_single_confirm,
            gas_batch_confirm,
        );

        // Save detailed metrics
        let record = json!({
            "batchSize": n,
            "submitShare": {
                "single_total_gas": total_gas_single_submit.to_string(),
                "single_per_user_gas": (total_gas_single_submit / U256::from(n)).to_string(),
                "single_elapsed_ms": elapsed_single_submit.as_millis(),
                "batch_total_gas": total_gas_batch_submit.to_string(),
                "batch_per_user_gas": (total_gas_batch_submit / U256::from(n)).to_string(),
                "batch_elapsed_ms": elapsed_batch_submit.as_millis(),
                "gas_savings_pct": if total_gas_single_submit > U256::zero() {
                    let saved = total_gas_single_submit.saturating_sub(total_gas_batch_submit);
                    format!("{:.1}", saved.as_u128() as f64 / total_gas_single_submit.as_u128() as f64 * 100.0)
                } else { "0".to_string() },
            },
            "confirmCredential": {
                "single_total_gas": total_gas_single_confirm.to_string(),
                "single_per_user_gas": (total_gas_single_confirm / U256::from(n)).to_string(),
                "single_elapsed_ms": elapsed_single_confirm.as_millis(),
                "batch_total_gas": gas_batch_confirm.to_string(),
                "batch_per_user_gas": (gas_batch_confirm / U256::from(n)).to_string(),
                "batch_elapsed_ms": elapsed_batch_confirm.as_millis(),
                "gas_savings_pct": if total_gas_single_confirm > U256::zero() {
                    let saved = total_gas_single_confirm.saturating_sub(gas_batch_confirm);
                    format!("{:.1}", saved.as_u128() as f64 / total_gas_single_confirm.as_u128() as f64 * 100.0)
                } else { "0".to_string() },
            },
            "addMember": {
                "single_total_gas": total_gas_single_add.to_string(),
                "single_per_user_gas": (total_gas_single_add / U256::from(n)).to_string(),
                "single_elapsed_ms": elapsed_single_add.as_millis(),
                "batch_total_gas": gas_batch_add.to_string(),
                "batch_per_user_gas": (gas_batch_add / U256::from(n)).to_string(),
                "batch_elapsed_ms": elapsed_batch_add.as_millis(),
                "gas_savings_pct": if total_gas_single_add > U256::zero() {
                    let saved = total_gas_single_add.saturating_sub(gas_batch_add);
                    format!("{:.1}", saved.as_u128() as f64 / total_gas_single_add.as_u128() as f64 * 100.0)
                } else { "0".to_string() },
            },
            "verifyPairing": {
                "single_total_gas": total_gas_single_pair.to_string(),
                "single_per_user_gas": (total_gas_single_pair / U256::from(n)).to_string(),
                "single_elapsed_ms": elapsed_single_pair.as_millis(),
                "batch_total_gas": gas_batch_pair.to_string(),
                "batch_per_user_gas": (gas_batch_pair / U256::from(n)).to_string(),
                "batch_elapsed_ms": elapsed_batch_pair.as_millis(),
                "gas_savings_pct": if total_gas_single_pair > U256::zero() {
                    let saved = total_gas_single_pair.saturating_sub(gas_batch_pair);
                    format!("{:.1}", saved.as_u128() as f64 / total_gas_single_pair.as_u128() as f64 * 100.0)
                } else { "0".to_string() },
            },
        });
        metrics_append(&metrics_file, record);

        // Revert the main snapshot (clean slate for next batch size)
        let _: serde_json::Value = client.provider().request("evm_revert", [snapshot_id]).await?;
    }

    println!();
    println!("[done] Results written to {}", metrics_file);

    // ---- Print summary tables ----
    println!();
    println!("=== GAS SAVINGS SUMMARY (per-user amortized) ===");
    println!();

    // Re-read metrics and print
    if let Ok(data) = fs::read_to_string(&metrics_file) {
        println!("{:<6} {:>12} {:>12} {:>8} | {:>12} {:>12} {:>8} | {:>12} {:>12} {:>8} | {:>12} {:>12} {:>8}",
            "N", "submit/u", "batch/u", "save%",
            "confirm/u", "batch/u", "save%",
            "addMbr/u", "batch/u", "save%",
            "pair/u", "batch/u", "save%");
        println!("{}", "-".repeat(170));

        for line in data.lines() {
            if line.trim().is_empty() { continue; }
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let bs = v["batchSize"].as_u64().unwrap_or(0);
            let ss_pu = v["submitShare"]["single_per_user_gas"].as_str().unwrap_or("0");
            let sb_pu = v["submitShare"]["batch_per_user_gas"].as_str().unwrap_or("0");
            let ss_pct = v["submitShare"]["gas_savings_pct"].as_str().unwrap_or("0");
            let cs_pu = v["confirmCredential"]["single_per_user_gas"].as_str().unwrap_or("0");
            let cb_pu = v["confirmCredential"]["batch_per_user_gas"].as_str().unwrap_or("0");
            let cs_pct = v["confirmCredential"]["gas_savings_pct"].as_str().unwrap_or("0");
            let as_pu = v["addMember"]["single_per_user_gas"].as_str().unwrap_or("0");
            let ab_pu = v["addMember"]["batch_per_user_gas"].as_str().unwrap_or("0");
            let as_pct = v["addMember"]["gas_savings_pct"].as_str().unwrap_or("0");
            let ps_pu = v["verifyPairing"]["single_per_user_gas"].as_str().unwrap_or("0");
            let pb_pu = v["verifyPairing"]["batch_per_user_gas"].as_str().unwrap_or("0");
            let ps_pct = v["verifyPairing"]["gas_savings_pct"].as_str().unwrap_or("0");
            println!("{:<6} {:>12} {:>12} {:>7}% | {:>12} {:>12} {:>7}% | {:>12} {:>12} {:>7}% | {:>12} {:>12} {:>7}%",
                bs, ss_pu, sb_pu, ss_pct, cs_pu, cb_pu, cs_pct, as_pu, ab_pu, as_pct, ps_pu, pb_pu, ps_pct);
        }
    }

    Ok(())
}
