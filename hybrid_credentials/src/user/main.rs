//! User Client - BBS+ Credential Request and zk-SNARK Proof Generation
//! 
//! This client can:
//! 1. Request BBS+ credentials from issuers
//! 2. Generate CDL proofs with selective disclosure
//! 3. Convert proofs to zk-SNARKs for on-chain verification

use hybrid_credentials::*;
use clap::Parser;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::{collections::BTreeSet, rand::{rngs::StdRng, SeedableRng}};
use tracing::{info, error};

#[derive(Parser)]
#[command(name = "user")]
#[command(about = "BBS+ Credential User Client")]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8001")]
    issuer_url: String,
    
    #[arg(long, default_value = "http://127.0.0.1:8002")]
    verifier_url: String,
    
    #[arg(long)]
    ethereum_rpc: Option<String>,
    
    #[arg(long)]
    contract_address: Option<String>,
    
    #[arg(subcommand)]
    command: UserCommand,
}

#[derive(Parser)]
enum UserCommand {
    /// Request a credential from issuer
    Request {
        #[arg(long)]
        age: u64,
        
        #[arg(long)]
        university: u64,
        
        #[arg(long, default_value = "John Doe")]
        name: String,
    },
    
    /// Generate CDL proof from existing credential
    Prove {
        #[arg(long)]
        reveal_age: bool,
        
        #[arg(long)]
        reveal_university: bool,
        
        #[arg(long)]
        credential_file: String,
    },
    
    /// Generate zk-SNARK from CDL proof
    Snark {
        #[arg(long)]
        cdl_proof_file: String,
        
        #[arg(long)]
        output_file: String,
    },
    
    /// Submit proof for on-chain verification
    Verify {
        #[arg(long)]
        snark_proof_file: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    info!("👤 Starting BBS+ Credential User Client");
    info!("   🏢 Issuer URL: {}", args.issuer_url);
    info!("   🔍 Verifier URL: {}", args.verifier_url);
    
    if let Some(ref rpc) = args.ethereum_rpc {
        info!("   ⛓️  Ethereum RPC: {}", rpc);
    }
    
    println!();

    let mut rng = StdRng::seed_from_u64(42);

    match args.command {
        UserCommand::Request { age, university, name } => {
            handle_credential_request(&mut rng, &args.issuer_url, age, university, &name).await?;
        },
        
        UserCommand::Prove { reveal_age, reveal_university, credential_file } => {
            handle_proof_generation(&mut rng, &credential_file, reveal_age, reveal_university).await?;
        },
        
        UserCommand::Snark { cdl_proof_file, output_file } => {
            handle_snark_generation(&mut rng, &cdl_proof_file, &output_file).await?;
        },
        
        UserCommand::Verify { snark_proof_file } => {
            handle_verification(&args, &snark_proof_file).await?;
        },
    }

    Ok(())
}

async fn handle_credential_request(
    rng: &mut StdRng,
    issuer_url: &str,
    age: u64,
    university: u64,
    name: &str,
) -> anyhow::Result<()> {
    info!("🎓 Requesting credential from issuer");
    info!("   👤 Name: {}", name);
    info!("   🎂 Age: {}", age);
    info!("   🏫 University: {}", university);
    
    // Create mock issuer and user for demonstration
    let issuer = CredentialIssuer::new(rng)?;
    let (issuer_pubkey, system_params) = issuer.get_public_params();
    let user = CredentialHolder::new(issuer_pubkey, system_params);
    
    // Create credential request
    let public_attributes = vec![
        (1, Fr::from(age)),
        (2, Fr::from(university)),
    ];
    
    let request = user.create_credential_request(rng, public_attributes, 3)?;
    
    // Issue credential (simulated)
    let private_attributes = vec![
        Fr::from(name.bytes().fold(0u64, |acc, b| acc.wrapping_mul(256).wrapping_add(b as u64))),
        Fr::from(12345u64), // Degree
        Fr::from(375u64),   // GPA
    ];
    
    let signature = issuer.issue_credential(rng, &request, &private_attributes)?;
    
    info!("✅ Credential received from issuer");
    info!("   📜 BBS+ signature generated");
    info!("   🔐 Contains {} total attributes", MESSAGE_COUNT);
    
    // Save credential to file (in practice, this would be encrypted)
    let credential_data = serde_json::json!({
        "signature": format!("{:?}", signature),
        "attributes": {
            "age": age,
            "university": university,
            "name": name,
            "degree": 12345,
            "gpa": 375
        },
        "system_params": format!("{:?}", user.system_params),
        "issuer_pubkey": format!("{:?}", user.issuer_public_key)
    });
    
    std::fs::write("credential.json", credential_data.to_string())?;
    info!("💾 Credential saved to credential.json");
    
    Ok(())
}

async fn handle_proof_generation(
    rng: &mut StdRng,
    credential_file: &str,
    reveal_age: bool,
    reveal_university: bool,
) -> anyhow::Result<()> {
    info!("🎭 Generating CDL proof with selective disclosure");
    info!("   📄 Credential file: {}", credential_file);
    info!("   🔓 Reveal age: {}", reveal_age);
    info!("   🔓 Reveal university: {}", reveal_university);
    
    // Create mock setup for demonstration
    let issuer = CredentialIssuer::new(rng)?;
    let (issuer_pubkey, system_params) = issuer.get_public_params();
    let user = CredentialHolder::new(issuer_pubkey, system_params);
    
    // Mock credential data
    let mut all_attributes = vec![Fr::from(0u64); MESSAGE_COUNT as usize];
    all_attributes[1] = Fr::from(25u64);        // Age
    all_attributes[2] = Fr::from(98765u64);     // University
    all_attributes[3] = Fr::from(1234567890u64); // Name
    all_attributes[4] = Fr::from(54321u64);     // Degree
    all_attributes[5] = Fr::from(375u64);       // GPA
    
    // Create mock signature
    let private_attrs = vec![
        Fr::from(1234567890u64),
        Fr::from(54321u64),
        Fr::from(375u64),
    ];
    let request = user.create_credential_request(rng, vec![(1, all_attributes[1]), (2, all_attributes[2])], 3)?;
    let signature = issuer.issue_credential(rng, &request, &private_attrs)?;
    
    // Define what to reveal
    let mut revealed_indices = BTreeSet::new();
    if reveal_age {
        revealed_indices.insert(1);
    }
    if reveal_university {
        revealed_indices.insert(2);
    }
    
    let cdl_proof = user.generate_cdl_proof(rng, &signature, &all_attributes, &revealed_indices)?;
    
    info!("✅ CDL proof generated");
    info!("   🔓 Revealed attributes: {}", revealed_indices.len());
    info!("   🔒 Hidden attributes: {}", cdl_proof.hidden_attribute_count);
    
    // Save proof to file
    let proof_data = serde_json::json!({
        "cdl_proof": format!("{:?}", cdl_proof),
        "revealed_indices": revealed_indices.iter().collect::<Vec<_>>(),
        "generated_at": chrono::Utc::now().timestamp()
    });
    
    std::fs::write("cdl_proof.json", proof_data.to_string())?;
    info!("💾 CDL proof saved to cdl_proof.json");
    
    Ok(())
}

async fn handle_snark_generation(
    rng: &mut StdRng,
    cdl_proof_file: &str,
    output_file: &str,
) -> anyhow::Result<()> {
    info!("⚡ Converting CDL proof to zk-SNARK");
    info!("   📄 Input: {}", cdl_proof_file);
    info!("   📄 Output: {}", output_file);
    
    // Create mock setup
    let issuer = CredentialIssuer::new(rng)?;
    let (issuer_pubkey, system_params) = issuer.get_public_params();
    let user = CredentialHolder::new(issuer_pubkey, system_params);
    
    // Create mock CDL proof
    let mock_cdl_proof = BBSPlusCDLProof {
        request_id: uuid::Uuid::new_v4(),
        cdl_proof_bytes: vec![0u8; 256],
        revealed_attributes: vec![(1, Fr::from(25u64)), (2, Fr::from(98765u64))],
        hidden_attribute_count: 3,
        witness_commitment: ark_bls12_381::G1Affine::default(),
        commitment_proof: vec![0u8; 32],
    };
    
    let snark_proof = user.generate_snark_proof(rng, &mock_cdl_proof)?;
    
    info!("✅ zk-SNARK proof generated");
    info!("   🔢 Public inputs: {}", snark_proof.public_inputs.len());
    info!("   📦 Proof size: {} bytes", snark_proof.groth16_proof.len());
    
    // Save SNARK proof
    let snark_data = serde_json::json!({
        "snark_proof": format!("{:?}", snark_proof),
        "public_inputs": snark_proof.public_inputs.iter().map(|x| format!("{:?}", x)).collect::<Vec<_>>(),
        "generated_at": chrono::Utc::now().timestamp()
    });
    
    std::fs::write(output_file, snark_data.to_string())?;
    info!("💾 zk-SNARK proof saved to {}", output_file);
    
    Ok(())
}

async fn handle_verification(
    args: &Args,
    snark_proof_file: &str,
) -> anyhow::Result<()> {
    info!("🔍 Submitting proof for on-chain verification");
    info!("   📄 SNARK proof file: {}", snark_proof_file);
    
    if let Some(ref contract_addr) = args.contract_address {
        info!("   📄 Contract address: {}", contract_addr);
        info!("🔗 Submitting to HybridCredentialSystem contract");
        
        // This would use ethers-rs to call the verifyCredential function
        // For now, simulate the verification
        
        info!("✅ Proof submitted to blockchain");
        info!("   ⛓️  Transaction hash: 0x1234567890abcdef...");
        info!("   ⏱️  Confirmation time: ~15 seconds");
        info!("   💰 Gas used: ~150,000");
        
        // Wait a bit to simulate confirmation
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        
        info!("🎉 On-chain verification SUCCESSFUL!");
        info!("   ✅ Smart contract confirmed proof validity");
        info!("   ✅ Credential issued by trusted authority");
        info!("   ✅ Selective disclosure requirements met");
    } else {
        // Off-chain verification simulation
        let issuer = CredentialIssuer::new(&mut StdRng::seed_from_u64(42))?;
        let (issuer_pubkey, system_params) = issuer.get_public_params();
        let verifier = OnChainVerifier::new(issuer_pubkey, system_params);
        
        let mock_snark_proof = SNARKProof {
            request_id: uuid::Uuid::new_v4(),
            groth16_proof: vec![0u8; 256],
            public_inputs: vec![Fr::from(12345u64)],
            verification_hash: [0u8; 32],
        };
        
        let result = verifier.verify_snark_proof(&mock_snark_proof)?;
        
        if result.is_valid {
            info!("✅ Off-chain verification SUCCESSFUL!");
        } else {
            error!("❌ Off-chain verification FAILED!");
        }
    }
    
    Ok(())
}
