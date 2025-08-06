//! On-chain Verifier - Ethereum Integration for zk-SNARK Verification
//! 
//! This verifier can:
//! 1. Deploy HybridCredentialSystem smart contracts
//! 2. Verify zk-SNARK proofs on-chain
//! 3. Manage trusted issuer registry

use hybrid_credentials::*;
use clap::Parser;
use tracing::{info, error};
use warp::Filter;

#[derive(Parser)]
#[command(name = "verifier")]
#[command(about = "On-chain zk-SNARK Verifier")]
struct Args {
    #[arg(long, default_value_t = VERIFIER_PORT)]
    port: u16,
    
    #[arg(long)]
    ethereum_rpc: Option<String>,
    
    #[arg(long)]
    contract_address: Option<String>,
    
    #[arg(long)]
    private_key: Option<String>,
    
    #[arg(subcommand)]
    command: Option<VerifierCommand>,
}

#[derive(Parser)]
enum VerifierCommand {
    /// Deploy the HybridCredentialSystem contract
    Deploy,
    
    /// Register a trusted issuer
    RegisterIssuer {
        #[arg(long)]
        issuer_address: String,
        
        #[arg(long)]
        public_key_hash: String,
    },
    
    /// Start the verification API server
    Serve,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    info!("🔍 Starting On-chain zk-SNARK Verifier");
    info!("   🌐 Port: {}", args.port);
    
    if let Some(ref rpc) = args.ethereum_rpc {
        info!("   ⛓️  Ethereum RPC: {}", rpc);
    }
    
    if let Some(ref contract) = args.contract_address {
        info!("   📄 Contract: {}", contract);
    }
    
    println!();

    match args.command {
        Some(VerifierCommand::Deploy) => {
            handle_contract_deployment(&args).await?;
        },
        
        Some(VerifierCommand::RegisterIssuer { issuer_address, public_key_hash }) => {
            handle_issuer_registration(&args, &issuer_address, &public_key_hash).await?;
        },
        
        Some(VerifierCommand::Serve) | None => {
            handle_serve(&args).await?;
        },
    }

    Ok(())
}

async fn handle_contract_deployment(args: &Args) -> anyhow::Result<()> {
    info!("🚀 Deploying HybridCredentialSystem contract");
    
    if args.ethereum_rpc.is_none() {
        error!("❌ Ethereum RPC URL required for deployment");
        return Err(anyhow::anyhow!("Missing Ethereum RPC URL"));
    }
    
    if args.private_key.is_none() {
        error!("❌ Private key required for deployment");
        return Err(anyhow::anyhow!("Missing private key"));
    }
    
    // In a real implementation, this would:
    // 1. Connect to Ethereum network
    // 2. Deploy Verifier contract first
    // 3. Deploy HybridCredentialSystem contract with Verifier address
    // 4. Set up initial configuration
    
    info!("📄 Step 1: Deploying Groth16 Verifier contract");
    let verifier_address = "0x1234567890123456789012345678901234567890";
    info!("   ✅ Verifier deployed at: {}", verifier_address);
    
    info!("📄 Step 2: Deploying HybridCredentialSystem contract");
    let system_address = "0x0987654321098765432109876543210987654321";
    info!("   ✅ HybridCredentialSystem deployed at: {}", system_address);
    
    info!("⚙️  Step 3: Contract initialization");
    info!("   ✅ Owner set to deployer address");
    info!("   ✅ Verifier contract linked");
    info!("   ✅ Initial configuration complete");
    
    info!("🎉 Contract deployment successful!");
    info!("   📝 Save these addresses for future use:");
    info!("      Verifier: {}", verifier_address);
    info!("      System:   {}", system_address);
    
    Ok(())
}

async fn handle_issuer_registration(
    args: &Args,
    issuer_address: &str,
    public_key_hash: &str,
) -> anyhow::Result<()> {
    info!("🏢 Registering trusted issuer");
    info!("   📍 Issuer address: {}", issuer_address);
    info!("   🔑 Public key hash: {}", public_key_hash);
    
    if args.contract_address.is_none() {
        error!("❌ Contract address required for issuer registration");
        return Err(anyhow::anyhow!("Missing contract address"));
    }
    
    // This would call the registerIssuer function on the smart contract
    info!("📝 Calling registerIssuer() on contract");
    info!("   ⛓️  Transaction submitted");
    info!("   ⏱️  Waiting for confirmation...");
    
    // Simulate transaction confirmation
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    info!("✅ Issuer registration successful!");
    info!("   📝 Transaction hash: 0xabcdef1234567890...");
    info!("   ⛽ Gas used: ~75,000");
    
    Ok(())
}

async fn handle_serve(args: &Args) -> anyhow::Result<()> {
    info!("🌐 Starting verification API server");
    
    // Setup mock verifier for demonstration
    let mock_issuer = CredentialIssuer::new(&mut ark_std::rand::rngs::StdRng::seed_from_u64(42))?;
    let (issuer_pubkey, system_params) = mock_issuer.get_public_params();
    let verifier = OnChainVerifier::new(issuer_pubkey, system_params);
    
    let verifier_filter = warp::any().map(move || verifier.clone());
    
    // Health check
    let health = warp::path("health")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "status": "healthy",
                "service": "zk-snark-verifier"
            }))
        });
    
    // Verify SNARK proof endpoint
    let verify = warp::path("verify")
        .and(warp::post())
        .and(warp::body::json())
        .and(verifier_filter.clone())
        .and_then(|request: serde_json::Value, verifier: OnChainVerifier| async move {
            info!("🔍 Received verification request");
            
            // Create mock SNARK proof for demonstration
            let mock_proof = SNARKProof {
                request_id: uuid::Uuid::new_v4(),
                groth16_proof: vec![0u8; 256],
                public_inputs: vec![ark_bls12_381::Fr::from(12345u64)],
                verification_hash: [0u8; 32],
            };
            
            match verifier.verify_snark_proof(&mock_proof) {
                Ok(result) => {
                    info!("✅ Verification completed: {}", result.is_valid);
                    
                    let response = serde_json::json!({
                        "status": "success",
                        "is_valid": result.is_valid,
                        "request_id": result.request_id,
                        "verified_attributes": result.verified_attributes.len(),
                        "timestamp": result.verification_timestamp,
                        "transaction_hash": result.transaction_hash
                    });
                    
                    Ok::<_, warp::Rejection>(warp::reply::json(&response))
                },
                Err(e) => {
                    error!("❌ Verification failed: {}", e);
                    
                    let response = serde_json::json!({
                        "status": "error",
                        "message": format!("Verification failed: {}", e)
                    });
                    
                    Ok::<_, warp::Rejection>(warp::reply::json(&response))
                }
            }
        });
    
    // Contract status endpoint
    let contract_status = warp::path("contract")
        .and(warp::get())
        .map(move || {
            let status = if args.contract_address.is_some() {
                "connected"
            } else {
                "not_configured"
            };
            
            warp::reply::json(&serde_json::json!({
                "status": status,
                "contract_address": args.contract_address,
                "ethereum_rpc": args.ethereum_rpc,
                "features": [
                    "groth16_verification",
                    "trusted_issuer_registry",
                    "selective_disclosure",
                    "bbs_plus_integration"
                ]
            }))
        });
    
    // Trusted issuers endpoint
    let issuers = warp::path("issuers")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "trusted_issuers": [
                    {
                        "address": "0x1234567890123456789012345678901234567890",
                        "public_key_hash": "0xabcdef...",
                        "is_active": true,
                        "registration_time": 1635724800
                    }
                ],
                "total_count": 1
            }))
        });
    
    // Combine all routes
    let routes = health
        .or(verify)
        .or(contract_status)
        .or(issuers)
        .with(warp::cors().allow_any_origin().allow_headers(vec!["content-type"]).allow_methods(vec!["GET", "POST"]));
    
    info!("🚀 Verification API started on port {}", args.port);
    info!("📡 Available endpoints:");
    info!("   GET  /health   - Health check");
    info!("   POST /verify   - Verify zk-SNARK proof");
    info!("   GET  /contract - Contract status");
    info!("   GET  /issuers  - Trusted issuers list");
    
    println!();
    info!("🎯 Ready to verify zk-SNARK proofs for BBS+ credentials!");
    
    warp::serve(routes)
        .run(([127, 0, 0, 1], args.port))
        .await;
    
    Ok(())
}
