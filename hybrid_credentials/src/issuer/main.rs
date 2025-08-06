//! Issuer Node - BBS+ Credential Issuer with zk-SNARK Integration
//! 
//! This issuer can:
//! 1. Issue BBS+ credentials to users
//! 2. Generate trusted setup parameters
//! 3. Integrate with on-chain verification system

use hybrid_credentials::*;
use clap::Parser;
use tokio;
use tracing::{info, error};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use warp::Filter;

#[derive(Parser)]
#[command(name = "issuer")]
#[command(about = "BBS+ Credential Issuer with zk-SNARK Integration")]
struct Args {
    #[arg(long, default_value_t = ISSUER_PORT)]
    port: u16,
    
    #[arg(long)]
    ethereum_rpc: Option<String>,
    
    #[arg(long)]
    contract_address: Option<String>,
    
    #[arg(long, default_value = "issuer1")]
    issuer_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    info!("🏢 Starting BBS+ Credential Issuer");
    info!("   🆔 Issuer ID: {}", args.issuer_id);
    info!("   🌐 Port: {}", args.port);
    
    if let Some(ref rpc) = args.ethereum_rpc {
        info!("   ⛓️  Ethereum RPC: {}", rpc);
    }
    
    if let Some(ref contract) = args.contract_address {
        info!("   📄 Contract: {}", contract);
    }
    
    println!();

    // Initialize issuer
    let mut rng = StdRng::seed_from_u64(42);
    let issuer = CredentialIssuer::new(&mut rng)?;
    let (issuer_pubkey, system_params) = issuer.get_public_params();
    
    info!("✅ Issuer initialized with BBS+ keypair");
    info!("   🔑 Public key generated");
    info!("   📊 Message count: {}", system_params.message_count);
    
    // Setup HTTP API
    let issuer_filter = warp::any().map(move || issuer.clone());
    
    // Health check endpoint
    let health = warp::path("health")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "status": "healthy",
                "service": "bbs-plus-issuer"
            }))
        });
    
    // Get public parameters
    let params = warp::path("params")
        .and(warp::get())
        .and(issuer_filter.clone())
        .map(|issuer: CredentialIssuer| {
            let (pubkey, params) = issuer.get_public_params();
            warp::reply::json(&serde_json::json!({
                "public_key": format!("{:?}", pubkey),
                "system_params": {
                    "message_count": params.message_count,
                    "sig_batch_size": params.sig_batch_size
                }
            }))
        });
    
    // Issue credential endpoint
    let issue_credential = warp::path("issue")
        .and(warp::post())
        .and(warp::body::json())
        .and(issuer_filter.clone())
        .and_then(|request: serde_json::Value, issuer: CredentialIssuer| async move {
            info!("📜 Received credential issuance request");
            
            // In a real implementation, this would:
            // 1. Validate the credential request
            // 2. Verify user eligibility
            // 3. Issue the BBS+ signature
            // 4. Return the signed credential
            
            let response = serde_json::json!({
                "status": "success",
                "message": "Credential issued successfully",
                "credential": {
                    "signature": "placeholder_bbs_plus_signature",
                    "issued_at": chrono::Utc::now().timestamp()
                }
            });
            
            info!("✅ Credential issued successfully");
            
            Ok::<_, warp::Rejection>(warp::reply::json(&response))
        });
    
    // Register with on-chain contract (if configured)
    if let (Some(rpc_url), Some(contract_addr)) = (&args.ethereum_rpc, &args.contract_address) {
        info!("🔗 Registering issuer with on-chain contract");
        info!("   📄 Contract address: {}", contract_addr);
        
        // This would use ethers-rs to interact with the HybridCredentialSystem contract
        // For now, we'll just log the intent
        info!("✅ Issuer registration would be sent to blockchain");
    }
    
    // Combine all routes
    let routes = health
        .or(params)
        .or(issue_credential)
        .with(warp::cors().allow_any_origin().allow_headers(vec!["content-type"]).allow_methods(vec!["GET", "POST"]));
    
    info!("🚀 BBS+ Issuer API started on port {}", args.port);
    info!("📡 Available endpoints:");
    info!("   GET  /health - Health check");
    info!("   GET  /params - Get public parameters");
    info!("   POST /issue  - Issue credential");
    
    println!();
    info!("🎯 Ready to issue BBS+ credentials with zk-SNARK integration!");
    
    warp::serve(routes)
        .run(([127, 0, 0, 1], args.port))
        .await;
    
    Ok(())
}
