//! Config loader for orchestration binaries. Phase 0 stub.
use ethers::types::Address;

#[derive(Debug, Clone)]
pub struct Config {
    pub eth_ws: String,
    pub chain_id: u64,
    pub params_contract: Address,
    pub req_contract: Address,
    pub registry_contract: Option<Address>,
    pub acc_contract: Option<Address>,
    pub cred_name: String,
    pub message_count: Option<u32>,
    pub threshold: Option<u16>,
    pub total: Option<u16>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        let eth_ws = std::env::var("ETH_WS").unwrap_or_else(|_| "ws://127.0.0.1:8545".into());
        let chain_id = std::env::var("CHAIN_ID").unwrap_or_else(|_| "31337".into()).parse()?;
        let params_contract = std::env::var("PARAMS_CONTRACT").ok().and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("PARAMS_CONTRACT missing"))?;
        let req_contract = std::env::var("REQ_CONTRACT").ok().and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("REQ_CONTRACT missing"))?;
        let registry_contract = std::env::var("REGISTRY_CONTRACT").ok().and_then(|s| s.parse().ok());
        let acc_contract = std::env::var("ACC_CONTRACT").ok().and_then(|s| s.parse().ok());
        let cred_name = std::env::var("CRED_NAME").unwrap_or_else(|_| "ANON_CRED".into());
        let message_count = std::env::var("MESSAGE_COUNT").ok().and_then(|s| s.parse().ok());
        let threshold = std::env::var("THRESHOLD").ok().and_then(|s| s.parse().ok());
        let total = std::env::var("TOTAL").ok().and_then(|s| s.parse().ok());
        Ok(Self { eth_ws, chain_id, params_contract, req_contract, registry_contract, acc_contract, cred_name, message_count, threshold, total })
    }
}
