use std::sync::Arc;
use ethers::abi::Abi;
use ethers::contract::Contract;
use ethers::contract::builders::ContractCall;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::{Address, Bytes as EthBytes, Filter, H256, U256, ValueOrArray};

use crate::orchestration::chain::abi::{load_abi_from_artifact, load_embedded_abi};
use once_cell::sync::OnceCell;
use std::sync::RwLock;

pub struct RegistryClient<M> {
    contract: Contract<M>,
}

impl<M: Middleware + 'static> RegistryClient<M> {
    pub fn new(addr: Address, client: Arc<M>) -> anyhow::Result<Self> {
        let abi = load_embedded_abi("CredentialRegistry").or_else(|| load_abi_from_artifact("artifacts/contracts/CredentialRegistry.sol/CredentialRegistry.json").ok())
            .ok_or_else(|| anyhow::anyhow!("registry ABI not found"))?;
        Ok(Self { contract: Contract::new(addr, abi, client) })
    }
    pub fn address(&self) -> Address { self.contract.address() }
    pub async fn get_signature(&self, cred_name: String, sid: U256) -> anyhow::Result<(ethers::types::Bytes, U256, U256, u8)> {
        Ok(self.contract.method("getSignature", (cred_name, sid))?.call().await?)
    }
    pub fn aggregated_filter(&self, cred_name: &str, sid: u64) -> Filter {
        let event_sig = H256::from(ethers::utils::keccak256(b"Aggregated(string,uint256,bytes,uint256,uint256)"));
        let name_topic = H256::from(ethers::utils::keccak256(cred_name.as_bytes()));
        let mut sid_be = [0u8; 32]; U256::from(sid).to_big_endian(&mut sid_be); let sid_topic = H256::from(sid_be);
        Filter::new().address(ValueOrArray::Value(self.contract.address())).topic0(ValueOrArray::Value(event_sig)).topic1(ValueOrArray::Value(name_topic)).topic2(ValueOrArray::Value(sid_topic)).from_block(ethers::types::BlockNumber::Latest)
    }

    // Build a submitShare call so callers can tweak gas and send.
    pub fn submit_share_call(
        &self,
        cred_name: String,
        sid: U256,
        participant_id: u16,
        r_bytes128: EthBytes,
        u_u256: U256,
        e_u256: U256,
        s_u256: U256,
        t: u16,
    ) -> anyhow::Result<ContractCall<M, ()>> {
        Ok(self.contract.method(
            "submitShare",
            (cred_name, sid, participant_id, r_bytes128, u_u256, e_u256, s_u256, t),
        )?)
    }

    /// Build a `submitShareBatch` call for N users in one tx.
    /// `r_concat` is the concatenation of N × 128-byte R points.
    pub fn submit_share_batch_call(
        &self,
        cred_name: String,
        user_ids: Vec<U256>,
        participant_id: u16,
        r_concat: EthBytes,
        us: Vec<U256>,
        es: Vec<U256>,
        ss: Vec<U256>,
    ) -> anyhow::Result<ContractCall<M, ()>> {
        Ok(self.contract.method(
            "submitShareBatch",
            (cred_name, user_ids, participant_id, r_concat, us, es, ss),
        )?)
    }

    /// Build a `confirmBatchRandomized` call — batch pairing verification (Eq 27).
    /// Permissionless: can be called by any issuer once all users have Unverified status.
    pub fn confirm_batch_randomized_call(
        &self,
        cred_name: String,
        user_ids: Vec<U256>,
    ) -> anyhow::Result<ContractCall<M, ()>> {
        Ok(self.contract.method(
            "confirmBatchRandomized",
            (cred_name, user_ids),
        )?)
    }
}

pub struct VerifyClient<M> { pub contract: Contract<M> }
impl<M: Middleware + 'static> VerifyClient<M> {
    pub fn new(addr: Address, client: Arc<M>) -> anyhow::Result<Self> {
        let abi = load_embedded_abi("VerifyWrapper").or_else(|| load_abi_from_artifact("artifacts/contracts/Verify.sol/VerifyWrapper.json").ok())
            .ok_or_else(|| anyhow::anyhow!("verify ABI not found"))?;
        Ok(Self { contract: Contract::new(addr, abi, client) })
    }
}

pub struct AccumulatorClient<M> { pub contract: Contract<M> }
impl<M: Middleware + 'static> AccumulatorClient<M> {
    pub fn new(addr: Address, client: Arc<M>) -> anyhow::Result<Self> {
        let abi = load_embedded_abi("Accumulator").or_else(|| load_abi_from_artifact("artifacts/contracts/Accumulator.sol/Accumulator.json").ok())
            .ok_or_else(|| anyhow::anyhow!("accumulator ABI not found"))?;
        Ok(Self { contract: Contract::new(addr, abi, client) })
    }
}

// Thin ParamsClient with small, thread-safe caches for common getters
pub struct ParamsClient<M> {
    pub contract: Contract<M>,
    threshold_cache: OnceCell<RwLock<std::collections::HashMap<String, u16>>>,
    h_cache: OnceCell<RwLock<std::collections::HashMap<String, Vec<EthBytes>>>>,
    g1h0g2_cache: OnceCell<RwLock<std::collections::HashMap<String, (EthBytes, EthBytes, EthBytes)>>>,
    mcount_cache: OnceCell<RwLock<std::collections::HashMap<String, u32>>>,
}

impl<M: Middleware + 'static> ParamsClient<M> {
    pub fn new(addr: Address, client: Arc<M>) -> anyhow::Result<Self> {
        let abi = load_embedded_abi("Params").or_else(|| load_abi_from_artifact("artifacts/contracts/Params.sol/Params.json").ok())
            .ok_or_else(|| anyhow::anyhow!("params ABI not found"))?;
        Ok(Self {
            contract: Contract::new(addr, abi, client),
            threshold_cache: OnceCell::new(),
            h_cache: OnceCell::new(),
            g1h0g2_cache: OnceCell::new(),
            mcount_cache: OnceCell::new(),
        })
    }

    pub fn address(&self) -> Address { self.contract.address() }

    pub async fn get_threshold_cached(&self, cred_name: String) -> anyhow::Result<u16> {
        // try cache
        if let Some(lock) = self.threshold_cache.get() {
            if let Ok(map) = lock.read() {
                if let Some(v) = map.get(&cred_name) { return Ok(*v); }
            }
        }
        // fetch and cache from getParamsByName (CredParams tuple)
        let pc: (
            U256, U256, U256, Vec<U256>, U256, EthBytes, EthBytes, EthBytes, EthBytes, Vec<EthBytes>, EthBytes, EthBytes, U256, U256
        ) = self.contract.method("getParamsByName", cred_name.clone())?.call().await?;
        let t = pc.1.as_u64() as u16;
        let lock = self.threshold_cache.get_or_init(|| RwLock::new(std::collections::HashMap::new()));
        if let Ok(mut map) = lock.write() { map.insert(cred_name, t); }
        Ok(t)
    }

    pub async fn get_h_cached(&self, cred_name: String) -> anyhow::Result<Vec<EthBytes>> {
        if let Some(lock) = self.h_cache.get() {
            if let Ok(map) = lock.read() {
                if let Some(v) = map.get(&cred_name) { return Ok(v.clone()); }
            }
        }
        let hs: Vec<EthBytes> = self.contract.method("getHByName", cred_name.clone())?.call().await?;
        let lock = self.h_cache.get_or_init(|| RwLock::new(std::collections::HashMap::new()));
        if let Ok(mut map) = lock.write() { map.insert(cred_name, hs.clone()); }
        Ok(hs)
    }

    pub async fn get_message_count_cached(&self, cred_name: String) -> anyhow::Result<u32> {
        if let Some(lock) = self.mcount_cache.get() {
            if let Ok(map) = lock.read() {
                if let Some(v) = map.get(&cred_name) { return Ok(*v); }
            }
        }
        let pc: (
            U256, U256, U256, Vec<U256>, U256, EthBytes, EthBytes, EthBytes, EthBytes, Vec<EthBytes>, EthBytes, EthBytes, U256, U256
        ) = self.contract.method("getParamsByName", cred_name.clone())?.call().await?;
        let m = pc.0.as_u64() as u32;
        let lock = self.mcount_cache.get_or_init(|| RwLock::new(std::collections::HashMap::new()));
        if let Ok(mut map) = lock.write() { map.insert(cred_name, m); }
        Ok(m)
    }

    pub async fn get_g1h0g2_cached(&self, cred_name: String) -> anyhow::Result<(EthBytes, EthBytes, EthBytes)> {
        if let Some(lock) = self.g1h0g2_cache.get() {
            if let Ok(map) = lock.read() {
                if let Some(v) = map.get(&cred_name) { return Ok(v.clone()); }
            }
        }
        let triple: (EthBytes, EthBytes, EthBytes) = self.contract.method("getG1H0G2ByName", cred_name.clone())?.call().await?;
        let lock = self.g1h0g2_cache.get_or_init(|| RwLock::new(std::collections::HashMap::new()));
        if let Ok(mut map) = lock.write() { map.insert(cred_name, triple.clone()); }
        Ok(triple)
    }

    pub async fn get_issuers(&self) -> anyhow::Result<Vec<Address>> {
        Ok(self.contract.method::<_, Vec<Address>>("getIssuers", ())?.call().await?)
    }

    pub async fn issuer_allowed(&self, issuer: Address) -> anyhow::Result<bool> {
        Ok(self.contract.method::<_, bool>("issuerAllowed", issuer)?.call().await?)
    }

    pub async fn issuer_index(&self, issuer: Address) -> anyhow::Result<u16> {
        let idx: U256 = self.contract.method("issuerIndex", issuer)?.call().await?;
        Ok(idx.as_u64() as u16)
    }

    pub async fn get_batch_sizes(&self, cred_name: String) -> anyhow::Result<(u32, u32)> {
        let result: (U256, U256) = self.contract
            .method("getBatchSizesByName", cred_name)?
            .call().await?;
        Ok((result.0.as_u32(), result.1.as_u32()))
    }

    pub async fn get_issuer_multiaddrs(&self, issuer: Address) -> anyhow::Result<Vec<String>> {
        Ok(self.contract.method::<_, Vec<String>>("getIssuerMultiaddrs", issuer)?.call().await?)
    }

    /// Invalidate all cached entries (useful after resetting on-chain params or redeploys
    /// without restarting the process).
    pub fn invalidate_all(&self) {
        if let Some(lock) = self.threshold_cache.get() { if let Ok(mut m) = lock.write() { m.clear(); } }
        if let Some(lock) = self.h_cache.get() { if let Ok(mut m) = lock.write() { m.clear(); } }
        if let Some(lock) = self.g1h0g2_cache.get() { if let Ok(mut m) = lock.write() { m.clear(); } }
        if let Some(lock) = self.mcount_cache.get() { if let Ok(mut m) = lock.write() { m.clear(); } }
    }

    /// Invalidate cached entries for a specific credential name.
    pub fn invalidate_cred(&self, cred_name: &str) {
        if let Some(lock) = self.threshold_cache.get() { if let Ok(mut m) = lock.write() { m.remove(cred_name); } }
        if let Some(lock) = self.h_cache.get() { if let Ok(mut m) = lock.write() { m.remove(cred_name); } }
        if let Some(lock) = self.g1h0g2_cache.get() { if let Ok(mut m) = lock.write() { m.remove(cred_name); } }
        if let Some(lock) = self.mcount_cache.get() { if let Ok(mut m) = lock.write() { m.remove(cred_name); } }
    }
}

pub struct BatchVerifyClient<M> { pub contract: Contract<M> }
impl<M: Middleware + 'static> BatchVerifyClient<M> {
    pub fn new(addr: Address, client: Arc<M>) -> anyhow::Result<Self> {
        let abi = load_embedded_abi("BatchVerifyWrapper")
            .or_else(|| load_abi_from_artifact("artifacts/contracts/BatchVerify.sol/BatchVerifyWrapper.json").ok())
            .ok_or_else(|| anyhow::anyhow!("BatchVerifyWrapper ABI not found"))?;
        Ok(Self { contract: Contract::new(addr, abi, client) })
    }
}
