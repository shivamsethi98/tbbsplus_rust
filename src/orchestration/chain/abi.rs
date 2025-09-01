//! ABI loading helpers with optional compile-time embedding and caching.
use ethers::abi::Abi;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::sync::RwLock;

static ABI_CACHE: OnceCell<RwLock<HashMap<&'static str, Abi>>> = OnceCell::new();

pub fn load_abi_from_artifact(path: &str) -> anyhow::Result<Abi> {
    // Try cache first
    if let Some(cache) = ABI_CACHE.get() {
        if let Ok(map) = cache.read() {
            if let Some(a) = map.get(path) { return Ok(a.clone()); }
        }
    }
    // Fallback to reading from disk
    let v = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("read {}: {:?}", path, e))?;
    let j: serde_json::Value = serde_json::from_slice(&v)?;
    let abi_val = j.get("abi").cloned().ok_or_else(|| anyhow::anyhow!("abi missing in {}", path))?;
    let abi: Abi = serde_json::from_value(abi_val)?;
    let cell = ABI_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(mut m) = cell.write() { m.insert(Box::leak(path.to_string().into_boxed_str()), abi.clone()); }
    Ok(abi)
}

pub fn load_embedded_abi(name: &str) -> Option<Abi> {
    fn parse(bytes: &'static [u8]) -> Option<Abi> {
        let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        let abi_val = v.get("abi").cloned()?;
        serde_json::from_value::<Abi>(abi_val).ok()
    }
    match name {
        "Params" => parse(include_bytes!("../../../artifacts/contracts/Params.sol/Params.json")),
        "CredentialRegistry" => parse(include_bytes!("../../../artifacts/contracts/CredentialRegistry.sol/CredentialRegistry.json")),
        "VerifyWrapper" => parse(include_bytes!("../../../artifacts/contracts/Verify.sol/VerifyWrapper.json")),
        "Accumulator" => parse(include_bytes!("../../../artifacts/contracts/Accumulator.sol/Accumulator.json")),
        _ => None,
    }
}
