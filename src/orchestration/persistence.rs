//! Filesystem persistence utilities.
use ethers::types::{TxHash, U256};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use std::path::PathBuf;

fn cred_dir(user_id: &str, cred_name: &str) -> PathBuf {
    [".runtime", "users", user_id, cred_name].iter().collect()
}

pub fn persist_share(user_id: &str, cred_name: &str, idx: u16, payload: &[u8]) -> anyhow::Result<()> {
    use std::fs;
    let dir = cred_dir(user_id, cred_name).join("shares");
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(format!("{}.bin", idx)), payload)?;
    Ok(())
}

pub fn load_persisted_shares(user_id: &str, cred_name: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    use std::fs;
    let dir = cred_dir(user_id, cred_name).join("shares");
    if !dir.exists() { return Ok(Vec::new()); }
    let mut out = Vec::new();
    for e in fs::read_dir(dir)? { let p = e?.path(); if p.is_file() { out.push(fs::read(p)?); } }
    Ok(out)
}

pub fn persist_request_meta(user_id: &str, cred_name: &str, tx_hash: TxHash, block_number: u64) -> anyhow::Result<()> {
    use std::fs;
    let dir = cred_dir(user_id, cred_name);
    fs::create_dir_all(&dir)?;
    let meta = serde_json::json!({ "tx": format!("0x{:x}", tx_hash), "block": block_number });
    let tmp = dir.join("request_meta.json.tmp");
    let dst = dir.join("request_meta.json");
    fs::write(&tmp, serde_json::to_vec_pretty(&meta)?)?;
    fs::rename(tmp, dst)?;
    Ok(())
}

pub fn persist_revealed_pairs(user_id: &str, cred_name: &str, revealed_idx: &[u32], revealed_vals: &[U256]) -> anyhow::Result<()> {
    use std::fs;
    let dir = cred_dir(user_id, cred_name);
    fs::create_dir_all(&dir)?;
    let tmp = dir.join("revealed.json.tmp");
    let dst = dir.join("revealed.json");
    let vals_hex: Vec<String> = revealed_vals.iter().map(|v| {
        let mut be = [0u8; 32];
        v.to_big_endian(&mut be);
        format!("0x{}", hex::encode(be))
    }).collect();
    let obj = serde_json::json!({ "idx": revealed_idx, "vals": vals_hex });
    fs::write(&tmp, serde_json::to_vec_pretty(&obj)?)?;
    fs::rename(tmp, dst)?;
    Ok(())
}

pub fn load_revealed_pairs(user_id: &str, cred_name: &str) -> anyhow::Result<Option<Vec<(u32, Fr)>>> {
    let path = cred_dir(user_id, cred_name).join("revealed.json");
    if !path.exists() { return Ok(None); }
    let bytes = std::fs::read(path)?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)?;
    let mut out = Vec::new();
    if let (Some(idx_arr), Some(vals_arr)) = (v.get("idx").and_then(|x| x.as_array()), v.get("vals").and_then(|x| x.as_array())) {
        if idx_arr.len() != vals_arr.len() { anyhow::bail!("revealed.idx and vals length mismatch"); }
        for (i_v, s_v) in idx_arr.iter().zip(vals_arr.iter()) {
            let i_u32 = i_v.as_u64().ok_or_else(|| anyhow::anyhow!("idx not u64"))? as u32;
            let s = s_v.as_str().ok_or_else(|| anyhow::anyhow!("val not string"))?;
            let b = hex::decode(s.trim_start_matches("0x"))?;
            let mut be = [0u8; 32]; if b.len() > 32 { anyhow::bail!("revealed value too long: {}", b.len()); }
            be[(32 - b.len())..].copy_from_slice(&b);
            out.push((i_u32, Fr::from_be_bytes_mod_order(&be)));
        }
        return Ok(Some(out));
    }
    if let Some(arr) = v.as_array() {
        for pair in arr {
            let i = pair.get(0).and_then(|x| x.as_u64()).ok_or_else(|| anyhow::anyhow!("pair[0] missing"))? as u32;
            let s = pair.get(1).and_then(|x| x.as_str()).ok_or_else(|| anyhow::anyhow!("pair[1] missing"))?;
            let b = hex::decode(s.trim_start_matches("0x"))?;
            let mut be = [0u8; 32]; if b.len() > 32 { anyhow::bail!("revealed value too long: {}", b.len()); }
            be[(32 - b.len())..].copy_from_slice(&b);
            out.push((i, Fr::from_be_bytes_mod_order(&be)));
        }
        return Ok(Some(out));
    }
    Ok(None)
}

// ---- New typed serde models and a small store facade ----

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MessagesFile(pub Vec<String>);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SignatureFile {
    #[serde(rename = "A")]
    pub a: String,
    pub e: String,
    pub s: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RevealedFile {
    pub idx: Vec<u32>,
    pub vals: Vec<String>,
}

pub struct CredentialsStore<'a> {
    pub user_id: &'a str,
    pub cred_name: &'a str,
}

impl<'a> CredentialsStore<'a> {
    pub fn new(user_id: &'a str, cred_name: &'a str) -> Self { Self { user_id, cred_name } }
    pub fn base(&self) -> PathBuf { cred_dir(self.user_id, self.cred_name) }

    pub fn save_messages(&self, msgs: &MessagesFile) -> anyhow::Result<()> {
        use std::fs; fs::create_dir_all(self.base())?;
        let tmp = self.base().join("messages.json.tmp");
        let dst = self.base().join("messages.json");
        fs::write(&tmp, serde_json::to_vec_pretty(msgs)?)?; fs::rename(tmp, dst)?; Ok(())
    }
    pub fn save_signature(&self, sig: &SignatureFile) -> anyhow::Result<()> {
        use std::fs; fs::create_dir_all(self.base())?;
        let tmp = self.base().join("agg_signature.json.tmp");
        let dst = self.base().join("agg_signature.json");
        fs::write(&tmp, serde_json::to_vec_pretty(sig)?)?; fs::rename(tmp, dst)?; Ok(())
    }
    pub fn save_revealed(&self, r: &RevealedFile) -> anyhow::Result<()> {
        use std::fs; fs::create_dir_all(self.base())?;
        let tmp = self.base().join("revealed.json.tmp");
        let dst = self.base().join("revealed.json");
        fs::write(&tmp, serde_json::to_vec_pretty(r)?)?; fs::rename(tmp, dst)?; Ok(())
    }
    pub fn load_revealed(&self) -> anyhow::Result<Option<RevealedFile>> {
        let p = self.base().join("revealed.json"); if !p.exists() { return Ok(None); }
        let b = std::fs::read(p)?; Ok(Some(serde_json::from_slice(&b)?))
    }
    pub fn load_messages(&self) -> anyhow::Result<Option<MessagesFile>> {
        let p = self.base().join("messages.json"); if !p.exists() { return Ok(None); }
        let b = std::fs::read(p)?; Ok(Some(serde_json::from_slice(&b)?))
    }
    pub fn load_signature(&self) -> anyhow::Result<Option<SignatureFile>> {
        let p = self.base().join("agg_signature.json"); if !p.exists() { return Ok(None); }
        let b = std::fs::read(p)?; Ok(Some(serde_json::from_slice(&b)?))
    }
}
