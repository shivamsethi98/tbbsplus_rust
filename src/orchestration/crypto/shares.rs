use std::collections::BTreeMap;
use std::fs;
use ark_bls12_381::Fr;
use ark_serialize::CanonicalDeserialize;
use serde::Deserialize;
use base64::Engine as _;

#[derive(Deserialize)]
struct SharesFile {
    shares: BTreeMap<String, String>,
}

/// Load this participant's secret share from a TTP-generated JSON file.
/// The file shape is { "shares": { "1": base64, "2": base64, ... } }
pub fn load_share_from_file(path: &str, participant_id: u16) -> anyhow::Result<Fr> {
    let data = fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read shares file {}: {:?}", path, e))?;
    let parsed: SharesFile = serde_json::from_slice(&data)
        .map_err(|e| anyhow::anyhow!("failed to parse shares file {}: {:?}", path, e))?;
    let key = participant_id.to_string();
    let b64 = parsed
        .shares
        .get(&key)
        .ok_or_else(|| anyhow::anyhow!("no share for PID {} in {}", participant_id, path))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow::anyhow!("bad base64 in shares file {}: {:?}", path, e))?;
    let mut rdr = &bytes[..];
    let share: Fr = CanonicalDeserialize::deserialize_compressed(&mut rdr)
        .map_err(|e| anyhow::anyhow!("failed to deserialize Fr from shares file: {:?}", e))?;
    Ok(share)
}
