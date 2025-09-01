use std::fs::File;
use std::io::{BufRead, BufReader};
use serde::Deserialize;

#[derive(Deserialize)]
struct Row {
    scenario: String,
    sid: Option<u64>,
    ms: Option<u64>,
    gasUsed: Option<String>,
    effectiveGasPrice: Option<String>,
    costWei: Option<String>,
}

fn parse_u256(s: &str) -> Option<ethereum_types::U256> {
    use ethereum_types::U256;
    if s.is_empty() { return None; }
    if let Ok(v) = U256::from_dec_str(s) { return Some(v); }
    None
}

fn main() -> eyre::Result<()> {
    dotenvy::dotenv().ok();
    let path = std::env::var("METRICS_FILE").unwrap_or_else(|_| "metrics/results/client.ndjson".into());
    let f = File::open(&path)?;
    let rdr = BufReader::new(f);

    let mut off_ms: Vec<u64> = Vec::new();
    let mut pres_e2e_ms: Vec<u64> = Vec::new();
    let mut on_gas: Vec<(ethereum_types::U256, ethereum_types::U256)> = Vec::new();

    for line in rdr.lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        let val: serde_json::Value = serde_json::from_str(&line)?;
        let scenario = val.get("scenario").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if scenario == "off-chain_verify_time" {
            if let Some(ms) = val.get("ms").and_then(|v| v.as_u64()) { off_ms.push(ms); }
        } else if scenario == "presentation_e2e" {
            if let Some(ms) = val.get("ms").and_then(|v| v.as_u64()) { pres_e2e_ms.push(ms); }
        } else if scenario == "on_chain_verify_time" {
            let gu = val.get("gasUsed").and_then(|v| v.as_str()).and_then(parse_u256).unwrap_or_default();
            let gp = val.get("effectiveGasPrice").and_then(|v| v.as_str()).and_then(parse_u256).unwrap_or_default();
            on_gas.push((gu, gp));
        }
    }

    fn avg(v: &[u64]) -> Option<f64> { if v.is_empty() { None } else { Some(v.iter().copied().map(|x| x as f64).sum::<f64>() / (v.len() as f64)) } }

    let off_avg = avg(&off_ms);
    let e2e_avg = avg(&pres_e2e_ms);
    let mut gas_sum = ethereum_types::U256::zero();
    let mut cost_sum = ethereum_types::U256::zero();
    let mut n = 0u64;
    for (gu, gp) in on_gas { gas_sum += gu; cost_sum += gu * gp; n += 1; }
    let gas_avg = if n>0 { gas_sum / ethereum_types::U256::from(n) } else { ethereum_types::U256::zero() };
    let cost_avg = if n>0 { cost_sum / ethereum_types::U256::from(n) } else { ethereum_types::U256::zero() };

    println!("presentation.off_chain_verify_time.ms_avg={:?}", off_avg);
    println!("presentation.presentation_e2e.ms_avg={:?}", e2e_avg);
    println!("presentation.on_chain_verify.gasUsed_avg={}", gas_avg);
    println!("presentation.on_chain_verify.costWei_avg={}", cost_avg);

    Ok(())
}