use std::fs::File;
use std::io::{BufRead, BufReader};

use ethereum_types::U256;

fn parse_u256(s: &str) -> Option<U256> { U256::from_dec_str(s).ok() }

fn main() -> eyre::Result<()> {
    dotenvy::dotenv().ok();
    let sp_path = std::env::var("SP_METRICS_FILE").unwrap_or_else(|_| "metrics/results/service_provider.ndjson".into());
    let agg_path = std::env::var("AGG_METRICS_FILE").unwrap_or_else(|_| "metrics/results/aggregator.ndjson".into());

    let mut sp_open_ms: std::collections::BTreeMap<u16, Vec<u64>> = Default::default();
    let mut sp_rev_ms: std::collections::BTreeMap<u16, Vec<u64>> = Default::default();
    let mut open_gas: std::collections::BTreeMap<u16, Vec<U256>> = Default::default();
    let mut revoke_gas: std::collections::BTreeMap<u16, Vec<U256>> = Default::default();

    // Read SP
    let f = File::open(sp_path)?; let rdr = BufReader::new(f);
    for line in rdr.lines().flatten() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            let t = v.get("threshold").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
            match v.get("scenario").and_then(|x| x.as_str()) {
                Some("sp_open_e2e") => { if let Some(ms) = v.get("ms").and_then(|x| x.as_u64()) { sp_open_ms.entry(t).or_default().push(ms); } }
                Some("sp_revoke_e2e") => { if let Some(ms) = v.get("ms").and_then(|x| x.as_u64()) { sp_rev_ms.entry(t).or_default().push(ms); } }
                Some("sp_requestOpen") => {
                    if let Some(gu) = v.get("gasUsed").and_then(|x| x.as_str()).and_then(parse_u256) {
                        open_gas.entry(t).or_default().push(gu);
                    }
                }
                Some("sp_requestRevokeByE") => {
                    if let Some(gu) = v.get("gasUsed").and_then(|x| x.as_str()).and_then(parse_u256) {
                        revoke_gas.entry(t).or_default().push(gu);
                    }
                }
                _ => {}
            }
        }
    }

    // Read Aggregator
    let f = File::open(agg_path)?; let rdr = BufReader::new(f);
    for line in rdr.lines().flatten() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            let t = v.get("threshold").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
            match v.get("scenario").and_then(|x| x.as_str()) {
                Some("agg_publishOpenResult") => {
                    if let Some(gu) = v.get("gasUsed").and_then(|x| x.as_str()).and_then(parse_u256) {
                        open_gas.entry(t).or_default().push(gu);
                    }
                }
                Some("agg_deleteMember") => {
                    if let Some(gu) = v.get("gasUsed").and_then(|x| x.as_str()).and_then(parse_u256) {
                        revoke_gas.entry(t).or_default().push(gu);
                    }
                }
                _ => {}
            }
        }
    }

    // Averages
    for (t, vecms) in sp_open_ms.iter() { if !vecms.is_empty() {
        let avg = vecms.iter().copied().map(|x| x as f64).sum::<f64>() / (vecms.len() as f64);
        println!("opening.e2e.ms_avg.threshold_{}={}", t, avg);
    }}
    for (t, vecms) in sp_rev_ms.iter() { if !vecms.is_empty() {
        let avg = vecms.iter().copied().map(|x| x as f64).sum::<f64>() / (vecms.len() as f64);
        println!("revocation.e2e.ms_avg.threshold_{}={}", t, avg);
    }}
    for (t, vecg) in open_gas.iter() { if !vecg.is_empty() {
        let sum = vecg.iter().fold(U256::zero(), |acc, x| acc + *x);
        let avg = sum / U256::from(vecg.len());
        println!("opening.gasUsed_avg.threshold_{}={}", t, avg);
    }}
    for (t, vecg) in revoke_gas.iter() { if !vecg.is_empty() {
        let sum = vecg.iter().fold(U256::zero(), |acc, x| acc + *x);
        let avg = sum / U256::from(vecg.len());
        println!("revocation.gasUsed_avg.threshold_{}={}", t, avg);
    }}

    Ok(())
}


