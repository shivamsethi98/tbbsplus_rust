use std::fs::File;
use std::io::{BufRead, BufReader};
use serde::Deserialize;

fn main() -> eyre::Result<()> {
    dotenvy::dotenv().ok();
    let path = std::env::var("AGG_METRICS_FILE").unwrap_or_else(|_| "metrics/results/aggregator.ndjson".into());
    let f = File::open(&path)?;
    let rdr = BufReader::new(f);

    let mut ms: Vec<(u16, u64)> = Vec::new();
    let mut gas_by_t: std::collections::BTreeMap<u16, Vec<ethereum_types::U256>> = Default::default();

    for line in rdr.lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        let val: serde_json::Value = serde_json::from_str(&line)?;
        let scenario = val.get("scenario").and_then(|v| v.as_str()).unwrap_or("");
        if scenario == "acc_register_info_e2e" {
            let t = val.get("threshold").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let m = val.get("ms").and_then(|v| v.as_u64()).unwrap_or(0);
            ms.push((t, m));
            let gu = val.get("gasUsedTotal").and_then(|v| v.as_str()).and_then(|s| ethereum_types::U256::from_dec_str(s).ok()).unwrap_or_default();
            gas_by_t.entry(t).or_default().push(gu);
        }
    }

    let mut e2e_avg_by_t: std::collections::BTreeMap<u16, f64> = Default::default();
    {
        let mut groups: std::collections::BTreeMap<u16, Vec<u64>> = Default::default();
        for (t, m) in ms { groups.entry(t).or_default().push(m); }
        for (t, vecms) in groups.into_iter() {
            if vecms.is_empty() { continue; }
            let avg = vecms.iter().copied().map(|x| x as f64).sum::<f64>() / (vecms.len() as f64);
            e2e_avg_by_t.insert(t, avg);
        }
    }

    for (t, avg) in e2e_avg_by_t.iter() {
        println!("acc_register_info_e2e.ms_avg.threshold_{}={}", t, avg);
    }
    for (t, vecg) in gas_by_t.iter() {
        if vecg.is_empty() { continue; }
        let sum = vecg.iter().fold(ethereum_types::U256::zero(), |acc, x| acc + *x);
        let avg = sum / ethereum_types::U256::from(vecg.len());
        println!("acc_register_info.gasUsed_avg.threshold_{}={}", t, avg);
    }

    Ok(())
}


