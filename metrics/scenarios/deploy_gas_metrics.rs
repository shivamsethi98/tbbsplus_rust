use std::fs::{File, read_dir};
use std::io::{BufRead, BufReader};

use ethereum_types::U256;

fn parse_u256_str(s: &str) -> Option<U256> { U256::from_dec_str(s).ok() }

fn parse_u256_any(v: &serde_json::Value) -> Option<U256> {
    match v {
        serde_json::Value::String(s) => parse_u256_str(s),
        serde_json::Value::Number(n) => n.as_u64().map(U256::from),
        _ => None,
    }
}

fn main() -> eyre::Result<()> {
    dotenvy::dotenv().ok();
    // contract -> (sum_gas, sum_cost, count)
    use std::collections::BTreeMap;
    let mut acc: BTreeMap<String, (U256, U256, u64)> = BTreeMap::new();

    // 1) Read NDJSON if present
    let ndjson_path = std::env::var("DEPLOY_METRICS_FILE").unwrap_or_else(|_| "metrics/results/deploy.ndjson".into());
    if let Ok(f) = File::open(&ndjson_path) {
        let rdr = BufReader::new(f);
        for line in rdr.lines().flatten() {
            if line.trim().is_empty() { continue; }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            let scenario = v.get("scenario").and_then(|x| x.as_str()).unwrap_or("");
            if !(scenario.starts_with("deploy_") || v.get("contract").is_some()) { continue; }
            let contract = v.get("contract").and_then(|x| x.as_str()).map(|s| s.to_string())
                .unwrap_or_else(|| scenario.strip_prefix("deploy_").unwrap_or("unknown").to_string());
            let gas_used = v.get("gasUsed").and_then(parse_u256_any).unwrap_or_else(U256::zero);
            let eff_price = v.get("effectiveGasPrice").and_then(parse_u256_any).unwrap_or_else(U256::zero);
            let cost_wei = v.get("costWei").and_then(parse_u256_any).unwrap_or_else(|| gas_used * eff_price);
            let e = acc.entry(contract).or_insert((U256::zero(), U256::zero(), 0));
            e.0 += gas_used; e.1 += cost_wei; e.2 += 1;
        }
    }

    // 2) Also read metrics/results/deploy_gas.*.json if any
    if let Ok(dir) = read_dir("metrics/results") {
        for ent in dir.flatten() {
            let p = ent.path();
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                if name.starts_with("deploy_gas.") && name.ends_with(".json") {
                    if let Ok(f) = File::open(&p) {
                        let v: serde_json::Value = match serde_json::from_reader(f) { Ok(v)=>v, Err(_)=> continue };
                        if let Some(obj) = v.get("contracts").and_then(|x| x.as_object()) {
                            for (contract, info) in obj.iter() {
                                let gas_used = info.get("gasUsed").and_then(|x| x.as_str()).and_then(parse_u256_str).unwrap_or_else(U256::zero);
                                let e = acc.entry(contract.clone()).or_insert((U256::zero(), U256::zero(), 0));
                                e.0 += gas_used; e.2 += 1; // no cost info in this format
                            }
                        }
                    }
                }
            }
        }
    }

    for (name, (sum_g, sum_c, n)) in acc.into_iter() {
        if n == 0 { continue; }
        let avg_g = sum_g / U256::from(n);
        // cost may be zero if only deploy_gas JSON present
        let avg_c = if sum_c.is_zero() { U256::zero() } else { sum_c / U256::from(n) };
        println!("deployment.gasUsed_avg.contract_{}={}", name, avg_g);
        if !avg_c.is_zero() { println!("deployment.costWei_avg.contract_{}={}", name, avg_c); }
    }

    Ok(())
}


