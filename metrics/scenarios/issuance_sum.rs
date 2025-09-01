use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::{BTreeMap, BTreeSet};
use serde_json::Value;

// Summarize issuance metrics:
// - Average issuance gasUsed per session: (requestCredential.gasUsed + sum(submitShare.gasUsed)) averaged over selected sids
// - Average issuance E2E time (Confirmed) over selected sids
// Usage:
//   cargo run -q --bin issuance_metrics -- --issuer metrics/results/issuer_*.ndjson ... --client metrics/results/client.ndjson [--sid <n> ...]

fn parse_u256_str(s: &str) -> ethereum_types::U256 {
    if s.starts_with("0x") { ethereum_types::U256::from_str_radix(&s[2..], 16).unwrap_or_default() }
    else { ethereum_types::U256::from_dec_str(s).unwrap_or_default() }
}

fn parse_gas_used(v: &Value) -> Option<u128> {
    if let Some(g) = v.get("gasUsed").and_then(|x| x.as_str()) {
        if let Ok(val) = g.parse::<u128>() { return Some(val); }
    }
    None
}

fn collect_submit_share_gas(paths: &[String]) -> BTreeMap<u64, u128> {
    let mut per_sid: BTreeMap<u64, u128> = BTreeMap::new();
    for p in paths {
        let f = match File::open(p) { Ok(f) => f, Err(_) => continue };
        let rdr = BufReader::new(f);
        for line in rdr.lines().flatten() {
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if v.get("scenario").and_then(|x| x.as_str()) == Some("submitShare") {
                    if let Some(sid) = v.get("sid").and_then(|x| x.as_u64()) {
                        if let Some(gu) = parse_gas_used(&v) {
                            let entry = per_sid.entry(sid).or_insert(0);
                            *entry += gu;
                        }
                    }
                }
            }
        }
    }
    per_sid
}

fn collect_request_gas(client_path: &str) -> BTreeMap<u64, u128> {
    let mut per_sid: BTreeMap<u64, u128> = BTreeMap::new();
    let f = match File::open(client_path) { Ok(f) => f, Err(_) => return per_sid };
    let rdr = BufReader::new(f);
    for line in rdr.lines().flatten() {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            if v.get("scenario").and_then(|x| x.as_str()) == Some("requestCredential") {
                if let Some(sid) = v.get("sid").and_then(|x| x.as_u64()) {
                    if let Some(gu) = parse_gas_used(&v) {
                        per_sid.insert(sid, gu); // keep last seen per sid
                    }
                }
            }
        }
    }
    per_sid
}

fn collect_e2e_confirmed_ms(client_path: &str) -> BTreeMap<u64, u64> {
    let mut per_sid: BTreeMap<u64, u64> = BTreeMap::new();
    let f = match File::open(client_path) { Ok(f) => f, Err(_) => return per_sid };
    let rdr = BufReader::new(f);
    for line in rdr.lines().flatten() {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            if v.get("scenario").and_then(|x| x.as_str()) == Some("issuance_e2e_confirmed") {
                if let (Some(sid), Some(ms)) = (v.get("sid").and_then(|x| x.as_u64()), v.get("ms").and_then(|x| x.as_u64())) {
                    per_sid.insert(sid, ms); // keep last seen per sid
                }
            }
        }
    }
    per_sid
}

fn main() {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() { eprintln!("usage: issuance_metrics --issuer path ... [--issuer path ...] --client path [--sid n ...]"); std::process::exit(1); }
    let mut issuer_paths: Vec<String> = Vec::new();
    let mut client_path: Option<String> = None;
    let mut sid_filters: BTreeSet<u64> = BTreeSet::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--issuer" { i+=1; while i<args.len() && !args[i].starts_with("--") { issuer_paths.push(args[i].clone()); i+=1; } }
        else if args[i] == "--client" { i+=1; if i<args.len() { client_path = Some(args[i].clone()); i+=1; } }
        else if args[i] == "--sid" { i+=1; if i<args.len() { if let Ok(s) = args[i].parse::<u64>() { sid_filters.insert(s); } i+=1; } }
        else { i+=1; }
    }

    // Collect per-sid gas and times
    let issuer_gas = collect_submit_share_gas(&issuer_paths);
    let (request_gas, e2e_times) = if let Some(cp) = client_path.as_deref() {
        (collect_request_gas(cp), collect_e2e_confirmed_ms(cp))
    } else { (BTreeMap::new(), BTreeMap::new()) };

    // Determine sid set for gas averages (union of request and issuer sids, optionally filtered)
    let mut gas_sids: BTreeSet<u64> = issuer_gas.keys().copied().collect();
    gas_sids.extend(request_gas.keys().copied());
    if !sid_filters.is_empty() { gas_sids = gas_sids.intersection(&sid_filters).copied().collect(); }

    // Compute average issuance gasUsed per session (request + issuers)
    let mut total_gas: u128 = 0;
    let mut count_sessions: u64 = 0;
    for sid in gas_sids.iter() {
        let req = request_gas.get(sid).cloned().unwrap_or(0);
        let iss = issuer_gas.get(sid).cloned().unwrap_or(0);
        total_gas += req + iss;
        count_sessions += 1;
    }
    let avg_gas_used: u128 = if count_sessions > 0 { total_gas / (count_sessions as u128) } else { 0 };

    // Compute average E2E confirmed ms
    let mut e2e_total_ms: u128 = 0;
    let mut e2e_count: u64 = 0;
    for (sid, ms) in e2e_times.iter() {
        if sid_filters.is_empty() || sid_filters.contains(sid) {
            e2e_total_ms += *ms as u128;
            e2e_count += 1;
        }
    }
    let avg_e2e_ms: u64 = if e2e_count > 0 { (e2e_total_ms / (e2e_count as u128)) as u64 } else { 0 };

    println!(
        "{{\"issuanceSessionsCount\":{},\"avgIssuanceGasUsed\":{},\"avgE2EConfirmedMs\":{}}}",
        count_sessions,
        avg_gas_used,
        avg_e2e_ms
    );
}


