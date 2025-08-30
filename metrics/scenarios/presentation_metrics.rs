use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::env;

fn parse_gas(s: &str) -> Option<u128> { s.parse::<u128>().ok() }

fn collect(client_path: &str) -> (BTreeMap<u64,u128>, BTreeMap<u64,u64>, BTreeMap<u64,u64>, BTreeMap<u64,u64>) {
    let mut gas: BTreeMap<u64,u128> = BTreeMap::new();
    let mut e2e_on: BTreeMap<u64,u64> = BTreeMap::new();
    let mut e2e_off: BTreeMap<u64,u64> = BTreeMap::new();
    let mut build: BTreeMap<u64,u64> = BTreeMap::new();
    let f = match File::open(client_path) { Ok(f)=>f, Err(_)=> return (gas,e2e_on,e2e_off,build) };
    let rdr = BufReader::new(f);
    for line in rdr.lines().flatten() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            match v.get("scenario").and_then(|x| x.as_str()) {
                // on-chain tx time
                Some("verifProveTime") | Some("on_chain_verify_time") => {
                    if let (Some(sid), Some(gu)) = (v.get("sid").and_then(|x| x.as_u64()), v.get("gasUsed").and_then(|x| x.as_str()).and_then(parse_gas)) {
                        gas.insert(sid, gu);
                    }
                }
                // on-chain e2e (construction -> tx mined)
                Some("presentation_e2e") => {
                    if let (Some(sid), Some(ms)) = (v.get("sid").and_then(|x| x.as_u64()), v.get("ms").and_then(|x| x.as_u64())) {
                        e2e_on.insert(sid, ms);
                    }
                }
                // off-chain combined verify (BBS+ + membership)
                Some("presentation_offchain_e2e") | Some("off-chain_prove_time") | Some("off-chain_verify_time") => {
                    if let (Some(sid), Some(ms)) = (v.get("sid").and_then(|x| x.as_u64()), v.get("ms").and_then(|x| x.as_u64())) {
                        e2e_off.insert(sid, ms);
                    }
                }
                // proof construction time (off-chain)
                Some("proveCred") | Some("off_chain_proof_gen") => {
                    if let (Some(sid), Some(ms)) = (v.get("sid").and_then(|x| x.as_u64()), v.get("ms").and_then(|x| x.as_u64())) {
                        build.insert(sid, ms);
                    }
                }
                _ => {}
            }
        }
    }
    (gas, e2e_on, e2e_off, build)
}

fn main() {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() < 2 || args[0] != "--client" { eprintln!("usage: presentation_metrics --client metrics/results/client.ndjson [--sid n ...]"); std::process::exit(1); }
    let client_path = args[1].clone();
    let mut sid_filters = std::collections::BTreeSet::<u64>::new();
    let mut i = 2; while i < args.len() { if args[i] == "--sid" { i+=1; if i<args.len() { if let Ok(s) = args[i].parse::<u64>() { sid_filters.insert(s); } i+=1; } } else { i+=1; } }
    let (gas, e2e_on, e2e_off, build) = collect(&client_path);
    let mut sids: std::collections::BTreeSet<u64> = gas.keys().copied().collect(); sids.extend(e2e_on.keys().copied()); sids.extend(e2e_off.keys().copied()); sids.extend(build.keys().copied());
    if !sid_filters.is_empty() { sids = sids.intersection(&sid_filters).copied().collect(); }
    let mut sum_gas: u128 = 0; let mut n_gas: u64 = 0;
    let mut sum_on: u128 = 0; let mut n_on: u64 = 0;
    let mut sum_off: u128 = 0; let mut n_off: u64 = 0;
    let mut sum_build: u128 = 0; let mut n_build: u64 = 0;
    for sid in sids { if let Some(g) = gas.get(&sid) { sum_gas += *g; n_gas += 1; } if let Some(ms) = e2e_on.get(&sid) { sum_on += *ms as u128; n_on += 1; } if let Some(ms) = e2e_off.get(&sid) { sum_off += *ms as u128; n_off += 1; } if let Some(ms) = build.get(&sid) { sum_build += *ms as u128; n_build += 1; } }
    let avg_gas = if n_gas>0 { sum_gas/(n_gas as u128) } else { 0 };
    let avg_on = if n_on>0 { (sum_on/(n_on as u128)) as u64 } else { 0 };
    let avg_off = if n_off>0 { (sum_off/(n_off as u128)) as u64 } else { 0 };
    let avg_build = if n_build>0 { (sum_build/(n_build as u128)) as u64 } else { 0 };
    println!("{{\"avgPresentGasUsed\":{},\"avgPresentE2EOnMs\":{},\"avgPresentE2EOffMs\":{},\"avgProofConstructMs\":{}}}", avg_gas, avg_on, avg_off, avg_build);
}


