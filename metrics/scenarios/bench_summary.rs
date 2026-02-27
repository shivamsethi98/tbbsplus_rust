//! bench_summary — Aggregate batched benchmark NDJSON files into gas + timing tables.
//!
//! Reads NDJSON files produced by request_aggregator, issuer_onchain, opener_aggregator,
//! service_provider, presentation_aggregator, and client, then prints Markdown tables of
//! amortised per-user gas cost and average timing (ms) at each batch size.
//!
//! Usage (glob-expand in bash):
//!   cargo run --bin bench_summary -- \
//!     --req    metrics/results/request_aggregator_n*.ndjson \
//!     --issuer metrics/results/issuer_*.ndjson \
//!     --opener metrics/results/aggregator.ndjson \
//!     --sp     metrics/results/service_provider.ndjson \
//!     --pres   metrics/results/presentation_aggregator_n*.ndjson \
//!     --client metrics/results/client_n*.ndjson

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader};

use serde_json::Value;

/// Parse a decimal or "0x…" hex string into u64, ignoring errors.
fn parse_u64_str(v: &Value, field: &str) -> Option<u64> {
    let s = v.get(field)?.as_str()?;
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Load `gasUsed` (or `gasUsedTotal`) values grouped by `batch_size` for a given scenario.
fn load_gas_by_size(paths: &[String], scenario: &str) -> BTreeMap<u64, Vec<u64>> {
    let mut by_size: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for path in paths {
        let f = match File::open(path) {
            Ok(f) => f,
            Err(e) => { eprintln!("[warn] cannot open {}: {}", path, e); continue; }
        };
        for line in BufReader::new(f).lines().flatten() {
            let v: Value = match serde_json::from_str(&line) { Ok(v) => v, Err(_) => continue };
            let sc = v.get("scenario").and_then(|x| x.as_str()).unwrap_or("");
            if sc != scenario { continue; }
            let bs = v.get("batch_size")
                .and_then(|x| x.as_u64())
                .or_else(|| parse_u64_str(&v, "batch_size"))
                .unwrap_or(1);
            // Try gasUsed first, then gasUsedTotal (opener_aggregator uses the latter)
            let gu = parse_u64_str(&v, "gasUsed")
                .or_else(|| parse_u64_str(&v, "gasUsedTotal"))
                .unwrap_or(0);
            by_size.entry(bs).or_default().push(gu);
        }
    }
    by_size
}

/// Load `ms` timing values grouped by `batch_size` for a given scenario.
fn load_timing_by_size(paths: &[String], scenario: &str) -> BTreeMap<u64, Vec<u64>> {
    let mut by_size: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for path in paths {
        let f = match File::open(path) {
            Ok(f) => f,
            Err(e) => { eprintln!("[warn] cannot open {}: {}", path, e); continue; }
        };
        for line in BufReader::new(f).lines().flatten() {
            let v: Value = match serde_json::from_str(&line) { Ok(v) => v, Err(_) => continue };
            let sc = v.get("scenario").and_then(|x| x.as_str()).unwrap_or("");
            if sc != scenario { continue; }
            let bs = v.get("batch_size")
                .and_then(|x| x.as_u64())
                .or_else(|| parse_u64_str(&v, "batch_size"))
                .unwrap_or(1);
            let ms = v.get("ms").and_then(|x| x.as_u64()).unwrap_or(0);
            by_size.entry(bs).or_default().push(ms);
        }
    }
    by_size
}

/// Load `ms` timing values for client-side scenarios (no batch_size field — group by count).
/// Each record represents one user; we group by the number of records seen so far per NDJSON file.
/// Alternative: we accept a `--batch-sizes` arg or just count unique userIds per file.
/// Simplest: the bench scripts write one client NDJSON per batch size, so we infer N from filename
/// suffix _nN.ndjson, or count records.
fn load_client_timing(paths: &[String], scenario: &str) -> BTreeMap<u64, Vec<u64>> {
    let mut by_size: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for path in paths {
        // Try to infer batch size from filename like client_n8.ndjson
        let inferred_n: Option<u64> = {
            let fname = std::path::Path::new(path).file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if let Some(suffix) = fname.strip_prefix("client_n").or_else(|| fname.strip_prefix("client_pres_n")) {
                suffix.parse().ok()
            } else {
                None
            }
        };
        let f = match File::open(path) {
            Ok(f) => f,
            Err(e) => { eprintln!("[warn] cannot open {}: {}", path, e); continue; }
        };
        let mut records: Vec<u64> = Vec::new();
        for line in BufReader::new(f).lines().flatten() {
            let v: Value = match serde_json::from_str(&line) { Ok(v) => v, Err(_) => continue };
            let sc = v.get("scenario").and_then(|x| x.as_str()).unwrap_or("");
            if sc != scenario { continue; }
            let ms = v.get("ms").and_then(|x| x.as_u64()).unwrap_or(0);
            records.push(ms);
        }
        if records.is_empty() { continue; }
        let n = inferred_n.unwrap_or(records.len() as u64);
        by_size.entry(n).or_default().extend(records);
    }
    by_size
}

/// Sum all `gasUsed` entries for a given batch size (0 if absent).
fn sum_gas(map: &BTreeMap<u64, Vec<u64>>, n: u64) -> u64 {
    map.get(&n).map(|v| v.iter().sum()).unwrap_or(0)
}

/// Average ms for a given batch size (0 if absent).
fn avg_ms(map: &BTreeMap<u64, Vec<u64>>, n: u64) -> u64 {
    match map.get(&n) {
        Some(v) if !v.is_empty() => v.iter().sum::<u64>() / v.len() as u64,
        _ => 0,
    }
}

/// Sum all ms entries for a given batch size (0 if absent).
fn sum_ms(map: &BTreeMap<u64, Vec<u64>>, n: u64) -> u64 {
    map.get(&n).map(|v| v.iter().sum()).unwrap_or(0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    enum Section { Req, Issuer, Opener, Sp, Pres, Client, None }
    let mut section = Section::None;
    let mut req_files: Vec<String> = Vec::new();
    let mut issuer_files: Vec<String> = Vec::new();
    let mut opener_files: Vec<String> = Vec::new();
    let mut sp_files: Vec<String> = Vec::new();
    let mut pres_files: Vec<String> = Vec::new();
    let mut client_files: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--req"    => { section = Section::Req;    i += 1; continue; }
            "--issuer" => { section = Section::Issuer; i += 1; continue; }
            "--opener" => { section = Section::Opener; i += 1; continue; }
            "--sp"     => { section = Section::Sp;     i += 1; continue; }
            "--pres"   => { section = Section::Pres;   i += 1; continue; }
            "--client" => { section = Section::Client;  i += 1; continue; }
            arg if arg.starts_with("--") => { section = Section::None; i += 1; continue; }
            arg => match section {
                Section::Req    => req_files.push(arg.to_string()),
                Section::Issuer => issuer_files.push(arg.to_string()),
                Section::Opener => opener_files.push(arg.to_string()),
                Section::Sp     => sp_files.push(arg.to_string()),
                Section::Pres   => pres_files.push(arg.to_string()),
                Section::Client => client_files.push(arg.to_string()),
                Section::None   => {}
            }
        }
        i += 1;
    }

    // Load gas data for all scenarios
    let req    = load_gas_by_size(&req_files,    "batchBroadcastSigReqBBSPlusVerified");
    let submit = load_gas_by_size(&issuer_files, "submitShareBatch");
    let confirm= load_gas_by_size(&issuer_files, "confirmBatchRandomized");
    let acc    = load_gas_by_size(&opener_files, "acc_addMembers_batch");
    let sp     = load_gas_by_size(&sp_files,     "requestOpen");
    let pres   = load_gas_by_size(&pres_files,   "verifyPresentationBatch");

    // Load timing data for on-chain scenarios
    let req_t    = load_timing_by_size(&req_files,    "batchBroadcastSigReqBBSPlusVerified");
    let submit_t = load_timing_by_size(&issuer_files, "submitShareBatch");
    let confirm_t= load_timing_by_size(&issuer_files, "confirmBatchRandomized");
    let acc_t    = load_timing_by_size(&opener_files, "acc_addMembers_batch");
    let sp_t     = load_timing_by_size(&sp_files,     "requestOpen");
    let pres_t   = load_timing_by_size(&pres_files,   "verifyPresentationBatch");

    // Load client-side timing
    let issuance_e2e_t  = load_client_timing(&client_files, "issuance_e2e_confirmed");
    let witness_sync_t  = load_client_timing(&client_files, "witness_sync");
    let pres_build_t    = load_client_timing(&client_files, "presentation_build");

    // Collect all batch sizes seen across any file
    let mut sizes: BTreeSet<u64> = BTreeSet::new();
    for m in [&req, &submit, &confirm, &acc, &sp, &pres] {
        sizes.extend(m.keys().copied());
    }
    // Also include sizes from timing-only sources
    for m in [&issuance_e2e_t, &witness_sync_t, &pres_build_t] {
        sizes.extend(m.keys().copied());
    }

    if sizes.is_empty() {
        eprintln!("No records found. Check file paths and --req/--issuer/--opener/--sp/--pres/--client flags.");
        std::process::exit(1);
    }

    // ══════════════════════════════════════════════════════
    // Table 1: Per-user gas cost (all phases)
    // ══════════════════════════════════════════════════════
    println!("## Per-User Gas Cost\n");
    println!(
        "| {:>4} | {:>12} | {:>12} | {:>12} | {:>12} | {:>11} | {:>11} | {:>12} | {:>12} |",
        "N", "reqBroadcast", "submitShare", "confirmBatch", "accAddMember", "requestOpen", "presBatch", "issuanceSum", "presSum"
    );
    println!("|{:-^6}|{:-^14}|{:-^14}|{:-^14}|{:-^14}|{:-^13}|{:-^13}|{:-^14}|{:-^14}|",
        "", "", "", "", "", "", "", "", "");

    for &n in &sizes {
        let r  = sum_gas(&req,     n) / n.max(1);
        let s  = sum_gas(&submit,  n) / n.max(1);
        let c  = sum_gas(&confirm, n) / n.max(1);
        let a  = sum_gas(&acc,     n) / n.max(1);
        let sp_pu = sum_gas(&sp,   n) / n.max(1);
        let p  = sum_gas(&pres,    n) / n.max(1);
        let iss_total = r + s + c + a;
        let pres_total = sp_pu + p;
        println!(
            "| {:>4} | {:>12} | {:>12} | {:>12} | {:>12} | {:>11} | {:>11} | {:>12} | {:>12} |",
            n, r, s, c, a, sp_pu, p, iss_total, pres_total
        );
    }

    // ══════════════════════════════════════════════════════
    // Table 2: On-chain tx timing (ms, all phases)
    // ══════════════════════════════════════════════════════
    let has_timing = [&req_t, &submit_t, &confirm_t, &acc_t, &sp_t, &pres_t]
        .iter().any(|m| !m.is_empty());
    if has_timing {
        println!("\n## On-Chain Tx Timing (ms)\n");
        println!(
            "| {:>4} | {:>12} | {:>12} | {:>12} | {:>12} | {:>11} | {:>11} | {:>12} | {:>12} |",
            "N", "reqBroadcast", "submitShare", "confirmBatch", "accAddMember", "requestOpen", "presBatch", "issuanceSum", "presSum"
        );
        println!("|{:-^6}|{:-^14}|{:-^14}|{:-^14}|{:-^14}|{:-^13}|{:-^13}|{:-^14}|{:-^14}|",
            "", "", "", "", "", "", "", "", "");

        for &n in &sizes {
            let r_ms  = avg_ms(&req_t,     n);
            let s_ms  = sum_ms(&submit_t,  n);  // sum across T issuers
            let c_ms  = avg_ms(&confirm_t, n);  // typically 1 issuer confirms
            let a_ms  = avg_ms(&acc_t,     n);
            let sp_ms = sum_ms(&sp_t,      n);  // N individual requestOpen txs → total
            let p_ms  = avg_ms(&pres_t,    n);
            let iss_ms = r_ms + s_ms + c_ms + a_ms;
            let pres_ms = sp_ms + p_ms;
            println!(
                "| {:>4} | {:>12} | {:>12} | {:>12} | {:>12} | {:>11} | {:>11} | {:>12} | {:>12} |",
                n, r_ms, s_ms, c_ms, a_ms, sp_ms, p_ms, iss_ms, pres_ms
            );
        }
    }

    // ══════════════════════════════════════════════════════
    // Table 3: Issuance E2E Summary (per-user amortised)
    // ══════════════════════════════════════════════════════
    {
        let has_iss_data = [&req, &submit, &confirm, &acc].iter().any(|m| !m.is_empty());
        if has_iss_data {
            println!("\n## Issuance E2E Summary (per-user amortised)\n");
            println!(
                "| {:>4} | {:>14} | {:>14} | {:>18} |",
                "N", "gasPerUser", "serverMs", "clientE2eMs(avg)"
            );
            println!("|{:-^6}|{:-^16}|{:-^16}|{:-^20}|",
                "", "", "", "");

            for &n in &sizes {
                let r  = sum_gas(&req,     n) / n.max(1);
                let s  = sum_gas(&submit,  n) / n.max(1);
                let c  = sum_gas(&confirm, n) / n.max(1);
                let a  = sum_gas(&acc,     n) / n.max(1);
                let gas_pu = r + s + c + a;
                if gas_pu == 0 { continue; }

                let r_ms  = avg_ms(&req_t,     n);
                let s_ms  = sum_ms(&submit_t,  n);
                let c_ms  = avg_ms(&confirm_t, n);
                let a_ms  = avg_ms(&acc_t,     n);
                let server_ms = r_ms + s_ms + c_ms + a_ms;

                let client_ms = avg_ms(&issuance_e2e_t, n);
                let client_str = if client_ms > 0 { format!("{}", client_ms) } else { "-".into() };

                println!(
                    "| {:>4} | {:>14} | {:>14} | {:>18} |",
                    n, gas_pu, server_ms, client_str
                );
            }
        }
    }

    // ══════════════════════════════════════════════════════
    // Table 4: Client-side timing (ms, per user average)
    // ══════════════════════════════════════════════════════
    let has_client = [&issuance_e2e_t, &witness_sync_t, &pres_build_t]
        .iter().any(|m| !m.is_empty());
    if has_client {
        println!("\n## Client-Side Timing (ms, avg per user)\n");
        println!(
            "| {:>4} | {:>16} | {:>16} | {:>16} |",
            "N", "issuance_e2e", "witness_sync", "pres_build"
        );
        println!("|{:-^6}|{:-^18}|{:-^18}|{:-^18}|",
            "", "", "", "");

        for &n in &sizes {
            let ie = avg_ms(&issuance_e2e_t, n);
            let ws = avg_ms(&witness_sync_t, n);
            let pb = avg_ms(&pres_build_t,   n);
            if ie == 0 && ws == 0 && pb == 0 { continue; }
            println!(
                "| {:>4} | {:>16} | {:>16} | {:>16} |",
                n, ie, ws, pb
            );
        }
    }
}
