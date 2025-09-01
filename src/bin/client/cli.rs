// Minimal CLI/interactive helpers for the client binary
use std::io::{self, Write};
use ethers::types::U256;

pub fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    if !prompt.is_empty() { print!("{}: ", prompt); io::stdout().flush()?; }
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s.trim_end().to_string())
}

pub fn prompt_parse_u64(prompt: &str, default: u64) -> anyhow::Result<u64> {
    let l = prompt_line(&format!("{} [default: {}]", prompt, default))?;
    if l.trim().is_empty() { return Ok(default); }
    Ok(l.trim().parse()?)
}

pub fn parse_revealed(line: &str) -> anyhow::Result<(Vec<u32>, Vec<U256>)> {
    let mut idx = Vec::new();
    let mut vals = Vec::new();
    for part in line.split(',') {
        let p = part.trim();
        if p.is_empty() { continue; }
        let mut it = p.split('=');
        let i: u32 = it.next().ok_or_else(|| anyhow::anyhow!("bad pair"))?.trim().parse()?;
        let v_str = it.next().ok_or_else(|| anyhow::anyhow!("bad pair"))?.trim();
        let v = if v_str.starts_with("0x") { U256::from_str_radix(&v_str[2..], 16)? } else { U256::from_dec_str(v_str)? };
        idx.push(i); vals.push(v);
    }
    Ok((idx, vals))
}
