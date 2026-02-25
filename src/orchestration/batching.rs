//! Batching utilities for aggregated credential presentation and request verification.
//!
//! This module provides:
//! - `PresentationData` — per-user presentation proof data (as produced by `build_presentation_tuples`)
//! - `pack_batch_input` — packs `Vec<PresentationData>` into the ABI token for `BatchPresInput`
//! - `RequestData` — per-user credential request proof data (commitment PoK)
//! - `pack_batch_request_input` — packs `Vec<RequestData>` into ABI tokens for `batchBroadcastSigReqBBSPlusVerified`
//!
//! The on-chain counterparts are:
//! - `BatchVerifyWrapper.verifyPresentationBatch` in `contracts/BatchVerify.sol`
//! - `RequestCredential.batchBroadcastSigReqBBSPlusVerified` in `contracts/RequestCredential.sol`

use std::fs::OpenOptions;

use ethers::abi::Token;
use ethers::types::{Address, Bytes as EthBytes, U256};
use serde::{Deserialize, Serialize};

/// Per-user presentation proof data, matching the components produced by
/// `build_presentation_tuples` + accumulator PoK construction.
///
/// Field names reference the Solidity `BatchPresInput` struct layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationData {
    // ── BBS+ signature parts (3 × 128 B G1 points) ──
    /// Randomized A' (128 B)
    pub a_prime: Vec<u8>,
    /// Blinded ABar (128 B)
    pub a_bar: Vec<u8>,
    /// Auxiliary commitment d (128 B)
    pub d: Vec<u8>,

    // ── BBS+ Schnorr commitments (2 × 128 B G1 points) ──
    /// Schnorr relation 1 commitment T1 (128 B)
    pub t1_bbs: Vec<u8>,
    /// Schnorr relation 2 commitment T2 (128 B)
    pub t2_bbs: Vec<u8>,

    // ── BBS+ challenge + responses ──
    /// BBS+ PoK challenge c
    pub bbs_challenge: U256,
    /// respA (response for witness -e with base A')
    pub resp_a: U256,
    /// respH0 (response for witness r2 with base h0)
    pub resp_h0: U256,
    /// respR3 (response for witness r3 with base d)
    pub resp_r3: U256,
    /// respSPrime (response for witness -s' with base h0)
    pub resp_sprime: U256,
    /// Responses for undisclosed messages, in the order of undisclosed bases
    pub resp_msgs: Vec<U256>,

    // ── Encryption (3 × 128 B G1 points + 2 scalars) ──
    /// T1_enc ciphertext part 1 (128 B)
    pub t1_enc: Vec<u8>,
    /// T2_enc ciphertext part 2 (128 B)
    pub t2_enc: Vec<u8>,
    /// Tenc Schnorr commitment for encryption relation (128 B)
    pub t_enc: Vec<u8>,
    /// respA3 encryption response
    pub resp_a3: U256,
    /// respK encryption response
    pub resp_k: U256,

    // ── Accumulator membership PoK (3 × 128 B G1 + 1 challenge + 2 responses) ──
    /// A'_acc (128 B)
    pub a_prime_acc: Vec<u8>,
    /// ABar_acc (128 B)
    pub a_bar_acc: Vec<u8>,
    /// t_acc Schnorr commitment (128 B)
    pub t_acc: Vec<u8>,
    /// Accumulator PoK challenge
    pub acc_challenge: U256,
    /// respR (witness r response)
    pub resp_r_acc: U256,
    /// respE (witness e response)
    pub resp_e_acc: U256,

    // ── Revealed messages (per user — may differ across batch) ──
    pub revealed_idx: Vec<u32>,
    pub revealed_vals: Vec<U256>,
}

impl PresentationData {
    /// Validate that all G1 points are 128 bytes.
    pub fn validate(&self) -> anyhow::Result<()> {
        let checks = [
            ("a_prime", &self.a_prime),
            ("a_bar", &self.a_bar),
            ("d", &self.d),
            ("t1_bbs", &self.t1_bbs),
            ("t2_bbs", &self.t2_bbs),
            ("t1_enc", &self.t1_enc),
            ("t2_enc", &self.t2_enc),
            ("t_enc", &self.t_enc),
            ("a_prime_acc", &self.a_prime_acc),
            ("a_bar_acc", &self.a_bar_acc),
            ("t_acc", &self.t_acc),
        ];
        for (name, pt) in checks {
            if pt.len() != 128 {
                anyhow::bail!("{}: expected 128 bytes, got {}", name, pt.len());
            }
        }
        Ok(())
    }

    /// Construct from the tuples produced by `build_presentation_tuples` + acc PoK.
    pub fn from_tuples(
        sig_t: &(EthBytes, EthBytes, EthBytes),
        challenge_u256: U256,
        p1_t: &(EthBytes, U256, U256),
        p2_t: &(EthBytes, Vec<U256>, U256, U256),
        enc_t1: &EthBytes,
        enc_t2enc: &EthBytes,
        enc_tenc: &EthBytes,
        enc_resp_a3: U256,
        enc_resp_k: U256,
        acc_a_prime: &EthBytes,
        acc_a_bar: &EthBytes,
        acc_t: &EthBytes,
        acc_challenge: U256,
        acc_resp_r: U256,
        acc_resp_e: U256,
        revealed_idx: Vec<u32>,
        revealed_vals: Vec<U256>,
    ) -> Self {
        Self {
            a_prime: sig_t.0.to_vec(),
            a_bar: sig_t.1.to_vec(),
            d: sig_t.2.to_vec(),
            t1_bbs: p1_t.0.to_vec(),
            t2_bbs: p2_t.0.to_vec(),
            bbs_challenge: challenge_u256,
            resp_a: p1_t.1,
            resp_h0: p1_t.2,
            resp_r3: p2_t.2,
            resp_sprime: p2_t.3,
            resp_msgs: p2_t.1.clone(),
            t1_enc: enc_t1.to_vec(),
            t2_enc: enc_t2enc.to_vec(),
            t_enc: enc_tenc.to_vec(),
            resp_a3: enc_resp_a3,
            resp_k: enc_resp_k,
            a_prime_acc: acc_a_prime.to_vec(),
            a_bar_acc: acc_a_bar.to_vec(),
            t_acc: acc_t.to_vec(),
            acc_challenge,
            resp_r_acc: acc_resp_r,
            resp_e_acc: acc_resp_e,
            revealed_idx,
            revealed_vals,
        }
    }
}

/// Pack a batch of presentations into the ABI-encoded `BatchPresInput` token.
///
/// The returned `Token::Tuple` matches the Solidity struct:
/// ```solidity
/// struct BatchPresInput {
///     bytes     sigPts;          // B × 384 B
///     bytes     bbsT;            // B × 256 B
///     uint256[] bbsC;            // B
///     uint256[] bbsResp;         // Σ R_j (variable per user)
///     uint256[] bbsRespOffsets;   // B+1 prefix sums
///     bytes     encPts;          // B × 384 B
///     uint256[] encResp;         // B × 2
///     bytes     accPts;          // B × 384 B
///     uint256[] accC;            // B
///     uint256[] accResp;         // B × 2
///     uint32[]  revIdxFlat;      // concatenated per-user revealed indices
///     uint256[] revValsFlat;     // concatenated per-user revealed values
///     uint256[] revOffsets;      // B+1 prefix sums
/// }
/// ```
///
/// Users may reveal different attribute sets.  The `bbsRespOffsets` and
/// `revOffsets` arrays encode per-user variable-length data as flat arrays
/// with prefix-sum offsets.
pub fn pack_batch_input(presentations: &[PresentationData]) -> anyhow::Result<Token> {
    let b = presentations.len();
    if b == 0 {
        anyhow::bail!("empty batch");
    }

    // ── sigPts: B × 384 B (A', ABar, d per user) ──
    let mut sig_pts = Vec::with_capacity(b * 384);
    for p in presentations {
        sig_pts.extend_from_slice(&p.a_prime);
        sig_pts.extend_from_slice(&p.a_bar);
        sig_pts.extend_from_slice(&p.d);
    }

    // ── bbsT: B × 256 B (T1, T2 per user) ──
    let mut bbs_t = Vec::with_capacity(b * 256);
    for p in presentations {
        bbs_t.extend_from_slice(&p.t1_bbs);
        bbs_t.extend_from_slice(&p.t2_bbs);
    }

    // ── bbsC: B challenges ──
    let bbs_c: Vec<Token> = presentations.iter().map(|p| Token::Uint(p.bbs_challenge)).collect();

    // ── bbsResp + bbsRespOffsets: variable-length per user ──
    // Layout per user: [respA, respH0, respR3, respSPrime, respMsgs[0..U_j-1]]
    let mut bbs_resp = Vec::new();
    let mut bbs_resp_offsets: Vec<Token> = Vec::with_capacity(b + 1);
    let mut offset: u64 = 0;
    bbs_resp_offsets.push(Token::Uint(U256::from(0u64)));
    for p in presentations {
        bbs_resp.push(Token::Uint(p.resp_a));
        bbs_resp.push(Token::Uint(p.resp_h0));
        bbs_resp.push(Token::Uint(p.resp_r3));
        bbs_resp.push(Token::Uint(p.resp_sprime));
        for m in &p.resp_msgs {
            bbs_resp.push(Token::Uint(*m));
        }
        offset += 4 + p.resp_msgs.len() as u64;
        bbs_resp_offsets.push(Token::Uint(U256::from(offset)));
    }

    // ── encPts: B × 384 B (T1enc, T2enc, Tenc per user) ──
    let mut enc_pts = Vec::with_capacity(b * 384);
    for p in presentations {
        enc_pts.extend_from_slice(&p.t1_enc);
        enc_pts.extend_from_slice(&p.t2_enc);
        enc_pts.extend_from_slice(&p.t_enc);
    }

    // ── encResp: B × 2 (respA3, respK per user) ──
    let mut enc_resp = Vec::with_capacity(b * 2);
    for p in presentations {
        enc_resp.push(Token::Uint(p.resp_a3));
        enc_resp.push(Token::Uint(p.resp_k));
    }

    // ── accPts: B × 384 B (A'acc, ABaracc, tacc per user) ──
    let mut acc_pts = Vec::with_capacity(b * 384);
    for p in presentations {
        acc_pts.extend_from_slice(&p.a_prime_acc);
        acc_pts.extend_from_slice(&p.a_bar_acc);
        acc_pts.extend_from_slice(&p.t_acc);
    }

    // ── accC: B challenges ──
    let acc_c: Vec<Token> = presentations.iter().map(|p| Token::Uint(p.acc_challenge)).collect();

    // ── accResp: B × 2 (respR, respE per user) ──
    let mut acc_resp = Vec::with_capacity(b * 2);
    for p in presentations {
        acc_resp.push(Token::Uint(p.resp_r_acc));
        acc_resp.push(Token::Uint(p.resp_e_acc));
    }

    // ── revIdxFlat, revValsFlat, revOffsets: per-user revealed data ──
    let mut rev_idx_flat = Vec::new();
    let mut rev_vals_flat = Vec::new();
    let mut rev_offsets: Vec<Token> = Vec::with_capacity(b + 1);
    let mut rev_offset: u64 = 0;
    rev_offsets.push(Token::Uint(U256::from(0u64)));
    for p in presentations {
        for &i in &p.revealed_idx {
            rev_idx_flat.push(Token::Uint(U256::from(i)));
        }
        for v in &p.revealed_vals {
            rev_vals_flat.push(Token::Uint(*v));
        }
        rev_offset += p.revealed_idx.len() as u64;
        rev_offsets.push(Token::Uint(U256::from(rev_offset)));
    }

    Ok(Token::Tuple(vec![
        Token::Bytes(sig_pts),
        Token::Bytes(bbs_t),
        Token::Array(bbs_c),
        Token::Array(bbs_resp),
        Token::Array(bbs_resp_offsets),
        Token::Bytes(enc_pts),
        Token::Array(enc_resp),
        Token::Bytes(acc_pts),
        Token::Array(acc_c),
        Token::Array(acc_resp),
        Token::Array(rev_idx_flat),
        Token::Array(rev_vals_flat),
        Token::Array(rev_offsets),
    ]))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Batched credential request (commitment PoK) data
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-user credential request proof data for the batched commitment PoK
/// verification in `RequestCredential.batchBroadcastSigReqBBSPlusVerified`.
///
/// Produced by the client during the credential request phase and consumed
/// by the `request_aggregator` binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestData {
    /// Ethereum address of the requesting user (hex, checksummed or lowercase)
    pub user_addr: String,
    /// Pedersen commitment C = h_0^blinding · prod(h_i^m_i) (128 B, EIP-2537)
    pub commitment_u: Vec<u8>,
    /// Same commitment bytes for the "b" copy (128 B)
    pub commitment_b: Vec<u8>,
    /// h_0 generator (128 B, EIP-2537)
    pub h0: Vec<u8>,
    /// H generators for all message slots (each 128 B)
    pub h: Vec<Vec<u8>>,
    /// Indices of revealed messages (shared across batch when identical)
    pub revealed_idx: Vec<u32>,
    /// Revealed message values
    pub revealed_vals: Vec<U256>,
    /// Indices of hidden messages
    pub hidden_idx: Vec<u32>,
    /// Schnorr commitment T (128 B, EIP-2537)
    pub t: Vec<u8>,
    /// Schnorr challenge c (Fr scalar)
    pub challenge: U256,
    /// Schnorr responses [s_blinding, s_{m_i1}, s_{m_i2}, ...] — length = 1 + |hidden_idx|
    pub responses: Vec<U256>,
    /// Application context bytes
    pub context: Vec<u8>,
    /// Credential name
    pub cred_name: String,
}

impl RequestData {
    /// Validate that G1 points are 128 bytes.
    pub fn validate(&self) -> anyhow::Result<()> {
        let checks = [
            ("commitment_u", &self.commitment_u),
            ("commitment_b", &self.commitment_b),
            ("h0", &self.h0),
            ("t", &self.t),
        ];
        for (name, pt) in checks {
            if pt.len() != 128 {
                anyhow::bail!("{}: expected 128 bytes, got {}", name, pt.len());
            }
        }
        for (i, hpt) in self.h.iter().enumerate() {
            if hpt.len() != 128 {
                anyhow::bail!("h[{}]: expected 128 bytes, got {}", i, hpt.len());
            }
        }
        if self.responses.len() != self.hidden_idx.len() + 1 {
            anyhow::bail!(
                "responses length {} != hidden_idx length {} + 1",
                self.responses.len(),
                self.hidden_idx.len()
            );
        }
        Ok(())
    }
}

/// Pack a batch of request data into the individual arrays needed by
/// `batchBroadcastSigReqBBSPlusVerified`.
///
/// Returns a tuple: (name, user_addrs, commitment_us, commitment_bs, h0, H,
///   hidden_idx, Ts, challenges, flat_responses, all_revealed_idx,
///   all_revealed_vals, contexts).
///
/// Shared parameters (h0, H, hidden_idx) are taken from the first entry.
/// All entries must share the same `cred_name`, `h0`, `H`, and `hidden_idx`.
pub fn pack_batch_request_input(
    requests: &[RequestData],
) -> anyhow::Result<(
    String,                 // cred_name
    Vec<Address>,           // userAddrs
    Vec<EthBytes>,          // commitmentUs
    Vec<EthBytes>,          // commitmentBs
    EthBytes,               // h0
    Vec<EthBytes>,          // H
    Vec<u32>,               // hiddenIdx
    Vec<EthBytes>,          // Ts
    Vec<U256>,              // challenges
    Vec<U256>,              // flatResponses
    Vec<Vec<u32>>,          // allRevealedIdx
    Vec<Vec<U256>>,         // allRevealedVals
    Vec<EthBytes>,          // contexts
)> {
    let n = requests.len();
    if n == 0 {
        anyhow::bail!("empty request batch");
    }

    let cred_name = requests[0].cred_name.clone();
    let h0 = EthBytes::from(requests[0].h0.clone());
    let h_shared: Vec<EthBytes> = requests[0].h.iter().map(|hb| EthBytes::from(hb.clone())).collect();
    let hidden_idx = requests[0].hidden_idx.clone();
    let resp_len = hidden_idx.len() + 1; // 1 (blinding) + |hidden|

    let mut user_addrs = Vec::with_capacity(n);
    let mut commitment_us = Vec::with_capacity(n);
    let mut commitment_bs = Vec::with_capacity(n);
    let mut ts = Vec::with_capacity(n);
    let mut challenges = Vec::with_capacity(n);
    let mut flat_responses = Vec::with_capacity(n * resp_len);
    let mut all_revealed_idx = Vec::with_capacity(n);
    let mut all_revealed_vals = Vec::with_capacity(n);
    let mut contexts = Vec::with_capacity(n);

    for (j, r) in requests.iter().enumerate() {
        if r.cred_name != cred_name {
            anyhow::bail!("request {} cred_name '{}' != '{}'", j, r.cred_name, cred_name);
        }
        if r.hidden_idx != hidden_idx {
            anyhow::bail!("request {} hidden_idx differs from request 0", j);
        }
        if r.responses.len() != resp_len {
            anyhow::bail!(
                "request {} has {} responses, expected {}",
                j,
                r.responses.len(),
                resp_len
            );
        }

        let addr: Address = r.user_addr.parse()
            .map_err(|e| anyhow::anyhow!("request {} bad address '{}': {}", j, r.user_addr, e))?;
        user_addrs.push(addr);
        commitment_us.push(EthBytes::from(r.commitment_u.clone()));
        commitment_bs.push(EthBytes::from(r.commitment_b.clone()));
        ts.push(EthBytes::from(r.t.clone()));
        challenges.push(r.challenge);
        for resp in &r.responses {
            flat_responses.push(*resp);
        }
        all_revealed_idx.push(r.revealed_idx.clone());
        all_revealed_vals.push(r.revealed_vals.clone());
        contexts.push(EthBytes::from(r.context.clone()));
    }

    Ok((
        cred_name,
        user_addrs,
        commitment_us,
        commitment_bs,
        h0,
        h_shared,
        hidden_idx,
        ts,
        challenges,
        flat_responses,
        all_revealed_idx,
        all_revealed_vals,
        contexts,
    ))
}

// ═══════════════════════════════════════════════════════════════════════════════
// File-locked batch consumption for persistent aggregators
// ═══════════════════════════════════════════════════════════════════════════════

/// File-locked read: if the JSON array in `path` has >= `threshold` entries,
/// drain exactly `threshold` from the front, write the remainder back, and
/// return the consumed entries.  Returns an empty Vec if not ready.
///
/// Uses `fs2` advisory locking to prevent races with concurrent client appends.
pub fn consume_batch_if_ready<T: serde::de::DeserializeOwned + serde::Serialize>(
    path: &str,
    threshold: usize,
) -> anyhow::Result<Vec<T>> {
    use fs2::FileExt;

    if threshold == 0 {
        return Ok(Vec::new());
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;
    file.lock_exclusive()?;

    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut entries: Vec<T> = if content.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&content)?
    };

    if entries.len() < threshold {
        file.unlock()?;
        return Ok(Vec::new());
    }

    // Consume exactly `threshold` entries from the front
    let consumed: Vec<T> = entries.drain(..threshold).collect();

    // Write remaining back (empty string if none left)
    std::fs::write(
        path,
        if entries.is_empty() {
            String::new()
        } else {
            serde_json::to_string_pretty(&entries)?
        },
    )?;
    file.unlock()?;

    Ok(consumed)
}
