use blake2::Digest;

fn be_u64(first8: [u8; 8]) -> u64 {
    u64::from_be_bytes(first8)
}

fn derive_seed(tag: &str, parts: &[&[u8]]) -> u64 {
    let mut h = blake2::Blake2b512::new();
    h.update(tag.as_bytes());
    for p in parts { h.update(p); }
    let out = h.finalize();
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&out[..8]);
    be_u64(first8)
}

/// Deterministic seed for Base-OT parameters shared across all issuers for a credential.
pub fn base_ot_seed(cred_name: &str, total: u16, kappa: usize, ssp: usize) -> u64 {
    derive_seed(
        "TBBS+_BASE_OT_SEED_v1",
        &[
            cred_name.as_bytes(),
            &total.to_be_bytes(),
            &(kappa as u64).to_be_bytes(),
            &(ssp as u64).to_be_bytes(),
        ],
    )
}

/// Per-session Phase 1 seed for a participant and sid.
pub fn phase1_seed(participant_id: u16, sid: u64) -> u64 {
    derive_seed("TBBS+_PHASE1_SEED_v1", &[&participant_id.to_be_bytes(), &sid.to_be_bytes()])
}

/// Per-session Phase 2 seed for a participant and sid.
pub fn phase2_seed(participant_id: u16, sid: u64) -> u64 {
    derive_seed("TBBS+_PHASE2_SEED_v1", &[&participant_id.to_be_bytes(), &sid.to_be_bytes()])
}
