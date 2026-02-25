use ark_bls12_381::{Bls12_381, Fr};

/// Verify commitment PoK from on-chain fields using the canonical implementation in crypto::pok.
/// Thin re-export to keep call sites stable while we phase out legacy helpers and shims.
pub fn verify_from_fields(
    params_bbs: &bbs_plus::prelude::SignatureParamsG1<Bls12_381>,
    commitment: &<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine,
    user_id: &ethers::types::U256,
    cred_name: &str,
    revealed_idx: &[u32],
    revealed_vals: &[ethers::types::U256],
    context: &[u8],
    hidden_idx: Vec<u32>,
    t_eip: &[u8],
    c_fr: &Fr,
    resp_fr: &[Fr],
) -> anyhow::Result<()> {
    crate::orchestration::crypto::pok::verify_commitment_pok_from_fields(
        params_bbs,
        commitment,
        user_id,
        cred_name,
        &revealed_idx.to_vec(),
        &revealed_vals.to_vec(),
        context,
        hidden_idx,
        t_eip,
        c_fr,
        &resp_fr.to_vec(),
    )
}
