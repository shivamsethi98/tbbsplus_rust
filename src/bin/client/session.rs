use std::sync::Arc;
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalDeserialize;
use bbs_plus::signature::SignatureG1;

use tbbsplus_rust::orchestration::onchain::{self, ParamsContract, ParamsBundle};
use tbbsplus_rust::orchestration::persistence::{CredentialsStore, MessagesFile, RevealedFile};
use ethers::types::{Bytes as EthBytes, U256};

#[derive(Clone)]
pub struct Session {
    pub user_id: String,
    pub cred_name: String,
    pub sid: u64,
    pub params: ParamsBundle,
    pub messages: Vec<Fr>,
    pub signature: SignatureG1<Bls12_381>,
    pub revealed: Option<RevealedFile>,
}

impl Session {
    pub async fn load<M: ethers::providers::Middleware + 'static>(
        user_id: &str,
        cred_name: &str,
        sid: u64,
        params_contract: &ParamsContract<M>,
    ) -> anyhow::Result<Self> {
        let params = onchain::fetch_params_bundle(params_contract, cred_name).await?;
        let store = CredentialsStore::new(user_id, cred_name);

        let msgs_hex: Vec<String> = match store.load_messages(sid)? {
            Some(MessagesFile(v)) => v,
            None => anyhow::bail!("messages.json missing"),
        };
        let mut messages: Vec<Fr> = Vec::with_capacity(msgs_hex.len());
        for h in msgs_hex {
            let bytes = hex::decode(h.trim_start_matches("0x"))?;
            messages.push(Fr::deserialize_compressed(&bytes[..])?);
        }
        let sig_file = store
            .load_signature(sid)?
            .ok_or_else(|| anyhow::anyhow!("agg_signature.json missing"))?;
        let a_hex = sig_file.a.as_str();
        let e_hex = sig_file.e.as_str();
        let s_hex = sig_file.s.as_str();
        let a = <Bls12_381 as ark_ec::pairing::Pairing>::G1Affine::deserialize_compressed(
            &hex::decode(a_hex.trim_start_matches("0x"))?[..],
        )?;
        let e = Fr::deserialize_compressed(&hex::decode(e_hex.trim_start_matches("0x"))?[..])?;
        let s = Fr::deserialize_compressed(&hex::decode(s_hex.trim_start_matches("0x"))?[..])?;
        let signature = SignatureG1::<Bls12_381> { A: a, e, s };
        let revealed = store.load_revealed(sid)?;

        Ok(Session {
            user_id: user_id.to_owned(),
            cred_name: cred_name.to_owned(),
            sid,
            params,
            messages,
            signature,
            revealed,
        })
    }
}

/// Ephemeral session for the request phase carrying only non-sensitive, derived artifacts
/// required to make the on-chain verified request. This deliberately avoids keeping the
/// user's blinding or hidden message scalars to minimize exposure.
#[derive(Clone)]
pub struct RequestSession {
    pub user_id: String,
    pub cred_name: String,
    pub sid: u64,
    pub params: ParamsBundle,
    pub revealed_idx: Vec<u32>,
    pub revealed_vals: Vec<U256>,
    pub commitment_u: EthBytes,
    pub commitment_b: EthBytes,
    pub h0_b: EthBytes,
    pub h_b: Vec<EthBytes>,
    pub hidden_idx_vec: Vec<u32>,
    pub t_b: EthBytes,
    pub c_u256: U256,
    pub resp_vec_u256: Vec<U256>,
    pub context_bytes: ethers::types::Bytes,
}

impl RequestSession {
    pub fn new(
        user_id: &str,
        cred_name: &str,
        sid: u64,
        params: ParamsBundle,
        revealed_idx: Vec<u32>,
        revealed_vals: Vec<U256>,
        commitment_u: EthBytes,
        commitment_b: EthBytes,
        h0_b: EthBytes,
        h_b: Vec<EthBytes>,
        hidden_idx_vec: Vec<u32>,
        t_b: EthBytes,
        c_u256: U256,
        resp_vec_u256: Vec<U256>,
        context_bytes: ethers::types::Bytes,
    ) -> Self {
        Self { user_id: user_id.to_owned(), cred_name: cred_name.to_owned(), sid, params, revealed_idx, revealed_vals, commitment_u, commitment_b, h0_b, h_b, hidden_idx_vec, t_b, c_u256, resp_vec_u256, context_bytes }
    }
}
