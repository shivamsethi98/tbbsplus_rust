use std::collections::BTreeMap;
use ark_bls12_381::{Bls12_381, Fr};
use bbs_plus::{prelude::*, threshold::threshold_bbs_plus::BBSPlusSignatureShare};
use serde::{Serialize, Deserialize};

use crate::orchestration::threshold_phases::{
    ThresholdSigningOrchestrator,
};
use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
use ark_std::rand::{rngs::StdRng, SeedableRng};

pub type SessionId = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    pub session_id: SessionId,
    pub message_count: u32,
}

pub struct Session {
    pub id: SessionId,
    pub messages: Vec<Fr>,
    pub params: SignatureParamsG1<Bls12_381>,
    pub public_key: PublicKeyG2<Bls12_381>,
    pub orchestrator: ThresholdSigningOrchestrator,
}

pub struct SessionManager {
    pub threshold: u16,
    pub total: u16,
    pub sessions: BTreeMap<SessionId, Session>,
}

impl SessionManager {
    pub fn new(threshold: u16, total: u16) -> Self {
        Self { threshold, total, sessions: BTreeMap::new() }
    }

    pub fn create_session(&mut self, session_id: SessionId, message_count: u32) -> anyhow::Result<()> {
    if self.sessions.contains_key(&session_id) { return Ok(()); }

        let mut rng = StdRng::seed_from_u64(42 + session_id as u64);
        let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, message_count);
        // For demo: generate a fresh threshold key per session
        let (secret_key, shares) = {
            let (secret, shares, _) = deal_random_secret(&mut rng, self.threshold, self.total)
                .map_err(|e| anyhow::anyhow!("deal_random_secret: {:?}", e))?;
            (secret, shares.0.into_iter().map(|s| s.share).collect::<Vec<_>>())
        };
        let public_key = PublicKeyG2::generate_using_secret_key(&SecretKey(secret_key), &params);

        // This node acts as participant 1 for now (extend to choose dynamically)
        let my_id = 1u16;
        let signing_key_share = shares[(my_id - 1) as usize];
        let orchestrator = ThresholdSigningOrchestrator::new(my_id, self.threshold, self.total, signing_key_share);

        let messages: Vec<Fr> = (0..message_count).map(|i| Fr::from(100 + i as u64)).collect();

        self.sessions.insert(session_id, Session { id: session_id, messages, params, public_key, orchestrator });
        Ok(())
    }
}
