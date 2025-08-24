use std::collections::{BTreeMap, BTreeSet};
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use bbs_plus::{
    prelude::*,
    threshold::{
        threshold_bbs_plus::{BBSPlusSignatureShare, Phase1Output},
        multiplication_phase::Phase2Output,
        ParticipantId,
    },
};
use ark_bls12_381::Fr as BBSField;

type BBSPhase1Output = Phase1Output<BBSField>;

#[cfg(feature = "mpc")]
use crate::orchestration::mesh::p2p::MeshHandle;

// Constants for the MPC protocol
pub const BASE_OT_KEY_SIZE: u16 = 128;
pub const KAPPA: u16 = 256;
pub const STATISTICAL_SECURITY_PARAMETER: u16 = 80;

/// Messages for Phase 1 coordination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Phase1Message {
    /// Initial commitment broadcast
    Commitment {
        from: ParticipantId,
        commitment: Vec<u8>, // Serialized Commitments
        zero_share_commitments: BTreeMap<ParticipantId, Vec<u8>>, // Serialized zero share commitments
    },
    /// Share exchange between specific parties
    ShareExchange {
        from: ParticipantId,
        to: ParticipantId,
        shares: Vec<u8>, // Serialized shares
        zero_shares: Vec<u8>, // Serialized zero shares
    },
    /// Phase 1 completion notification
    Phase1Complete {
        from: ParticipantId,
        output_hash: String, // Hash of the phase 1 output for verification
    },
}

/// Messages for Phase 2 coordination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Phase2Message {
    /// Round 1 message in multiplication protocol
    Round1 {
        from: ParticipantId,
        to: ParticipantId,
        message: Vec<u8>, // Serialized Message1
    },
    /// Round 2 message in multiplication protocol
    Round2 {
        from: ParticipantId,
        to: ParticipantId,
        message: Vec<u8>, // Serialized Message2
    },
    /// Phase 2 completion notification
    Phase2Complete {
        from: ParticipantId,
        output_hash: String, // Hash of the phase 2 output for verification
    },
}

/// Combined message type for all threshold protocol messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThresholdMessage {
    Phase1(Phase1Message),
    Phase2(Phase2Message),
    /// Final signature share to be sent to the user
    SignatureShare {
        from: ParticipantId,
        sid: u64, // Session ID
        share: Vec<u8>, // Serialized BBSPlusSignatureShare
    },
}

/// Simplified coordinator state for the threshold protocol
pub struct ThresholdCoordinator {
    pub participant_id: ParticipantId,
    pub threshold: u16,
    pub total: u16,
    pub signing_key_share: Fr,
    pub phase1_output: Option<BBSPhase1Output>,
    pub phase2_output: Option<Phase2Output<Fr>>,
    #[cfg(feature = "mpc")]
    pub mesh_handle: Option<MeshHandle>,
}

impl ThresholdCoordinator {
    pub fn new(
        participant_id: ParticipantId,
        threshold: u16,
        total: u16,
        signing_key_share: Fr,
    ) -> Self {
        Self {
            participant_id,
            threshold,
            total,
            signing_key_share,
            phase1_output: None,
            phase2_output: None,
            #[cfg(feature = "mpc")]
            mesh_handle: None,
        }
    }

    #[cfg(feature = "mpc")]
    pub fn set_mesh_handle(&mut self, handle: MeshHandle) {
        self.mesh_handle = Some(handle);
    }

    /// Store Phase 1 output
    pub fn set_phase1_output(&mut self, output: BBSPhase1Output) {
        self.phase1_output = Some(output);
    }

    /// Store Phase 2 output
    pub fn set_phase2_output(&mut self, output: Phase2Output<Fr>) {
        self.phase2_output = Some(output);
    }

    /// Generate signature share for given messages
    pub async fn generate_signature_share(
        &self,
        messages: &[Fr],
        sig_index: usize,
        params: &SignatureParamsG1<Bls12_381>,
        session_id: u64,
    ) -> anyhow::Result<BBSPlusSignatureShare<Bls12_381>> {
        let phase1_output = self.phase1_output.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Phase 1 output not set"))?;
        let phase2_output = self.phase2_output.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Phase 2 output not set"))?;

        let share = BBSPlusSignatureShare::new(
            messages,
            sig_index,
            phase1_output,
            phase2_output,
            params,
        ).map_err(|e| anyhow::anyhow!("Failed to create signature share: {:?}", e))?;

        // Broadcast the signature share
        #[cfg(feature = "mpc")]
        if let Some(handle) = &self.mesh_handle {
            let mut share_bytes = Vec::new();
            share.serialize_compressed(&mut share_bytes)?;

            let msg = ThresholdMessage::SignatureShare {
                from: self.participant_id,
                sid: session_id,
                share: share_bytes,
            };

            handle.publish("threshold-signatures", &msg).await?;
        }

        Ok(share)
    }

    /// Broadcast Phase 1 commitment
    pub async fn broadcast_phase1_commitment(
        &self,
        commitment: Vec<u8>,
        zero_commitments: BTreeMap<ParticipantId, Vec<u8>>,
    ) -> anyhow::Result<()> {
        let msg = ThresholdMessage::Phase1(Phase1Message::Commitment {
            from: self.participant_id,
            commitment,
            zero_share_commitments: zero_commitments,
        });

        #[cfg(feature = "mpc")]
        if let Some(handle) = &self.mesh_handle {
            handle.publish("threshold-phase1", &msg).await?;
        }

        Ok(())
    }

    /// Broadcast Phase 1 shares
    pub async fn broadcast_phase1_shares(
        &self,
        to: ParticipantId,
        shares: Vec<u8>,
        zero_shares: Vec<u8>,
    ) -> anyhow::Result<()> {
        let msg = ThresholdMessage::Phase1(Phase1Message::ShareExchange {
            from: self.participant_id,
            to,
            shares,
            zero_shares,
        });

        #[cfg(feature = "mpc")]
        if let Some(handle) = &self.mesh_handle {
            handle.publish("threshold-phase1", &msg).await?;
        }

        Ok(())
    }

    /// Broadcast Phase 2 round 1 message
    pub async fn broadcast_phase2_round1(
        &self,
        to: ParticipantId,
        message: Vec<u8>,
    ) -> anyhow::Result<()> {
        let msg = ThresholdMessage::Phase2(Phase2Message::Round1 {
            from: self.participant_id,
            to,
            message,
        });

        #[cfg(feature = "mpc")]
        if let Some(handle) = &self.mesh_handle {
            handle.publish("threshold-phase2", &msg).await?;
        }

        Ok(())
    }

    /// Broadcast Phase 2 round 2 message
    pub async fn broadcast_phase2_round2(
        &self,
        to: ParticipantId,
        message: Vec<u8>,
    ) -> anyhow::Result<()> {
        let msg = ThresholdMessage::Phase2(Phase2Message::Round2 {
            from: self.participant_id,
            to,
            message,
        });

        #[cfg(feature = "mpc")]
        if let Some(handle) = &self.mesh_handle {
            handle.publish("threshold-phase2", &msg).await?;
        }

        Ok(())
    }
}

/// Helper function to aggregate signature shares from multiple participants
pub fn aggregate_signature_shares(
    shares: Vec<BBSPlusSignatureShare<Bls12_381>>,
) -> anyhow::Result<SignatureG1<Bls12_381>> {
    BBSPlusSignatureShare::aggregate(shares)
        .map_err(|e| anyhow::anyhow!("Failed to aggregate shares: {:?}", e))
}

/// Collect signature shares from serialized messages
pub fn collect_signature_shares(
    messages: Vec<ThresholdMessage>,
) -> anyhow::Result<Vec<BBSPlusSignatureShare<Bls12_381>>> {
    let mut shares = Vec::new();
    
    for msg in messages {
        if let ThresholdMessage::SignatureShare { share, .. } = msg {
            let sig_share: BBSPlusSignatureShare<Bls12_381> = 
                CanonicalDeserialize::deserialize_compressed(&share[..])?;
            shares.push(sig_share);
        }
    }
    
    Ok(shares)
}
