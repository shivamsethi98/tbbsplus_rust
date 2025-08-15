use std::collections::{BTreeMap, BTreeSet};
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use bbs_plus::{
    prelude::*,
    threshold::{
    threshold_bbs_plus::{BBSPlusSignatureShare, Phase1Output as BBSPhase1Output},
    multiplication_phase::{Phase2, Phase2Output},
        randomness_generation_phase::Phase1,
        ParticipantId,
    },
};
use bbs_plus::signature::SignatureG1;
use blake2::Blake2b512;
use sha3::Shake256;
use oblivious_transfer_protocols::cointoss::Commitments;
use oblivious_transfer_protocols::ot_based_multiplication::{
    base_ot_multi_party_pairwise::BaseOTOutput,
    dkls18_mul_2p::MultiplicationOTEParams,
    dkls19_batch_mul_2p::GadgetVector,
};

#[cfg(feature = "mpc")]
use crate::orchestration::mesh::p2p::{Mesh, MeshHandle};

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

/// Coordinator for Phase 1 of the threshold BBS+ protocol
pub struct Phase1Coordinator {
    pub id: ParticipantId,
    pub threshold: u16,
    pub total: u16,
    pub batch_size: u32,
    pub protocol_id: Vec<u8>,
    pub phase1: Option<Phase1<Fr, 256>>,
    pub commitments: BTreeMap<ParticipantId, Commitments>,
    pub zero_commitments: BTreeMap<ParticipantId, BTreeMap<ParticipantId, Commitments>>,
    pub shares_received: BTreeSet<ParticipantId>,
    #[cfg(feature = "mpc")]
    pub mesh_handle: Option<MeshHandle>,
}

impl Phase1Coordinator {
    pub fn new(
        id: ParticipantId,
        threshold: u16,
        total: u16,
        batch_size: u32,
        protocol_id: Vec<u8>,
    ) -> Self {
        Self {
            id,
            threshold,
            total,
            batch_size,
            protocol_id,
            phase1: None,
            commitments: BTreeMap::new(),
            zero_commitments: BTreeMap::new(),
            shares_received: BTreeSet::new(),
            #[cfg(feature = "mpc")]
            mesh_handle: None,
        }
    }

    #[cfg(feature = "mpc")]
    pub fn set_mesh_handle(&mut self, handle: MeshHandle) {
        self.mesh_handle = Some(handle);
    }

    /// Initialize Phase 1 and generate commitments
    pub async fn initialize<R: ark_std::rand::RngCore>(
        &mut self,
        rng: &mut R,
    ) -> anyhow::Result<()> {
        // Collect all participating parties except self
        // For a threshold signing, we typically use the first 'threshold' parties
        let others: BTreeSet<ParticipantId> = (1..=self.threshold)
            .filter(|&p| p != self.id)
            .collect();

    let (phase1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs_plus::<_, Blake2b512>(
            rng,
            self.batch_size,
            self.id,
            others,
            self.protocol_id.clone(),
    ).map_err(|e| anyhow::anyhow!("phase1 init failed: {:?}", e))?;

        self.phase1 = Some(phase1);

        // Serialize and broadcast commitments
        let mut commitment_bytes = Vec::new();
        comm.serialize_compressed(&mut commitment_bytes)?;

        let mut zero_commitments_map = BTreeMap::new();
        for (pid, zc) in comm_zero {
            let mut zc_bytes = Vec::new();
            zc.serialize_compressed(&mut zc_bytes)?;
            zero_commitments_map.insert(pid, zc_bytes);
        }

        #[cfg(feature = "mpc")]
        {
            let msg = ThresholdMessage::Phase1(Phase1Message::Commitment {
                from: self.id,
                commitment: commitment_bytes,
                zero_share_commitments: zero_commitments_map,
            });
            if let Some(handle) = &self.mesh_handle {
                handle.publish("threshold-phase1", &msg).await?;
            }
        }

        Ok(())
    }

    /// Process received commitment message
    pub fn process_commitment(&mut self, msg: Phase1Message) -> anyhow::Result<()> {
        match msg {
            Phase1Message::Commitment { from, commitment, zero_share_commitments } => {
                if from == self.id {
                    // Ignore self commitments seen via pubsub
                    return Ok(());
                }
                // Deserialize commitment
                let comm: Commitments = CanonicalDeserialize::deserialize_compressed(&commitment[..])
                    .map_err(|e| anyhow::anyhow!("deserialize commitment failed: {:?}", e))?;
                self.commitments.insert(from, comm.clone());

                // Process zero share commitment for this participant
                if let Some(zc_bytes) = zero_share_commitments.get(&self.id) {
                    let zc: Commitments = CanonicalDeserialize::deserialize_compressed(&zc_bytes[..])
                        .map_err(|e| anyhow::anyhow!("deserialize zero commitment failed: {:?}", e))?;
                    
                    if let Some(phase1) = &mut self.phase1 {
                        phase1.receive_commitment(from, comm, zc)
                            .map_err(|e| anyhow::anyhow!("receive_commitment failed: {:?}", e))?;
                    }
                }

                // Store all zero commitments for later
                let mut zc_map = BTreeMap::new();
                for (pid, zc_bytes) in zero_share_commitments {
                    let zc: Commitments = CanonicalDeserialize::deserialize_compressed(&zc_bytes[..])
                        .map_err(|e| anyhow::anyhow!("deserialize zero commitment failed: {:?}", e))?;
                    zc_map.insert(pid, zc);
                }
                self.zero_commitments.insert(from, zc_map);
            }
            _ => {}
        }
        Ok(())
    }

    /// Generate and send shares after receiving all commitments
    pub async fn generate_shares(&mut self) -> anyhow::Result<()> {
        let phase1 = self.phase1.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Phase 1 not initialized"))?;

        // Send shares to each other participant
        for pid in 1..=self.threshold {
            if pid == self.id {
                continue;
            }

            let shares = phase1.get_comm_shares_and_salts();
            let zero_shares = phase1.get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&pid);

            let mut shares_bytes = Vec::new();
            shares.serialize_compressed(&mut shares_bytes)?;

            let mut zero_shares_bytes = Vec::new();
            zero_shares.serialize_compressed(&mut zero_shares_bytes)?;

            #[cfg(feature = "mpc")]
            {
                let msg = ThresholdMessage::Phase1(Phase1Message::ShareExchange {
                    from: self.id,
                    to: pid,
                    shares: shares_bytes,
                    zero_shares: zero_shares_bytes,
                });
                if let Some(handle) = &self.mesh_handle {
                    handle.publish("threshold-phase1", &msg).await?;
                }
            }
        }

        Ok(())
    }

    /// Process received share exchange message
    pub fn process_share_exchange(&mut self, msg: Phase1Message) -> anyhow::Result<()> {
        match msg {
            Phase1Message::ShareExchange { from, to, shares, zero_shares } => {
                if to != self.id {
                    return Ok(()); // Not for us
                }

                if let Some(phase1) = &mut self.phase1 {
                    // Deserialize and process shares
                    let shares_data: Vec<(Fr, [u8; 256])> = 
                        CanonicalDeserialize::deserialize_compressed(&shares[..])
                        .map_err(|e| anyhow::anyhow!("deserialize shares failed: {:?}", e))?;
                    let zero_shares_data: Vec<(Fr, [u8; 256])> = 
                        CanonicalDeserialize::deserialize_compressed(&zero_shares[..])
                        .map_err(|e| anyhow::anyhow!("deserialize zero shares failed: {:?}", e))?;

                    phase1.receive_shares::<Blake2b512>(from, shares_data, zero_shares_data)
                        .map_err(|e| anyhow::anyhow!("receive_shares failed: {:?}", e))?;
                    self.shares_received.insert(from);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Complete Phase 1 and return the output
    pub fn finalize(&mut self, signing_key: &Fr) -> anyhow::Result<BBSPhase1Output<Fr>> {
        let phase1 = self.phase1.take()
            .ok_or_else(|| anyhow::anyhow!("Phase 1 not initialized"))?;

        let output = phase1
            .finish_for_bbs_plus::<Blake2b512>(signing_key)
            .map_err(|e| anyhow::anyhow!("phase1 finalize failed: {:?}", e))?;
        Ok(output)
    }

    /// Check if enough data has been received to finalize Phase 1
    pub fn is_ready(&self) -> bool {
        if let Some(p1) = &self.phase1 {
            p1.ready_to_compute_randomness_and_arguments_for_multiplication()
        } else {
            false
        }
    }
}

/// Coordinator for Phase 2 of the threshold BBS+ protocol
pub struct Phase2Coordinator {
    pub id: ParticipantId,
    pub threshold: u16,
    pub phase2: Option<Phase2<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>>,
    pub round1_messages: BTreeMap<ParticipantId, Vec<u8>>,
    pub round2_messages: BTreeMap<ParticipantId, Vec<u8>>,
    // Role-aware expectations: R1 from lower IDs, R2 from higher IDs
    pub expected_r1_from: BTreeSet<ParticipantId>,
    pub expected_r2_from: BTreeSet<ParticipantId>,
    pub got_r1_from: BTreeSet<ParticipantId>,
    pub got_r2_from: BTreeSet<ParticipantId>,
    #[cfg(feature = "mpc")]
    pub mesh_handle: Option<MeshHandle>,
}

impl Phase2Coordinator {
    pub fn new(id: ParticipantId, threshold: u16) -> Self {
        Self {
            id,
            threshold,
            phase2: None,
            round1_messages: BTreeMap::new(),
            round2_messages: BTreeMap::new(),
            expected_r1_from: BTreeSet::new(),
            expected_r2_from: BTreeSet::new(),
            got_r1_from: BTreeSet::new(),
            got_r2_from: BTreeSet::new(),
            #[cfg(feature = "mpc")]
            mesh_handle: None,
        }
    }

    #[cfg(feature = "mpc")]
    pub fn set_mesh_handle(&mut self, handle: MeshHandle) {
        self.mesh_handle = Some(handle);
    }

    /// Initialize Phase 2 with the output from Phase 1
    pub async fn initialize<R: ark_std::rand::RngCore>(
        &mut self,
        rng: &mut R,
        phase1_output: &BBSPhase1Output<Fr>,
        base_ot_output: BaseOTOutput,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> anyhow::Result<()> {
        // Use the same set of others from Phase 1 output
        let others_set: BTreeSet<ParticipantId> = phase1_output.others.iter().cloned().collect();

        let (phase2, messages) = Phase2::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::init::<_, Shake256>(
            rng,
            self.id,
            phase1_output.masked_signing_key_shares.clone(),
            phase1_output.masked_rs.clone(),
            base_ot_output,
            others_set.clone(),
            ote_params,
            gadget_vector,
    ).map_err(|e| anyhow::anyhow!("phase2 init failed: {:?}", e))?;

        self.phase2 = Some(phase2);

        // Compute expected senders based on id ordering
        self.expected_r1_from = others_set.iter().copied().filter(|pid| *pid < self.id).collect();
        self.expected_r2_from = others_set.iter().copied().filter(|pid| *pid > self.id).collect();
        self.got_r1_from.clear();
        self.got_r2_from.clear();
        println!(
            "[P{}] Phase2 init: expect R1 from {:?}, R2 from {:?}",
            self.id, self.expected_r1_from, self.expected_r2_from
        );
        // Send round 1 messages
        for (_to, msg) in messages {
            println!("[P{}] send R1 to {}", self.id, _to);
            let mut msg_bytes = Vec::new();
            msg.serialize_compressed(&mut msg_bytes)?;

            #[cfg(feature = "mpc")]
            {
                let threshold_msg = ThresholdMessage::Phase2(Phase2Message::Round1 {
                    from: self.id,
                    to: _to,
                    message: msg_bytes,
                });
                if let Some(handle) = &self.mesh_handle {
                    handle.publish("threshold-phase2", &threshold_msg).await?;
                }
            }
        }

        Ok(())
    }

    /// Process Phase 2 round 1 message
    pub async fn process_round1(
        &mut self,
        msg: Phase2Message,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> anyhow::Result<()> {
        match msg {
            Phase2Message::Round1 { from, to, message } => {
                println!("[P{}] recv R1 from {} to {}", self.id, from, to);
                if to != self.id {
                    return Ok(()); // Not for us
                }

                if let Some(phase2) = &mut self.phase2 {
                    // Deserialize and process message
                    let msg1 = CanonicalDeserialize::deserialize_compressed(&message[..])
                        .map_err(|e| anyhow::anyhow!("deserialize round1 failed: {:?}", e))?;
                    let msg2 = phase2.receive_message1::<Blake2b512, Shake256>(
                        from,
                        msg1,
                        gadget_vector,
                    ).map_err(|e| anyhow::anyhow!("receive_message1 failed: {:?}", e))?;

                    // Mark Round1 received from this peer (only if expected)
                    if self.expected_r1_from.contains(&from) {
                        self.got_r1_from.insert(from);
                        println!("[P{}] got R1 from {} ({} / {})", self.id, from, self.got_r1_from.len(), self.expected_r1_from.len());
                    }

                    // Send round 2 message back
                    let mut msg2_bytes = Vec::new();
                    msg2.serialize_compressed(&mut msg2_bytes)?;

                    #[cfg(feature = "mpc")]
                    {
                        let threshold_msg = ThresholdMessage::Phase2(Phase2Message::Round2 {
                            from: self.id,
                            to: from,
                            message: msg2_bytes,
                        });
                        if let Some(handle) = &self.mesh_handle {
                            handle.publish("threshold-phase2", &threshold_msg).await?;
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Process Phase 2 round 2 message
    pub fn process_round2(
        &mut self,
        msg: Phase2Message,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> anyhow::Result<()> {
        match msg {
            Phase2Message::Round2 { from, to, message } => {
                println!("[P{}] recv R2 from {} to {}", self.id, from, to);
                if to != self.id {
                    return Ok(()); // Not for us
                }

                if let Some(phase2) = &mut self.phase2 {
                    // Deserialize and process message
                    let msg2 = CanonicalDeserialize::deserialize_compressed(&message[..])
                        .map_err(|e| anyhow::anyhow!("deserialize round2 failed: {:?}", e))?;
                    phase2.receive_message2::<Blake2b512>(from, msg2, &gadget_vector)
                        .map_err(|e| anyhow::anyhow!("receive_message2 failed: {:?}", e))?;

                    // Mark Round2 received from this peer (only if expected)
                    if self.expected_r2_from.contains(&from) {
                        self.got_r2_from.insert(from);
                        println!("[P{}] got R2 from {} ({} / {})", self.id, from, self.got_r2_from.len(), self.expected_r2_from.len());
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Complete Phase 2 and return the output
    pub fn finalize(&mut self) -> anyhow::Result<Phase2Output<Fr>> {
        let phase2 = self.phase2.take()
            .ok_or_else(|| anyhow::anyhow!("Phase 2 not initialized"))?;

        let output = phase2.finish();
        Ok(output)
    }
}

impl Phase2Coordinator {
    /// Whether Phase 2 can be finalized (all expected messages received)
    pub fn is_ready(&self) -> bool {
        self.got_r1_from.len() == self.expected_r1_from.len()
            && self.got_r2_from.len() == self.expected_r2_from.len()
    }
}

// (phase2_ready and complete_phase2 are implemented on the main orchestrator impl below)

/// High-level orchestrator for the complete threshold signing protocol
pub struct ThresholdSigningOrchestrator {
    pub participant_id: ParticipantId,
    pub threshold: u16,
    pub total: u16,
    pub signing_key_share: Fr,
    pub base_ot_output: Option<BaseOTOutput>,
    pub phase1_coordinator: Option<Phase1Coordinator>,
    pub phase2_coordinator: Option<Phase2Coordinator>,
    pub ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    pub gadget_vector: GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    #[cfg(feature = "mpc")]
    pub mesh_handle: Option<MeshHandle>,
}

impl ThresholdSigningOrchestrator {
    pub fn phase2_ready(&self) -> bool {
        self.phase2_coordinator
            .as_ref()
            .map(|p| p.is_ready())
            .unwrap_or(false)
    }
    pub fn new(
        participant_id: ParticipantId,
        threshold: u16,
        total: u16,
        signing_key_share: Fr,
    ) -> Self {
        let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<Blake2b512>(
            ote_params,
            b"threshold-bbs-plus-gadget",
        );

        Self {
            participant_id,
            threshold,
            total,
            signing_key_share,
            base_ot_output: None,
            phase1_coordinator: None,
            phase2_coordinator: None,
            ote_params,
            gadget_vector,
            #[cfg(feature = "mpc")]
            mesh_handle: None,
        }
    }

    #[cfg(feature = "mpc")]
    pub fn set_mesh_handle(&mut self, handle: MeshHandle) {
        self.mesh_handle = Some(handle.clone());
        
        if let Some(p1) = &mut self.phase1_coordinator {
            p1.set_mesh_handle(handle.clone());
        }
        if let Some(p2) = &mut self.phase2_coordinator {
            p2.set_mesh_handle(handle.clone());
        }
    }

    pub fn set_base_ot(&mut self, base_ot: BaseOTOutput) {
        self.base_ot_output = Some(base_ot);
    }

    /// Start Phase 1 of the protocol
    pub async fn start_phase1<R: ark_std::rand::RngCore>(
        &mut self,
        rng: &mut R,
        batch_size: u32,
        protocol_id: Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut coordinator = Phase1Coordinator::new(
            self.participant_id,
            self.threshold,
            self.total,
            batch_size,
            protocol_id,
        );

        #[cfg(feature = "mpc")]
        if let Some(handle) = &self.mesh_handle {
            coordinator.set_mesh_handle(handle.clone());
        }

        coordinator.initialize(rng).await?;
        self.phase1_coordinator = Some(coordinator);
        Ok(())
    }

    /// Complete Phase 1 and prepare for Phase 2
    pub fn complete_phase1(&mut self) -> anyhow::Result<BBSPhase1Output<Fr>> {
        let coordinator = self.phase1_coordinator.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Phase 1 not started"))?;

        coordinator.finalize(&self.signing_key_share)
    }

    /// Trigger sending Phase 1 shares to other participants
    pub async fn phase1_send_shares(&mut self) -> anyhow::Result<()> {
        let coordinator = self
            .phase1_coordinator
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Phase 1 not started"))?;
        coordinator.generate_shares().await
    }

    /// Whether Phase 1 can be finalized (all commitments and shares received)
    pub fn phase1_ready(&self) -> bool {
        self.phase1_coordinator.as_ref().map(|p| p.is_ready()).unwrap_or(false)
    }

    /// Start Phase 2 of the protocol
    pub async fn start_phase2<R: ark_std::rand::RngCore>(
        &mut self,
        rng: &mut R,
    phase1_output: &BBSPhase1Output<Fr>,
    ) -> anyhow::Result<()> {
        let base_ot = self.base_ot_output.clone()
            .ok_or_else(|| anyhow::anyhow!("Base OT not set"))?;

        let mut coordinator = Phase2Coordinator::new(
            self.participant_id,
            self.threshold,
        );

        #[cfg(feature = "mpc")]
        if let Some(handle) = &self.mesh_handle {
            coordinator.set_mesh_handle(handle.clone());
        }

    coordinator.initialize(
            rng,
            phase1_output,
            base_ot,
            self.ote_params,
            &self.gadget_vector,
    ).await?;

        self.phase2_coordinator = Some(coordinator);
        Ok(())
    }

    /// Complete Phase 2
    pub fn complete_phase2(&mut self) -> anyhow::Result<Phase2Output<Fr>> {
        if !self.phase2_ready() {
            anyhow::bail!("phase2 not ready: waiting for expected Round1 and Round2 messages");
        }
        let coordinator = self
            .phase2_coordinator
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Phase 2 not started"))?;
        coordinator.finalize()
    }

    /// Generate signature share for given messages
    pub async fn generate_signature_share(
        &self,
        messages: &[Fr],
        sig_index: usize,
    phase1_output: &BBSPhase1Output<Fr>,
        phase2_output: &Phase2Output<Fr>,
        params: &SignatureParamsG1<Bls12_381>,
    _session_id: u64,
    ) -> anyhow::Result<BBSPlusSignatureShare<Bls12_381>> {
        let share = BBSPlusSignatureShare::new(
            messages,
            sig_index,
            phase1_output,
            phase2_output,
            params,
    ).map_err(|e| anyhow::anyhow!("create signature share failed: {:?}", e))?;

        // Broadcast the signature share
        let mut share_bytes = Vec::new();
        share.serialize_compressed(&mut share_bytes)
            .map_err(|e| anyhow::anyhow!("serialize share failed: {:?}", e))?;

        #[cfg(feature = "mpc")]
        {
            let msg = ThresholdMessage::SignatureShare {
                from: self.participant_id,
                sid: _session_id,
                share: share_bytes,
            };
            if let Some(handle) = &self.mesh_handle {
                handle.publish("threshold-signatures", &msg).await?;
            }
        }

        Ok(share)
    }

    /// Process incoming threshold messages
    pub async fn process_message(
        &mut self,
        msg: ThresholdMessage,
    ) -> anyhow::Result<()> {
        match msg {
            ThresholdMessage::Phase1(p1_msg) => {
                if let Some(coordinator) = &mut self.phase1_coordinator {
                    match &p1_msg {
                        Phase1Message::Commitment { .. } => {
                            coordinator.process_commitment(p1_msg)?;
                        }
                        Phase1Message::ShareExchange { .. } => {
                            coordinator.process_share_exchange(p1_msg)?;
                        }
                        _ => {}
                    }
                }
            }
            ThresholdMessage::Phase2(p2_msg) => {
                if let Some(coordinator) = &mut self.phase2_coordinator {
                    match &p2_msg {
                        Phase2Message::Round1 { .. } => {
                            coordinator.process_round1(p2_msg, &self.gadget_vector).await?;
                        }
                        Phase2Message::Round2 { .. } => {
                            coordinator.process_round2(p2_msg, &self.gadget_vector)?;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
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
