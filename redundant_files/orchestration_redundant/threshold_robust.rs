// Robust threshold signing orchestrator that handles messages in any order
use std::collections::{BTreeMap, BTreeSet};
use ark_bls12_381::Fr;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use blake2::Blake2b512;
use sha3::Shake256;

use bbs_plus::threshold::{
    threshold_bbs_plus::Phase1Output as BBSPhase1Output,
    multiplication_phase::{Phase2, Phase2Output},
    randomness_generation_phase::Phase1,
    ParticipantId,
};
use oblivious_transfer_protocols::cointoss::Commitments;
use oblivious_transfer_protocols::ot_based_multiplication::{
    base_ot_multi_party_pairwise::BaseOTOutput,
    dkls18_mul_2p::MultiplicationOTEParams,
    dkls19_batch_mul_2p::GadgetVector,
};

use super::threshold_phases::{Phase1Message, Phase2Message, ThresholdMessage};

#[cfg(feature = "mpc")]
use crate::orchestration::mesh::p2p::MeshHandle;

const KAPPA: u16 = 256;
const STATISTICAL_SECURITY_PARAMETER: u16 = 80;

/// Robust Phase 1 coordinator that handles messages in any order
pub struct RobustPhase1Coordinator {
    pub id: ParticipantId,
    pub threshold: u16,
    pub total: u16,
    pub batch_size: u32,
    pub protocol_id: Vec<u8>,
    pub phase1: Option<Phase1<Fr, 256>>,
    
    // Track which participants we're working with
    pub participant_set: BTreeSet<ParticipantId>,
    
    // Store received data
    pub commitments_received: BTreeMap<ParticipantId, Vec<u8>>,
    pub zero_commitments_received: BTreeMap<ParticipantId, BTreeMap<ParticipantId, Vec<u8>>>,
    pub shares_received: BTreeMap<ParticipantId, (Vec<u8>, Vec<u8>)>, // (shares, zero_shares)
    
    // Track processing state
    pub commitments_processed: BTreeSet<ParticipantId>,
    pub shares_processed: BTreeSet<ParticipantId>,
    pub shares_sent: bool,
    
    #[cfg(feature = "mpc")]
    pub mesh_handle: Option<MeshHandle>,
}

impl RobustPhase1Coordinator {
    pub fn new(
        id: ParticipantId,
        threshold: u16,
        total: u16,
        batch_size: u32,
        protocol_id: Vec<u8>,
    ) -> Self {
        // Determine the participant set (first 'threshold' participants)
        let participant_set: BTreeSet<ParticipantId> = (1..=threshold).collect();
        
        Self {
            id,
            threshold,
            total,
            batch_size,
            protocol_id,
            phase1: None,
            participant_set,
            commitments_received: BTreeMap::new(),
            zero_commitments_received: BTreeMap::new(),
            shares_received: BTreeMap::new(),
            commitments_processed: BTreeSet::new(),
            shares_processed: BTreeSet::new(),
            shares_sent: false,
            #[cfg(feature = "mpc")]
            mesh_handle: None,
        }
    }

    #[cfg(feature = "mpc")]
    pub fn set_mesh_handle(&mut self, handle: MeshHandle) {
        self.mesh_handle = Some(handle);
    }

    /// Initialize Phase 1 and broadcast commitment
    pub async fn initialize<R: ark_std::rand::RngCore>(
        &mut self,
        rng: &mut R,
    ) -> anyhow::Result<()> {
        // Only initialize if we're part of the active set
        if !self.participant_set.contains(&self.id) {
            return Ok(());
        }

        let mut others = self.participant_set.clone();
        others.remove(&self.id);

        let (phase1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs_plus::<_, Blake2b512>(
            rng,
            self.batch_size,
            self.id,
            others.clone(),
            self.protocol_id.clone(),
        ).map_err(|e| anyhow::anyhow!("phase1 init failed: {:?}", e))?;

        self.phase1 = Some(phase1);

        // Serialize commitments
        let mut commitment_bytes = Vec::new();
        comm.serialize_compressed(&mut commitment_bytes)?;

        let mut zero_commitments_map = BTreeMap::new();
        for (pid, zc) in comm_zero {
            let mut zc_bytes = Vec::new();
            zc.serialize_compressed(&mut zc_bytes)?;
            zero_commitments_map.insert(pid, zc_bytes);
        }

        // Broadcast commitment to all participants
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

    /// Store incoming commitment (can be called in any order)
    pub fn store_commitment(&mut self, msg: Phase1Message) -> anyhow::Result<()> {
        match msg {
            Phase1Message::Commitment { from, commitment, zero_share_commitments } => {
                if from == self.id || !self.participant_set.contains(&from) {
                    return Ok(());
                }

                self.commitments_received.insert(from, commitment);
                self.zero_commitments_received.insert(from, zero_share_commitments);
                
                // Try to process any pending commitments
                self.process_pending_commitments()?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Store incoming share exchange (can be called in any order)
    pub fn store_share(&mut self, msg: Phase1Message) -> anyhow::Result<()> {
        match msg {
            Phase1Message::ShareExchange { from, to, shares, zero_shares } => {
                if to != self.id || !self.participant_set.contains(&from) {
                    return Ok(());
                }

                self.shares_received.insert(from, (shares, zero_shares));
                
                // Try to process any pending shares
                self.process_pending_shares()?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Process any commitments that we have both data and Phase1 ready for
    fn process_pending_commitments(&mut self) -> anyhow::Result<()> {
        if self.phase1.is_none() {
            return Ok(());
        }

        let phase1 = self.phase1.as_mut().unwrap();
        let mut newly_processed = Vec::new();

        for (from, commitment_bytes) in &self.commitments_received {
            if self.commitments_processed.contains(from) {
                continue;
            }

            // Check if we have the zero commitment for us
            if let Some(zero_comms) = self.zero_commitments_received.get(from) {
                if let Some(zc_bytes) = zero_comms.get(&self.id) {
                    // Deserialize and process
                    let comm = CanonicalDeserialize::deserialize_compressed(&commitment_bytes[..])
                        .map_err(|e| anyhow::anyhow!("deserialize commitment failed: {:?}", e))?;
                    let zc = CanonicalDeserialize::deserialize_compressed(&zc_bytes[..])
                        .map_err(|e| anyhow::anyhow!("deserialize zero commitment failed: {:?}", e))?;

                    phase1.receive_commitment(*from, comm, zc)
                        .map_err(|e| anyhow::anyhow!("receive_commitment failed: {:?}", e))?;

                    newly_processed.push(*from);
                }
            }
        }

        for from in newly_processed {
            self.commitments_processed.insert(from);
        }

        Ok(())
    }

    /// Process any shares that we have data for
    fn process_pending_shares(&mut self) -> anyhow::Result<()> {
        if self.phase1.is_none() {
            return Ok(());
        }

        let phase1 = self.phase1.as_mut().unwrap();
        let mut newly_processed = Vec::new();

        for (from, (shares_bytes, zero_shares_bytes)) in &self.shares_received {
            if self.shares_processed.contains(from) {
                continue;
            }

            // Deserialize and process
            let shares_data: Vec<(Fr, [u8; 256])> = 
                CanonicalDeserialize::deserialize_compressed(&shares_bytes[..])
                .map_err(|e| anyhow::anyhow!("deserialize shares failed: {:?}", e))?;
            let zero_shares_data: Vec<(Fr, [u8; 256])> = 
                CanonicalDeserialize::deserialize_compressed(&zero_shares_bytes[..])
                .map_err(|e| anyhow::anyhow!("deserialize zero shares failed: {:?}", e))?;

            phase1.receive_shares::<Blake2b512>(*from, shares_data, zero_shares_data)
                .map_err(|e| anyhow::anyhow!("receive_shares failed: {:?}", e))?;

            newly_processed.push(*from);
        }

        for from in newly_processed {
            self.shares_processed.insert(from);
        }

        Ok(())
    }

    /// Check if we have received all commitments from other participants
    pub fn all_commitments_received(&self) -> bool {
        if !self.participant_set.contains(&self.id) {
            return true; // Non-participants are always ready
        }

        let expected_count = self.participant_set.len() - 1; // All except self
        self.commitments_processed.len() == expected_count
    }

    /// Send shares to all other participants (should be called after all commitments received)
    pub async fn send_shares(&mut self) -> anyhow::Result<()> {
        if self.shares_sent || self.phase1.is_none() {
            return Ok(());
        }

        let phase1 = self.phase1.as_ref().unwrap();

        for pid in &self.participant_set {
            if *pid == self.id {
                continue;
            }

            let shares = phase1.get_comm_shares_and_salts();
            let zero_shares = phase1.get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(pid);

            let mut shares_bytes = Vec::new();
            shares.serialize_compressed(&mut shares_bytes)?;

            let mut zero_shares_bytes = Vec::new();
            zero_shares.serialize_compressed(&mut zero_shares_bytes)?;

            #[cfg(feature = "mpc")]
            {
                let msg = ThresholdMessage::Phase1(Phase1Message::ShareExchange {
                    from: self.id,
                    to: *pid,
                    shares: shares_bytes,
                    zero_shares: zero_shares_bytes,
                });
                if let Some(handle) = &self.mesh_handle {
                    handle.publish("threshold-phase1", &msg).await?;
                }
            }
        }

        self.shares_sent = true;
        Ok(())
    }

    /// Check if we have received all shares from other participants
    pub fn all_shares_received(&self) -> bool {
        if !self.participant_set.contains(&self.id) {
            return true; // Non-participants are always ready
        }

        let expected_count = self.participant_set.len() - 1; // All except self
        self.shares_processed.len() == expected_count
    }

    /// Check if Phase 1 is ready to finalize
    pub fn is_ready(&self) -> bool {
        self.participant_set.contains(&self.id) &&
        self.all_commitments_received() &&
        self.shares_sent &&
        self.all_shares_received() &&
        self.phase1.as_ref().map(|p| p.ready_to_compute_randomness_and_arguments_for_multiplication()).unwrap_or(false)
    }

    /// Finalize Phase 1
    pub fn finalize(&mut self, signing_key: &Fr) -> anyhow::Result<BBSPhase1Output<Fr>> {
        if !self.is_ready() {
            return Err(anyhow::anyhow!("Phase 1 not ready to finalize"));
        }

        let phase1 = self.phase1.take()
            .ok_or_else(|| anyhow::anyhow!("Phase 1 not initialized"))?;

        let output = phase1
            .finish_for_bbs_plus::<Blake2b512>(signing_key)
            .map_err(|e| anyhow::anyhow!("phase1 finalize failed: {:?}", e))?;
        
        Ok(output)
    }
}

/// Robust Phase 2 coordinator that handles messages in any order
pub struct RobustPhase2Coordinator {
    pub id: ParticipantId,
    pub participant_set: BTreeSet<ParticipantId>,
    pub phase2: Option<Phase2<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>>,
    
    // Store received messages
    pub round1_received: BTreeMap<ParticipantId, Vec<u8>>,
    pub round2_received: BTreeMap<ParticipantId, Vec<u8>>,
    
    // Track processing state
    pub round1_processed: BTreeSet<ParticipantId>,
    pub round2_processed: BTreeSet<ParticipantId>,
    pub round2_sent: BTreeSet<ParticipantId>,
    
    #[cfg(feature = "mpc")]
    pub mesh_handle: Option<MeshHandle>,
}

impl RobustPhase2Coordinator {
    pub fn new(id: ParticipantId, participant_set: BTreeSet<ParticipantId>) -> Self {
        Self {
            id,
            participant_set,
            phase2: None,
            round1_received: BTreeMap::new(),
            round2_received: BTreeMap::new(),
            round1_processed: BTreeSet::new(),
            round2_processed: BTreeSet::new(),
            round2_sent: BTreeSet::new(),
            #[cfg(feature = "mpc")]
            mesh_handle: None,
        }
    }

    #[cfg(feature = "mpc")]
    pub fn set_mesh_handle(&mut self, handle: MeshHandle) {
        self.mesh_handle = Some(handle);
    }

    /// Initialize Phase 2 and send round 1 messages
    pub async fn initialize<R: ark_std::rand::RngCore>(
        &mut self,
        rng: &mut R,
        phase1_output: &BBSPhase1Output<Fr>,
        base_ot_output: BaseOTOutput,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> anyhow::Result<()> {
        if !self.participant_set.contains(&self.id) {
            return Ok(());
        }

        // Use others from phase1_output to ensure consistency
        let others: BTreeSet<ParticipantId> = phase1_output.others.iter().cloned().collect();

        let (phase2, messages) = Phase2::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::init::<_, Shake256>(
            rng,
            self.id,
            phase1_output.masked_signing_key_shares.clone(),
            phase1_output.masked_rs.clone(),
            base_ot_output,
            others,
            ote_params,
            gadget_vector,
        ).map_err(|e| anyhow::anyhow!("phase2 init failed: {:?}", e))?;

        self.phase2 = Some(phase2);

        // Send round 1 messages
        println!("[Node {}] Phase2::init generated {} messages", self.id, messages.len());
        for (to, msg) in messages {
            let mut msg_bytes = Vec::new();
            msg.serialize_compressed(&mut msg_bytes)?;

            #[cfg(feature = "mpc")]
            {
                let threshold_msg = ThresholdMessage::Phase2(Phase2Message::Round1 {
                    from: self.id,
                    to,
                    message: msg_bytes,
                });
                if let Some(handle) = &self.mesh_handle {
                    println!("[Node {}] Publishing Phase2 Round1 message to Node {}", self.id, to);
                    handle.publish("threshold-phase2", &threshold_msg).await?;
                } else {
                    println!("[Node {}] ERROR: No mesh handle to send Phase2 message!", self.id);
                }
            }
        }

        Ok(())
    }

    /// Store incoming round 1 message (can be called in any order)
    pub async fn store_round1(
        &mut self,
        msg: Phase2Message,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> anyhow::Result<()> {
        match msg {
            Phase2Message::Round1 { from, to, message } => {
                if to != self.id || !self.participant_set.contains(&from) {
                    return Ok(());
                }

                self.round1_received.insert(from, message);
                
                // Try to process pending round 1 messages
                self.process_pending_round1(gadget_vector).await?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Process any round 1 messages we have data for
    async fn process_pending_round1(
        &mut self,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> anyhow::Result<()> {
        if self.phase2.is_none() {
            return Ok(());
        }

        let mut to_process = Vec::new();
        for (from, msg_bytes) in &self.round1_received {
            if !self.round1_processed.contains(from) && !self.round2_sent.contains(from) {
                to_process.push((*from, msg_bytes.clone()));
            }
        }

        for (from, msg_bytes) in to_process {
            let phase2 = self.phase2.as_mut().unwrap();
            
            // Deserialize and process
            let msg1 = CanonicalDeserialize::deserialize_compressed(&msg_bytes[..])
                .map_err(|e| anyhow::anyhow!("deserialize round1 failed: {:?}", e))?;
            
            let msg2 = phase2.receive_message1::<Blake2b512, Shake256>(
                from,
                msg1,
                gadget_vector,
            ).map_err(|e| anyhow::anyhow!("receive_message1 failed: {:?}", e))?;

            self.round1_processed.insert(from);

            // Send round 2 response
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

            self.round2_sent.insert(from);
        }

        Ok(())
    }

    /// Store incoming round 2 message (can be called in any order)
    pub fn store_round2(
        &mut self,
        msg: Phase2Message,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> anyhow::Result<()> {
        match msg {
            Phase2Message::Round2 { from, to, message } => {
                if to != self.id || !self.participant_set.contains(&from) {
                    return Ok(());
                }

                self.round2_received.insert(from, message);
                
                // Try to process pending round 2 messages
                self.process_pending_round2(gadget_vector)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Process any round 2 messages we have data for
    fn process_pending_round2(
        &mut self,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> anyhow::Result<()> {
        if self.phase2.is_none() {
            return Ok(());
        }

        let phase2 = self.phase2.as_mut().unwrap();
        let mut newly_processed = Vec::new();

        for (from, msg_bytes) in &self.round2_received {
            if self.round2_processed.contains(from) {
                continue;
            }

            // Deserialize and process
            let msg2 = CanonicalDeserialize::deserialize_compressed(&msg_bytes[..])
                .map_err(|e| anyhow::anyhow!("deserialize round2 failed: {:?}", e))?;
            
            phase2.receive_message2::<Blake2b512>(*from, msg2, gadget_vector)
                .map_err(|e| anyhow::anyhow!("receive_message2 failed: {:?}", e))?;

            newly_processed.push(*from);
        }

        for from in newly_processed {
            self.round2_processed.insert(from);
        }

        Ok(())
    }

    /// Check if Phase 2 is ready to finalize
    pub fn is_ready(&self) -> bool {
        if !self.participant_set.contains(&self.id) {
            return true;
        }

        let expected_count = self.participant_set.len() - 1;
        self.round1_processed.len() == expected_count &&
        self.round2_processed.len() == expected_count
    }

    /// Finalize Phase 2
    pub fn finalize(&mut self) -> anyhow::Result<Phase2Output<Fr>> {
        if !self.is_ready() {
            return Err(anyhow::anyhow!("Phase 2 not ready to finalize"));
        }

        let phase2 = self.phase2.take()
            .ok_or_else(|| anyhow::anyhow!("Phase 2 not initialized"))?;

        Ok(phase2.finish())
    }
}
