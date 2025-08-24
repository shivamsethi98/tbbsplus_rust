// Threshold signing coordinator with proper hybrid mesh integration
use std::collections::{BTreeMap, BTreeSet};
use ark_bls12_381::Fr;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::rand::SeedableRng;
use blake2::Blake2b512;
use sha3::Shake256;
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc::Receiver;
use anyhow::{Result, anyhow};

use bbs_plus::threshold::{
    threshold_bbs_plus::{Phase1Output as BBSPhase1Output, BBSPlusSignatureShare},
    multiplication_phase::{Phase2, Phase2Output},
    randomness_generation_phase::Phase1,
    ParticipantId,
};
use ark_bls12_381::Bls12_381;

use oblivious_transfer_protocols::ot_based_multiplication::{
    base_ot_multi_party_pairwise::BaseOTOutput,
    dkls18_mul_2p::MultiplicationOTEParams,
    dkls19_batch_mul_2p::GadgetVector,
};

use super::mesh_v2_simple::p2p::{MeshHandle, DirectMessage};

const KAPPA: u16 = 256;
const STATISTICAL_SECURITY_PARAMETER: u16 = 80;

// Message types for the protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolMessage {
    Phase1Commitment {
        from: ParticipantId,
        commitment: Vec<u8>,
        zero_commitments: BTreeMap<ParticipantId, Vec<u8>>,
    },
    Phase1Share {
        from: ParticipantId,
        to: ParticipantId,
        shares: Vec<u8>,
        zero_shares: Vec<u8>,
    },
    Phase2Round1 {
        from: ParticipantId,
        to: ParticipantId,
        data: Vec<u8>,
    },
    Phase2Round2 {
        from: ParticipantId,
        to: ParticipantId,
        data: Vec<u8>,
    },
    SignatureShare {
        from: ParticipantId,
        share: Vec<u8>,
    },
}

/// Main coordinator for threshold signing protocol
pub struct ThresholdCoordinator {
    // Identity
    pub id: ParticipantId,
    pub threshold: u16,
    pub total: u16,
    
    // Network
    mesh_handle: MeshHandle,
    broadcast_rx: Option<Receiver<Vec<u8>>>,
    direct_rx: Option<Receiver<DirectMessage>>,
    
    // Protocol state
    participant_set: BTreeSet<ParticipantId>,
    protocol_id: Vec<u8>,
    batch_size: u32,
    
    // Phase 1 state
    phase1: Option<Phase1<Fr, 256>>,
    phase1_commitments: BTreeMap<ParticipantId, (Vec<u8>, BTreeMap<ParticipantId, Vec<u8>>)>,
    phase1_shares: BTreeMap<ParticipantId, (Vec<u8>, Vec<u8>)>,
    phase1_output: Option<BBSPhase1Output<Fr>>,
    
    // Phase 2 state
    phase2: Option<Phase2<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>>,
    phase2_round1_received: BTreeMap<ParticipantId, Vec<u8>>,
    phase2_round2_received: BTreeMap<ParticipantId, Vec<u8>>,
    phase2_round1_processed: BTreeSet<ParticipantId>,
    phase2_round2_processed: BTreeSet<ParticipantId>,
    phase2_output: Option<Phase2Output<Fr>>,
    
    // Signature shares
    signature_shares: BTreeMap<ParticipantId, Vec<u8>>,
}

impl ThresholdCoordinator {
    pub fn new(
        id: ParticipantId,
        threshold: u16,
        total: u16,
        batch_size: u32,
        protocol_id: Vec<u8>,
        mesh_handle: MeshHandle,
        broadcast_rx: Receiver<Vec<u8>>,
        direct_rx: Receiver<DirectMessage>,
    ) -> Self {
        let participant_set: BTreeSet<ParticipantId> = (1..=threshold).collect();
        
        Self {
            id,
            threshold,
            total,
            mesh_handle,
            broadcast_rx: Some(broadcast_rx),
            direct_rx: Some(direct_rx),
            participant_set,
            protocol_id,
            batch_size,
            phase1: None,
            phase1_commitments: BTreeMap::new(),
            phase1_shares: BTreeMap::new(),
            phase1_output: None,
            phase2: None,
            phase2_round1_received: BTreeMap::new(),
            phase2_round2_received: BTreeMap::new(),
            phase2_round1_processed: BTreeSet::new(),
            phase2_round2_processed: BTreeSet::new(),
            phase2_output: None,
            signature_shares: BTreeMap::new(),
        }
    }
    
    /// Initialize and run Phase 1
    pub async fn run_phase1<R: ark_std::rand::RngCore>(
        &mut self,
        rng: &mut R,
        signing_key: &Fr,
    ) -> Result<()> {
        if !self.participant_set.contains(&self.id) {
            return Ok(()); // Not participating
        }
        
        println!("[Node {}] Starting Phase 1", self.id);
        
        // Initialize Phase 1
        let mut others = self.participant_set.clone();
        others.remove(&self.id);
        
        let (phase1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs_plus::<_, Blake2b512>(
            rng,
            self.batch_size,
            self.id,
            others.clone(),
            self.protocol_id.clone(),
        ).map_err(|e| anyhow!("Phase1 init failed: {:?}", e))?;
        
        self.phase1 = Some(phase1);
        
        // Serialize and broadcast commitment
        let mut comm_bytes = Vec::new();
        comm.serialize_compressed(&mut comm_bytes)?;
        
        let mut zero_comms_map = BTreeMap::new();
        for (pid, zc) in comm_zero {
            let mut zc_bytes = Vec::new();
            zc.serialize_compressed(&mut zc_bytes)?;
            zero_comms_map.insert(pid, zc_bytes);
        }
        
        let commitment_msg = ProtocolMessage::Phase1Commitment {
            from: self.id,
            commitment: comm_bytes,
            zero_commitments: zero_comms_map,
        };
        
        self.mesh_handle.broadcast(
            "phase1-commitments",
            serde_json::to_vec(&commitment_msg)?,
        ).await?;
        
        println!("[Node {}] Broadcast commitment", self.id);
        
        // Wait for all commitments
        self.collect_phase1_commitments().await?;
        
        // Send shares directly to each peer
        for peer_id in &others {
            let shares = self.phase1.as_ref().unwrap().get_comm_shares_and_salts();
            let zero_shares = self.phase1.as_ref().unwrap()
                .get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(peer_id);
            
            let mut shares_bytes = Vec::new();
            shares.serialize_compressed(&mut shares_bytes)?;
            
            let mut zero_shares_bytes = Vec::new();
            zero_shares.serialize_compressed(&mut zero_shares_bytes)?;
            
            let share_msg = ProtocolMessage::Phase1Share {
                from: self.id,
                to: *peer_id,
                shares: shares_bytes,
                zero_shares: zero_shares_bytes,
            };
            
            self.mesh_handle.send_to(
                *peer_id,
                serde_json::to_vec(&share_msg)?,
            ).await?;
            
            println!("[Node {}] Sent shares to Node {}", self.id, peer_id);
        }
        
        // Collect shares from others
        self.collect_phase1_shares().await?;
        
        // Finalize Phase 1
        let phase1 = self.phase1.take().unwrap();
        let output = phase1.finish_for_bbs_plus::<Blake2b512>(signing_key)
            .map_err(|e| anyhow!("Phase1 finish failed: {:?}", e))?;
        
        self.phase1_output = Some(output);
        println!("[Node {}] Phase 1 complete", self.id);
        
        Ok(())
    }
    
    /// Collect Phase 1 commitments from broadcast channel
    async fn collect_phase1_commitments(&mut self) -> Result<()> {
        let expected_count = self.participant_set.len() - 1;
        let mut rx = self.broadcast_rx.take().unwrap();
        
        while self.phase1_commitments.len() < expected_count {
            if let Some(data) = rx.recv().await {
                if let Ok(msg) = serde_json::from_slice::<ProtocolMessage>(&data) {
                    if let ProtocolMessage::Phase1Commitment { from, commitment, zero_commitments } = msg {
                        if from != self.id && self.participant_set.contains(&from) {
                            // Process commitment
                            if let Some(zc_for_me) = zero_commitments.get(&self.id) {
                                let comm_obj = CanonicalDeserialize::deserialize_compressed(&commitment[..])
                                    .map_err(|e| anyhow!("Deserialize commitment failed: {:?}", e))?;
                                let zc_obj = CanonicalDeserialize::deserialize_compressed(&zc_for_me[..])
                                    .map_err(|e| anyhow!("Deserialize zero commitment failed: {:?}", e))?;
                                
                                self.phase1.as_mut().unwrap()
                                    .receive_commitment(from, comm_obj, zc_obj)
                                    .map_err(|e| anyhow!("Receive commitment failed: {:?}", e))?;
                                
                                self.phase1_commitments.insert(from, (commitment, zero_commitments));
                                println!("[Node {}] Received commitment from Node {}", self.id, from);
                            }
                        }
                    }
                }
            }
        }
        
        self.broadcast_rx = Some(rx);
        Ok(())
    }
    
    /// Collect Phase 1 shares from direct messages
    async fn collect_phase1_shares(&mut self) -> Result<()> {
        let expected_count = self.participant_set.len() - 1;
        let mut rx = self.direct_rx.take().unwrap();
        
        while self.phase1_shares.len() < expected_count {
            if let Some(direct_msg) = rx.recv().await {
                if let Ok(msg) = serde_json::from_slice::<ProtocolMessage>(&direct_msg.data) {
                    if let ProtocolMessage::Phase1Share { from, to, shares, zero_shares } = msg {
                        if to == self.id && self.participant_set.contains(&from) {
                            // Process shares
                            let shares_obj: Vec<(Fr, [u8; 256])> = 
                                CanonicalDeserialize::deserialize_compressed(&shares[..])
                                .map_err(|e| anyhow!("Deserialize shares failed: {:?}", e))?;
                            let zero_shares_obj: Vec<(Fr, [u8; 256])> = 
                                CanonicalDeserialize::deserialize_compressed(&zero_shares[..])
                                .map_err(|e| anyhow!("Deserialize zero shares failed: {:?}", e))?;
                            
                            self.phase1.as_mut().unwrap()
                                .receive_shares::<Blake2b512>(from, shares_obj, zero_shares_obj)
                                .map_err(|e| anyhow!("Receive shares failed: {:?}", e))?;
                            
                            self.phase1_shares.insert(from, (shares, zero_shares));
                            println!("[Node {}] Received shares from Node {}", self.id, from);
                        }
                    }
                }
            }
        }
        
        self.direct_rx = Some(rx);
        Ok(())
    }
    
    /// Initialize and run Phase 2
    pub async fn run_phase2<R: ark_std::rand::RngCore>(
        &mut self,
        rng: &mut R,
        base_ot_output: BaseOTOutput,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<()> {
        if !self.participant_set.contains(&self.id) {
            return Ok(()); // Not participating
        }
        
        let phase1_output = self.phase1_output.as_ref()
            .ok_or_else(|| anyhow!("Phase 1 not complete"))?;
        
        println!("[Node {}] Starting Phase 2", self.id);
        
        // Initialize Phase 2
        let others: BTreeSet<ParticipantId> = phase1_output.others.iter().cloned().collect();
        
        let (phase2, messages) = Phase2::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::init::<_, Shake256>(
            rng,
            self.id,
            phase1_output.masked_signing_key_shares.clone(),
            phase1_output.masked_rs.clone(),
            base_ot_output,
            others.clone(),
            ote_params,
            gadget_vector,
        ).map_err(|e| anyhow!("Phase2 init failed: {:?}", e))?;
        
        self.phase2 = Some(phase2);
        
        // Send round 1 messages
        for (to_id, msg) in messages {
            let mut msg_bytes = Vec::new();
            msg.serialize_compressed(&mut msg_bytes)?;
            
            let round1_msg = ProtocolMessage::Phase2Round1 {
                from: self.id,
                to: to_id,
                data: msg_bytes,
            };
            
            self.mesh_handle.send_to(
                to_id,
                serde_json::to_vec(&round1_msg)?,
            ).await?;
            
            println!("[Node {}] Sent Phase2 round 1 to Node {}", self.id, to_id);
        }
        
        // Process round 1 and 2
        self.process_phase2_messages(gadget_vector).await?;
        
        // Finalize Phase 2
        let phase2 = self.phase2.take().unwrap();
        self.phase2_output = Some(phase2.finish());
        
        println!("[Node {}] Phase 2 complete", self.id);
        Ok(())
    }
    
    /// Process Phase 2 messages (both rounds)
    async fn process_phase2_messages(
        &mut self,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<()> {
        let expected_count = self.participant_set.len() - 1;
        let mut rx = self.direct_rx.take().unwrap();
        
        while self.phase2_round2_processed.len() < expected_count {
            if let Some(direct_msg) = rx.recv().await {
                if let Ok(msg) = serde_json::from_slice::<ProtocolMessage>(&direct_msg.data) {
                    match msg {
                        ProtocolMessage::Phase2Round1 { from, to, data } => {
                            if to == self.id && self.participant_set.contains(&from) {
                                self.phase2_round1_received.insert(from, data);
                                
                                // Try to process if we haven't already
                                if !self.phase2_round1_processed.contains(&from) {
                                    self.process_phase2_round1(from, gadget_vector).await?;
                                }
                            }
                        }
                        ProtocolMessage::Phase2Round2 { from, to, data } => {
                            if to == self.id && self.participant_set.contains(&from) {
                                self.phase2_round2_received.insert(from, data);
                                
                                // Try to process if we haven't already
                                if !self.phase2_round2_processed.contains(&from) {
                                    self.process_phase2_round2(from, gadget_vector)?;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        
        self.direct_rx = Some(rx);
        Ok(())
    }
    
    /// Process Phase 2 round 1 message and send round 2 response
    async fn process_phase2_round1(
        &mut self,
        from: ParticipantId,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<()> {
        if let Some(msg_bytes) = self.phase2_round1_received.get(&from) {
            let msg1 = CanonicalDeserialize::deserialize_compressed(&msg_bytes[..])
                .map_err(|e| anyhow!("Deserialize round1 failed: {:?}", e))?;
            
            let msg2 = self.phase2.as_mut().unwrap()
                .receive_message1::<Blake2b512, Shake256>(from, msg1, gadget_vector)
                .map_err(|e| anyhow!("Receive message1 failed: {:?}", e))?;
            
            self.phase2_round1_processed.insert(from);
            
            // Send round 2 response
            let mut msg2_bytes = Vec::new();
            msg2.serialize_compressed(&mut msg2_bytes)?;
            
            let round2_msg = ProtocolMessage::Phase2Round2 {
                from: self.id,
                to: from,
                data: msg2_bytes,
            };
            
            self.mesh_handle.send_to(
                from,
                serde_json::to_vec(&round2_msg)?,
            ).await?;
            
            println!("[Node {}] Processed round 1 from {} and sent round 2", self.id, from);
        }
        
        Ok(())
    }
    
    /// Process Phase 2 round 2 message
    fn process_phase2_round2(
        &mut self,
        from: ParticipantId,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<()> {
        if let Some(msg_bytes) = self.phase2_round2_received.get(&from) {
            let msg2 = CanonicalDeserialize::deserialize_compressed(&msg_bytes[..])
                .map_err(|e| anyhow!("Deserialize round2 failed: {:?}", e))?;
            
            self.phase2.as_mut().unwrap()
                .receive_message2::<Blake2b512>(from, msg2, gadget_vector)
                .map_err(|e| anyhow!("Receive message2 failed: {:?}", e))?;
            
            self.phase2_round2_processed.insert(from);
            println!("[Node {}] Processed round 2 from {}", self.id, from);
        }
        
        Ok(())
    }
    
    /// Generate signature share
    pub fn generate_signature_share(
        &self,
        messages: &[Fr],
        sig_index: usize,
        params: &bbs_plus::prelude::SignatureParamsG1<ark_bls12_381::Bls12_381>,
    ) -> Result<BBSPlusSignatureShare<Bls12_381>> {
        let phase1_output = self.phase1_output.as_ref()
            .ok_or_else(|| anyhow!("Phase 1 not complete"))?;
        let phase2_output = self.phase2_output.as_ref()
            .ok_or_else(|| anyhow!("Phase 2 not complete"))?;
        
        BBSPlusSignatureShare::new(
            messages,
            sig_index,
            phase1_output,
            phase2_output,
            params,
        ).map_err(|e| anyhow!("Generate signature share failed: {:?}", e))
    }
    
    /// Broadcast signature share
    pub async fn broadcast_signature_share(
        &mut self,
        share: &BBSPlusSignatureShare<Bls12_381>,
    ) -> Result<()> {
        let mut share_bytes = Vec::new();
        share.serialize_compressed(&mut share_bytes)?;
        
        let msg = ProtocolMessage::SignatureShare {
            from: self.id,
            share: share_bytes,
        };
        
        self.mesh_handle.broadcast(
            "signature-shares",
            serde_json::to_vec(&msg)?,
        ).await?;
        
        println!("[Node {}] Broadcast signature share", self.id);
        Ok(())
    }
    
    /// Collect signature shares from all participants
    pub async fn collect_signature_shares(&mut self) -> Result<Vec<BBSPlusSignatureShare<Bls12_381>>> {
        let expected_count = self.participant_set.len() - 1;
        let mut rx = self.broadcast_rx.take().unwrap();
        let mut shares = Vec::new();
        
        // Add our own share first
        if let Ok(our_share) = self.generate_signature_share(
            &[Fr::from(1)], // Dummy messages for collection
            0,
            &bbs_plus::prelude::SignatureParamsG1::generate_using_rng(
                &mut ark_std::rand::rngs::StdRng::seed_from_u64(0),
                1
            ),
        ) {
            shares.push(our_share);
        }
        
        while self.signature_shares.len() < expected_count {
            if let Some(data) = rx.recv().await {
                if let Ok(msg) = serde_json::from_slice::<ProtocolMessage>(&data) {
                    if let ProtocolMessage::SignatureShare { from, share } = msg {
                        if from != self.id && self.participant_set.contains(&from) {
                            let share_obj = CanonicalDeserialize::deserialize_compressed(&share[..])
                                .map_err(|e| anyhow!("Deserialize signature share failed: {:?}", e))?;
                            
                            shares.push(share_obj);
                            self.signature_shares.insert(from, share);
                            println!("[Node {}] Received signature share from Node {}", self.id, from);
                        }
                    }
                }
            }
        }
        
        self.broadcast_rx = Some(rx);
        Ok(shares)
    }
}
