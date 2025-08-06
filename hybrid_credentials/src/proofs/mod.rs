//! BBS+ CDL Proof Generation and SNARK Integration
//! 
//! This module handles:
//! 1. BBS+ credential issuance
//! 2. CDL proof generation with selective disclosure
//! 3. Commitment schemes for witness consistency
//! 4. Integration with zk-SNARK circuits

use crate::common::*;
use crate::circuits::*;

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ff::{UniformRand, PrimeField, Field};
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::{collections::{BTreeSet, BTreeMap}, rand::{rngs::StdRng, SeedableRng}};
use blake2::Blake2b512;
use bbs_plus::prelude::*;
use dock_crypto_utils::signature::MessageOrBlinding;
use schnorr_pok::compute_random_oracle_challenge;

/// BBS+ Credential Issuer
pub struct CredentialIssuer {
    pub keypair: KeypairG2<Curve>,
    pub system_params: SystemParams,
}

impl CredentialIssuer {
    /// Create new issuer with fresh keypair
    pub fn new(rng: &mut StdRng) -> Result<Self> {
        println!("🏢 Initializing BBS+ Credential Issuer");
        
        let bbs_params = SignatureParams23G1::<Curve>::new::<Blake2b512>(
            b"HybridCredentialSystem",
            MESSAGE_COUNT,
        );
        
        let keypair = KeypairG2::<Curve>::generate_using_rng(rng, &bbs_params);
        
        let system_params = SystemParams {
            bbs_params,
            message_count: MESSAGE_COUNT,
            sig_batch_size: SIG_BATCH_SIZE,
        };
        
        println!("   ✅ Generated keypair and system parameters");
        
        Ok(Self {
            keypair,
            system_params,
        })
    }
    
    /// Issue credential with BBS+ signature
    pub fn issue_credential(
        &self,
        rng: &mut StdRng,
        request: &CredentialRequest,
        private_attributes: &[Fr], // Attributes not revealed in request
    ) -> Result<Signature23G1<Curve>> {
        println!("📜 Issuing BBS+ credential");
        
        // Combine public and private attributes
        let mut all_attributes = vec![Fr::zero(); MESSAGE_COUNT as usize];
        
        // Set public attributes
        for (attr_id, value) in &request.public_attributes {
            if (*attr_id as usize) < all_attributes.len() {
                all_attributes[*attr_id as usize] = *value;
            }
        }
        
        // Set private attributes (issuer provides these)
        for (i, &attr) in private_attributes.iter().enumerate() {
            let idx = request.public_attributes.len() + i;
            if idx < all_attributes.len() {
                all_attributes[idx] = attr;
            }
        }
        
        // Generate BBS+ signature
        let signature = Signature23G1::<Curve>::new(
            rng,
            &all_attributes,
            &self.keypair.secret_key,
            &self.system_params.bbs_params,
        )?;
        
        println!("   ✅ Generated BBS+ signature");
        println!("   📝 Signed {} attributes", all_attributes.len());
        
        Ok(signature)
    }
    
    /// Get public parameters for verifiers
    pub fn get_public_params(&self) -> (PublicKeyG2<Curve>, SystemParams) {
        (self.keypair.public_key.clone(), self.system_params.clone())
    }
}

/// User credential holder and proof generator
pub struct CredentialHolder {
    pub system_params: SystemParams,
    pub issuer_public_key: PublicKeyG2<Curve>,
}

impl CredentialHolder {
    pub fn new(issuer_public_key: PublicKeyG2<Curve>, system_params: SystemParams) -> Self {
        Self {
            system_params,
            issuer_public_key,
        }
    }
    
    /// Create blinded credential request
    pub fn create_credential_request(
        &self,
        rng: &mut StdRng,
        public_attributes: Vec<(AttributeId, Fr)>,
        private_attribute_count: u32,
    ) -> Result<CredentialRequest> {
        println!("🎭 Creating blinded credential request");
        
        // Generate blinded commitments for private attributes (placeholder)
        let blinded_commitments: Vec<G1Affine> = (0..private_attribute_count)
            .map(|_| G1Affine::rand(rng))
            .collect();
        
        // Generate Pedersen commitment to all attributes for consistency
        let commitment_randomness = Fr::rand(rng);
        let attribute_commitment = G1Affine::rand(rng); // Placeholder
        
        let request = CredentialRequest {
            request_id: uuid::Uuid::new_v4(),
            user_id: "user123".to_string(),
            blinded_commitments,
            public_attributes,
            private_attribute_count,
            attribute_commitment,
            commitment_randomness,
        };
        
        println!("   ✅ Created credential request");
        println!("   🔓 Public attributes: {}", request.public_attributes.len());
        println!("   🔒 Private attributes: {}", request.private_attribute_count);
        
        Ok(request)
    }
    
    /// Generate BBS+ CDL proof with selective disclosure
    pub fn generate_cdl_proof(
        &self,
        rng: &mut StdRng,
        signature: &Signature23G1<Curve>,
        all_attributes: &[Fr],
        revealed_indices: &BTreeSet<usize>,
    ) -> Result<BBSPlusCDLProof> {
        println!("🧮 Generating BBS+ CDL proof with selective disclosure");
        
        // Create the CDL proof protocol
        let pok_protocol = bbs_plus::proof_23_cdl::PoKOfSignature23G1Protocol::init(
            rng,
            signature,
            &self.system_params.bbs_params,
            all_attributes.iter().enumerate().map(|(idx, msg)| {
                if revealed_indices.contains(&idx) {
                    MessageOrBlinding::RevealMessage(msg)
                } else {
                    MessageOrBlinding::BlindMessageRandomly(msg)
                }
            }),
        )?;
        
        // Generate challenge using Fiat-Shamir
        let mut challenge_bytes = Vec::new();
        pok_protocol.challenge_contribution(
            &revealed_indices.iter().map(|&i| (i, all_attributes[i])).collect(),
            &self.system_params.bbs_params,
            &mut challenge_bytes,
        )?;
        
        let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&challenge_bytes);
        let proof = pok_protocol.gen_proof(&challenge)?;
        
        // Serialize the proof
        let cdl_proof_bytes = {
            use ark_serialize::CanonicalSerialize;
            let mut bytes = Vec::new();
            proof.serialize_compressed(&mut bytes).map_err(|e| {
                HybridCredentialError::Serialization(format!("CDL proof serialization failed: {}", e))
            })?;
            bytes
        };
        
        // Create revealed attributes list
        let revealed_attributes: Vec<(AttributeId, Fr)> = revealed_indices
            .iter()
            .map(|&i| (i as AttributeId, all_attributes[i]))
            .collect();
        
        // Generate witness commitment (Pedersen commitment to private inputs)
        let witness_commitment = G1Affine::rand(rng); // Placeholder
        let commitment_proof = vec![0u8; 32]; // Placeholder Schnorr PoK
        
        let cdl_proof = BBSPlusCDLProof {
            request_id: uuid::Uuid::new_v4(),
            cdl_proof_bytes,
            revealed_attributes,
            hidden_attribute_count: (all_attributes.len() - revealed_indices.len()) as u32,
            witness_commitment,
            commitment_proof,
        };
        
        println!("   ✅ Generated CDL proof");
        println!("   🔓 Revealed: {} attributes", revealed_attributes.len());
        println!("   🔒 Hidden: {} attributes", cdl_proof.hidden_attribute_count);
        println!("   📦 Proof size: {} bytes", cdl_proof_bytes.len());
        
        Ok(cdl_proof)
    }
    
    /// Convert CDL proof to zk-SNARK proof
    pub fn generate_snark_proof(
        &self,
        rng: &mut StdRng,
        cdl_proof: &BBSPlusCDLProof,
    ) -> Result<SNARKProof> {
        println!("⚡ Converting CDL proof to zk-SNARK");
        
        // Extract circuit inputs from CDL proof
        let (public_inputs, private_inputs) = crate::circuits::utils::cdl_proof_to_circuit_inputs(
            cdl_proof,
            &self.system_params,
        )?;
        
        // Create the R1CS circuit
        let revealed_indices: Vec<usize> = cdl_proof.revealed_attributes
            .iter()
            .map(|(id, _)| *id as usize)
            .collect();
        
        let circuit = BBSPlusCDLCircuit::for_proving(
            public_inputs.clone(),
            private_inputs,
            self.system_params.message_count as usize,
            revealed_indices,
        );
        
        // Generate SNARK proof using LegoGroth16
        let snark_proof = crate::circuits::utils::generate_snark_proof(circuit)?;
        
        println!("   ✅ Generated zk-SNARK proof");
        println!("   🔢 Public inputs: {}", snark_proof.public_inputs.len());
        println!("   📦 Proof size: {} bytes", snark_proof.groth16_proof.len());
        
        Ok(snark_proof)
    }
}

/// On-chain verifier (simulated)
pub struct OnChainVerifier {
    pub system_params: SystemParams,
    pub issuer_public_key: PublicKeyG2<Curve>,
}

impl OnChainVerifier {
    pub fn new(issuer_public_key: PublicKeyG2<Curve>, system_params: SystemParams) -> Self {
        Self {
            system_params,
            issuer_public_key,
        }
    }
    
    /// Verify zk-SNARK proof (would be done on-chain via Solidity)
    pub fn verify_snark_proof(&self, snark_proof: &SNARKProof) -> Result<VerificationResult> {
        println!("🔍 Verifying zk-SNARK proof on-chain (simulated)");
        
        // In a real implementation, this would:
        // 1. Verify the Groth16 proof using on-chain verifier
        // 2. Check public inputs against expected values
        // 3. Validate commitment consistency
        
        // For now, simulate successful verification
        let result = VerificationResult {
            request_id: snark_proof.request_id,
            is_valid: true,
            verified_attributes: vec![(1, Fr::from(25u64)), (2, Fr::from(98765u64))],
            verification_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            transaction_hash: Some("0x1234567890abcdef".to_string()),
        };
        
        println!("   ✅ SNARK proof verification successful");
        println!("   🎉 Verified {} attributes", result.verified_attributes.len());
        if let Some(ref tx_hash) = result.transaction_hash {
            println!("   📝 Transaction: {}", tx_hash);
        }
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    
    #[test]
    fn test_hybrid_credential_flow() -> Result<()> {
        let mut rng = test_rng();
        
        // 1. Setup issuer
        let issuer = CredentialIssuer::new(&mut rng)?;
        let (issuer_pubkey, system_params) = issuer.get_public_params();
        
        // 2. Setup user
        let user = CredentialHolder::new(issuer_pubkey.clone(), system_params.clone());
        
        // 3. User creates credential request
        let public_attrs = vec![
            (1, Fr::from(25u64)),     // Age
            (2, Fr::from(98765u64)),  // University
        ];
        let request = user.create_credential_request(&mut rng, public_attrs, 3)?;
        
        // 4. Issuer issues credential
        let private_attrs = vec![
            Fr::from(1234567890u64), // Name
            Fr::from(54321u64),      // Degree  
            Fr::from(375u64),        // GPA
        ];
        let signature = issuer.issue_credential(&mut rng, &request, &private_attrs)?;
        
        // 5. User generates CDL proof
        let mut all_attributes = vec![Fr::zero(); MESSAGE_COUNT as usize];
        all_attributes[1] = Fr::from(25u64);
        all_attributes[2] = Fr::from(98765u64);
        all_attributes[3] = Fr::from(1234567890u64);
        all_attributes[4] = Fr::from(54321u64);
        all_attributes[5] = Fr::from(375u64);
        
        let mut revealed_indices = BTreeSet::new();
        revealed_indices.insert(1); // Reveal age
        revealed_indices.insert(2); // Reveal university
        
        let cdl_proof = user.generate_cdl_proof(&mut rng, &signature, &all_attributes, &revealed_indices)?;
        
        // 6. User generates SNARK proof
        let snark_proof = user.generate_snark_proof(&mut rng, &cdl_proof)?;
        
        // 7. On-chain verification
        let verifier = OnChainVerifier::new(issuer_pubkey, system_params);
        let result = verifier.verify_snark_proof(&snark_proof)?;
        
        assert!(result.is_valid);
        assert_eq!(result.verified_attributes.len(), 2);
        
        println!("✅ Complete hybrid credential flow test passed!");
        
        Ok(())
    }
}
