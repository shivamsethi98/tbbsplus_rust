//! Example: BBS+ Proof System Integration Demo
//! 
//! This example demonstrates:
//! 1. Creating BBS+ signatures and proofs with selective disclosure
//! 2. Using the proof_system library to combine BBS+ with other protocols
//! 3. Showing how this would integrate with on-chain verification

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::{rngs::StdRng, SeedableRng},
};
use blake2::Blake2b512;

// Import BBS+ signature components
use ::bbs_plus::prelude::*;
use dock_crypto_utils::signature::MessageOrBlinding;

// Import proof system components
use proof_system::{
    prelude::*,
    statement::bbs_plus::{
        PoKBBSSignatureG1Prover as BBSProverStatement,
        PoKBBSSignatureG1Verifier as BBSVerifierStatement,
    },
    witness::PoKBBSSignatureG1 as BBSWitness,
};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🚀 BBS+ Proof System Integration Demo");
    println!("======================================\n");

    let mut rng = StdRng::seed_from_u64(0u64);

    // Step 1: Setup BBS+ signature system
    println!("📝 Step 1: Setting up BBS+ signature system");
    let message_count = 5;
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, message_count);
    let keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &params);
    
    let messages = vec![
        Fr::from(100u64),   // Age
        Fr::from(2024u64),  // Year  
        Fr::from(12345u64), // ID (will be hidden)
        Fr::from(67890u64), // Score (will be hidden)
        Fr::from(42u64),    // Secret (will be hidden)
    ];
    
    let signature = SignatureG1::new(&mut rng, &messages, &keypair.secret_key, &params)
        .map_err(|e| format!("Failed to create signature: {:?}", e))?;
    
    signature.verify(&messages, keypair.public_key.clone(), params.clone())
        .map_err(|e| format!("Failed to verify signature: {:?}", e))?;
    
    println!("   ✅ Created and verified BBS+ signature");

    // Step 2: Create BBS+ proof with selective disclosure
    println!("\n🔍 Step 2: Creating selective disclosure proof");
    
    // Reveal only age and year (indices 0 and 1)
    let revealed_indices = vec![0, 1].into_iter().collect::<BTreeSet<_>>();
    
    let protocol = PoKOfSignatureG1Protocol::init(
        &mut rng,
        &signature,
        &params,
        messages.iter().enumerate().map(|(idx, msg)| {
            if revealed_indices.contains(&idx) {
                MessageOrBlinding::RevealMessage(msg)
            } else {
                MessageOrBlinding::BlindMessageRandomly(msg)
            }
        }),
    ).map_err(|e| format!("Failed to init protocol: {:?}", e))?;
    
    // Generate challenge
    let mut challenge_bytes = Vec::new();
    let revealed_msgs: BTreeMap<usize, Fr> = revealed_indices
        .iter()
        .map(|&idx| (idx, messages[idx]))
        .collect();
    
    protocol.challenge_contribution(&revealed_msgs, &params, &mut challenge_bytes)
        .map_err(|e| format!("Failed to create challenge: {:?}", e))?;
    
    let challenge = Fr::from_le_bytes_mod_order(&challenge_bytes);
    
    let proof = protocol.gen_proof(&challenge)
        .map_err(|e| format!("Failed to generate proof: {:?}", e))?;
    
    println!("   ✅ Generated proof revealing:");
    println!("      • Age: {}", messages[0]);
    println!("      • Year: {}", messages[1]);
    println!("      • Hidden: ID, Score, Secret");

    // Step 3: Verify the proof
    println!("\n✅ Step 3: Verifying selective disclosure proof");
    
    proof.verify(&revealed_msgs, &challenge, keypair.public_key.clone(), params.clone())
        .map_err(|e| format!("Failed to verify proof: {:?}", e))?;
    
    println!("   ✅ Proof verified successfully!");

    // Step 4: Use proof_system to combine with other protocols
    println!("\n🔧 Step 4: Using proof_system for combined proofs");
    
    // Create a proof that combines BBS+ signature with other predicates
    let mut statements = Statements::<Bls12_381>::new();
    
    // Add BBS+ signature statement
    statements.add(BBSProverStatement::new_statement_from_params(
        params.clone(),
        revealed_msgs.clone(), 
    ));
    
    // Create witnesses - only include unrevealed messages
    let mut witnesses = Witnesses::new();
    let unrevealed_messages: BTreeMap<usize, Fr> = messages
        .iter()
        .enumerate()
        .filter(|(idx, _)| !revealed_indices.contains(idx))
        .map(|(idx, msg)| (idx, *msg))
        .collect();
    witnesses.add(BBSWitness::new_as_witness(
        signature.clone(),
        unrevealed_messages,
    ));
    
    // Create proof specification
    let proof_spec = ProofSpec::new(
        statements.clone(),
        MetaStatements::new(),
        vec![],
        None,
    );
    proof_spec.validate()
        .map_err(|e| format!("Invalid proof spec: {:?}", e))?;
    
    // Generate combined proof
    let combined_proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses,
        None,
        Default::default(),
    ).map_err(|e| format!("Failed to create combined proof: {:?}", e))?.0;
    
    println!("   ✅ Created combined proof using proof_system");

    // Step 5: Verify combined proof
    println!("\n🔍 Step 5: Verifying combined proof");
    
    // Create verifier's statements
    let mut verifier_statements = Statements::<Bls12_381>::new();
    verifier_statements.add(BBSVerifierStatement::new_statement_from_params(
        params.clone(),
        keypair.public_key.clone(),
        revealed_msgs,
    ));
    
    let verifier_proof_spec = ProofSpec::new(
        verifier_statements,
        MetaStatements::new(),
        vec![],
        None,
    );
    
    combined_proof.verify::<StdRng, Blake2b512>(
        &mut rng,
        verifier_proof_spec,
        None,
        Default::default(),
    ).map_err(|e| format!("Failed to verify combined proof: {:?}", e))?;
    
    println!("   ✅ Combined proof verified successfully!");

    // Step 6: Show how this would integrate with on-chain verification
    println!("\n💡 Step 6: On-chain verification strategy");
    println!("   For on-chain verification, we would:");
    println!("   1. Convert this BBS+ proof to a SNARK using LegoGroth16");
    println!("   2. The SNARK circuit would verify the BBS+ equations");
    println!("   3. Public inputs: revealed messages + public key hash");
    println!("   4. Private witnesses: proof components + hidden messages");
    println!("   5. On-chain cost: ~200-300k gas instead of >10M");
    
    // Demonstrate proof serialization
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("Failed to serialize: {:?}", e))?;
    
    println!("\n📊 Proof Statistics:");
    println!("   • BBS+ proof size: {} bytes", proof_bytes.len());
    println!("   • Revealed messages: {}", revealed_indices.len());
    println!("   • Hidden messages: {}", messages.len() - revealed_indices.len());
    
    println!("\n🎉 Demo complete!");
    println!("   This demonstrates the foundation for on-chain verification:");
    println!("   • Selective disclosure works");
    println!("   • Proof system integration works");
    println!("   • Next step: Implement the SNARK circuit for on-chain verification");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bbs_proof_system() {
        main().expect("Demo should run successfully");
    }
}
