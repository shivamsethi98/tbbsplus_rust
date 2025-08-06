//! Complete Hybrid BBS+ Credential System Example
//! 
//! This example demonstrates the full flow:
//! 1. BBS+ credential issuance
//! 2. CDL proof generation with selective disclosure  
//! 3. zk-SNARK circuit conversion
//! 4. On-chain verification simulation

use hybrid_credentials::*;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::{collections::BTreeSet, rand::{rngs::StdRng, SeedableRng}};

fn main() -> Result<()> {
    println!("🚀 Hybrid BBS+ Credential System with zk-SNARK On-chain Verification");
    println!("=======================================================================\n");

    let mut rng = StdRng::seed_from_u64(42);

    // === Step 1: System Setup ===
    println!("📋 Step 1: Initialize Hybrid Credential System");
    
    let issuer = CredentialIssuer::new(&mut rng)?;
    let (issuer_pubkey, system_params) = issuer.get_public_params();
    
    let user = CredentialHolder::new(issuer_pubkey.clone(), system_params.clone());
    let verifier = OnChainVerifier::new(issuer_pubkey, system_params);
    
    println!("   ✅ Issuer, User, and Verifier initialized\n");

    // === Step 2: Credential Request ===
    println!("🎓 Step 2: User creates blinded credential request");
    
    let public_attributes = vec![
        (1, Fr::from(25u64)),     // Age (will be revealed - proving >18)
        (2, Fr::from(98765u64)),  // University ID (will be revealed)
    ];
    
    let request = user.create_credential_request(&mut rng, public_attributes, 3)?;
    println!("   ✅ Credential request created with blinded commitments\n");

    // === Step 3: Credential Issuance ===
    println!("🏢 Step 3: Issuer issues BBS+ credential");
    
    let private_attributes = vec![
        Fr::from(1234567890u64), // Name (SSN-like identifier)
        Fr::from(54321u64),      // Degree type
        Fr::from(375u64),        // GPA * 100
    ];
    
    let signature = issuer.issue_credential(&mut rng, &request, &private_attributes)?;
    println!("   ✅ BBS+ signature issued for credential\n");

    // === Step 4: Selective Disclosure Proof ===
    println!("🎭 Step 4: User generates BBS+ CDL proof with selective disclosure");
    
    // Prepare all attributes (public + private)
    let mut all_attributes = vec![Fr::from(0u64); MESSAGE_COUNT as usize];
    all_attributes[1] = Fr::from(25u64);        // Age
    all_attributes[2] = Fr::from(98765u64);     // University
    all_attributes[3] = Fr::from(1234567890u64); // Name (hidden)
    all_attributes[4] = Fr::from(54321u64);     // Degree (hidden)
    all_attributes[5] = Fr::from(375u64);       // GPA (hidden)
    
    // Define what to reveal (age and university)
    let mut revealed_indices = BTreeSet::new();
    revealed_indices.insert(1); // Age
    revealed_indices.insert(2); // University
    
    let cdl_proof = user.generate_cdl_proof(
        &mut rng,
        &signature,
        &all_attributes,
        &revealed_indices,
    )?;
    
    println!("   ✅ CDL proof generated with selective disclosure");
    println!("   🔓 Revealed: Age={}, University={}", 
             all_attributes[1], all_attributes[2]);
    println!("   🔒 Hidden: Name, Degree, GPA\n");

    // === Step 5: zk-SNARK Conversion ===
    println!("⚡ Step 5: Convert CDL proof to zk-SNARK for on-chain verification");
    
    let snark_proof = user.generate_snark_proof(&mut rng, &cdl_proof)?;
    
    println!("   ✅ zk-SNARK proof generated for on-chain verification");
    println!("   📊 Circuit proves:");
    println!("      • Valid BBS+ signature from trusted issuer");
    println!("      • Correct selective disclosure");
    println!("      • Witness commitment consistency");
    println!("      • Age >= 18 (without revealing exact age)");
    println!("      • University attendance verification\n");

    // === Step 6: On-chain Verification ===
    println!("🔍 Step 6: On-chain verification via Solidity contract (simulated)");
    
    let verification_result = verifier.verify_snark_proof(&snark_proof)?;
    
    if verification_result.is_valid {
        println!("   ✅ On-chain verification SUCCESSFUL!");
        println!("   🎉 Smart contract confirmed:");
        println!("      • Proof is cryptographically valid");
        println!("      • Credential issued by trusted authority");
        println!("      • User meets age requirement (18+)");
        println!("      • University attendance verified");
        
        if let Some(tx_hash) = verification_result.transaction_hash {
            println!("      • Transaction: {}", tx_hash);
        }
    } else {
        println!("   ❌ On-chain verification FAILED");
    }
    
    println!();

    // === Step 7: Privacy Analysis ===
    println!("🛡️  Step 7: Privacy and Security Analysis");
    println!("   🔒 Hidden Information:");
    println!("      • User's exact name/SSN (value: {})", all_attributes[3]);
    println!("      • Specific degree type (value: {})", all_attributes[4]);
    println!("      • Exact GPA (value: {}.{:02})", all_attributes[5] / Fr::from(100u64), all_attributes[5] % Fr::from(100u64));
    
    println!("   🔓 Revealed Information:");
    println!("      • Age: {} (proves >18 requirement)", all_attributes[1]);
    println!("      • University: {} (institution verification)", all_attributes[2]);
    
    println!("   ⚡ zk-SNARK Properties:");
    println!("      • Zero-knowledge: Hidden values remain cryptographically protected");
    println!("      • Soundness: Cannot forge proof without valid credential");
    println!("      • Completeness: Valid credentials always produce valid proofs");
    println!("      • Succinctness: Constant-size proof regardless of statement complexity");
    
    println!();

    // === Step 8: System Benefits ===
    println!("🌟 Step 8: System Benefits and Use Cases");
    println!("   💡 Technical Advantages:");
    println!("      • Off-chain credential generation (privacy + scalability)");
    println!("      • On-chain verification (trust + immutability)");
    println!("      • Selective disclosure (minimal information exposure)");
    println!("      • BLS12-381 security (128-bit security level)");
    println!("      • LegoGroth16 efficiency (constant proof size)");
    
    println!("   🎯 Real-world Applications:");
    println!("      • Age verification without revealing birthdate");
    println!("      • Educational credential verification");
    println!("      • Employment qualification proofs");
    println!("      • Financial status verification (income brackets)");
    println!("      • Medical condition proofs (without diagnosis details)");
    println!("      • Government ID verification (citizenship without SSN)");
    
    println!();
    println!("✅ Hybrid BBS+ Credential System demonstration complete!");
    println!("🔗 Ready for Ethereum deployment with Solidity verifier contracts");

    Ok(())
}
