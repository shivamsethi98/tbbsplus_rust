use ark_bls12_381::Bls12_381;
use ark_std::{collections::BTreeMap, rand::{rngs::StdRng, SeedableRng}};
use blake2::Blake2b512;
use bbs_plus::prelude::*;
use ark_ff::UniformRand;

/// This example demonstrates a more sophisticated anonymous credential workflow
/// with blind signatures where some attributes are hidden from the issuer:
/// 1. TTP creates signature parameters
/// 2. Issuer generates a keypair  
/// 3. User creates a commitment to some secret attributes
/// 4. User reveals only some attributes to the issuer
/// 5. Issuer creates a blind signature over committed + known attributes
/// 6. User unblinds the signature and verifies it

fn main() -> Result<(), BBSPlusError> {
    println!("🕶️  Advanced Anonymous Credential System with Blind BBS+ Signatures");
    println!("=====================================================================\n");

    // Initialize random number generator
    let mut rng = StdRng::seed_from_u64(42);

    // === Step 1: TTP creates signature parameters ===
    println!("📋 Step 1: TTP creates signature parameters");
    
    // Support 6 attributes: Name, Age, University, Degree, GPA, SSN
    let message_count = 6;
    
    let params = SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(
        b"BlindCredentialSystem",
        message_count,
    );
    
    assert!(params.is_valid(), "Invalid signature parameters");
    println!("   ✅ Created signature parameters for {} attributes", message_count);
    println!();

    // === Step 2: Issuer generates keypair ===
    println!("🏛️  Step 2: Issuer generates keypair");
    
    let issuer_keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &params);
    assert!(issuer_keypair.public_key.is_valid(), "Invalid public key");
    println!("   ✅ Issuer generated valid keypair\n");

    // === Step 3: User prepares attributes (some secret, some revealed) ===
    println!("👤 Step 3: User prepares credential attributes");
    
    type Fr = <Bls12_381 as ark_ec::pairing::Pairing>::ScalarField;
    
    // All user's attributes
    let all_messages = vec![
        Fr::from(1234567890u64),  // Name (will be hidden)
        Fr::from(25u64),          // Age (will be revealed)
        Fr::from(98765u64),       // University (will be revealed)
        Fr::from(54321u64),       // Degree (will be revealed) 
        Fr::from(375u64),         // GPA (will be hidden)
        Fr::from(987654321u64),   // SSN (will be hidden)
    ];
    
    // User decides to hide: Name (index 0), GPA (index 4), SSN (index 5)
    // User reveals: Age (index 1), University (index 2), Degree (index 3)
    
    let hidden_indices = vec![0, 4, 5];  // Name, GPA, SSN
    let revealed_indices = vec![1, 2, 3]; // Age, University, Degree
    
    println!("   📄 User's complete attribute set:");
    println!("   • Name: {} (🔒 will be hidden)", all_messages[0]);
    println!("   • Age: {} (🔓 will be revealed)", all_messages[1]);
    println!("   • University: {} (🔓 will be revealed)", all_messages[2]);
    println!("   • Degree: {} (🔓 will be revealed)", all_messages[3]);
    println!("   • GPA: {} (🔒 will be hidden)", all_messages[4]);
    println!("   • SSN: {} (🔒 will be hidden)", all_messages[5]);
    println!();

    // === Step 4: User creates commitment to hidden attributes ===
    println!("🎭 Step 4: User creates commitment to hidden attributes");
    
    // Create blinding factor
    let blinding = Fr::rand(&mut rng);
    
    // Create map of hidden messages
    let hidden_messages: BTreeMap<usize, &Fr> = hidden_indices
        .iter()
        .map(|&i| (i, &all_messages[i]))
        .collect();
    
    // Create Pedersen commitment to hidden messages
    let commitment = params.commit_to_messages(hidden_messages, &blinding)?;
    
    println!("   🔐 Created Pedersen commitment to hidden attributes");
    println!("   🎲 Used random blinding factor");
    println!("   📍 Commitment: Valid group element");
    println!();

    // === Step 5: User reveals some attributes to issuer ===
    println!("📤 Step 5: User reveals selected attributes to issuer");
    
    let revealed_messages: BTreeMap<usize, &Fr> = revealed_indices
        .iter()
        .map(|&i| (i, &all_messages[i]))
        .collect();
    
    println!("   📋 Revealed to issuer:");
    for (&index, &message) in &revealed_messages {
        let attr_name = match index {
            1 => "Age",
            2 => "University", 
            3 => "Degree",
            _ => "Unknown",
        };
        println!("   • {}: {}", attr_name, message);
    }
    println!("   🔒 Hidden attributes remain in commitment");
    println!();

    // === Step 6: Issuer creates blind signature ===
    println!("✍️  Step 6: Issuer creates blind signature");
    
    // In practice, issuer would verify user's proof of knowledge of committed values
    // For this demo, we assume the issuer trusts the commitment
    
    let blind_signature = SignatureG1::<Bls12_381>::new_with_committed_messages(
        &mut rng,
        &commitment,
        revealed_messages,
        &issuer_keypair.secret_key,
        &params,
    )?;
    
    println!("   ✅ Issuer created blind signature");
    println!("   📝 Signature covers both revealed and committed attributes");
    println!();

    // === Step 6.5: Security test (before unblinding) ===
    println!("🔬 Step 6.5: Security test - Blind signature should fail with full messages");
    
    // 1. Blind signature should NOT verify with all messages
    match blind_signature.clone().verify(&all_messages, issuer_keypair.public_key.clone(), params.clone()) {
        Ok(_) => panic!("Blind signature should not verify with unblinded messages"),
        Err(_) => println!("   ✅ Blind signature correctly fails without unblinding"),
    }
    println!();

    // === Step 7: User unblinds the signature ===
    println!("🔓 Step 7: User unblinds the signature");
    
    let unblinded_signature = blind_signature.unblind(&blinding);
    
    println!("   ✅ Successfully unblinded the signature");
    println!("   🔑 Signature now covers all original attributes");
    println!();

    // === Step 8: User verifies the complete signature ===
    println!("🔍 Step 8: User verifies the complete signature");
    
    unblinded_signature.verify(&all_messages, issuer_keypair.public_key.clone(), params.clone())?;
    
    println!("   ✅ Signature verification successful!");
    println!("   🎉 All attributes (hidden + revealed) are properly signed");
    println!();

    // === Step 9: Demonstrate remaining security properties ===
    println!("🔬 Step 9: Additional security demonstrations");
    
    // Create revealed messages map again for testing
    let revealed_messages_again: BTreeMap<usize, &Fr> = revealed_indices
        .iter()
        .map(|&i| (i, &all_messages[i]))
        .collect();
    
    // Create a fresh blind signature for testing different blinding
    let test_blind_signature = SignatureG1::<Bls12_381>::new_with_committed_messages(
        &mut rng,
        &commitment,
        revealed_messages_again,
        &issuer_keypair.secret_key,
        &params,
    )?;
    
    // 2. Wrong blinding should produce invalid signature
    println!("   🧪 Testing that wrong blinding produces invalid signature:");
    let wrong_blinding = Fr::rand(&mut rng);
    let wrong_unblinded = test_blind_signature.unblind(&wrong_blinding);
    match wrong_unblinded.verify(&all_messages, issuer_keypair.public_key.clone(), params.clone()) {
        Ok(_) => panic!("Should fail with wrong blinding"),
        Err(_) => println!("   ✅ Wrong blinding correctly produces invalid signature"),
    }
    
    // 3. Tampering with committed messages should fail
    println!("   🧪 Testing tamper resistance:");
    let mut tampered_messages = all_messages.clone();
    tampered_messages[0] = Fr::from(9999999999u64); // Change hidden name
    match unblinded_signature.verify(&tampered_messages, issuer_keypair.public_key.clone(), params.clone()) {
        Ok(_) => panic!("Should fail with tampered messages"),
        Err(_) => println!("   ✅ Correctly detected tampering with hidden attributes"),
    }

    println!("\n🎯 Summary of Blind Signature Protocol:");
    println!("   • User can hide sensitive attributes from issuer");
    println!("   • Issuer can still issue valid signatures over hidden data");
    println!("   • Only user can unblind and use the final signature");
    println!("   • Security is maintained against tampering and forgery");
    
    println!("\n💡 This enables privacy-preserving credentials where:");
    println!("   • Universities can issue degrees without knowing SSN");
    println!("   • Age verification without revealing exact birthdate");
    println!("   • Selective disclosure of attributes as needed");

    Ok(())
}
