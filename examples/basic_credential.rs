use ark_bls12_381::Bls12_381;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use blake2::Blake2b512;
use bbs_plus::prelude::*;

/// This example demonstrates a basic anonymous credential workflow with BBS+ signatures:
/// 1. Trusted Third Party (TTP) creates signature parameters
/// 2. Issuer generates a keypair
/// 3. User creates credential request with messages
/// 4. Issuer issues a BBS+ signature over the credential
/// 5. User verifies the signature

fn main() -> Result<(), BBSPlusError> {
    println!("🚀 Basic Anonymous Credential System with BBS+ Signatures");
    println!("=========================================================\n");

    // Initialize random number generator
    let mut rng = StdRng::seed_from_u64(42);

    // === Step 1: TTP creates signature parameters ===
    println!("📋 Step 1: TTP creates signature parameters");
    
    // For this example, we'll support 5 attributes in a credential:
    // - Name, Age, University, Degree, GPA
    let message_count = 5;
    
    // Create signature parameters deterministically using a known label
    let params = SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(
        b"AnonymousCredentialSystem",
        message_count,
    );
    
    // Validate the parameters
    assert!(params.is_valid(), "Invalid signature parameters");
    println!("   ✅ Created signature parameters for {} attributes", message_count);
    println!("   📝 Parameters are valid and ready for use\n");

    // === Step 2: Issuer generates keypair ===
    println!("🏛️  Step 2: Issuer generates keypair");
    
    let issuer_keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &params);
    
    // Validate the keypair
    assert!(issuer_keypair.public_key.is_valid(), "Invalid public key");
    println!("   ✅ Issuer generated valid keypair");
    println!("   🔑 Public key is ready for distribution\n");

    // === Step 3: User prepares credential messages ===
    println!("👤 Step 3: User prepares credential attributes");
    
    // In a real system, these would be hashed appropriately to field elements
    // For this demo, we'll use simple field elements
    type Fr = <Bls12_381 as ark_ec::pairing::Pairing>::ScalarField;
    
    let messages = vec![
        Fr::from(1234567890u64),  // Name (hashed)
        Fr::from(25u64),          // Age
        Fr::from(98765u64),       // University (hashed)
        Fr::from(54321u64),       // Degree (hashed)
        Fr::from(375u64),         // GPA (scaled by 100, e.g., 3.75)
    ];
    
    println!("   📄 Prepared {} credential attributes:", messages.len());
    println!("   • Name: {} (hashed)", messages[0]);
    println!("   • Age: {}", messages[1]);
    println!("   • University: {} (hashed)", messages[2]);
    println!("   • Degree: {} (hashed)", messages[3]);
    println!("   • GPA: {} (scaled)", messages[4]);
    println!();

    // === Step 4: Issuer issues BBS+ signature ===
    println!("✍️  Step 4: Issuer creates BBS+ signature");
    
    let signature = SignatureG1::<Bls12_381>::new(
        &mut rng,
        &messages,
        &issuer_keypair.secret_key,
        &params,
    )?;
    
    // Validate the signature
    assert!(signature.is_non_zero(), "Invalid signature - zero element");
    println!("   ✅ Issuer successfully created BBS+ signature");
    println!("   📝 Signature components:");
    println!("      • A: Valid group element");
    println!("      • e: Random challenge");
    println!("      • s: Random salt");
    println!();

    // === Step 5: User verifies the signature ===
    println!("🔍 Step 5: User verifies the signature");
    
    signature.verify(&messages, issuer_keypair.public_key.clone(), params.clone())?;
    
    println!("   ✅ Signature verification successful!");
    println!("   🎉 The credential is valid and authentic\n");

    // === Additional demonstrations ===
    println!("🔬 Additional Features:");
    
    // Demonstrate that signature verification fails with wrong messages
    let mut wrong_messages = messages.clone();
    wrong_messages[1] = Fr::from(30u64); // Change age from 25 to 30
    
    match signature.verify(&wrong_messages, issuer_keypair.public_key.clone(), params.clone()) {
        Ok(_) => panic!("Should have failed with wrong messages"),
        Err(_) => println!("   ✅ Correctly rejected signature with tampered attributes"),
    }
    
    // Demonstrate that signature verification fails with wrong public key
    let wrong_keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &params);
    match signature.verify(&messages, wrong_keypair.public_key.clone(), params.clone()) {
        Ok(_) => panic!("Should have failed with wrong public key"),
        Err(_) => println!("   ✅ Correctly rejected signature with wrong issuer public key"),
    }

    println!("\n🎯 Summary:");
    println!("   • TTP established trusted parameters");
    println!("   • Issuer can issue credentials using BBS+ signatures");
    println!("   • Users can verify credential authenticity");
    println!("   • System detects tampering and forgery attempts");
    println!("\n💡 Next steps would include:");
    println!("   • Implementing zero-knowledge proofs for selective disclosure");
    println!("   • Adding Ethereum smart contract integration");
    println!("   • Creating a blind signature protocol for privacy");

    Ok(())
}
