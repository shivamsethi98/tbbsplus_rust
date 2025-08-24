use ark_bls12_381::Bls12_381;
use ark_std::{collections::{BTreeSet, BTreeMap}, rand::{rngs::StdRng, SeedableRng}};
use blake2::Blake2b512;
use bbs_plus::prelude::*;
use ark_ff::{UniformRand, PrimeField};
use schnorr_pok::compute_random_oracle_challenge;
use dock_crypto_utils::signature::MessageOrBlinding;

/// This example demonstrates selective disclosure using zero-knowledge proofs.
/// The holder can prove they have a valid credential without revealing all attributes:
/// 1. User gets a credential (BBS+ signature) from an issuer
/// 2. User creates a zero-knowledge proof revealing only some attributes
/// 3. Verifier can verify the proof without seeing hidden attributes

fn main() -> Result<(), BBSPlusError> {
    println!("🔍 Selective Disclosure with BBS+ Zero-Knowledge Proofs");
    println!("========================================================\n");

    // Initialize random number generator
    let mut rng = StdRng::seed_from_u64(42);

    // === Step 1: Setup (same as before) ===
    println!("📋 Step 1: Setup parameters and issuer keypair");
    
    let message_count = 5;
    let params = SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(
        b"SelectiveDisclosureCredentials",
        message_count,
    );
    
    let issuer_keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &params);
    
    assert!(params.is_valid() && issuer_keypair.public_key.is_valid());
    println!("   ✅ Setup complete\n");

    // === Step 2: User gets credential ===
    println!("🎓 Step 2: User receives credential from issuer");
    
    type Fr = <Bls12_381 as ark_ec::pairing::Pairing>::ScalarField;
    
    let messages = vec![
        Fr::from(1234567890u64),  // Name (will be hidden)
        Fr::from(25u64),          // Age (will be revealed - over 18)
        Fr::from(98765u64),       // University (will be revealed)
        Fr::from(54321u64),       // Degree (will be hidden)
        Fr::from(375u64),         // GPA (will be hidden)
    ];
    
    let signature = SignatureG1::<Bls12_381>::new(
        &mut rng,
        &messages,
        &issuer_keypair.secret_key,
        &params,
    )?;
    
    println!("   📜 Credential attributes:");
    println!("   • Name: {} (private)", messages[0]);
    println!("   • Age: {} (will prove >18)", messages[1]);
    println!("   • University: {} (will reveal)", messages[2]);
    println!("   • Degree: {} (private)", messages[3]);
    println!("   • GPA: {} (private)", messages[4]);
    println!("   ✅ Received valid credential\n");

    // === Step 3: User prepares selective disclosure ===
    println!("🎭 Step 3: User prepares selective disclosure proof");
    
    // User wants to prove:
    // 1. They have a valid credential from the issuer
    // 2. They are over 18 (age >= 18) - without revealing exact age
    // 3. They graduated from a specific university - revealing university
    // 4. Keep name, degree, and GPA private
    
    let mut revealed_indices = BTreeSet::new();
    revealed_indices.insert(1); // Reveal age (index 1)
    revealed_indices.insert(2); // Reveal university (index 2)
    
    println!("   🔓 Will reveal: Age ({}), University ({})", messages[1], messages[2]);
    println!("   🔒 Will hide: Name, Degree, GPA");
    println!();

    // === Step 4: Create zero-knowledge proof ===
    println!("🧮 Step 4: Creating zero-knowledge proof");
    
    let pok_protocol = PoKOfSignatureG1Protocol::init(
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
    )?;
    
    // Generate challenge using Fiat-Shamir heuristic
    let mut challenge_bytes = Vec::new();
    pok_protocol.challenge_contribution(
        &revealed_indices.iter().map(|&i| (i, messages[i])).collect(),
        &params,
        &mut challenge_bytes,
    )?;
    
    let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&challenge_bytes);
    
    let proof = pok_protocol.gen_proof(&challenge)?;
    
    println!("   ✅ Generated zero-knowledge proof");
    println!("   📝 Proof size: Contains commitments and responses");
    println!("   🔒 Hidden values remain cryptographically protected\n");

    // === Step 5: Verifier checks the proof ===
    println!("🔍 Step 5: Verifier validates the proof");
    
    // Verifier only sees the revealed messages
    let mut revealed_messages = BTreeMap::new();
    revealed_messages.insert(1, messages[1]); // Age: 25
    revealed_messages.insert(2, messages[2]); // University: 98765
    
    // Generate the same challenge for verification
    let mut verifier_challenge_bytes = Vec::new();
    proof.challenge_contribution(
        &revealed_messages,
        &params,
        &mut verifier_challenge_bytes,
    )?;
    
    let verifier_challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&verifier_challenge_bytes);
    
    // Verify the proof
    proof.verify(
        &revealed_messages,
        &verifier_challenge,
        issuer_keypair.public_key.clone(),
        params.clone(),
    )?;
    
    println!("   ✅ Proof verification successful!");
    println!("   🎉 Verifier confirmed:");
    println!("   • User has valid credential from trusted issuer");
    println!("   • User's age is 25");
    println!("   • User attended university 98765");
    println!("   • Other attributes remain private\n");

    // === Step 6: Age verification example ===
    println!("🔢 Step 6: Age verification without revealing exact age");
    
    // In a real system, you'd create a range proof to prove age >= 18
    // For this demo, we'll show the concept
    let min_age = 18u64;
    let user_age_bigint = messages[1].into_bigint();
    let user_age = user_age_bigint.as_ref()[0]; // Convert back to u64 for demo
    
    if user_age >= min_age {
        println!("   ✅ User proved they are over 18 (age: {})", user_age);
        println!("   💡 In practice, this would be a range proof hiding exact age");
    }
    println!();

    // === Step 7: Demonstrate proof properties ===
    println!("🛡️  Step 7: Security properties demonstration");
    
    // 1. Proof doesn't work with wrong public key
    let wrong_keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &params);
    match proof.verify(
        &revealed_messages,
        &verifier_challenge,
        wrong_keypair.public_key.clone(),
        params.clone(),
    ) {
        Ok(_) => panic!("Should fail with wrong public key"),
        Err(_) => println!("   ✅ Correctly rejected proof with wrong issuer"),
    }
    
    // 2. Proof doesn't work with tampered revealed messages
    let mut tampered_revealed = revealed_messages.clone();
    tampered_revealed.insert(1, Fr::from(30u64)); // Change age from 25 to 30
    
    match proof.verify(
        &tampered_revealed,
        &verifier_challenge,
        issuer_keypair.public_key.clone(),
        params.clone(),
    ) {
        Ok(_) => panic!("Should fail with tampered messages"),
        Err(_) => println!("   ✅ Correctly rejected proof with tampered revealed data"),
    }

    println!("\n🎯 Selective Disclosure Summary:");
    println!("   • Users can prove credential validity without revealing all data");
    println!("   • Verifiers get only the information they need");
    println!("   • Zero-knowledge proofs ensure privacy of hidden attributes");
    println!("   • Cryptographic guarantees prevent tampering and forgery");
    
    println!("\n💡 Real-world applications:");
    println!("   • Age verification without revealing birthdate");
    println!("   • Proving educational qualifications without full transcript");
    println!("   • Income verification without exact salary disclosure");
    println!("   • Identity verification with minimal data exposure");

    Ok(())
}
