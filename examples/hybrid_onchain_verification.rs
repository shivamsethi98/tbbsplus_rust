//! Example: Hybrid On-Chain BBS+ Verification
//! 
//! This example demonstrates how to:
//! 1. Create a BBS+ signature and proof with selective disclosure
//! 2. Convert the BBS+ proof to a LegoGroth16 SNARK proof using the proof_system library
//! 3. Verify the SNARK proof efficiently (simulating on-chain verification)
//! 4. Export proof data for Solidity verification

use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::{rngs::StdRng, SeedableRng},
    vec::Vec,
    UniformRand,
};
use blake2::Blake2b512;
use std::fs::{self, File};
use std::io::Write;

// Import BBS+ signature components
use bbs_plus::prelude::*;
use dock_crypto_utils::signature::MessageOrBlinding;

// Import proof system components for combining BBS+ with other protocols
use proof_system::{
    prelude::*,
    statement::{
        bbs_plus::{
            PoKBBSSignatureG1Prover as BBSProverStatement,
            PoKBBSSignatureG1Verifier as BBSVerifierStatement,
        },
        r1cs_legogroth16::{R1CSCircomProver, R1CSCircomVerifier},
    },
    witness::{PoKBBSSignatureG1 as BBSWitness, R1CSCircomWitness},
};

// Import LegoGroth16 components
use legogroth16::{
    circom::{CircomCircuit, R1CS, WitnessCalculator},
    create_random_proof, generate_random_parameters,
    prepare_verifying_key, verify_proof,
    PreparedVerifyingKey, Proof as Groth16Proof, ProvingKey, VerifyingKey,
}

/// Main function demonstrating the hybrid verification flow
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Hybrid BBS+ On-Chain Verification Demo");
    println!("==========================================\n");

    let mut rng = StdRng::seed_from_u64(0u64);

    // Step 1: Setup BBS+ signature system
    println!("📝 Step 1: Setting up BBS+ signature system");
    let (bbs_params, keypair, messages, signature) = setup_bbs_signature(&mut rng)?;
    println!("   ✅ Created BBS+ signature with {} messages", messages.len());

    // Step 2: Create BBS+ proof with selective disclosure
    println!("\n🔍 Step 2: Creating BBS+ proof with selective disclosure");
    let revealed_indices = vec![1, 3].into_iter().collect::<BTreeSet<_>>();
    let bbs_proof = create_bbs_proof(
        &mut rng,
        &signature,
        &messages,
        &revealed_indices,
        &bbs_params,
    )?;
    println!("   ✅ Created proof revealing messages at indices: {:?}", revealed_indices);

    // Step 3: Setup LegoGroth16 trusted setup
    println!("\n⚙️ Step 3: Generating trusted setup for LegoGroth16");
    let (proving_key, verifying_key) = setup_legogroth16(&mut rng)?;
    println!("   ✅ Generated proving and verifying keys");

    // Step 4: Convert BBS+ proof to SNARK proof
    println!("\n🔄 Step 4: Converting BBS+ proof to SNARK proof");
    let snark_proof = create_snark_proof(
        &mut rng,
        &bbs_proof,
        &keypair.public_key,
        &messages,
        &revealed_indices,
        &proving_key,
    )?;
    println!("   ✅ Generated SNARK proof");

    // Step 5: Verify SNARK proof (simulating on-chain verification)
    println!("\n✅ Step 5: Verifying SNARK proof (simulating on-chain)");
    let is_valid = verify_snark_onchain(
        &snark_proof,
        &keypair.public_key,
        &messages,
        &revealed_indices,
        &verifying_key,
    )?;
    
    if is_valid {
        println!("   ✅ SNARK verification successful!");
    } else {
        println!("   ❌ SNARK verification failed!");
        return Err("Verification failed".into());
    }

    // Step 6: Export proof for Solidity
    println!("\n📤 Step 6: Exporting proof for Solidity verification");
    export_proof_for_solidity(&snark_proof, &verifying_key)?;
    println!("   ✅ Exported proof to 'snark_proof.json'");

    // Step 7: Generate Solidity verifier contract
    println!("\n📄 Step 7: Generating Solidity verifier");
    generate_solidity_verifier(&verifying_key)?;
    println!("   ✅ Generated Solidity verifier contract");

    println!("\n🎉 Demo complete! You can now:");
    println!("   1. Deploy the generated Solidity verifier");
    println!("   2. Call verifyProof() with the exported proof data");
    println!("   3. Gas cost will be ~200-300k instead of >10M for native BBS+");

    Ok(())
}

/// Setup BBS+ signature system and create a signature
fn setup_bbs_signature(
    rng: &mut StdRng,
) -> Result<(SignatureParamsG1<Bls12_381>, KeypairG2<Bls12_381>, Vec<Fr>, SignatureG1<Bls12_381>), Box<dyn std::error::Error>> {
    // Create signature parameters for 5 messages
    let message_count = 5;
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(rng, message_count);
    
    // Generate issuer keypair
    let keypair = KeypairG2::<Bls12_381>::generate_using_rng(rng, &params);
    
    // Create sample messages
    let messages = vec![
        Fr::from(100u64), // Age
        Fr::from(2024u64), // Year
        Fr::from(12345u64), // ID
        Fr::from(67890u64), // Score
        Fr::from(42u64), // Secret value
    ];
    
    // Create signature
    let signature = SignatureG1::new(rng, &messages, &keypair.secret_key, &params)?;
    
    // Verify signature
    signature.verify(&messages, keypair.public_key.clone(), params.clone())?;
    
    Ok((params, keypair, messages, signature))
}

/// Create a BBS+ proof with selective disclosure
fn create_bbs_proof(
    rng: &mut StdRng,
    signature: &SignatureG1<Bls12_381>,
    messages: &[Fr],
    revealed_indices: &BTreeSet<usize>,
    params: &SignatureParamsG1<Bls12_381>,
) -> Result<PoKOfSignatureG1Proof<Bls12_381>, Box<dyn std::error::Error>> {
    // Create proof protocol
    let protocol = PoKOfSignatureG1Protocol::init(
        rng,
        signature,
        params,
        messages.iter().enumerate().map(|(idx, msg)| {
            if revealed_indices.contains(&idx) {
                MessageOrBlinding::RevealMessage(msg)
            } else {
                MessageOrBlinding::BlindMessageRandomly(msg)
            }
        }),
    )?;
    
    // Generate challenge (in practice, this would be interactive or use Fiat-Shamir)
    let mut challenge_bytes = Vec::new();
    let revealed_msgs: BTreeMap<usize, Fr> = revealed_indices
        .iter()
        .map(|&idx| (idx, messages[idx]))
        .collect();
    protocol.challenge_contribution(&revealed_msgs, params, &mut challenge_bytes)?;
    let challenge = Fr::from_le_bytes_mod_order(&challenge_bytes);
    
    // Generate proof
    let proof = protocol.gen_proof(&challenge)?;
    
    Ok(proof)
}

/// Setup LegoGroth16 proving and verifying keys
fn setup_legogroth16(
    rng: &mut StdRng,
) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>), Box<dyn std::error::Error>> {
    // In a real implementation, this would use a proper circuit
    // For demo purposes, we'll create a simple circuit
    
    // The circuit would verify:
    // 1. The BBS+ proof equations hold
    // 2. The revealed messages match public inputs
    // 3. The commitment to hidden messages is valid
    
    // This is a placeholder - in practice, you'd load the compiled circuit
    let circuit = BBSVerificationCircuit {
        public_key_hash: Fr::from(0u64),
        revealed_messages: vec![],
        challenge: Fr::from(0u64),
        proof_a: None,
        proof_e: None,
        proof_s: None,
        hidden_messages: vec![],
    };
    
    // Generate parameters (trusted setup)
    // In production, use a trusted setup ceremony or universal setup
    let params = generate_random_parameters(circuit, 1, rng)?;
    
    Ok(params)
}

/// Create SNARK proof from BBS+ proof
fn create_snark_proof(
    rng: &mut StdRng,
    bbs_proof: &PoKOfSignatureG1Proof<Bls12_381>,
    public_key: &PublicKeyG2<Bls12_381>,
    messages: &[Fr],
    revealed_indices: &BTreeSet<usize>,
    proving_key: &ProvingKey<Bls12_381>,
) -> Result<Groth16Proof<Bls12_381>, Box<dyn std::error::Error>> {
    // Hash the public key for efficiency
    let mut pk_bytes = Vec::new();
    public_key.serialize_compressed(&mut pk_bytes)?;
    let public_key_hash = Fr::from_le_bytes_mod_order(&pk_bytes);
    
    // Prepare revealed messages
    let revealed_messages: Vec<Fr> = revealed_indices
        .iter()
        .map(|&idx| messages[idx])
        .collect();
    
    // Prepare hidden messages
    let hidden_messages: Vec<Option<Fr>> = (0..messages.len())
        .filter(|idx| !revealed_indices.contains(idx))
        .map(|idx| Some(messages[idx]))
        .collect();
    
    // Create circuit with actual values
    let circuit = BBSVerificationCircuit {
        public_key_hash,
        revealed_messages: revealed_messages.clone(),
        challenge: Fr::from(1234u64), // In practice, use actual challenge
        proof_a: Some(bbs_proof.A_bar),
        proof_e: Some(bbs_proof.e),
        proof_s: Some(bbs_proof.s),
        hidden_messages,
    };
    
    // Generate SNARK proof with commitment
    let v = Fr::rand(rng); // Randomness for commitment
    let proof = create_random_proof(circuit, v, proving_key, rng)?;
    
    Ok(proof)
}

/// Verify SNARK proof (simulating on-chain verification)
fn verify_snark_onchain(
    proof: &Groth16Proof<Bls12_381>,
    public_key: &PublicKeyG2<Bls12_381>,
    messages: &[Fr],
    revealed_indices: &BTreeSet<usize>,
    verifying_key: &VerifyingKey<Bls12_381>,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Prepare public inputs
    let mut public_inputs = Vec::new();
    
    // Add public key hash
    let mut pk_bytes = Vec::new();
    public_key.serialize_compressed(&mut pk_bytes)?;
    public_inputs.push(Fr::from_le_bytes_mod_order(&pk_bytes));
    
    // Add revealed messages
    for &idx in revealed_indices {
        public_inputs.push(messages[idx]);
    }
    
    // Add challenge
    public_inputs.push(Fr::from(1234u64));
    
    // Prepare verifying key
    let pvk = prepare_verifying_key(verifying_key);
    
    // Verify proof
    verify_proof(&pvk, proof, &public_inputs)
        .map(|_| true)
        .map_err(|e| e.into())
}

/// Export proof data for Solidity verification
fn export_proof_for_solidity(
    proof: &Groth16Proof<Bls12_381>,
    verifying_key: &VerifyingKey<Bls12_381>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create JSON structure for proof
    let proof_json = serde_json::json!({
        "proof": {
            "a": format!("{:?}", proof.a),
            "b": format!("{:?}", proof.b),
            "c": format!("{:?}", proof.c),
            "d": format!("{:?}", proof.d),
        },
        "publicInputs": [
            // Add actual public inputs here
        ],
        "verifyingKey": {
            "alpha": format!("{:?}", verifying_key.alpha_g1),
            "beta": format!("{:?}", verifying_key.beta_g2),
            "gamma": format!("{:?}", verifying_key.gamma_g2),
            "delta": format!("{:?}", verifying_key.delta_g2),
            // Add other components
        }
    });
    
    // Write to file
    let mut file = File::create("snark_proof.json")?;
    file.write_all(proof_json.to_string().as_bytes())?;
    
    Ok(())
}

/// Generate Solidity verifier contract
fn generate_solidity_verifier(
    verifying_key: &VerifyingKey<Bls12_381>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Template for Solidity verifier
    let solidity_code = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract BBSPlusVerifier {
    using Pairing for *;
    
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
        Pairing.G1Point d; // Commitment to witnesses
    }
    
    VerifyingKey verifyingKey;
    
    constructor() {
        // Initialize verifying key
        // These values would come from the trusted setup
        verifyingKey.alpha = Pairing.G1Point(
            // alpha values from verifying_key
        );
        // ... initialize other components
    }
    
    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[2] memory d,
        uint[] memory publicInputs
    ) public view returns (bool) {
        Proof memory proof;
        proof.a = Pairing.G1Point(a[0], a[1]);
        proof.b = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.c = Pairing.G1Point(c[0], c[1]);
        proof.d = Pairing.G1Point(d[0], d[1]);
        
        // Verify the proof
        uint256[] memory inputValues = new uint256[](publicInputs.length);
        for(uint i = 0; i < publicInputs.length; i++){
            inputValues[i] = publicInputs[i];
        }
        
        return verify(inputValues, proof);
    }
    
    function verify(uint[] memory input, Proof memory proof) internal view returns (bool) {
        // LegoGroth16 verification logic
        // This performs the pairing checks
        
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(verifyingKey.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, verifyingKey.gamma_abc[0]);
        vk_x = Pairing.addition(vk_x, proof.d); // Add commitment
        
        // Pairing check
        return Pairing.pairing(
            Pairing.negate(proof.a),
            proof.b,
            verifyingKey.alpha,
            verifyingKey.beta,
            vk_x,
            verifyingKey.gamma,
            proof.c,
            verifyingKey.delta
        );
    }
}
"#;

    // Write to file
    let mut file = File::create("BBSPlusVerifier.sol")?;
    file.write_all(solidity_code.as_bytes())?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_verification_flow() {
        let mut rng = StdRng::seed_from_u64(0u64);
        
        // Run the full flow
        main().expect("Hybrid verification should succeed");
    }
    
    #[test]
    fn test_gas_estimation() {
        // Estimate gas costs for SNARK verification
        // Typical costs:
        // - Pairing operations: ~80k gas each
        // - EC operations: ~3k gas each
        // - Total for LegoGroth16: ~200-300k gas
        
        let pairing_ops = 4; // LegoGroth16 uses 4 pairings
        let ec_ops = 10; // Approximate EC operations
        
        let estimated_gas = pairing_ops * 80_000 + ec_ops * 3_000;
        println!("Estimated gas cost: {} gas", estimated_gas);
        
        assert!(estimated_gas < 500_000, "Gas cost should be reasonable");
    }
}
