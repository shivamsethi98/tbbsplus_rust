# Threshold BBS+ Signature System in Rust

A comprehensive implementation of **Threshold BBS+ signatures** and **anonymous credentials** in Rust, featuring distributed key generation, multi-party computation protocols, and zero-knowledge proofs for selective disclosure.

## 🎯 Overview

This codebase implements advanced cryptographic protocols for privacy-preserving credential systems based on the BBS+ signature scheme. The system enables:

- **Threshold Issuance**: Multiple issuers can collaboratively issue credentials without any single party knowing the full signing key
- **Anonymous Credentials**: Users can prove possession of valid credentials without revealing their identity
- **Selective Disclosure**: Zero-knowledge proofs allow revealing only specific attributes while keeping others private
- **Distributed Trust**: No single point of failure through threshold cryptography

## 📚 Key Papers Implemented

1. **BBS+ Signatures**: [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://eprint.iacr.org/2016/663)
2. **BBS Signatures**: [Revisiting BBS Signatures](https://eprint.iacr.org/2023/275)
3. **Threshold BBS+**: [Threshold BBS+ Signatures for Distributed Anonymous Credential Issuance](https://eprint.iacr.org/2023/602)
4. **Coconut**: [Security Analysis of Coconut, an Attribute-Based Credential Scheme with Threshold Issuance](https://eprint.iacr.org/2022/011)

## 🏗️ Architecture

```
tbbsplus_rust/
├── crypto/                      # Core cryptographic libraries
│   ├── bbs_plus/               # BBS and BBS+ signature implementations
│   │   ├── signature/          # Basic signature operations
│   │   ├── proof/              # Zero-knowledge proofs
│   │   └── threshold/          # Threshold signature protocols
│   ├── coconut/                # Coconut threshold credentials
│   ├── schnorr_pok/            # Schnorr proofs of knowledge
│   ├── secret_sharing_and_dkg/ # Shamir secret sharing & DKG
│   ├── oblivious_transfer/     # OT protocols for MPC
│   └── ...                     # Additional crypto primitives
├── examples/                    # Demonstration examples
│   ├── basic_credential.rs     # Simple credential issuance
│   ├── blind_credential.rs     # Blind signature protocol
│   ├── selective_disclosure.rs # Zero-knowledge selective reveal
│   └── threshold_system/       # Threshold signature demos
└── hybrid_credentials/          # Hybrid on/off-chain system
```

## 🚀 Key Features

### 1. **BBS+ Signatures**
- Full implementation of BBS+ signature scheme
- Support for both G1 and G2 variants
- Efficient batch verification
- Deterministic and randomized signing

### 2. **Threshold Signatures**
- Distributed key generation (DKG)
- Three-phase threshold signing protocol:
  - **Phase 1**: Randomness generation (independent of messages)
  - **Phase 2**: MPC multiplication protocol
  - **Phase 3**: Signature share generation
- Batch signing support for efficiency
- Based on oblivious transfer (OT) protocols

### 3. **Zero-Knowledge Proofs**
- Proof of knowledge of signature (PoK)
- Selective disclosure of attributes
- Predicate proofs (range proofs, equality)
- Multiple proof protocols (CDL, IETF variants)

### 4. **Anonymous Credentials**
- Blind issuance protocols
- Unlinkable multi-show credentials
- Attribute-based credentials
- Revocation support via accumulators

### 5. **Advanced Features**
- **Coconut**: Threshold issuance with enhanced privacy
- **Delegatable Credentials**: Credential delegation chains
- **Verifiable Encryption**: Encrypted credentials with proofs
- **Short Group Signatures**: Compact anonymous signatures

## 📖 Examples

### Basic Credential Issuance
```rust
// Create signature parameters (by trusted party)
let params = SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(
    b"CredentialSystem",
    message_count,
);

// Issuer generates keypair
let keypair = KeypairG2::generate_using_rng(&mut rng, &params);

// Create and sign credential
let messages = vec![name, age, university, degree, gpa];
let signature = SignatureG1::new(&mut rng, &messages, &keypair.secret_key, &params)?;

// Verify credential
signature.verify(&messages, keypair.public_key, params)?;
```

### Selective Disclosure
```rust
// User creates zero-knowledge proof revealing only selected attributes
let revealed_indices = BTreeSet::from([1, 2]); // Reveal age and university

let proof = PoKOfSignatureG1Protocol::init(
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

// Verifier checks proof with only revealed messages
proof.verify(&revealed_messages, &challenge, public_key, params)?;
```

### Threshold Signing
```rust
// Phase 1: Generate randomness (can be pre-computed)
let (phase1, commitments, zero_shares) = Phase1::init_for_bbs_plus(
    &mut rng, batch_size, signer_id, others, protocol_id
)?;

// Phase 2: MPC multiplication
let (phase2, messages) = Phase2::init(
    &mut rng, signer_id, masked_keys, masked_r, base_ot, others, params
)?;

// Phase 3: Generate signature share
let sig_share = BBSPlusSignatureShare::new(
    &messages, sig_index, &phase1_output, &phase2_output, &params
)?;

// Aggregate shares to form complete signature
let signature = BBSPlusSignatureShare::aggregate(sig_shares)?;
```

## 🔧 Getting Started

### Prerequisites
- Rust 1.70+ (edition 2021)
- Cargo

### Building
```bash
# Clone the repository
git clone <repository-url>
cd tbbsplus_rust

# Build the project
cargo build --release

# Run tests
cargo test

# Run examples
cargo run --example basic_credential
cargo run --example selective_disclosure
cargo run --example threshold_demo_simple
cargo run --example threshold_demo1
```

## 🧪 Running Examples

### Basic Credential System
```bash
cargo run --example basic_credential
```
Demonstrates simple credential issuance and verification.

### Selective Disclosure
```bash
cargo run --example selective_disclosure
```
Shows zero-knowledge proofs for revealing only specific attributes.

### Threshold Signatures (Simple)
```bash
cargo run --example threshold_demo_simple
```
Basic threshold signature without full MPC protocol.

### Threshold Signatures (Full MPC)
```bash
cargo run --example threshold_demo1
```
Complete threshold signing with distributed key generation and MPC.

## 🔒 Security Considerations

- **Cryptographic Assumptions**: Based on Strong Diffie-Hellman (SDH) and Decisional Diffie-Hellman (DDH) assumptions
- **Pairing-Friendly Curves**: Uses BLS12-381 curve for optimal security and performance
- **Side-Channel Resistance**: Constant-time operations where applicable
- **Randomness**: Requires secure random number generation

## 📊 Performance

The implementation is optimized for:
- **Batch Operations**: Multiple signatures can be generated/verified together
- **Parallelization**: MPC phases can run concurrently across signers
- **Pre-computation**: Phase 1 & 2 can be done offline before messages are known
- **Efficient Pairings**: Optimized pairing operations on BLS12-381

## 🤝 Use Cases

1. **Digital Identity Systems**: Privacy-preserving identity verification
2. **Access Control**: Anonymous authentication with attribute-based policies
3. **Supply Chain**: Confidential credential verification
4. **Healthcare**: Private medical credentials
5. **Education**: Anonymous academic transcripts
6. **DeFi**: Privacy-preserving KYC/AML compliance

## 🛠️ Development Status

This codebase represents a research implementation of threshold BBS+ signatures. Key components:

- ✅ **Core BBS/BBS+ signatures** - Complete
- ✅ **Zero-knowledge proofs** - Complete
- ✅ **Threshold protocols** - Complete
- ✅ **Selective disclosure** - Complete
- 🚧 **Hybrid credentials** - In development
- 🚧 **Smart contract integration** - Planned

## 📝 License

This project uses cryptographic libraries from the [Dock Network](https://github.com/docknetwork/crypto) and follows their licensing terms.

## 🔗 References

- [BBS+ Signatures Paper](https://eprint.iacr.org/2016/663)
- [Threshold BBS+ Paper](https://eprint.iacr.org/2023/602)
- [Coconut Paper](https://eprint.iacr.org/2022/011)
- [Dock Crypto Library](https://github.com/docknetwork/crypto)

## ⚠️ Disclaimer

This is a research implementation. While the cryptographic primitives are well-tested, the codebase should undergo thorough security auditing before production use.
