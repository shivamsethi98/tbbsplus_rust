// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./verifier.sol";

/**
 * @title HybridCredentialSystem
 * @dev On-chain verification of BBS+ credentials via zk-SNARKs
 * 
 * This contract provides:
 * 1. Registration of trusted issuers
 * 2. Verification of zk-SNARK proofs for BBS+ CDL proofs
 * 3. Storage of verification results
 * 4. Access control for credential verification
 */
contract HybridCredentialSystem {
    
    // Events
    event IssuerRegistered(address indexed issuer, bytes32 publicKeyHash);
    event CredentialVerified(
        bytes32 indexed requestId, 
        address indexed verifier,
        bool isValid,
        uint256 timestamp
    );
    event AttributesRevealed(
        bytes32 indexed requestId,
        uint256[] attributeIds,
        uint256[] attributeValues
    );
    
    // Structs
    struct TrustedIssuer {
        address issuerAddress;
        bytes32 publicKeyHash;
        bool isActive;
        uint256 registrationTime;
    }
    
    struct VerificationResult {
        bytes32 requestId;
        address verifier;
        bool isValid;
        bytes32 issuerPubKeyHash;
        bytes32 attributesHash;
        uint256 timestamp;
        bool exists;
    }
    
    // State variables
    mapping(address => TrustedIssuer) public trustedIssuers;
    mapping(bytes32 => VerificationResult) public verificationResults;
    
    address public owner;
    Verifier public immutable zkVerifier;
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    modifier onlyTrustedIssuer() {
        require(
            trustedIssuers[msg.sender].isActive, 
            "Only trusted issuers can call this function"
        );
        _;
    }
    
    constructor(address _zkVerifier) {
        owner = msg.sender;
        zkVerifier = Verifier(_zkVerifier);
    }
    
    /**
     * @dev Register a new trusted issuer
     * @param issuerAddress Address of the issuer
     * @param publicKeyHash Hash of the issuer's BBS+ public key
     */
    function registerIssuer(
        address issuerAddress, 
        bytes32 publicKeyHash
    ) external onlyOwner {
        require(issuerAddress != address(0), "Invalid issuer address");
        require(publicKeyHash != bytes32(0), "Invalid public key hash");
        
        trustedIssuers[issuerAddress] = TrustedIssuer({
            issuerAddress: issuerAddress,
            publicKeyHash: publicKeyHash,
            isActive: true,
            registrationTime: block.timestamp
        });
        
        emit IssuerRegistered(issuerAddress, publicKeyHash);
    }
    
    /**
     * @dev Deactivate a trusted issuer
     * @param issuerAddress Address of the issuer to deactivate
     */
    function deactivateIssuer(address issuerAddress) external onlyOwner {
        require(trustedIssuers[issuerAddress].isActive, "Issuer not active");
        trustedIssuers[issuerAddress].isActive = false;
    }
    
    /**
     * @dev Verify a zk-SNARK proof for BBS+ CDL credential
     * @param requestId Unique identifier for this verification request
     * @param proof The zk-SNARK proof (Groth16)
     * @param publicInputs Public inputs to the circuit
     * @return isValid Whether the proof is valid
     */
    function verifyCredential(
        bytes32 requestId,
        uint[8] calldata proof, // Groth16 proof: [a.x, a.y, b.x[0], b.x[1], b.y[0], b.y[1], c.x, c.y]
        uint[] calldata publicInputs
    ) external returns (bool isValid) {
        require(requestId != bytes32(0), "Invalid request ID");
        require(publicInputs.length >= 5, "Insufficient public inputs");
        
        // Extract public inputs
        uint issuerPubKeyHash = publicInputs[0];
        uint revealedAttrsHash = publicInputs[1]; 
        uint witnessCommitmentX = publicInputs[2];
        uint witnessCommitmentY = publicInputs[3];
        uint challengeHash = publicInputs[4];
        
        // Verify the zk-SNARK proof
        isValid = zkVerifier.verifyTx(proof, publicInputs);
        
        // Store verification result
        verificationResults[requestId] = VerificationResult({
            requestId: requestId,
            verifier: msg.sender,
            isValid: isValid,
            issuerPubKeyHash: bytes32(issuerPubKeyHash),
            attributesHash: bytes32(revealedAttrsHash),
            timestamp: block.timestamp,
            exists: true
        });
        
        emit CredentialVerified(requestId, msg.sender, isValid, block.timestamp);
        
        return isValid;
    }
    
    /**
     * @dev Record revealed attributes (called after successful verification)
     * @param requestId The verification request ID
     * @param attributeIds Array of revealed attribute IDs
     * @param attributeValues Array of revealed attribute values
     */
    function recordRevealedAttributes(
        bytes32 requestId,
        uint256[] calldata attributeIds,
        uint256[] calldata attributeValues
    ) external {
        require(
            verificationResults[requestId].exists, 
            "Verification result does not exist"
        );
        require(
            verificationResults[requestId].isValid, 
            "Cannot record attributes for invalid proof"
        );
        require(
            attributeIds.length == attributeValues.length, 
            "Attribute arrays length mismatch"
        );
        
        emit AttributesRevealed(requestId, attributeIds, attributeValues);
    }
    
    /**
     * @dev Check if an issuer is trusted and active
     * @param issuerAddress Address to check
     * @return isActive Whether the issuer is trusted and active
     */
    function isIssuerTrusted(address issuerAddress) external view returns (bool isActive) {
        return trustedIssuers[issuerAddress].isActive;
    }
    
    /**
     * @dev Get verification result for a request
     * @param requestId The verification request ID
     * @return result The verification result
     */
    function getVerificationResult(bytes32 requestId) 
        external 
        view 
        returns (VerificationResult memory result) 
    {
        require(verificationResults[requestId].exists, "Verification result does not exist");
        return verificationResults[requestId];
    }
    
    /**
     * @dev Verify a credential and check issuer trust in one call
     * @param requestId Unique identifier for this verification request
     * @param proof The zk-SNARK proof
     * @param publicInputs Public inputs to the circuit
     * @param issuerAddress Address of the credential issuer
     * @return isValid Whether the credential is valid and from trusted issuer
     */
    function verifyTrustedCredential(
        bytes32 requestId,
        uint[8] calldata proof,
        uint[] calldata publicInputs,
        address issuerAddress
    ) external returns (bool isValid) {
        // Check if issuer is trusted
        require(trustedIssuers[issuerAddress].isActive, "Issuer not trusted");
        
        // Verify the proof
        isValid = this.verifyCredential(requestId, proof, publicInputs);
        
        // Additional check: ensure the public key hash matches
        if (isValid) {
            bytes32 expectedPubKeyHash = trustedIssuers[issuerAddress].publicKeyHash;
            bytes32 proofPubKeyHash = bytes32(publicInputs[0]);
            require(expectedPubKeyHash == proofPubKeyHash, "Public key hash mismatch");
        }
        
        return isValid;
    }
    
    /**
     * @dev Emergency function to pause the contract
     */
    bool public paused = false;
    
    function pause() external onlyOwner {
        paused = true;
    }
    
    function unpause() external onlyOwner {
        paused = false;
    }
    
    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }
    
    // Add whenNotPaused to critical functions
    function verifyCredential(
        bytes32 requestId,
        uint[8] calldata proof,
        uint[] calldata publicInputs
    ) external whenNotPaused returns (bool isValid) {
        // Implementation moved to internal function
        return _verifyCredential(requestId, proof, publicInputs);
    }
    
    function _verifyCredential(
        bytes32 requestId,
        uint[8] calldata proof,
        uint[] calldata publicInputs
    ) internal returns (bool isValid) {
        require(requestId != bytes32(0), "Invalid request ID");
        require(publicInputs.length >= 5, "Insufficient public inputs");
        
        // Verify the zk-SNARK proof
        isValid = zkVerifier.verifyTx(proof, publicInputs);
        
        // Store verification result
        verificationResults[requestId] = VerificationResult({
            requestId: requestId,
            verifier: msg.sender,
            isValid: isValid,
            issuerPubKeyHash: bytes32(publicInputs[0]),
            attributesHash: bytes32(publicInputs[1]),
            timestamp: block.timestamp,
            exists: true
        });
        
        emit CredentialVerified(requestId, msg.sender, isValid, block.timestamp);
        
        return isValid;
    }
}
