// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BBS+ PoK Transcript Hasher (no pairings)
/// @notice Computes Fiat–Shamir challenge for BBS+ PoK using keccak256 mapped to BLS12-381 Fr.
///         This replicates verification logic inputs and ordering; cryptographic equations are deferred.
library BbsPlusPokTranscript {
    // BLS12-381 scalar field (Fr) modulus
    // r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    uint256 internal constant FR_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    struct Inputs {
        // Domain-binding and context hashes
        bytes32 paramsHash;
        bytes32 pkHash;
        bytes32 contextHash; // optional; use 0x00..00 if unused
        // Public scalar inputs
        uint256 sid; // session or statement id in Fr
        uint32 messageCount;
        uint32[] revealedIdx; // must be sorted ascending
        uint256[] revealedVals; // same length as revealedIdx, Fr scalars
        // Transcript group elements (uncompressed bytes in agreed format)
        bytes APrime; // A'
        bytes ABar;   // Ā
        bytes d;
        bytes T1;
        bytes T2;
    }

    /// @notice Map keccak256(data) to Fr by modular reduction.
    function frFromKeccak(bytes memory data) internal pure returns (uint256) {
        return uint256(keccak256(data)) % FR_MODULUS;
    }

    /// @notice Compute the Fiat–Shamir challenge c as an Fr element.
    /// Ordering is fixed and must match off-chain prover:
    ///   paramsHash | pkHash | contextHash | sid | messageCount |
    ///   for each i: (revealedIdx[i] | revealedVals[i]) |
    ///   APrime | ABar | d | T1 | T2
    /// All concatenated via abi.encodePacked.
    function computeChallenge(Inputs memory in_) internal pure returns (uint256) {
        require(in_.revealedIdx.length == in_.revealedVals.length, "len mismatch");
        bytes memory packed;
        // Static header
        packed = abi.encodePacked(
            bytes4(0x42504f4b), // "BPOK" tag for domain separation
            in_.paramsHash,
            in_.pkHash,
            in_.contextHash,
            in_.sid,
            in_.messageCount
        );
        // Revealed pairs in order
        for (uint256 i = 0; i < in_.revealedIdx.length; i++) {
            packed = bytes.concat(packed, abi.encodePacked(in_.revealedIdx[i], in_.revealedVals[i]));
        }
        // Transcript elements
        packed = bytes.concat(packed, in_.APrime, in_.ABar, in_.d, in_.T1, in_.T2);
        return frFromKeccak(packed);
    }

    /// @notice Compute challenge from a pre-built transcript byte string (exact bytes as prover used).
    function computeChallengeRaw(bytes memory transcript) internal pure returns (uint256) {
        return frFromKeccak(transcript);
    }
}
