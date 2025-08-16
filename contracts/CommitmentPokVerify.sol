// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Bls12381} from "./lib/Bls12381.sol";

/// @title Commitment PoK verification using EIP-2537 G1 MSM
/// @notice Verifies a Schnorr-style proof of knowledge of witnesses w = [s, m_i...] over bases [h0, H[i...] ]
///         such that commitment C = h0*s + sum_i H[i]*m_i. The proof checks MSM(bases, responses) == T + C*c.
library CommitmentPokVerify {
    error BadLens();
    error BadPointLen();

    /// @dev Verify Schnorr PoK of commitment correctness.
    /// @param h0 128-byte uncompressed G1 point for h_0
    /// @param H  array of 128-byte uncompressed G1 points for per-message bases, length == messageCount
    /// @param hiddenIdx indices into H that are hidden (sorted ascending); bases = [h0] + [ H[idx] ... ]
    /// @param T  128-byte uncompressed G1 commitment to randomness
    /// @param challenge field element in Fr (uint256 mod q)
    /// @param responses vector of responses aligned to bases: [resp_s, resp_m_i...]
    /// @param commitment 128-byte uncompressed G1 point C
    function verify(
        bytes memory h0,
        bytes[] memory H,
        uint32[] memory hiddenIdx,
        bytes memory T,
        uint256 challenge,
        uint256[] memory responses,
        bytes memory commitment
    ) internal view returns (bool) {
        if (h0.length != 128 || T.length != 128 || commitment.length != 128) revert BadPointLen();
        if (hiddenIdx.length + 1 != responses.length) revert BadLens();
        // Build bases array: h0 first, then H[idx] in order
        bytes[] memory bases = new bytes[](responses.length);
        bases[0] = h0;
        for (uint256 i = 0; i < hiddenIdx.length; i++) {
            uint32 ix = hiddenIdx[i];
            bases[i + 1] = H[uint256(ix)];
            if (bases[i + 1].length != 128) revert BadPointLen();
        }

        // Left side: MSM(bases, responses)
        bytes memory data = Bls12381.concatMSM(bases, responses);
        bytes memory left = Bls12381.g1msm(data);

        // Right side: T + MSM([commitment], [challenge])
        bytes[] memory onePt = new bytes[](1);
        uint256[] memory oneSc = new uint256[](1);
        onePt[0] = commitment;
        oneSc[0] = challenge;
        bytes memory cC = Bls12381.g1msm(Bls12381.concatMSM(onePt, oneSc));
        bytes memory right = Bls12381.g1add(T, cC);

        return keccak256(left) == keccak256(right);
    }
}



