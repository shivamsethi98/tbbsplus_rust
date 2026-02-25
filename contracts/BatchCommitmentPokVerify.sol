// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Bls12381} from "./lib/Bls12381.sol";
import {Fr} from "./lib/Fr.sol";

/// @title Batched Commitment PoK verification using random linear combination
/// @notice Verifies N Schnorr-style commitment PoKs in a single batched check.
///         For each user j with bases B, commitment C_j, randomness T_j, challenge c_j,
///         responses s_j, the individual check is: MSM(B, s_j) == T_j + c_j * C_j.
///
///         Batched check with random weights ρ_j:
///           MSM(B, Σ_j ρ_j · s_j) == Σ_j ρ_j · T_j + Σ_j (ρ_j · c_j) · C_j
///
///         This collapses N MSMs into 1 MSM(|B|) + 2 MSMs(N) via random linear combination.
///         Sound with negligible error probability 1/|Fr| per verification.
library BatchCommitmentPokVerify {

    /// @notice Verify N commitment PoKs in one batched check
    /// @param h0 128B base point for blinding factor
    /// @param H  Array of 128B base points (all message generators)
    /// @param hiddenIdx Shared hidden message indices (same schema for all users)
    /// @param commitments N × 128B commitment points C_j
    /// @param Ts N × 128B random commitment points T_j
    /// @param challenges N scalar challenges c_j
    /// @param flatResponses N * respLen packed scalars (user j responses at [j*respLen .. (j+1)*respLen))
    /// @return ok True if the batched check passes
    function batchVerify(
        bytes memory h0,
        bytes[] memory H,
        uint32[] memory hiddenIdx,
        bytes[] memory commitments,
        bytes[] memory Ts,
        uint256[] memory challenges,
        uint256[] memory flatResponses
    ) internal view returns (bool ok) {
        uint256 N = commitments.length;
        require(N > 0, "empty batch");
        require(Ts.length == N && challenges.length == N, "len mismatch");
        require(h0.length == 128, "bad h0 len");
        uint256 respLen = hiddenIdx.length + 1;
        require(flatResponses.length == N * respLen, "resp len mismatch");

        // 1. Derive batching weights ρ_j = H(j ‖ T_j ‖ C_j) mod r
        uint256[] memory rho = new uint256[](N);
        for (uint256 j = 0; j < N; j++) {
            rho[j] = uint256(keccak256(abi.encodePacked(j, Ts[j], commitments[j]))) % Fr.MOD;
            if (rho[j] == 0) rho[j] = 1; // avoid zero weight
        }

        // 2. Aggregate responses: aggResp[i] = Σ_j ρ_j · resp[j][i]  (mod r)
        uint256[] memory aggResp = new uint256[](respLen);
        for (uint256 i = 0; i < respLen; i++) {
            uint256 acc = 0;
            for (uint256 j = 0; j < N; j++) {
                acc = Fr.add(acc, Fr.mul(rho[j], flatResponses[j * respLen + i]));
            }
            aggResp[i] = acc;
        }

        // 3. LHS = MSM(bases, aggResp)  where bases = [h0, H[hiddenIdx[0]], H[hiddenIdx[1]], ...]
        bytes[] memory bases = new bytes[](respLen);
        bases[0] = h0;
        for (uint256 i = 0; i < hiddenIdx.length; i++) {
            bases[i + 1] = H[uint256(hiddenIdx[i])];
            require(bases[i + 1].length == 128, "bad H len");
        }
        bytes memory left = Bls12381.g1msm(Bls12381.concatMSM(bases, aggResp));

        // 4. RHS = MSM(Ts, ρ) + MSM(Cs, ρ·c)
        bytes memory rhs_t = Bls12381.g1msm(Bls12381.concatMSM(Ts, rho));

        uint256[] memory rhoC = new uint256[](N);
        for (uint256 j = 0; j < N; j++) {
            rhoC[j] = Fr.mul(rho[j], challenges[j]);
        }
        bytes memory rhs_c = Bls12381.g1msm(Bls12381.concatMSM(commitments, rhoC));

        bytes memory right = Bls12381.g1add(rhs_t, rhs_c);

        return keccak256(left) == keccak256(right);
    }
}
