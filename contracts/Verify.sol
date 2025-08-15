// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BbsPlusPokVerify} from "./BbsPlusPokVerify.sol";

/// @title Credential Presentation Verifier
/// @notice Verifies BBS+ PoK using EIP-2537 MSM precompiles and optionally runs a pairing check
///         via the PAIRING precompile (0x0f). The pairing inputs must already reflect any required
///         negations (e.g., pass -Abar for the second G1 when checking e(A', pk) == e(Abar, g2)).
library Verify {
    // EIP-2537 precompile addresses
    address internal constant PAIR = address(0x0f);

    error BadLen();
    error PairingFailed();

    function verifyPok(
        BbsPlusPokVerify.PublicSignatureParts memory sig,
        BbsPlusPokVerify.VerificationContext memory ctx,
        BbsPlusPokVerify.Revealed memory revealed,
        uint256 challenge,
        BbsPlusPokVerify.Proof1 memory p1,
        BbsPlusPokVerify.Proof2 memory p2
    ) internal view returns (bool) {
        return BbsPlusPokVerify.verify(sig, ctx, revealed, challenge, p1, p2);
    }

    /// @notice Verify product of pairings equals 1 using PAIR precompile
    /// @dev Expects 2 pairs: (G1_1, G2_1) and (G1_2, G2_2). Each G1 is 128 bytes, each G2 is 256 bytes
    /// @param g1_1 bytes(128) uncompressed x||y
    /// @param g2_1 bytes(256) uncompressed (x.c0||x.c1||y.c0||y.c1)
    /// @param g1_2 bytes(128) uncompressed x||y
    /// @param g2_2 bytes(256) uncompressed (x.c0||x.c1||y.c0||y.c1)
    function verifyPairing(
        bytes memory g1_1,
        bytes memory g2_1,
        bytes memory g1_2,
        bytes memory g2_2
    ) internal view returns (bool) {
        if (g1_1.length != 128 || g1_2.length != 128 || g2_1.length != 256 || g2_2.length != 256) revert BadLen();
        bytes memory input = bytes.concat(g1_1, g2_1, g1_2, g2_2);
        (bool ok, bytes memory out) = PAIR.staticcall(input);
        if (!ok || out.length != 32) revert PairingFailed();
        // out is 32-byte big-endian boolean; last byte must be 0x01 on success
        return out[31] == 0x01;
    }
}

contract VerifyWrapper {
    using Verify for BbsPlusPokVerify.PublicSignatureParts;

    function verifyPok(
        BbsPlusPokVerify.PublicSignatureParts memory sig,
        BbsPlusPokVerify.VerificationContext memory ctx,
        BbsPlusPokVerify.Revealed memory revealed,
        uint256 challenge,
        BbsPlusPokVerify.Proof1 memory p1,
        BbsPlusPokVerify.Proof2 memory p2
    ) external view returns (bool) {
        return Verify.verifyPok(sig, ctx, revealed, challenge, p1, p2);
    }

    function verifyPairing(
        bytes calldata g1_1,
        bytes calldata g2_1,
        bytes calldata g1_2,
        bytes calldata g2_2
    ) external view returns (bool) {
        return Verify.verifyPairing(g1_1, g2_1, g1_2, g2_2);
    }
}


