// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Bls12381} from "./lib/Bls12381.sol";

/// @title BBS+ PoK verification (no pairings) using EIP-2537 G1 MSM
/// @notice Verifies the 2 Schnorr equations from PoK-of-signature with a provided challenge.
library BbsPlusPokVerify {
    // BLS12-381 scalar field (Fr) modulus (aka main subgroup order q)
    uint256 internal constant FR_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    struct PublicSignatureParts {
        bytes APrime; // 128 bytes
        bytes ABar;   // 128 bytes
        bytes d;      // 128 bytes
    }

    struct VerificationContext {
        uint32 messageCount;
        bytes g1;     // generator, 128 bytes
        bytes h0;     // 128 bytes
        bytes[] H;    // length == messageCount, each 128 bytes
    }

    struct Revealed {
        uint32[] idx;     // sorted ascending, < messageCount
        uint256[] vals;   // same length, Fr scalars
    }

    struct Proof1 { // for relation 1
        bytes T1;         // 128 bytes (commitment)
        uint256 respA;    // response for witness -e with base APrime
        uint256 respH0;   // response for witness r2 with base h0
    }

    struct Proof2 { // for relation 2
        bytes T2;         // 128 bytes (commitment)
        uint256[] respMsgs; // responses for undisclosed message witnesses (aligned with undisclosed order)
        uint256 respR3;     // response for witness r3 with base d
        uint256 respSPrime; // response for witness -s' with base h0
    }

    error LengthMismatch();
    error BadPointLen();
    error BadHLen();
    error BadRevealedOrder();

    function _qMinus(uint256 x) internal pure returns (uint256) {
        uint256 r = x % FR_MODULUS;
        return r == 0 ? 0 : (FR_MODULUS - r);
    }

    function _check128(bytes memory p) private pure {
        if (p.length != 128) revert BadPointLen();
    }

    function _checkCtx(VerificationContext memory ctx) private pure {
        _check128(ctx.g1);
        _check128(ctx.h0);
        if (ctx.H.length != ctx.messageCount) revert BadHLen();
        for (uint256 i = 0; i < ctx.H.length; i++) _check128(ctx.H[i]);
    }

    function _checkSig(PublicSignatureParts memory s) private pure {
        _check128(s.APrime);
        _check128(s.ABar);
        _check128(s.d);
    }

    function _checkRevealed(Revealed memory r, uint32 mc) private pure returns (bool[] memory isRev) {
        if (r.idx.length != r.vals.length) revert LengthMismatch();
        isRev = new bool[](mc);
        uint32 prev = 0;
        bool hasPrev = false;
        for (uint256 i = 0; i < r.idx.length; i++) {
            uint32 ix = r.idx[i];
            if (ix >= mc) revert BadRevealedOrder();
            if (hasPrev) {
                if (ix <= prev) revert BadRevealedOrder();
            } else {
                hasPrev = true;
            }
            prev = ix;
            isRev[ix] = true;
        }
    }

    /// @notice Verify both Schnorr equations using EIP-2537 MSM. Returns true on success.
    function verify(
        PublicSignatureParts memory sig,
        VerificationContext memory ctx,
        Revealed memory revealed,
        uint256 challenge,
        Proof1 memory p1,
        Proof2 memory p2
    ) internal view returns (bool) {
        _checkCtx(ctx);
        _checkSig(sig);
        _check128(p1.T1);
        _check128(p2.T2);

        // Build revealed mask and undisclosed list
        bool[] memory isRev = _checkRevealed(revealed, ctx.messageCount);
        uint256 undisCount = ctx.messageCount - revealed.idx.length;
        bytes[] memory undisH = new bytes[](undisCount);
        uint256 k = 0;
        for (uint256 i = 0; i < ctx.messageCount; i++) {
            if (!isRev[i]) { undisH[k++] = ctx.H[i]; }
        }
        if (p2.respMsgs.length != undisCount) revert LengthMismatch();

        // First Schnorr: MSM([A', h0, A_bar, d], [respA, respH0, q-c, c]) == T1
        {
            bytes[] memory pts = new bytes[](4);
            uint256[] memory sc = new uint256[](4);
            pts[0] = sig.APrime; sc[0] = p1.respA % FR_MODULUS;
            pts[1] = ctx.h0;     sc[1] = p1.respH0 % FR_MODULUS;
            pts[2] = sig.ABar;   sc[2] = _qMinus(challenge);
            pts[3] = sig.d;      sc[3] = challenge % FR_MODULUS;
            bytes memory data = Bls12381.concatMSM(pts, sc);
            bytes memory out = Bls12381.g1msm(data);
            // compare to T1
            if (keccak256(out) != keccak256(p1.T1)) return false;
        }

        // Compute c_m = g1 + sum_{i in revealed} h[i]*m_i via MSM including g1*1
        bytes memory c_m;
        {
            uint256 kPairs = revealed.idx.length + 1;
            bytes[] memory pts = new bytes[](kPairs);
            uint256[] memory sc = new uint256[](kPairs);
            for (uint256 j = 0; j < revealed.idx.length; j++) {
                pts[j] = ctx.H[revealed.idx[j]];
                sc[j] = revealed.vals[j] % FR_MODULUS;
            }
            pts[kPairs - 1] = ctx.g1; sc[kPairs - 1] = 1;
            bytes memory data = Bls12381.concatMSM(pts, sc);
            c_m = Bls12381.g1msm(data);
        }

        // Second Schnorr: MSM([undis H..., d, h0, c_m], [respMsgs..., respR3, respSPrime, c]) == T2
        {
            bytes[] memory pts2 = new bytes[](undisCount + 3);
            uint256[] memory sc2 = new uint256[](undisCount + 3);
            for (uint256 j = 0; j < undisCount; j++) {
                pts2[j] = undisH[j];
                sc2[j] = p2.respMsgs[j] % FR_MODULUS;
            }
            pts2[undisCount + 0] = sig.d;  sc2[undisCount + 0] = p2.respR3 % FR_MODULUS;
            pts2[undisCount + 1] = ctx.h0; sc2[undisCount + 1] = p2.respSPrime % FR_MODULUS;
            pts2[undisCount + 2] = c_m;    sc2[undisCount + 2] = challenge % FR_MODULUS;
            bytes memory data2 = Bls12381.concatMSM(pts2, sc2);
            bytes memory out2 = Bls12381.g1msm(data2);
            if (keccak256(out2) != keccak256(p2.T2)) return false;
        }

        return true;
    }
}
