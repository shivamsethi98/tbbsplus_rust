// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BbsPlusPokVerify} from "./BbsPlusPokVerify.sol";
import {Bls12381} from "./lib/Bls12381.sol";
import {VBAccPokVerify} from "./VBAccPokVerify.sol";
import {Params} from "./Params.sol";

/// @title Credential Presentation Verifier
/// @notice Verifies BBS+ PoK using EIP-2537 MSM precompiles and optionally runs a pairing check
///         via the PAIRING precompile (0x0f). The pairing inputs must already reflect any required
///         negations (e.g., pass -Abar for the second G1 when checking e(A', pk) == e(Abar, g2)).


library Verify {
    // EIP-2537 precompile addresses
    address internal constant PAIR = address(0x0f);
    // BLS12-381 scalar field (Fr) modulus
    uint256 internal constant FR_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

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

interface IAccumulator {
    function getDelta(string calldata name) external view returns (bytes memory);
}

contract VerifyWrapper {
    using Verify for BbsPlusPokVerify.PublicSignatureParts;

    event PresentationVerified(string indexed name, address indexed prover, bytes T1, bytes T2);


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

    


    /// @notice [DEPRECATED] Verify PoK, encryption relation, pairing, AND accumulator membership with raw witness
    /// @dev Use verifyPokEncWithPairingAndMembershipPokFromParamsEmit (ZK membership proof) instead.
    ///      This path requires the prover to supply a raw witness128, exposing the witness to the verifier.
    ///      Kept for backwards compatibility only.
    function verifyPokEncWithPairingAndMembershipFromParamsEmit(
        BbsPlusPokVerify.PublicSignatureParts memory sig,
        BbsPlusPokVerify.VerificationContext memory ctx,
        BbsPlusPokVerify.Revealed memory revealed,
        uint256 challenge,
        BbsPlusPokVerify.Proof1 memory p1,
        BbsPlusPokVerify.Proof2 memory p2,
        // Encryption extras
        bytes calldata T1,
        bytes calldata T2enc,
        bytes calldata Tenc,
        uint256 respA3,
        uint256 respK,
        // Membership and params
        string calldata name,
        address paramsAddr,
        address accumulatorAddr,
        uint256 e,
        bytes calldata witness128
    ) external returns (bool) {
        Params p = Params(paramsAddr);
        ( , , bytes memory g2base) = p.getG1H0G2ByName(name);
        bytes memory pkG2 = p.getPkG2ByName(name);
        bytes memory pkAccG2 = p.getOpenerPkG2ByName(name);
        bytes memory ybar = p.getOpenerYbarByName(name);
        require(pkG2.length == 256 && pkAccG2.length == 256 && g2base.length == 256 && ybar.length == 128, "bad params");
        require(T1.length == 128 && T2enc.length == 128 && Tenc.length == 128, "bad T len");
        // Core PoK
        require(Verify.verifyPok(sig, ctx, revealed, challenge, p1, p2), "pok fail");
        // Encryption relation: lhs = A'*respA3 + Ybar*respK; rhs = Tenc + T2enc*challenge
        {
            bytes[] memory pts1 = new bytes[](1); pts1[0] = sig.APrime;
            uint256[] memory sc1 = new uint256[](1); sc1[0] = respA3;
            bytes memory lhsA3 = Bls12381.g1msm(Bls12381.concatMSM(pts1, sc1));

            bytes[] memory pts2 = new bytes[](1); pts2[0] = ybar;
            uint256[] memory sc2 = new uint256[](1); sc2[0] = respK;
            bytes memory lhsK  = Bls12381.g1msm(Bls12381.concatMSM(pts2, sc2));

            bytes memory lhs   = Bls12381.g1add(lhsA3, lhsK);

            bytes[] memory pts3 = new bytes[](1); pts3[0] = T2enc;
            uint256[] memory sc3 = new uint256[](1); sc3[0] = challenge;
            bytes memory rhsC  = Bls12381.g1msm(Bls12381.concatMSM(pts3, sc3));
            bytes memory rhs   = Bls12381.g1add(Tenc, rhsC);
            require(keccak256(lhs) == keccak256(rhs), "enc fail");
        }
        // Pairing (call external wrapper to avoid inlining stack growth)
        require(this.verifyPairing(sig.APrime, pkG2, Bls12381.g1neg(sig.ABar), g2base), "pair fail");
        // Membership
        // Call Accumulator.verifyMembership(name, e, witness)
        (bool ok, bytes memory ret) = accumulatorAddr.staticcall(abi.encodeWithSignature(
            "verifyMembership(string,uint256,bytes)", name, e, witness128
        ));
        require(ok && ret.length == 32 && ret[31] == 0x01, "acc fail");
        emit PresentationVerified(name, msg.sender, T1, T2enc);
        return true;
    }

    /// @notice [PRIMARY] Verify PoK, encryption relation, pairing, AND zk membership proof (no witness needed)
    function verifyPokEncWithPairingAndMembershipPokFromParamsEmit(
        BbsPlusPokVerify.PublicSignatureParts memory sig,
        BbsPlusPokVerify.VerificationContext memory ctx,
        BbsPlusPokVerify.Revealed memory revealed,
        uint256 challenge,
        uint256 challengeAcc,
        BbsPlusPokVerify.Proof1 memory p1,
        BbsPlusPokVerify.Proof2 memory p2,
        // Encryption extras
        bytes calldata T1,
        bytes calldata T2enc,
        bytes calldata Tenc,
        uint256 respA3,
        uint256 respK,
        // Params/accumulator
        string calldata name,
        address paramsAddr,
        address accumulatorAddr,
        // Membership PoK
        VBAccPokVerify.MembershipPok calldata mp
    ) external returns (bool) {
        Params p = Params(paramsAddr);
        ( , , bytes memory g2base) = p.getG1H0G2ByName(name);
        bytes memory pkG2 = p.getPkG2ByName(name);
        bytes memory pkAccG2_ = p.getOpenerPkG2ByName(name);
        bytes memory ybar = p.getOpenerYbarByName(name);
        require(pkG2.length == 256 && pkAccG2_.length == 256 && g2base.length == 256 && ybar.length == 128, "bad params");
        require(T1.length == 128 && T2enc.length == 128 && Tenc.length == 128, "bad T len");
        // Core PoK
        require(Verify.verifyPok(sig, ctx, revealed, challenge, p1, p2), "pok fail");
        // Encryption relation: lhs = A'*respA3 + Ybar*respK; rhs = Tenc + T2enc*challenge
        {
            bytes[] memory pts1 = new bytes[](1); pts1[0] = sig.APrime;
            uint256[] memory sc1 = new uint256[](1); sc1[0] = respA3;
            bytes memory lhsA3 = Bls12381.g1msm(Bls12381.concatMSM(pts1, sc1));

            bytes[] memory pts2 = new bytes[](1); pts2[0] = ybar;
            uint256[] memory sc2 = new uint256[](1); sc2[0] = respK;
            bytes memory lhsK  = Bls12381.g1msm(Bls12381.concatMSM(pts2, sc2));

            bytes memory lhs   = Bls12381.g1add(lhsA3, lhsK);

            bytes[] memory pts3 = new bytes[](1); pts3[0] = T2enc;
            uint256[] memory sc3 = new uint256[](1); sc3[0] = challenge;
            bytes memory rhsC  = Bls12381.g1msm(Bls12381.concatMSM(pts3, sc3));
            bytes memory rhs   = Bls12381.g1add(Tenc, rhsC);
            require(keccak256(lhs) == keccak256(rhs), "enc fail");
        }
        // Pairing
        require(Verify.verifyPairing(sig.APrime, pkG2, Bls12381.g1neg(sig.ABar), g2base), "pair fail");
        // Membership PoK
        bytes memory delta = IAccumulator(accumulatorAddr).getDelta(name);
        require(delta.length == 128, "bad delta");
        require(pkAccG2_.length == 256, "bad params");
        require(VBAccPokVerify.verify(delta, g2base, pkAccG2_, challengeAcc, mp), "acc pok fail");
        emit PresentationVerified(name, msg.sender, T1, T2enc);
        return true;
    }

    function verifyPairing(
        bytes calldata g1_1,
        bytes calldata g2_1,
        bytes calldata g1_2,
        bytes calldata g2_2
    ) external view returns (bool) {
        return Verify.verifyPairing(g1_1, g2_1, g1_2, g2_2);
    }

    // ========================== BATCH VERIFICATION ==========================

    event BatchPresentationVerified(string indexed name, uint256 count);

    /// @notice Batched BBS+ pairing verification using random linear combination.
    /// @dev For N signatures, instead of N individual pairing checks:
    ///        e(A'_j, pk) · e(-Abar_j, g2) = 1  (for each j)
    ///      uses one batched check:
    ///        e(∑ δ_j·A'_j, pk) · e(-(∑ δ_j·Abar_j), g2) = 1
    ///      Gas savings: 1 pairing instead of N pairings, plus 2 G1MSMs of size N.
    /// @param APrimes_concat N concatenated 128-byte A' points
    /// @param ABars_concat N concatenated 128-byte Abar points
    /// @param pkG2 256-byte shared public key in G2
    /// @param g2base 256-byte G2 generator
    /// @return ok true if batched pairing check passes
    function verifyBbsPairingBatch(
        bytes calldata APrimes_concat,
        bytes calldata ABars_concat,
        bytes memory pkG2,
        bytes memory g2base
    ) external view returns (bool ok) {
        uint256 n = APrimes_concat.length / 128;
        require(n > 0 && APrimes_concat.length == n * 128, "bad A' len");
        require(ABars_concat.length == n * 128, "bad Abar len");
        require(pkG2.length == 256 && g2base.length == 256, "bad G2 len");

        // Derive random challenges δ_j = H(APrimes || ABars || prevrandao || j) mod Fr
        bytes32 seed = keccak256(abi.encodePacked(APrimes_concat, ABars_concat, block.prevrandao));
        uint256[] memory deltas = new uint256[](n);
        bytes[] memory APrimes = new bytes[](n);
        bytes[] memory ABars = new bytes[](n);
        for (uint256 j = 0; j < n; j++) {
            deltas[j] = uint256(keccak256(abi.encodePacked(seed, j))) % Verify.FR_MODULUS;
            if (deltas[j] == 0) deltas[j] = 1;
            APrimes[j] = APrimes_concat[j * 128 : (j + 1) * 128];
            ABars[j] = ABars_concat[j * 128 : (j + 1) * 128];
        }

        // L = MSM(A'_j, δ_j) — combined A' for first pairing
        bytes memory L = Bls12381.g1msm(Bls12381.concatMSM(APrimes, deltas));

        // R = MSM(Abar_j, δ_j) — combined Abar for second pairing (negated)
        bytes memory R = Bls12381.g1msm(Bls12381.concatMSM(ABars, deltas));
        bytes memory negR = Bls12381.g1neg(R);

        // Single pairing check: e(L, pk) · e(-R, g2) = 1
        ok = Verify.verifyPairing(L, pkG2, negR, g2base);
    }

    /// @notice Batched accumulator membership pairing verification.
    /// @dev Same random linear combination technique for accumulator membership pairings:
    ///        e(A'_acc_j, pk_acc) · e(-Abar_acc_j, g2) = 1  (for each j)
    ///      becomes:
    ///        e(∑ δ_j·A'_acc_j, pk_acc) · e(-(∑ δ_j·Abar_acc_j), g2) = 1
    function verifyAccPairingBatch(
        bytes calldata APrimes_concat,
        bytes calldata ABars_concat,
        bytes memory pkAccG2,
        bytes memory g2base
    ) external view returns (bool ok) {
        uint256 n = APrimes_concat.length / 128;
        require(n > 0 && APrimes_concat.length == n * 128, "bad A' len");
        require(ABars_concat.length == n * 128, "bad Abar len");
        require(pkAccG2.length == 256 && g2base.length == 256, "bad G2 len");

        bytes32 seed = keccak256(abi.encodePacked(APrimes_concat, ABars_concat, block.prevrandao));
        uint256[] memory deltas = new uint256[](n);
        bytes[] memory APrimes = new bytes[](n);
        bytes[] memory ABars = new bytes[](n);
        for (uint256 j = 0; j < n; j++) {
            deltas[j] = uint256(keccak256(abi.encodePacked(seed, j))) % Verify.FR_MODULUS;
            if (deltas[j] == 0) deltas[j] = 1;
            APrimes[j] = APrimes_concat[j * 128 : (j + 1) * 128];
            ABars[j] = ABars_concat[j * 128 : (j + 1) * 128];
        }

        bytes memory L = Bls12381.g1msm(Bls12381.concatMSM(APrimes, deltas));
        bytes memory R = Bls12381.g1msm(Bls12381.concatMSM(ABars, deltas));
        bytes memory negR = Bls12381.g1neg(R);

        ok = Verify.verifyPairing(L, pkAccG2, negR, g2base);
    }


}


