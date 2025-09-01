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

    


    /// @notice Verify PoK, encryption relation, pairing, AND accumulator membership
    /// @dev Reads pk/g2base/Ybar from Params by name, then calls Accumulator.verifyMembership
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

    /// @notice Verify PoK, encryption relation, pairing, AND zk membership proof (no witness)
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


}


