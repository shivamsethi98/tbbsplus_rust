// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BbsPlusPokVerify} from "./BbsPlusPokVerify.sol";
import {Bls12381} from "./lib/Bls12381.sol";
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

    /// @notice Verify PoK and then pairing e(A', pkG2) == e(Abar, g2)
    /// @param pkG2 256-byte uncompressed G2 point (x.c0||x.c1||y.c0||y.c1)
    /// @param g2base 256-byte uncompressed G2 base used in SignatureParams.g2 (not necessarily canonical generator)
    function verifyPokWithPairing(
        BbsPlusPokVerify.PublicSignatureParts memory sig,
        BbsPlusPokVerify.VerificationContext memory ctx,
        BbsPlusPokVerify.Revealed memory revealed,
        uint256 challenge,
        BbsPlusPokVerify.Proof1 memory p1,
        BbsPlusPokVerify.Proof2 memory p2,
    bytes memory pkG2,
    bytes memory g2base
    ) internal view returns (bool) {
        if (!BbsPlusPokVerify.verify(sig, ctx, revealed, challenge, p1, p2)) return false;
        // Pairing expects (g1_1, g2_1, g1_2, g2_2) and returns true if product == 1
        // We need e(A', pk) * e(-Abar, g2) == 1
        bytes memory negAbar = Bls12381.g1neg(sig.ABar);
    return verifyPairing(sig.APrime, pkG2, negAbar, g2base);
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

    function verifyPokWithPairing(
        BbsPlusPokVerify.PublicSignatureParts memory sig,
        BbsPlusPokVerify.VerificationContext memory ctx,
        BbsPlusPokVerify.Revealed memory revealed,
        uint256 challenge,
        BbsPlusPokVerify.Proof1 memory p1,
        BbsPlusPokVerify.Proof2 memory p2,
        bytes calldata pkG2,
        bytes calldata g2base
    ) external view returns (bool) {
        return Verify.verifyPokWithPairing(sig, ctx, revealed, challenge, p1, p2, pkG2, g2base);
    }

    /// @notice Verify PoK and run pairing using pkG2 and g2Base fetched from Params by credential name
    /// @dev This avoids passing pk/g2base from the client; reads on-chain via Params.
    function verifyPokWithPairingFromParams(
        BbsPlusPokVerify.PublicSignatureParts memory sig,
        BbsPlusPokVerify.VerificationContext memory ctx,
        BbsPlusPokVerify.Revealed memory revealed,
        uint256 challenge,
        BbsPlusPokVerify.Proof1 memory p1,
        BbsPlusPokVerify.Proof2 memory p2,
        string calldata name,
        address paramsAddr
    ) external view returns (bool) {
        Params p = Params(paramsAddr);
        ( , , bytes memory g2base) = p.getG1H0G2ByName(name);
        bytes memory pkG2 = p.getPkG2ByName(name);
        if (pkG2.length == 0 || g2base.length != 256) return false;
        return Verify.verifyPokWithPairing(sig, ctx, revealed, challenge, p1, p2, pkG2, g2base);
    }

    /// @notice Verify PoK, optional encryption relation using opener Ybar, and pairing, all from Params
    function verifyPokEncWithPairingFromParams(
        BbsPlusPokVerify.PublicSignatureParts memory sig,
        BbsPlusPokVerify.VerificationContext memory ctx,
        BbsPlusPokVerify.Revealed memory revealed,
        uint256 challenge,
        BbsPlusPokVerify.Proof1 memory p1,
        BbsPlusPokVerify.Proof2 memory p2,
        // Encryption extras
        bytes calldata T2enc,
        bytes calldata Tenc,
        uint256 respA3,
        uint256 respK,
        string calldata name,
        address paramsAddr
    ) external view returns (bool) {
        Params p = Params(paramsAddr);
        ( , , bytes memory g2base) = p.getG1H0G2ByName(name);
        bytes memory pkG2 = p.getPkG2ByName(name);
        bytes memory ybar = p.getOpenerYbarByName(name);
        if (pkG2.length != 256 || g2base.length != 256 || ybar.length != 128) return false;
        // First verify core PoK
        if (!Verify.verifyPok(sig, ctx, revealed, challenge, p1, p2)) return false;
        // Then encryption relation: lhs = A'*respA3 + Ybar*respK; rhs = Tenc + T2enc*challenge
        bytes memory lhsA3 = this.msm1(sig.APrime, respA3);
        bytes memory lhsK  = this.msm1(ybar,     respK);
        bytes memory lhs   = this.g1add(lhsA3, lhsK);
        bytes memory rhsC  = this.msm1(T2enc,    challenge);
        bytes memory rhs   = this.g1add(Tenc, rhsC);
        if (keccak256(lhs) != keccak256(rhs)) return false;
        // Finally, pairing: e(A', pk) == e(Abar, g2)
        return Verify.verifyPairing(sig.APrime, pkG2, Bls12381.g1neg(sig.ABar), g2base);
    }

    /// @notice Verify all relations as above and emit an event carrying T1,T2 for opening
    function verifyPokEncWithPairingFromParamsEmit(
        BbsPlusPokVerify.PublicSignatureParts memory sig,
        BbsPlusPokVerify.VerificationContext memory ctx,
        BbsPlusPokVerify.Revealed memory revealed,
        uint256 challenge,
        BbsPlusPokVerify.Proof1 memory p1,
        BbsPlusPokVerify.Proof2 memory p2,
        // Extras for encryption and opening
        bytes calldata T1,
        bytes calldata T2enc,
        bytes calldata Tenc,
        uint256 respA3,
        uint256 respK,
        string calldata name,
        address paramsAddr
    ) external returns (bool) {
        Params p = Params(paramsAddr);
        ( , , bytes memory g2base) = p.getG1H0G2ByName(name);
        bytes memory pkG2 = p.getPkG2ByName(name);
        bytes memory ybar = p.getOpenerYbarByName(name);
        require(pkG2.length == 256 && g2base.length == 256 && ybar.length == 128, "bad params");
        // Core PoK
        require(Verify.verifyPok(sig, ctx, revealed, challenge, p1, p2), "pok fail");
        // Encryption relation
        require(T1.length == 128 && T2enc.length == 128 && Tenc.length == 128, "bad T len");
        bytes memory lhsA3 = this.msm1(sig.APrime, respA3);
        bytes memory lhsK  = this.msm1(ybar,     respK);
        bytes memory lhs   = this.g1add(lhsA3, lhsK);
        bytes memory rhsC  = this.msm1(T2enc,    challenge);
        bytes memory rhs   = this.g1add(Tenc, rhsC);
        require(keccak256(lhs) == keccak256(rhs), "enc fail");
        // Pairing
        require(Verify.verifyPairing(sig.APrime, pkG2, Bls12381.g1neg(sig.ABar), g2base), "pair fail");
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

    // Debug helper: just expose g1neg to tests for raw checks
    function g1neg(bytes calldata p) external pure returns (bytes memory) {
        return Bls12381.g1neg(p);
    }

    /// @notice Verify encryption relation only (optional third check)
    function verifyEnc(
        bytes calldata APrime,
        bytes calldata Ybar,
        bytes calldata T2enc,
        bytes calldata Tenc,
        uint256 respA3,
        uint256 respK,
        uint256 challenge
    ) external view returns (bool) {
        // Build lhs and rhs using primitive ops exposed by this wrapper to avoid node-specific reverts
        if (APrime.length != 128 || Ybar.length != 128 || T2enc.length != 128 || Tenc.length != 128) return false;
        bytes memory lhsA3 = this.msm1(APrime, respA3);
        bytes memory lhsK  = this.msm1(Ybar,   respK);
        bytes memory lhs   = this.g1add(lhsA3, lhsK);
        bytes memory rhsC  = this.msm1(T2enc,  challenge);
        bytes memory rhs   = this.g1add(Tenc,  rhsC);
        return keccak256(lhs) == keccak256(rhs);
    }

    /// @notice Debug: call G1 MSM with a single pair (p * s)
    function msm1(bytes calldata p, uint256 s) external view returns (bytes memory) {
        bytes[] memory pts = new bytes[](1);
        uint256[] memory sc = new uint256[](1);
        pts[0] = p; sc[0] = s;
        return Bls12381.g1msm(Bls12381.concatMSM(pts, sc));
    }

    /// @notice Debug: call G1 MSM with two pairs (p1*s1 + p2*s2)
    function msm2(bytes calldata p1, uint256 s1, bytes calldata p2, uint256 s2) external view returns (bytes memory) {
        bytes[] memory pts = new bytes[](2);
        uint256[] memory sc = new uint256[](2);
        pts[0] = p1; sc[0] = s1;
        pts[1] = p2; sc[1] = s2;
        return Bls12381.g1msm(Bls12381.concatMSM(pts, sc));
    }

    /// @notice Debug: compare 2 uncompressed G1 points by bytes
    function g1eq(bytes calldata a, bytes calldata b) external pure returns (bool) {
        if (a.length != 128 || b.length != 128) return false;
        return keccak256(a) == keccak256(b);
    }

    /// @notice Debug: expose G1ADD precompile for tests
    function g1add(bytes calldata a, bytes calldata b) external view returns (bytes memory) {
        return Bls12381.g1add(a, b);
    }
}


