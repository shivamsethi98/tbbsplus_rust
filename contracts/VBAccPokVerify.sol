// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Bls12381} from "./lib/Bls12381.sol";

/// @title VB Accumulator membership PoK verification (weak-BB PoK style)
/// @notice Verifies zk proof of knowledge of (e, witness) satisfying e(Delta, g2) = e(witness, g2^e * pk)
library VBAccPokVerify {
    // BLS12-381 scalar field (Fr) modulus
    uint256 internal constant FR_MODULUS =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    error BadPointLen();
    error BadG2Len();
    error SchnorrFailed();
    error PairingFailed();

    struct MembershipPok {
        bytes APrime; // 128B
        bytes ABar;   // 128B
        bytes t;      // 128B (Schnorr commitment)
        uint256 respR; // response for r
        uint256 respE; // response for e
    }

    function _qMinus(uint256 x) private pure returns (uint256) {
        uint256 r = x % FR_MODULUS;
        return r == 0 ? 0 : (FR_MODULUS - r);
    }

    function _check128(bytes memory p) private pure {
        if (p.length != 128) revert BadPointLen();
    }

    function _check256(bytes memory p) private pure {
        if (p.length != 256) revert BadG2Len();
    }

    /// @dev Verify membership PoK against Delta in G1, g2 base and accumulator pk in G2.
    ///      Checks:
    ///      - t == Delta*respR + (-APrime)*respE + ABar*(q - c)
    ///      - e(APrime, pk) * e(-ABar, g2) == 1
    function verify(
        bytes memory deltaG1,
        bytes memory g2base,
        bytes memory pkG2,
        uint256 challenge,
        MembershipPok calldata p
    ) internal view returns (bool) {
        _check128(deltaG1);
        _check128(p.APrime);
        _check128(p.ABar);
        _check128(p.t);
        _check256(g2base);
        _check256(pkG2);

        // Schnorr MSM: t == Delta*respR + (-A')*respE + Abar*(q-c)
        bytes[] memory pts = new bytes[](3);
        uint256[] memory sc = new uint256[](3);
        pts[0] = deltaG1;                  sc[0] = p.respR % FR_MODULUS;
        pts[1] = Bls12381.g1neg(p.APrime); sc[1] = p.respE % FR_MODULUS;
        pts[2] = p.ABar;                   sc[2] = _qMinus(challenge);
        bytes memory msmIn = Bls12381.concatMSM(pts, sc);
        bytes memory outT  = Bls12381.g1msm(msmIn);
        if (keccak256(outT) != keccak256(p.t)) revert SchnorrFailed();

        // Pairing: e(A', pk) * e(-Abar, g2) == 1
        address PAIR = address(0x0f);
        bytes memory input = bytes.concat(p.APrime, pkG2, Bls12381.g1neg(p.ABar), g2base);
        (bool ok, bytes memory out) = PAIR.staticcall(input);
        if (!ok || out.length != 32 || out[31] != 0x01) revert PairingFailed();

        return true;
    }
}


