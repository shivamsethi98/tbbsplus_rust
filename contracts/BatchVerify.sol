// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Bls12381} from "./lib/Bls12381.sol";
import {Params} from "./Params.sol";

/// @dev Minimal interface to fetch the accumulator delta from the Accumulator contract.
interface IAccDelta {
    function getDelta(string calldata name) external view returns (bytes memory);
}

/// @dev Per-user G1 point layout (all points 128 bytes, uncompressed EIP-2537 format):
///
///   sigPts  — per user (A', ABar, d)       = 384 B/user
///   bbsT    — per user (T1, T2)            = 256 B/user
///   encPts  — per user (T1enc, T2enc, Tenc)= 384 B/user
///   accPts  — per user (A'acc, ABaracc, tacc)= 384 B/user
///
/// Per-user scalar layout:
///   bbsResp[bbsRespOffsets[j] .. bbsRespOffsets[j+1]]:
///     [respA, respH0, respR3, respSPrime, respMsgs[0..U_j-1]]
///     where R_j = 4 + U_j and U_j = messageCount - |revIdx_j|
///   encResp[j*2..j*2+1]: [respA3, respK]
///   accResp[j*2..j*2+1]: [respR, respE]
///
/// Per-user revealed attributes are stored as flat arrays with prefix-sum offsets:
///   revIdxFlat[revOffsets[j] .. revOffsets[j+1]]:  revealed indices for user j
///   revValsFlat[revOffsets[j] .. revOffsets[j+1]]: revealed values for user j
struct BatchPresInput {
    bytes     sigPts;          // B × 384 B
    bytes     bbsT;            // B × 256 B
    uint256[] bbsC;            // B  (BBS+ PoK challenge per user)
    uint256[] bbsResp;         // Σ R_j  (variable per user)
    uint256[] bbsRespOffsets;  // B+1 prefix sums
    bytes     encPts;          // B × 384 B
    uint256[] encResp;         // B × 2
    bytes     accPts;          // B × 384 B
    uint256[] accC;            // B  (accumulator PoK challenge per user)
    uint256[] accResp;         // B × 2
    uint32[]  revIdxFlat;      // concatenated per-user revealed indices
    uint256[] revValsFlat;     // concatenated per-user revealed values
    uint256[] revOffsets;      // B+1 prefix sums
}

/// @title  Batched Credential Presentation Verifier (Paper §3.3.3)
/// @notice Verifies B credential presentations in a single transaction by aggregating
///         all discrete-log (Schnorr) and pairing checks.
///
///         For each user j the per-user batching weight is
///              ρ_j := keccak256(j ∥ θ_j) mod Fr
///         where θ_j is the user's full presentation data (G1 points + challenges).
///
///         Checks performed (each via a single aggregated MSM followed by identity check):
///           1. BBS+ Schnorr Relation 1  (T1 equation)
///           2. BBS+ Schnorr Relation 2  (T2 equation)
///           3. Encryption relation       (enc Schnorr)
///           4. Accumulator Schnorr       (membership PoK discrete-log)
///           5+6. Combined BBS+ and accumulator pairing  (4-pair check)
///
///         Gas savings: constant number of pairing operations (4), aggregated MSMs
///         with sub-linear precompile pricing, and a single transaction/event for B users.
contract BatchVerifyWrapper {
    uint256 internal constant FR_MOD =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    address internal constant PAIR = address(0x0f);

    event BatchPresentationVerified(
        string indexed name,
        uint256 batchSize,
        bytes T1s,   // B × 128 B  concatenated encryption T1 ciphertexts
        bytes T2s    // B × 128 B  concatenated encryption T2 ciphertexts
    );

    // ═══════════════════════════════════════════════════════════════════
    //   Main entry point
    // ═══════════════════════════════════════════════════════════════════

    /// @notice Verify a batch of B credential presentations.
    /// @dev    Users may reveal different attribute sets.  Relation 2 (T2) is
    ///         verified per-user; all other checks are aggregated across users.
    /// @param name            Credential name registered in Params
    /// @param paramsAddr      Address of the Params contract
    /// @param accumulatorAddr Address of the Accumulator contract
    /// @param inp             Packed presentation data for B users
    function verifyPresentationBatch(
        string calldata name,
        address paramsAddr,
        address accumulatorAddr,
        BatchPresInput calldata inp
    ) external returns (bool) {

        // ── 0. Derive B and validate lengths ─────────────────────────
        uint256 B = inp.bbsC.length;
        require(B > 0, "empty batch");
        require(inp.sigPts.length  == B * 384, "sigPts len");
        require(inp.bbsT.length    == B * 256, "bbsT len");
        require(inp.encPts.length  == B * 384, "encPts len");
        require(inp.encResp.length == B * 2,   "encResp len");
        require(inp.accPts.length  == B * 384, "accPts len");
        require(inp.accC.length    == B,       "accC len");
        require(inp.accResp.length == B * 2,   "accResp len");
        require(inp.bbsRespOffsets.length == B + 1, "bbsRespOffsets len");
        require(inp.bbsRespOffsets[B] == inp.bbsResp.length, "bbsResp total len");
        require(inp.revOffsets.length == B + 1, "revOffsets len");
        require(inp.revIdxFlat.length == inp.revOffsets[B], "revIdxFlat len");
        require(inp.revValsFlat.length == inp.revOffsets[B], "revValsFlat len");

        // ── 1. Fetch shared params ───────────────────────────────────
        Params prm = Params(paramsAddr);
        (bytes memory g1, bytes memory h0, bytes memory g2base) =
            prm.getG1H0G2ByName(name);

        bytes[] memory H = prm.getHByName(name);
        uint256 msgCount = H.length;

        // ── 2. Compute per-user weights ρ_j ─────────────────────────
        uint256[] memory rhos = _computeRhos(B, inp);

        // ── 3. Aggregated Schnorr Relation 1 — T1 equation ──────────
        // Single-user:  MSM([A', h0, ABar, d], [respA, respH0, q-c, c]) == T1
        // Batched:      Σ_j ρ_j·(LHS_j - T1_j) == O  (identity)
        //
        // MSM entries: (h0, Σ ρ_j·respH0_j) shared
        //   per user j: (A'_j, ρ_j·respA_j), (ABar_j, ρ_j·(q-c_j)),
        //               (d_j, ρ_j·c_j), (T1_j, q-ρ_j)
        {
            uint256 n = 1 + 4 * B;
            bytes memory msm = new bytes(160 * n);

            uint256 aggH0 = 0;
            for (uint256 j = 0; j < B; j++) {
                aggH0 = addmod(
                    aggH0,
                    mulmod(rhos[j], inp.bbsResp[inp.bbsRespOffsets[j] + 1] % FR_MOD, FR_MOD),
                    FR_MOD
                );
            }
            _wPtM(msm, 0, h0);
            _wSc(msm, 0, aggH0);

            for (uint256 j = 0; j < B; j++) {
                uint256 bi = 1 + j * 4;
                uint256 rho = rhos[j];
                uint256 cj     = inp.bbsC[j] % FR_MOD;
                uint256 respAj = inp.bbsResp[inp.bbsRespOffsets[j]] % FR_MOD;
                uint256 qmc    = cj == 0 ? 0 : FR_MOD - cj;

                _wPtCd(msm, bi,     inp.sigPts, j * 384);       // A'
                _wSc  (msm, bi,     mulmod(rho, respAj, FR_MOD));
                _wPtCd(msm, bi + 1, inp.sigPts, j * 384 + 128); // ABar
                _wSc  (msm, bi + 1, mulmod(rho, qmc, FR_MOD));
                _wPtCd(msm, bi + 2, inp.sigPts, j * 384 + 256); // d
                _wSc  (msm, bi + 2, mulmod(rho, cj, FR_MOD));
                _wPtCd(msm, bi + 3, inp.bbsT,   j * 256);       // T1 (negated)
                _wSc  (msm, bi + 3, FR_MOD - rho);
            }

            require(_isId(Bls12381.g1msm(msm)), "rel1 fail");
        }

        // ── 4. Per-user Schnorr Relation 2 — T2 equation ─────────────
        // Each user j may reveal a different attribute set, so undisclosed H
        // bases and c_m differ per user.  Verified individually (no ρ weights).
        //
        // Single-user check:
        //   MSM([undisH_j..., d_j, h0, c_m_j, T2_j],
        //       [respMsgs_j..., respR3_j, respSPrime_j, c_j, -1]) == O
        for (uint256 j = 0; j < B; j++) {
            uint256 rStart = inp.revOffsets[j];
            uint256 rEnd   = inp.revOffsets[j + 1];
            uint256 nRev_j = rEnd - rStart;
            uint256 undisCount_j = msgCount - nRev_j;
            uint256 base = inp.bbsRespOffsets[j];

            // Validate R_j = 4 + undisCount_j
            require(inp.bbsRespOffsets[j + 1] - base == 4 + undisCount_j, "R_j mismatch");

            // Build per-user revealed mask
            bool[] memory isRev_j = new bool[](msgCount);
            for (uint256 i = rStart; i < rEnd; i++) {
                require(inp.revIdxFlat[i] < msgCount, "rev oob");
                isRev_j[inp.revIdxFlat[i]] = true;
            }

            // Compute c_m_j = g1 + Σ H[revIdx] · revVal
            bytes memory c_m_j;
            {
                uint256 nP = nRev_j + 1;
                bytes[] memory pts = new bytes[](nP);
                uint256[] memory sc = new uint256[](nP);
                for (uint256 i = 0; i < nRev_j; i++) {
                    pts[i] = H[inp.revIdxFlat[rStart + i]];
                    sc[i]  = inp.revValsFlat[rStart + i] % FR_MOD;
                }
                pts[nP - 1] = g1;
                sc[nP - 1]  = 1;
                c_m_j = Bls12381.g1msm(Bls12381.concatMSM(pts, sc));
            }

            // MSM check: [undisH_j..., d_j, h0, c_m_j, T2_j]
            //             [respMsgs..., respR3, respSPrime, c_j, -1]
            {
                uint256 n_msm = undisCount_j + 4;
                bytes memory msm = new bytes(160 * n_msm);

                uint256 kk = 0;
                for (uint256 i = 0; i < msgCount; i++) {
                    if (!isRev_j[i]) {
                        _wPtM(msm, kk, H[i]);
                        _wSc(msm, kk, inp.bbsResp[base + 4 + kk] % FR_MOD);
                        kk++;
                    }
                }
                _wPtCd(msm, undisCount_j,     inp.sigPts, j * 384 + 256); // d
                _wSc  (msm, undisCount_j,     inp.bbsResp[base + 2] % FR_MOD); // respR3
                _wPtM (msm, undisCount_j + 1, h0);
                _wSc  (msm, undisCount_j + 1, inp.bbsResp[base + 3] % FR_MOD); // respSPrime
                _wPtM (msm, undisCount_j + 2, c_m_j);
                _wSc  (msm, undisCount_j + 2, inp.bbsC[j] % FR_MOD); // c
                _wPtCd(msm, undisCount_j + 3, inp.bbsT, j * 256 + 128); // T2 (negated)
                _wSc  (msm, undisCount_j + 3, FR_MOD - 1);

                require(_isId(Bls12381.g1msm(msm)), "rel2 fail");
            }
        }

        // ── 5. Aggregated Encryption Relation ────────────────────────
        // Single-user:  A'·respA3 + ybar·respK == Tenc + T2enc·c
        //           ⟺  A'·respA3 + ybar·respK - Tenc - T2enc·c == O
        //
        // MSM: (ybar, Σ ρ_j·respK_j) shared
        //   per user j: (A'_j, ρ_j·respA3_j), (Tenc_j, q-ρ_j), (T2enc_j, q-(ρ_j·c_j))
        {
            bytes memory ybar = prm.getOpenerYbarByName(name);
            require(ybar.length == 128, "bad ybar");

            uint256 n = 1 + 3 * B;
            bytes memory msm = new bytes(160 * n);

            uint256 aggY = 0;
            for (uint256 j = 0; j < B; j++) {
                aggY = addmod(aggY, mulmod(rhos[j], inp.encResp[j * 2 + 1] % FR_MOD, FR_MOD), FR_MOD);
            }
            _wPtM(msm, 0, ybar);
            _wSc (msm, 0, aggY);

            for (uint256 j = 0; j < B; j++) {
                uint256 bi = 1 + j * 3;
                uint256 rho     = rhos[j];
                uint256 cj      = inp.bbsC[j] % FR_MOD;
                uint256 respA3j = inp.encResp[j * 2] % FR_MOD;
                uint256 rhoCj   = mulmod(rho, cj, FR_MOD);

                _wPtCd(msm, bi,     inp.sigPts, j * 384);       // A'  (same point as in BBS+)
                _wSc  (msm, bi,     mulmod(rho, respA3j, FR_MOD));
                _wPtCd(msm, bi + 1, inp.encPts, j * 384 + 256); // Tenc (negated)
                _wSc  (msm, bi + 1, FR_MOD - rho);
                _wPtCd(msm, bi + 2, inp.encPts, j * 384 + 128); // T2enc (negated * c)
                _wSc  (msm, bi + 2, rhoCj == 0 ? 0 : FR_MOD - rhoCj);
            }

            require(_isId(Bls12381.g1msm(msm)), "enc fail");
        }

        // ── 6. Aggregated Accumulator Schnorr ────────────────────────
        // Single-user:  delta·respR + (-A'acc)·respE + ABaracc·(q-c_acc) == t_acc
        //           ⟺  delta·respR + A'acc·(q-respE) + ABaracc·(q-c_acc) - t_acc == O
        //
        // MSM: (delta, Σ ρ_j·respR_j) shared
        //   per user j: (A'acc_j, ρ_j·(q-respE_j)),
        //               (ABaracc_j, ρ_j·(q-c_acc_j)),
        //               (t_acc_j, q-ρ_j)
        {
            bytes memory delta = IAccDelta(accumulatorAddr).getDelta(name);
            require(delta.length == 128, "bad delta");

            uint256 n = 1 + 3 * B;
            bytes memory msm = new bytes(160 * n);

            uint256 aggD = 0;
            for (uint256 j = 0; j < B; j++) {
                aggD = addmod(aggD, mulmod(rhos[j], inp.accResp[j * 2] % FR_MOD, FR_MOD), FR_MOD);
            }
            _wPtM(msm, 0, delta);
            _wSc (msm, 0, aggD);

            for (uint256 j = 0; j < B; j++) {
                uint256 bi = 1 + j * 3;
                uint256 rho    = rhos[j];
                uint256 caccj  = inp.accC[j] % FR_MOD;
                uint256 respEj = inp.accResp[j * 2 + 1] % FR_MOD;
                uint256 qmRE   = respEj == 0 ? 0 : FR_MOD - respEj;
                uint256 qmCA   = caccj  == 0 ? 0 : FR_MOD - caccj;

                _wPtCd(msm, bi,     inp.accPts, j * 384);       // A'acc
                _wSc  (msm, bi,     mulmod(rho, qmRE, FR_MOD));
                _wPtCd(msm, bi + 1, inp.accPts, j * 384 + 128); // ABaracc
                _wSc  (msm, bi + 1, mulmod(rho, qmCA, FR_MOD));
                _wPtCd(msm, bi + 2, inp.accPts, j * 384 + 256); // tacc (negated)
                _wSc  (msm, bi + 2, FR_MOD - rho);
            }

            require(_isId(Bls12381.g1msm(msm)), "acc schnorr fail");
        }

        // ── 7. Combined BBS+ and Accumulator Pairing ────────────────
        // BBS+:  e(Σ ρ_j A'_j,  pkG2)    · e(-(Σ ρ_j ABar_j),    g2) = 1
        // Acc:   e(Σ ρ_j A'acc_j, pkAccG2) · e(-(Σ ρ_j ABaracc_j), g2) = 1
        //
        // Combined into one 4-pair PAIRING precompile call.
        {
            bytes memory pkG2    = prm.getPkG2ByName(name);
            bytes memory pkAccG2 = prm.getOpenerPkG2ByName(name);
            require(pkG2.length == 256 && pkAccG2.length == 256 && g2base.length == 256, "bad G2");

            bytes memory msmBuf = new bytes(160 * B);

            // L_bbs = MSM(A'_j, ρ_j)
            for (uint256 j = 0; j < B; j++) {
                _wPtCd(msmBuf, j, inp.sigPts, j * 384);
                _wSc  (msmBuf, j, rhos[j]);
            }
            bytes memory Lbbs = Bls12381.g1msm(msmBuf);

            // R_bbs = -MSM(ABar_j, ρ_j)
            for (uint256 j = 0; j < B; j++) {
                _wPtCd(msmBuf, j, inp.sigPts, j * 384 + 128);
                _wSc  (msmBuf, j, rhos[j]);
            }
            bytes memory negRbbs = Bls12381.g1neg(Bls12381.g1msm(msmBuf));

            // L_acc = MSM(A'acc_j, ρ_j)
            for (uint256 j = 0; j < B; j++) {
                _wPtCd(msmBuf, j, inp.accPts, j * 384);
                _wSc  (msmBuf, j, rhos[j]);
            }
            bytes memory Lacc = Bls12381.g1msm(msmBuf);

            // R_acc = -MSM(ABaracc_j, ρ_j)
            for (uint256 j = 0; j < B; j++) {
                _wPtCd(msmBuf, j, inp.accPts, j * 384 + 128);
                _wSc  (msmBuf, j, rhos[j]);
            }
            bytes memory negRacc = Bls12381.g1neg(Bls12381.g1msm(msmBuf));

            // 4-pair pairing: e(Lbbs,pkG2) · e(negRbbs,g2) · e(Lacc,pkAccG2) · e(negRacc,g2)
            bytes memory pairIn = bytes.concat(
                Lbbs,    pkG2,
                negRbbs, g2base,
                Lacc,    pkAccG2,
                negRacc, g2base
            );
            (bool ok, bytes memory out) = PAIR.staticcall(pairIn);
            require(ok && out.length == 32 && out[31] == 0x01, "pairing fail");
        }

        // ── 8. Emit batch event with encryption ciphertexts ──────────
        {
            bytes memory t1s = new bytes(B * 128);
            bytes memory t2s = new bytes(B * 128);
            for (uint256 j = 0; j < B; j++) {
                _cpCd(t1s, j * 128, inp.encPts, j * 384);       // T1enc_j
                _cpCd(t2s, j * 128, inp.encPts, j * 384 + 128); // T2enc_j
            }
            emit BatchPresentationVerified(name, B, t1s, t2s);
        }

        return true;
    }

    // ═══════════════════════════════════════════════════════════════════
    //   ρ_j derivation — binds weight to user's full proof transcript
    // ═══════════════════════════════════════════════════════════════════

    /// @dev  ρ_j = keccak256(j ∥ sigPts_j ∥ bbsT_j ∥ bbsC_j ∥ encPts_j ∥ accPts_j ∥ accC_j) mod Fr
    ///       Includes all publicly visible presentation data so that a malicious prover
    ///       cannot craft θ_j to exploit the batch aggregation weights.
    function _computeRhos(uint256 B, BatchPresInput calldata inp)
        private
        pure
        returns (uint256[] memory rhos)
    {
        // Extract struct members for assembly .offset access.
        bytes calldata     sigPts_ = inp.sigPts;
        bytes calldata     bbsT_   = inp.bbsT;
        uint256[] calldata bbsC_   = inp.bbsC;
        bytes calldata     encPts_ = inp.encPts;
        bytes calldata     accPts_ = inp.accPts;
        uint256[] calldata accC_   = inp.accC;

        rhos = new uint256[](B);
        // Pre-allocate a reusable 1504-byte scratch buffer for hashing.
        bytes memory scratch = new bytes(1504);
        for (uint256 j = 0; j < B; j++) {
            bytes32 h;
            // ρ_j = keccak256(j ∥ sigPts_j ∥ bbsT_j ∥ bbsC_j ∥ encPts_j ∥ accPts_j ∥ accC_j)
            // Layout: [0..31]=j, [32..415]=sigPts, [416..671]=bbsT,
            //         [672..703]=bbsC, [704..1087]=encPts, [1088..1471]=accPts, [1472..1503]=accC
            assembly ("memory-safe") {
                let ptr := add(scratch, 0x20)
                mstore(ptr, j)
                calldatacopy(add(ptr, 32),   add(sigPts_.offset, mul(j, 384)), 384)
                calldatacopy(add(ptr, 416),  add(bbsT_.offset,   mul(j, 256)), 256)
                mstore(add(ptr, 672), calldataload(add(bbsC_.offset, mul(j, 32))))
                calldatacopy(add(ptr, 704),  add(encPts_.offset,  mul(j, 384)), 384)
                calldatacopy(add(ptr, 1088), add(accPts_.offset,  mul(j, 384)), 384)
                mstore(add(ptr, 1472), calldataload(add(accC_.offset, mul(j, 32))))
                h := keccak256(ptr, 1504)
            }
            uint256 rho = uint256(h) % FR_MOD;
            if (rho == 0) rho = 1;
            rhos[j] = rho;
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //   Assembly helpers for MSM buffer construction
    // ═══════════════════════════════════════════════════════════════════

    /// @dev Write a 128-byte G1 point from memory into MSM buffer at pair index `idx`
    function _wPtM(bytes memory msm, uint256 idx, bytes memory pt) private pure {
        assembly ("memory-safe") {
            let dst := add(add(msm, 0x20), mul(idx, 160))
            let src := add(pt, 0x20)
            mstore(dst,              mload(src))
            mstore(add(dst, 0x20),   mload(add(src, 0x20)))
            mstore(add(dst, 0x40),   mload(add(src, 0x40)))
            mstore(add(dst, 0x60),   mload(add(src, 0x60)))
        }
    }

    /// @dev Write a 128-byte G1 point from calldata into MSM buffer at pair index `idx`
    ///      `cd` is a calldata bytes slice and `off` is a byte offset within it.
    function _wPtCd(bytes memory msm, uint256 idx, bytes calldata cd, uint256 off)
        private
        pure
    {
        assembly ("memory-safe") {
            calldatacopy(
                add(add(msm, 0x20), mul(idx, 160)),
                add(cd.offset, off),
                128
            )
        }
    }

    /// @dev Write a 32-byte scalar into MSM buffer at pair index `idx`
    function _wSc(bytes memory msm, uint256 idx, uint256 sc) private pure {
        assembly ("memory-safe") {
            mstore(add(add(msm, 0x20), add(mul(idx, 160), 128)), sc)
        }
    }

    /// @dev Copy 128 bytes from calldata to a memory bytes buffer
    function _cpCd(bytes memory dst, uint256 dstOff, bytes calldata src, uint256 srcOff)
        private
        pure
    {
        assembly ("memory-safe") {
            calldatacopy(add(add(dst, 0x20), dstOff), add(src.offset, srcOff), 128)
        }
    }

    /// @dev Check if a 128-byte G1 point is the identity (all 128 bytes zero)
    function _isId(bytes memory pt) private pure returns (bool ok) {
        assembly ("memory-safe") {
            let p := add(pt, 0x20)
            ok := and(
                and(iszero(mload(p)),              iszero(mload(add(p, 0x20)))),
                and(iszero(mload(add(p, 0x40))),   iszero(mload(add(p, 0x60))))
            )
        }
    }
}
