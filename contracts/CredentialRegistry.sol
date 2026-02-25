// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Params} from "./Params.sol";
import {Bls12381} from "./lib/Bls12381.sol";
import {Fr} from "./lib/Fr.sol";
import {Verify} from "./Verify.sol";

/// @title CredentialRegistry with on-chain aggregation
/// @notice Collects issuer partial shares and aggregates them to a full BBS+ signature (A,e,s)
interface IAccumulatorLike {
    function publishMappingFromRegistry(string calldata name, uint256 userId, bytes calldata A128, uint256 e) external;
}

contract CredentialRegistry {
    using Fr for uint256;

    Params public immutable params;
    address public owner;
    address public requestContract;
    address public accumulator;

    modifier onlyOwner { require(msg.sender == owner, "only owner"); _; }

    constructor(Params _params) {
        params = _params;
        owner = msg.sender;
    }

    // --- Access control for issuers (delegates to Params) ---
    modifier onlyIssuer(uint16 idx) {
        require(params.issuerAllowed(msg.sender), "not issuer");
        require(params.issuerIndex(msg.sender) == idx, "idx mismatch");
        _;
    }

    enum Status { None, Unverified, Verified, Revoked }

    struct Sig {
        bytes A; // 128-byte G1 uncompressed
        uint256 e; // Fr
        uint256 s; // Fr
        Status status;
        bytes Bprime; // 128-byte G1 commitment from user (no g1 included)
    }

    // key: keccak256(name, userId)  // one credential per user per credential name
    mapping(bytes32 => Sig) private sigs;
    mapping(bytes32 => address) private owners; // requester who can confirm
    mapping(address => bool) public accumulatorManagers;

    // Partial shares accumulator per credential (ephemeral until aggregated)
    struct Pending {
        // sum_R is G1 accumulator (128-byte point)
        bytes sum_R; // 128 bytes (accumulated via G1ADD)
        uint256 sum_u; // Fr sum of scalars
        uint256 e;
        uint256 s;
        uint16 tNeeded;
        uint16 count;
        mapping(uint16 => bool) seenIdx; // dedupe per issuer idx
    }
    mapping(bytes32 => Pending) private pendings;

    event PartialShareAccepted(address indexed issuer, string indexed name, uint256 indexed userId, uint16 idx);
    event Aggregated(string indexed name, uint256 indexed userId, bytes A, uint256 e, uint256 s);
    event Confirmed(string indexed name, uint256 indexed userId);
    event BprimeRecorded(string indexed name, uint256 indexed userId);

    function _key(string memory name, uint256 userId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(name, userId));
    }

    function setRequestContract(address rc) external onlyOwner {
        require(rc != address(0), "bad rc");
        requestContract = rc;
    }

    function setAccumulator(address acc) external onlyOwner {
        require(acc != address(0), "bad acc");
        accumulator = acc;
    }

    function noteRequest(string calldata name, uint256 userId, address owner_) external {
        require(msg.sender == requestContract, "only request");
        bytes32 k = _key(name, userId);
        // One credential per user per credential name
        require(owners[k] == address(0) || owners[k] == owner_, "one cred per user");
        if (owners[k] == address(0)) {
            owners[k] = owner_;
        }
    }

    function setAccumulatorManager(address mgr, bool allowed) external onlyOwner { accumulatorManagers[mgr] = allowed; }

    function recordBprime(string calldata name, uint256 userId, bytes calldata Bprime) external {
        require(msg.sender == requestContract, "only request");
        require(Bprime.length == 128, "bad B' len");
        bytes32 k = _key(name, userId);
        Sig storage srec = sigs[k];
        // Keep B' required for verification; stash in session store if record not yet created
        if (srec.status != Status.None) {
            srec.Bprime = Bprime;
        }
        bprimes[k] = Bprime;
        emit BprimeRecorded(name, userId);
    }

    mapping(bytes32 => bytes) private bprimes;
    // revealed pairs persisted per (name,sid)
    mapping(bytes32 => uint32[]) private revealedIdxs;
    mapping(bytes32 => uint256[]) private revealedVals;

    event RevealedRecorded(string indexed name, uint256 indexed userId, uint256 count);
    function recordRevealed(
        string calldata name,
        uint256 userId,
        uint32[] calldata idx,
        uint256[] calldata vals
    ) external {
        require(msg.sender == requestContract, "only request");
        require(idx.length == vals.length, "len mismatch");
        bytes32 k = _key(name, userId);
        delete revealedIdxs[k];
        delete revealedVals[k];
        for (uint256 i = 0; i < idx.length; i++) {
            revealedIdxs[k].push(idx[i]);
            revealedVals[k].push(vals[i]);
        }
        emit RevealedRecorded(name, userId, idx.length);
    }

    /// @notice Submit a single partial share with auto-confirm when threshold is reached.
    /// @dev Uses _accumulateShare for aggregation, then does individual pairing check.
    function submitShare(
        string calldata name,
        uint256 userId,
        uint16 idx,
        bytes calldata R128,
        uint256 u,
        uint256 e,
        uint256 s,
        uint16 /*t*/
    ) external onlyIssuer(idx) {
        _accumulateShare(name, userId, idx, R128, u, e, s);

        // Auto-confirm if aggregation just completed and B' is available
        bytes32 k = _key(name, userId);
        Sig storage srec = sigs[k];
        if (srec.status == Status.Unverified && srec.Bprime.length == 128) {
            _autoConfirmSingle(name, userId);
        }
    }

    /// @dev Auto-confirm a single credential via individual pairing check (original behavior)
    function _autoConfirmSingle(string calldata name, uint256 userId) internal {
        bytes32 k = _key(name, userId);
        Sig storage srec = sigs[k];
        (bytes memory g1, bytes memory h0, bytes memory g2base) = params.getG1H0G2ByName(name);
        bytes memory pkG2 = params.getPkG2ByName(name);
        require(g1.length == 128 && h0.length == 128 && g2base.length == 256 && pkG2.length == 256, "params unset");
        bytes memory h0s = Bls12381.g1msm(Bls12381.concatMSM(_oneArray(h0), _oneScalar(srec.s)));
        bytes memory Bpp = Bls12381.g1add(srec.Bprime, h0s);
        uint32[] storage ridx2 = revealedIdxs[k];
        uint256[] storage rvals2 = revealedVals[k];
        if (ridx2.length > 0) {
            Params.CredParams memory cp2 = params.getParamsByName(name);
            bytes[] memory H = params.getHByName(name);
            require(H.length == cp2.messageCount, "H len");
            bytes[] memory pts = new bytes[](ridx2.length);
            uint256[] memory scs = new uint256[](ridx2.length);
            for (uint256 i = 0; i < ridx2.length; i++) { pts[i] = H[uint256(ridx2[i])]; scs[i] = rvals2[i]; }
            bytes memory sumRevealed = Bls12381.g1msm(Bls12381.concatMSM(pts, scs));
            Bpp = Bls12381.g1add(Bpp, sumRevealed);
        }
        bytes memory g1PlusBpp = Bls12381.g1add(g1, Bpp);
        uint256[] memory sc_one = _oneScalar(srec.e);
        bytes[] memory g2_one = new bytes[](1); g2_one[0] = g2base;
        bytes memory eg2 = Bls12381.g2msm(Bls12381.concatMSM_G2(g2_one, sc_one));
        bytes memory pk_plus_eg2 = Bls12381.g2add(pkG2, eg2);
        bytes memory neg_g1_plus_bpp = Bls12381.g1neg(g1PlusBpp);
        bool ok = Verify.verifyPairing(srec.A, pk_plus_eg2, neg_g1_plus_bpp, g2base);
        if (ok) {
            srec.status = Status.Verified;
            emit Confirmed(name, userId);
            if (accumulator != address(0)) { IAccumulatorLike(accumulator).publishMappingFromRegistry(name, userId, srec.A, srec.e); }
            delete revealedIdxs[k];
            delete revealedVals[k];
            delete bprimes[k];
        }
    }

    /// @notice User confirms by providing g1PlusBpp = g1 + (h0^s * prod h_i^{m_i}) as 128-byte G1; pairing checked against pkG2
    function confirmCredential(string calldata name, uint256 userId) external {
        bytes32 k = _key(name, userId);
        Sig storage srec = sigs[k];
        // Allow re-check even if already Verified to enable metrics collection; avoid reverting
        require(owners[k] == msg.sender || accumulatorManagers[msg.sender], "not allowed");
        require(srec.Bprime.length == 128 || bprimes[k].length == 128, "B' missing");
        bytes memory Bp = srec.Bprime.length == 128 ? srec.Bprime : bprimes[k];
        // Fetch params
        (bytes memory g1, bytes memory h0, bytes memory g2base) = params.getG1H0G2ByName(name);
        bytes memory pkG2 = params.getPkG2ByName(name);
        require(g1.length == 128 && h0.length == 128 && g2base.length == 256 && pkG2.length == 256, "params unset");
        // Compute h0^s and add to B'
        bytes memory h0s = Bls12381.g1msm(Bls12381.concatMSM(_oneArray(h0), _oneScalar(srec.s)));
        bytes memory Bpp = Bls12381.g1add(Bp, h0s);
        // Add MSM over revealed pairs: sum H[i]^m_i
        uint32[] storage ridx = revealedIdxs[k];
        uint256[] storage rvals = revealedVals[k];
        if (ridx.length > 0) {
            Params.CredParams memory cp2 = params.getParamsByName(name);
            bytes[] memory H = params.getHByName(name);
            require(H.length == cp2.messageCount, "H len");
            bytes[] memory pts = new bytes[](ridx.length);
            uint256[] memory scs = new uint256[](ridx.length);
            for (uint256 i = 0; i < ridx.length; i++) {
                uint256 j = uint256(ridx[i]);
                require(j < H.length, "idx oob");
                pts[i] = H[j];
                scs[i] = rvals[i];
            }
            bytes memory sumRevealed = Bls12381.g1msm(Bls12381.concatMSM(pts, scs));
            Bpp = Bls12381.g1add(Bpp, sumRevealed);
        }
        // g1 + B''
        bytes memory g1PlusBpp = Bls12381.g1add(g1, Bpp);
        // Include e in pairing: check e(A, pkG2 + e*g2base) == e(g1 + B'', g2base)
        uint256[] memory sc_one = _oneScalar(srec.e);
        bytes[] memory g2_one = new bytes[](1);
        g2_one[0] = g2base;
        bytes memory eg2 = Bls12381.g2msm(Bls12381.concatMSM_G2(g2_one, sc_one));
        bytes memory pk_plus_eg2 = Bls12381.g2add(pkG2, eg2);
        bytes memory neg_g1_plus_bpp = Bls12381.g1neg(g1PlusBpp);
        bool ok = Verify.verifyPairing(srec.A, pk_plus_eg2, neg_g1_plus_bpp, g2base);
        require(ok, "pairing fail");
        // Update status and emit only if transitioning to Verified
        if (srec.status != Status.Verified) {
            srec.status = Status.Verified;
            emit Confirmed(name, userId);
            if (accumulator != address(0)) { IAccumulatorLike(accumulator).publishMappingFromRegistry(name, userId, srec.A, srec.e); }
        }
        // cleanup per-session request data
        delete revealedIdxs[k];
        delete revealedVals[k];
        delete bprimes[k];
    }

    function getSignature(string calldata name, uint256 userId) external view returns (bytes memory A, uint256 e, uint256 s, Status status) {
        bytes32 k = _key(name, userId);
        Sig storage srec = sigs[k];
        return (srec.A, srec.e, srec.s, srec.status);
    }

    function getRequestData(string calldata name, uint256 userId) external view returns (
        bytes memory Bprime_, uint32[] memory idx, uint256[] memory vals
    ) {
        bytes32 k = _key(name, userId);
        Sig storage srec = sigs[k];
        bytes memory Bp = srec.Bprime.length == 128 ? srec.Bprime : bprimes[k];
        return (Bp, revealedIdxs[k], revealedVals[k]);
    }


    // ========================== BATCH FUNCTIONS ==========================

    event BatchSharesAccepted(address indexed issuer, string indexed name, uint16 idx, uint256 count);
    event BatchConfirmed(string indexed name, uint256 count);

    /// @notice Submit partial shares for multiple users in a single transaction.
    /// @dev Each user's share is accumulated independently. When count >= tNeeded for a user,
    ///      the signature is aggregated (A computed) and stored as Unverified.
    ///      Confirmation is deferred to confirmBatchRandomized() for batched pairing.
    /// @param name Credential name (same for all users in batch)
    /// @param userIds Array of N user IDs
    /// @param idx This issuer's index
    /// @param R128concat Concatenated N * 128-byte G1 points (R for each user)
    /// @param us Array of N Fr scalars (u for each user)
    /// @param es Array of N Fr scalars (e for each user)
    /// @param ss Array of N Fr scalars (s for each user)
    function submitShareBatch(
        string calldata name,
        uint256[] calldata userIds,
        uint16 idx,
        bytes calldata R128concat,
        uint256[] calldata us,
        uint256[] calldata es,
        uint256[] calldata ss
    ) external onlyIssuer(idx) {
        uint256 n = userIds.length;
        require(R128concat.length == n * 128, "bad R concat len");
        require(us.length == n && es.length == n && ss.length == n, "len mismatch");

        for (uint256 j = 0; j < n; j++) {
            bytes calldata R128 = R128concat[j * 128 : (j + 1) * 128];
            _accumulateShare(name, userIds[j], idx, R128, us[j], es[j], ss[j]);
        }
        emit BatchSharesAccepted(msg.sender, name, idx, n);
    }

    /// @dev Internal accumulation logic (shared by submitShare and submitShareBatch).
    ///      Aggregates sum_R and sum_u. When count >= tNeeded, computes A and stores as Unverified.
    ///      Does NOT do pairing confirmation (caller decides: auto-confirm or batch confirm).
    function _accumulateShare(
        string calldata name,
        uint256 userId,
        uint16 idx,
        bytes calldata R128,
        uint256 u,
        uint256 e,
        uint256 s
    ) internal {
        require(R128.length == 128, "bad R len");
        bytes32 k = _key(name, userId);

        Pending storage p = pendings[k];
        if (p.tNeeded == 0) {
            Params.CredParams memory cp = params.getParamsByName(name);
            require(cp.t > 0 && cp.t <= type(uint16).max, "bad thresh");
            p.tNeeded = uint16(cp.t);
            p.e = e;
            p.s = s;
            p.sum_u = 0;
            p.count = 0;
        } else {
            require(p.e == e && p.s == s, "e/s mismatch");
        }
        require(!p.seenIdx[idx], "dup idx");
        p.seenIdx[idx] = true;

        if (p.count == 0) {
            p.sum_R = R128;
        } else {
            p.sum_R = Bls12381.g1add(p.sum_R, bytes(R128));
        }
        p.sum_u = p.sum_u.add(u);
        unchecked { p.count += 1; }
        emit PartialShareAccepted(msg.sender, name, userId, idx);

        // When threshold reached, aggregate A but do NOT confirm (saves pairing for batch)
        if (p.count >= p.tNeeded) {
            uint256 inv_sum_u = Fr.inv(p.sum_u);
            bytes memory msmInput = Bls12381.concatMSM(_oneArray(p.sum_R), _oneScalar(inv_sum_u));
            bytes memory A128 = Bls12381.g1msm(msmInput);
            Sig storage srec = sigs[k];
            srec.A = A128;
            srec.e = p.e;
            srec.s = p.s;
            srec.status = Status.Unverified;
            if (bprimes[k].length == 128) { srec.Bprime = bprimes[k]; }
            emit Aggregated(name, userId, A128, p.e, p.s);
            delete pendings[k];
        }
    }

    /// @notice Batched credential verification using random linear combination (Eq 27 from paper).
    /// @dev For N credentials (A_j, e_j, s_j) with B''_j, checks:
    ///      e(∑ δ_j·A_j, pk) · e(∑ δ_j·e_j·A_j − ∑ δ_j·(g1+B''_j), g2) = 1
    ///      using a single pairing call with 2 pairs instead of N individual pairings.
    ///      Random δ_j are derived on-chain: δ_j = uint256(keccak256(seed || j)) where
    ///      seed = keccak256(A_1 || ... || A_N || block.prevrandao).
    /// @param name Credential name
    /// @param userIds Array of N user IDs to confirm
    function confirmBatchRandomized(
        string calldata name,
        uint256[] calldata userIds
    ) external {
        uint256 n = userIds.length;
        require(n > 0, "empty batch");

        // Fetch params once
        (bytes memory g1, bytes memory h0, bytes memory g2base) = params.getG1H0G2ByName(name);
        bytes memory pkG2 = params.getPkG2ByName(name);
        require(g1.length == 128 && h0.length == 128 && g2base.length == 256 && pkG2.length == 256, "params unset");

        // Collect all A values and compute seed for random challenges
        bytes[] memory As = new bytes[](n);
        for (uint256 j = 0; j < n; j++) {
            bytes32 k = _key(name, userIds[j]);
            Sig storage srec = sigs[k];
            require(srec.A.length == 128, "A missing");
            require(srec.status == Status.Unverified, "not unverified");
            require(srec.Bprime.length == 128 || bprimes[k].length == 128, "B' missing");
            As[j] = srec.A;
        }

        // Derive random seed: H(A_1 || ... || A_N || prevrandao)
        bytes memory seedInput = new bytes(0);
        for (uint256 j = 0; j < n; j++) {
            seedInput = bytes.concat(seedInput, As[j]);
        }
        seedInput = bytes.concat(seedInput, bytes32(block.prevrandao));
        bytes32 seed = keccak256(seedInput);

        // Compute δ_j for each credential
        uint256[] memory deltas = new uint256[](n);
        for (uint256 j = 0; j < n; j++) {
            // δ_j = H(seed || j) mod Fr
            deltas[j] = uint256(keccak256(abi.encodePacked(seed, j))) % Fr.MOD;
            if (deltas[j] == 0) deltas[j] = 1; // avoid zero
        }

        // Build MSM inputs:
        // L = ∑ δ_j · A_j  (for pairing with pk)
        // M = ∑ (δ_j · e_j) · A_j  (for pairing with g2)
        // R = ∑ δ_j · (g1 + B''_j)  (subtracted from M in the second pairing)
        bytes[] memory A_pts = new bytes[](n);
        uint256[] memory delta_scalars = new uint256[](n);
        uint256[] memory delta_e_scalars = new uint256[](n);
        
        // For R, we need to compute g1 + B''_j for each j, then MSM with δ_j
        bytes[] memory g1Bpp_pts = new bytes[](n);

        Params.CredParams memory cp2 = params.getParamsByName(name);
        bytes[] memory H = params.getHByName(name);

        for (uint256 j = 0; j < n; j++) {
            bytes32 k = _key(name, userIds[j]);
            Sig storage srec = sigs[k];
            
            A_pts[j] = srec.A;
            delta_scalars[j] = deltas[j];
            delta_e_scalars[j] = Fr.mul(deltas[j], srec.e);

            // Compute B'' = B' + h0^s + ∑ H[i]^m_i (for revealed messages)
            bytes memory Bp = srec.Bprime.length == 128 ? srec.Bprime : bprimes[k];
            bytes memory h0s = Bls12381.g1msm(Bls12381.concatMSM(_oneArray(h0), _oneScalar(srec.s)));
            bytes memory Bpp = Bls12381.g1add(Bp, h0s);

            // Add revealed messages
            uint32[] storage ridx = revealedIdxs[k];
            uint256[] storage rvals = revealedVals[k];
            if (ridx.length > 0) {
                require(H.length == cp2.messageCount, "H len");
                bytes[] memory rpts = new bytes[](ridx.length);
                uint256[] memory rscs = new uint256[](ridx.length);
                for (uint256 i = 0; i < ridx.length; i++) {
                    rpts[i] = H[uint256(ridx[i])];
                    rscs[i] = rvals[i];
                }
                bytes memory sumRevealed = Bls12381.g1msm(Bls12381.concatMSM(rpts, rscs));
                Bpp = Bls12381.g1add(Bpp, sumRevealed);
            }

            // g1 + B''
            g1Bpp_pts[j] = Bls12381.g1add(g1, Bpp);
        }

        // L = MSM(A_pts, δ_scalars)
        bytes memory L = Bls12381.g1msm(Bls12381.concatMSM(A_pts, delta_scalars));

        // M = MSM(A_pts, δ·e scalars)
        bytes memory M = Bls12381.g1msm(Bls12381.concatMSM(A_pts, delta_e_scalars));

        // R = MSM(g1Bpp_pts, δ_scalars)
        bytes memory R = Bls12381.g1msm(Bls12381.concatMSM(g1Bpp_pts, delta_scalars));

        // Second G1 input: M - R = M + (-R)
        bytes memory negR = Bls12381.g1neg(R);
        bytes memory M_minus_R = Bls12381.g1add(M, negR);

        // Single check: e(A_j, pk + e_j·g2) = e(g1 + B''_j, g2)
        // => e(A_j, pk) · e(e_j·A_j, g2) · e(-(g1+B''_j), g2) = 1
        //
        // Batch: ∏_j [...]^δ_j = 1
        // => e(L, pk) · e(M, g2) · e(-R, g2) = 1
        // => e(L, pk) · e(M-R, g2) = 1
        //
        // M_minus_R is already M-R, so pass it directly — no extra negation needed.
        bool ok = Verify.verifyPairing(L, pkG2, M_minus_R, g2base);
        require(ok, "batch pairing fail");

        // Mark all as Verified
        for (uint256 j = 0; j < n; j++) {
            bytes32 k = _key(name, userIds[j]);
            Sig storage srec = sigs[k];
            if (srec.status != Status.Verified) {
                srec.status = Status.Verified;
                emit Confirmed(name, userIds[j]);
                if (accumulator != address(0)) {
                    IAccumulatorLike(accumulator).publishMappingFromRegistry(name, userIds[j], srec.A, srec.e);
                }
            }
            // Cleanup per-session data
            delete revealedIdxs[k];
            delete revealedVals[k];
            delete bprimes[k];
        }
        emit BatchConfirmed(name, n);
    }

    // --- helpers ---
    function _oneArray(bytes memory p128) private pure returns (bytes[] memory arr) {
        arr = new bytes[](1);
        arr[0] = p128;
    }
    function _oneScalar(uint256 s) private pure returns (uint256[] memory arr) {
        arr = new uint256[](1);
        arr[0] = s;
    }
}



