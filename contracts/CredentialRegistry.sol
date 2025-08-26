// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Params} from "./Params.sol";
import {Bls12381} from "./lib/Bls12381.sol";
import {Fr} from "./lib/Fr.sol";
import {Verify} from "./Verify.sol";

/// @title CredentialRegistry with on-chain aggregation
/// @notice Collects issuer partial shares and aggregates them to a full BBS+ signature (A,e,s)
interface IAccumulatorLike {
    function publishMappingFromRegistry(string calldata name, uint256 sid, bytes calldata A128, uint256 e) external;
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

    // key: keccak256(name, sid)  // assumes (name,sid) uniquely identify a credential session
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

    event PartialShareAccepted(address indexed issuer, string indexed name, uint256 indexed sid, uint16 idx);
    event Aggregated(string indexed name, uint256 indexed sid, bytes A, uint256 e, uint256 s);
    event Confirmed(string indexed name, uint256 indexed sid);
    event BprimeRecorded(string indexed name, uint256 indexed sid);

    function _key(string memory name, uint256 sid) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(name, sid));
    }

    function setRequestContract(address rc) external onlyOwner {
        require(rc != address(0), "bad rc");
        requestContract = rc;
    }

    function setAccumulator(address acc) external onlyOwner {
        require(acc != address(0), "bad acc");
        accumulator = acc;
    }

    function noteRequest(string calldata name, uint256 sid, address owner_) external {
        require(msg.sender == requestContract, "only request");
        bytes32 k = _key(name, sid);
        if (owners[k] == address(0)) {
            owners[k] = owner_;
        } else {
            require(owners[k] == owner_, "owner mismatch");
        }
    }

    function setAccumulatorManager(address mgr, bool allowed) external onlyOwner { accumulatorManagers[mgr] = allowed; }

    function recordBprime(string calldata name, uint256 sid, bytes calldata Bprime) external {
        require(msg.sender == requestContract, "only request");
        require(Bprime.length == 128, "bad B' len");
        bytes32 k = _key(name, sid);
        // Store directly on the aggregated record if exists, else pending via sum_R placeholder
        Sig storage srec = sigs[k];
        if (srec.status != Status.None) {
            srec.Bprime = Bprime;
        } else {
            // Temporarily store in pending by abusing sum_R storage if empty? Better: stash in dedicated mapping
            pendings[k].sum_R; // noop to silence warnings
            // We use a separate mapping for B' to avoid storage collision
        }
        bprimes[k] = Bprime;
        emit BprimeRecorded(name, sid);
    }

    mapping(bytes32 => bytes) private bprimes;
    // revealed pairs persisted per (name,sid)
    mapping(bytes32 => uint32[]) private revealedIdxs;
    mapping(bytes32 => uint256[]) private revealedVals;

    event RevealedRecorded(string indexed name, uint256 indexed sid, uint256 count);
    function recordRevealed(
        string calldata name,
        uint256 sid,
        uint32[] calldata idx,
        uint256[] calldata vals
    ) external {
        require(msg.sender == requestContract, "only request");
        require(idx.length == vals.length, "len mismatch");
        bytes32 k = _key(name, sid);
        delete revealedIdxs[k];
        delete revealedVals[k];
        for (uint256 i = 0; i < idx.length; i++) {
            revealedIdxs[k].push(idx[i]);
            revealedVals[k].push(vals[i]);
        }
        emit RevealedRecorded(name, sid, idx.length);
    }

    /// @notice Submit a partial share payload. The payload format and aggregation are TODO: wire to thin wrapper.
    /// @dev For now, we expect the issuer to provide (R128, u, e, s) already extracted from the share.
    ///      Later we will parse BBSPlusSignatureShare bytes and compute (R,u) with MSM where needed.
    function submitShare(
        string calldata name,
        uint256 sid,
        uint16 idx,
        bytes calldata R128,
        uint256 u,
        uint256 e,
        uint256 s,
        uint16 /*t*/
    ) external onlyIssuer(idx) {
        require(R128.length == 128, "bad R len");
        bytes32 k = _key(name, sid);

        Pending storage p = pendings[k];
        if (p.tNeeded == 0) {
            // derive threshold from Params
            Params.CredParams memory cp = params.getParamsByName(name);
            require(cp.t > 0 && cp.t <= type(uint16).max, "bad thresh");
            p.tNeeded = uint16(cp.t);
            p.e = e;
            p.s = s;
            p.sum_u = 0;
            p.count = 0;
            // sum_R empty means zero; we will initialize on first add as R128
        } else {
            require(p.e == e && p.s == s, "e/s mismatch");
        }
        require(!p.seenIdx[idx], "dup idx");
        p.seenIdx[idx] = true;

        // Accumulate sum_R via G1ADD and sum_u in Fr
        if (p.count == 0) {
            p.sum_R = R128;
        } else {
            p.sum_R = Bls12381.g1add(p.sum_R, R128);
        }
        p.sum_u = p.sum_u.add(u);
        p.count += 1;
        emit PartialShareAccepted(msg.sender, name, sid, idx);

        if (p.count >= p.tNeeded) {
            // Finalize: A = sum_R * inv(sum_u). For now, we can't scale a point via EVM natively; use MSM with a single pair.
            uint256 inv_sum_u = Fr.inv(p.sum_u);
            bytes memory msmInput = Bls12381.concatMSM(_oneArray(p.sum_R), _oneScalar(inv_sum_u));
            bytes memory A128 = Bls12381.g1msm(msmInput);
            Sig storage srec = sigs[k];
            srec.A = A128;
            srec.e = p.e;
            srec.s = p.s;
            srec.status = Status.Unverified;
            // Attach B' if already recorded
            if (bprimes[k].length == 128) { srec.Bprime = bprimes[k]; }
            emit Aggregated(name, sid, A128, p.e, p.s);
            // cleanup pending
            delete pendings[k];

            // Auto-confirm if B' available
            if (srec.Bprime.length == 128) {
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
                if (ok) { srec.status = Status.Verified; emit Confirmed(name, sid);
                    if (accumulator != address(0)) { IAccumulatorLike(accumulator).publishMappingFromRegistry(name, sid, srec.A, srec.e); }
                }
            }
        }
    }

    /// @notice User confirms by providing g1PlusBpp = g1 + (h0^s * prod h_i^{m_i}) as 128-byte G1; pairing checked against pkG2
    function confirmCredential(string calldata name, uint256 sid) external {
        bytes32 k = _key(name, sid);
        Sig storage srec = sigs[k];
        require(srec.status == Status.Unverified, "bad status");
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
        srec.status = Status.Verified;
        emit Confirmed(name, sid);
        if (accumulator != address(0)) { IAccumulatorLike(accumulator).publishMappingFromRegistry(name, sid, srec.A, srec.e); }
    }

    function getSignature(string calldata name, uint256 sid) external view returns (bytes memory A, uint256 e, uint256 s, Status status) {
        bytes32 k = _key(name, sid);
        Sig storage srec = sigs[k];
        return (srec.A, srec.e, srec.s, srec.status);
    }

    function getRequestData(string calldata name, uint256 sid) external view returns (
        bytes memory Bprime_, uint32[] memory idx, uint256[] memory vals
    ) {
        bytes32 k = _key(name, sid);
        Sig storage srec = sigs[k];
        bytes memory Bp = srec.Bprime.length == 128 ? srec.Bprime : bprimes[k];
        return (Bp, revealedIdxs[k], revealedVals[k]);
    }

    function debugComputeBpp(string calldata name, uint256 sid) external view returns (
        bytes memory Bpp, bytes memory g1PlusBpp
    ) {
        bytes32 k = _key(name, sid);
        Sig storage srec = sigs[k];
        bytes memory Bp = srec.Bprime.length == 128 ? srec.Bprime : bprimes[k];
        require(Bp.length == 128, "B' missing");
        (bytes memory g1, bytes memory h0, ) = params.getG1H0G2ByName(name);
        require(g1.length == 128 && h0.length == 128, "params unset");
        bytes memory h0s = Bls12381.g1msm(Bls12381.concatMSM(_oneArray(h0), _oneScalar(srec.s)));
        bytes memory base = Bls12381.g1add(Bp, h0s);
        uint32[] storage ridx = revealedIdxs[k];
        uint256[] storage rvals = revealedVals[k];
        if (ridx.length > 0) {
            bytes[] memory H = params.getHByName(name);
            bytes[] memory pts = new bytes[](ridx.length);
            uint256[] memory scs = new uint256[](ridx.length);
            for (uint256 i = 0; i < ridx.length; i++) { pts[i] = H[uint256(ridx[i])]; scs[i] = rvals[i]; }
            bytes memory sumRevealed = Bls12381.g1msm(Bls12381.concatMSM(pts, scs));
            base = Bls12381.g1add(base, sumRevealed);
        }
        return (base, Bls12381.g1add(g1, base));
    }

    function debugVerifyPairing(string calldata name, uint256 sid) external view returns (bool) {
        bytes32 k = _key(name, sid);
        Sig storage srec = sigs[k];
        bytes memory Bp = srec.Bprime.length == 128 ? srec.Bprime : bprimes[k];
        require(Bp.length == 128, "B' missing");
        (bytes memory g1, bytes memory h0, bytes memory g2base) = params.getG1H0G2ByName(name);
        bytes memory pkG2 = params.getPkG2ByName(name);
        bytes memory h0s = Bls12381.g1msm(Bls12381.concatMSM(_oneArray(h0), _oneScalar(srec.s)));
        bytes memory base = Bls12381.g1add(Bp, h0s);
        uint32[] storage ridx = revealedIdxs[k];
        uint256[] storage rvals = revealedVals[k];
        if (ridx.length > 0) {
            bytes[] memory H = params.getHByName(name);
            bytes[] memory pts = new bytes[](ridx.length);
            uint256[] memory scs = new uint256[](ridx.length);
            for (uint256 i = 0; i < ridx.length; i++) { pts[i] = H[uint256(ridx[i])]; scs[i] = rvals[i]; }
            bytes memory sumRevealed = Bls12381.g1msm(Bls12381.concatMSM(pts, scs));
            base = Bls12381.g1add(base, sumRevealed);
        }
        bytes memory g1PlusBpp = Bls12381.g1add(g1, base);
        // Include e in debug pairing as well
        uint256[] memory sc_one = _oneScalar(srec.e);
        bytes[] memory g2_one = new bytes[](1);
        g2_one[0] = g2base;
        bytes memory eg2 = Bls12381.g2msm(Bls12381.concatMSM_G2(g2_one, sc_one));
        bytes memory pk_plus_eg2 = Bls12381.g2add(pkG2, eg2);
        return Verify.verifyPairing(srec.A, pk_plus_eg2, Bls12381.g1neg(g1PlusBpp), g2base);
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
    // no-op
}



