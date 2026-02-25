// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {CommitmentPokVerify} from "./CommitmentPokVerify.sol";
import {BatchCommitmentPokVerify} from "./BatchCommitmentPokVerify.sol";
// Minimal interface to the registry for recording request data
interface ICredentialRegistry {
    function noteRequest(string calldata name, uint256 userId, address owner_) external;
    function recordBprime(string calldata name, uint256 userId, bytes calldata Bprime) external;
    function recordRevealed(string calldata name, uint256 userId, uint32[] calldata idx, uint256[] calldata vals) external;
}

contract RequestCredential {
    // For now we skip in-contract curve checks; off-chain PoK/zk to be added later using precompiles.

    // Optional registry to record request metadata so CredentialRegistry can later confirm via pairing
    address public registry;
    event RegistrySet(address registry);
    function setRegistry(address r) external {
        require(registry == address(0), "registry set");
        require(r != address(0), "bad reg");
        registry = r;
        emit RegistrySet(r);
    }

    // Legacy broadcastSigReq removed – use broadcastSigReqBBSPlusVerified

    // Non-verified BBS+ request removed intentionally to enforce on-chain PoK verification

    // New gated request with on-chain verification of commitment correctness PoK (Schnorr)
    event SigReqBBSPlusVerified(
        address indexed client,
        uint256 indexed userId,
        string indexed name,
        bytes commitmentB,
        uint32[] revealedIdx,
        uint256[] revealedVals,
        uint32[] hiddenIdx,
        bytes T,
        uint256 challenge,
        uint256[] responses,
        bytes context
    );

    /// @notice Verify commitment-correctness PoK and emit verified request
    /// @dev userId is derived from msg.sender: uint256(uint160(msg.sender))
    /// @param h0 128B
    /// @param H array of 128B, length == messageCount
    /// @param hiddenIdx sorted indices of hidden messages (subset of [0..messageCount-1], typically excludes 0)
    /// @param T 128B commitment to randomness
    /// @param challenge Fr scalar
    /// @param responses aligned responses: [resp_s, resp_m_i...]
    function broadcastSigReqBBSPlusVerified(
        string calldata name,
        bytes calldata commitmentU,
        bytes calldata commitmentB,
        uint32[] calldata revealedIdx,
        uint256[] calldata revealedVals,
        bytes calldata h0,
        bytes[] calldata H,
        uint32[] calldata hiddenIdx,
        bytes calldata T,
        uint256 challenge,
        uint256[] calldata responses,
        bytes calldata context
    ) external {
        uint256 userId = uint256(uint160(msg.sender));
        bool ok = CommitmentPokVerify.verify(h0, H, hiddenIdx, T, challenge, responses, commitmentU);
        require(ok, "commitment PoK failed");
        // If a registry is configured and has been granted request authority via setRequestContract,
        // record the request owner, B' and revealed pairs for later confirmCredential
        if (registry != address(0)) {
            ICredentialRegistry reg = ICredentialRegistry(registry);
            // These will succeed only if CredentialRegistry.setRequestContract(address(this)) was called by owner
            // prior to this call; otherwise they will revert with "only request".
            try reg.noteRequest(name, userId, msg.sender) {} catch {}
            try reg.recordBprime(name, userId, commitmentB) {} catch {}
            try reg.recordRevealed(name, userId, revealedIdx, revealedVals) {} catch {}
        }
        emit SigReqBBSPlusVerified(msg.sender, userId, name, commitmentB, revealedIdx, revealedVals, hiddenIdx, T, challenge, responses, context);
    }

    /// @notice Verify N commitment-correctness PoKs in a single batched check and emit verified request events
    /// @dev All users must share the same credential schema (same h0, H, hiddenIdx).
    ///      Uses random linear combination for batched Schnorr verification.
    /// @param name credential name
    /// @param userAddrs N user addresses (userId derived from each, used as owner in registry)
    /// @param commitmentUs N × 128B "U" commitments (used for PoK verification)
    /// @param commitmentBs N × 128B "B'" commitments (stored in registry for credential confirmation)
    /// @param h0 128B base point
    /// @param H array of 128B base points (message generators)
    /// @param hiddenIdx shared hidden message indices (sorted ascending)
    /// @param Ts N × 128B commitment-to-randomness points
    /// @param challenges N scalar challenges
    /// @param flatResponses N * (|hiddenIdx|+1) packed response scalars
    /// @param allRevealedIdx N arrays of revealed message indices
    /// @param allRevealedVals N arrays of revealed message values
    /// @param contexts N context blobs
    function batchBroadcastSigReqBBSPlusVerified(
        string calldata name,
        address[] calldata userAddrs,
        bytes[] calldata commitmentUs,
        bytes[] calldata commitmentBs,
        bytes calldata h0,
        bytes[] calldata H,
        uint32[] calldata hiddenIdx,
        bytes[] calldata Ts,
        uint256[] calldata challenges,
        uint256[] calldata flatResponses,
        uint32[][] calldata allRevealedIdx,
        uint256[][] calldata allRevealedVals,
        bytes[] calldata contexts
    ) external {
        uint256 N = userAddrs.length;
        require(N > 0, "empty batch");
        require(
            commitmentUs.length == N && commitmentBs.length == N &&
            Ts.length == N && challenges.length == N &&
            allRevealedIdx.length == N && allRevealedVals.length == N &&
            contexts.length == N,
            "array length mismatch"
        );

        // Batched Schnorr verification
        bool ok = BatchCommitmentPokVerify.batchVerify(
            h0, H, hiddenIdx, commitmentUs, Ts, challenges, flatResponses
        );
        require(ok, "batch commitment PoK failed");

        // Record each user's data in the registry and emit events
        uint256 respLen = hiddenIdx.length + 1;
        for (uint256 j = 0; j < N; j++) {
            uint256 userId = uint256(uint160(userAddrs[j]));

            if (registry != address(0)) {
                ICredentialRegistry reg = ICredentialRegistry(registry);
                try reg.noteRequest(name, userId, userAddrs[j]) {} catch {}
                try reg.recordBprime(name, userId, commitmentBs[j]) {} catch {}
                try reg.recordRevealed(name, userId, allRevealedIdx[j], allRevealedVals[j]) {} catch {}
            }

            // Extract per-user responses for the event
            uint256[] memory respJ = new uint256[](respLen);
            for (uint256 i = 0; i < respLen; i++) {
                respJ[i] = flatResponses[j * respLen + i];
            }

            emit SigReqBBSPlusVerified(
                userAddrs[j], userId, name,
                commitmentBs[j], allRevealedIdx[j], allRevealedVals[j],
                hiddenIdx, Ts[j], challenges[j], respJ, contexts[j]
            );
        }
    }
}
