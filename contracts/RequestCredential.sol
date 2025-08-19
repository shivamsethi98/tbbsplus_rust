// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {CommitmentPokVerify} from "./CommitmentPokVerify.sol";
// Minimal interface to the registry for recording request data
interface ICredentialRegistry {
    function noteRequest(string calldata name, uint256 sid, address owner_) external;
    function recordBprime(string calldata name, uint256 sid, bytes calldata Bprime) external;
    function recordRevealed(string calldata name, uint256 sid, uint32[] calldata idx, uint256[] calldata vals) external;
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

    event SigReqBroadcast(
        address indexed client,
        uint256 sid,
        string name,
        uint256 sigid,
        uint256[] attribute,
        uint256 no_of_private_attribute,
        uint256[2] B_dash,
        uint256[] k,
        uint256 c
    );


    function broadcastSigReq(
        uint256 sid,
        string calldata name,
        uint256 sigid,
        uint256[] calldata attribute,
        uint256 _no_of_private_attribute,
        uint256[2] calldata _B_dash,
        uint256[] calldata k,
        uint256 c
    ) external {
        // PoK verification stubbed for v1; accept and broadcast. To be replaced with EIP-2537-based check.
        emit SigReqBroadcast(
            msg.sender,
            sid,
            name,
            sigid,
            attribute,
            _no_of_private_attribute,
            _B_dash,
            k,
            c
        );
    }

    // Non-verified BBS+ request removed intentionally to enforce on-chain PoK verification

    // New gated request with on-chain verification of commitment correctness PoK (Schnorr)
    event SigReqBBSPlusVerified(
        address indexed client,
        uint256 indexed sid,
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
    /// @param h0 128B
    /// @param H array of 128B, length == messageCount
    /// @param hiddenIdx sorted indices of hidden messages (subset of [0..messageCount-1], typically excludes 0)
    /// @param T 128B commitment to randomness
    /// @param challenge Fr scalar
    /// @param responses aligned responses: [resp_s, resp_m_i...]
    function broadcastSigReqBBSPlusVerified(
        uint256 sid,
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
        bool ok = CommitmentPokVerify.verify(h0, H, hiddenIdx, T, challenge, responses, commitmentU);
        require(ok, "commitment PoK failed");
        // If a registry is configured and has been granted request authority via setRequestContract,
        // record the request owner, B' and revealed pairs for later confirmCredential
        if (registry != address(0)) {
            ICredentialRegistry reg = ICredentialRegistry(registry);
            // These will succeed only if CredentialRegistry.setRequestContract(address(this)) was called by owner
            // prior to this call; otherwise they will revert with "only request".
            try reg.noteRequest(name, sid, msg.sender) {} catch {}
            try reg.recordBprime(name, sid, commitmentB) {} catch {}
            try reg.recordRevealed(name, sid, revealedIdx, revealedVals) {} catch {}
        }
        emit SigReqBBSPlusVerified(msg.sender, sid, name, commitmentB, revealedIdx, revealedVals, hiddenIdx, T, challenge, responses, context);
    }
}
