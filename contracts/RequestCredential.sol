// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

contract RequestCredential {
    // For now we skip in-contract curve checks; off-chain PoK/zk to be added later using precompiles.

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

    // BBS+ specific request carrying full commitment to hidden messages and revealed subset
    event SigReqBBSPlus(
        address indexed client,
        uint256 indexed sid,
        string indexed name,
        bytes commitmentB,
        uint32[] revealedIdx,
        uint256[] revealedVals,
        bytes proof,   // opaque bytes for PoK (issuers verify off-chain for now)
        bytes context  // optional domain/context binding
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

    function broadcastSigReqBBSPlus(
        uint256 sid,
        string calldata name,
        bytes calldata commitmentB,
        uint32[] calldata revealedIdx,
        uint256[] calldata revealedVals,
        bytes calldata proof,
        bytes calldata context
    ) external {
        // PoK verification is off-chain for now; precompile-based check to be added later.
        emit SigReqBBSPlus(
            msg.sender,
            sid,
            name,
            commitmentB,
            revealedIdx,
            revealedVals,
            proof,
            context
        );
    }
}
