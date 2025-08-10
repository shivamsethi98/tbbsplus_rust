// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

import {Params} from "./Params.sol";

contract PartialSignatureRelay {
    address private owner;
    Params private params;

    constructor(Params _params) {
        owner = msg.sender;
        params = _params;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    // On-chain issuer allowlisting and index assignment (1..n)
    mapping(address => bool) public issuers;
    mapping(address => uint16) public issuerIndex; // 1..n

    event IssuerSet(address indexed issuer, uint16 idx, bool allowed);

    function setIssuer(address issuer, uint16 idx, bool allowed) external onlyOwner {
        require(idx > 0, "bad idx");
        issuers[issuer] = allowed;
        issuerIndex[issuer] = idx;
        emit IssuerSet(issuer, idx, allowed);
    }

    modifier onlyIssuers(uint16 idx) {
        require(issuers[msg.sender], "not issuer");
        require(issuerIndex[msg.sender] == idx, "idx mismatch");
        _;
    }

    // Dedupe key: (id, sid, idx)
    mapping(bytes32 => bool) private seen;

    event PartialShare(
        uint256 indexed id,
        string indexed name,
        uint256 indexed sid,
        address issuer,
        uint16 idx,
        bytes payload
    );

    function submitPartialShare(
        string calldata name,
        uint256 sid,
        uint16 idx,
        bytes calldata payload
    ) external onlyIssuers(idx) {
        uint256 id = params.getMapCredentials(name);
        require(id != 0, "no such cred");
        bytes32 key = keccak256(abi.encodePacked(id, sid, idx));
        require(!seen[key], "dup share");
        seen[key] = true;
        emit PartialShare(id, name, sid, msg.sender, idx, payload);
    }
}
