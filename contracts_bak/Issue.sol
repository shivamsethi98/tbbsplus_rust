// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

import {Params} from "./Params.sol";

contract Issue {
    Params private params;
    address private owner;

    constructor(Params _params) { owner = msg.sender; params = _params; }
    modifier onlyOwner { require(msg.sender == owner, "only owner"); _; }

    function set_params(address addr) public onlyOwner { params = Params(addr); }

    mapping(address => bool) private issuers;
    event IssuerUpdated(address indexed issuer, bool allowed);

    function addIssuer(address issuer_address) public onlyOwner { issuers[issuer_address] = true; emit IssuerUpdated(issuer_address, true); }
    function removeIssuer(address issuer_address) public onlyOwner { issuers[issuer_address] = false; emit IssuerUpdated(issuer_address, false); }

    modifier onlyIssuers { require(issuers[msg.sender], "not issuer"); _; }

    event emitIssue(uint256 indexed id, address indexed receiver, address issuer_address, uint256[2] h, uint256[2] t);

    function SendBlindSign(string memory name, address receiver, uint256[2] memory h, uint256[2] memory t_) public onlyIssuers {
        uint256 id = params.getMapCredentials(name);
        require(id != 0, "No such AC.");
        emit emitIssue(id, receiver, msg.sender, h, t_);
    }
}
