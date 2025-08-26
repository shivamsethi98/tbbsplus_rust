// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

contract SetupPublicParams {
    address private owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner { require(msg.sender == owner, "only owner"); _; }

    // Event to broadcast public parameters (H vector as G1 x,y pairs, and an opaque X string)
    event PublicParam(address indexed publisher, uint256[2][] H, string X);

    function sendPublicParam(uint256[2][] memory H, string memory X) public onlyOwner {
        emit PublicParam(msg.sender, H, X);
    }
}
