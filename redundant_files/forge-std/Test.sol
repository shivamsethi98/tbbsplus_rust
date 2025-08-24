// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimal subset of forge-std Test for vm cheatcodes and asserts
interface Vm {
    // env
    function envOr(string calldata key, string calldata defaultValue) external view returns (string memory);
    // fs
    function readFile(string calldata path) external view returns (string memory);
    // parsing
    function parseUint(string calldata) external pure returns (uint256);
    function parseBytes(string calldata) external pure returns (bytes memory);
}

contract Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    event log(string);

    function assertTrue(bool cond, string memory message) internal pure {
        if (!cond) revert("assertTrue failed");
    }
}
