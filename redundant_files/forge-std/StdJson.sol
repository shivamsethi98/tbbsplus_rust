// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimal StdJson helpers compatible with forge-std API subset used in tests.
library stdJson {
    function readUint(string memory, string memory) internal pure returns (uint256) {
        revert("StdJson mock: not supported at runtime");
    }
    function readBytes(string memory, string memory) internal pure returns (bytes memory) {
        revert("StdJson mock: not supported at runtime");
    }
    function readString(string memory, string memory) internal pure returns (string memory) {
        revert("StdJson mock: not supported at runtime");
    }
    function readStringArray(string memory, string memory) internal pure returns (string[] memory) {
        revert("StdJson mock: not supported at runtime");
    }
    function readUintArray(string memory, string memory) internal pure returns (uint256[] memory) {
        revert("StdJson mock: not supported at runtime");
    }
}
