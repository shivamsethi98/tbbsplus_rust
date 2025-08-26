// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SSTORE2 - cheaper and more efficient storage for large byte arrays
/// @notice Minimal vendored implementation (based on 0age's SSTORE2). Stores data in deployed runtime bytecode.
library SSTORE2 {
    /// @dev Prefix a STOP opcode (0x00) to prevent execution into the data section
    bytes internal constant PREFIX = hex"00";

    /// @notice Write a byte array to contract bytecode and return the pointer address
    function write(bytes memory data) internal returns (address pointer) {
        // create2 with salt of zero for simplicity; uniqueness ensured by data hash and nonce
        bytes memory code = bytes.concat(PREFIX, data);
        assembly {
            // deploy with CREATE (cheaper/gas-compatible on most chains); ignore salt
            pointer := create(0, add(code, 0x20), mload(code))
        }
        require(pointer != address(0), "SSTORE2: deploy failed");
    }

    /// @notice Read the full data stored at `pointer`
    function read(address pointer) internal view returns (bytes memory data) {
        uint256 len;
        assembly {
            len := extcodesize(pointer)
        }
        require(len > 1, "SSTORE2: no data");
        // skip the STOP prefix
        unchecked { len -= 1; }
        data = new bytes(len);
        assembly {
            extcodecopy(pointer, add(data, 0x20), 1, len)
        }
    }

    /// @notice Read a slice [start, start+length) from data at `pointer`
    function read(address pointer, uint256 start, uint256 length) internal view returns (bytes memory out) {
        uint256 size;
        assembly { size := extcodesize(pointer) }
        require(size > 1, "SSTORE2: no data");
        // skip STOP prefix
        unchecked { size -= 1; }
        require(start + length <= size, "SSTORE2: oob");
        out = new bytes(length);
        assembly { extcodecopy(pointer, add(out, 0x20), add(start, 1), length) }
    }
}

