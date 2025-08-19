// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BLS12-381 Fr (scalar field) helpers
/// @notice Minimal modular arithmetic over Fr with MODEXP-based inversion
library Fr {
    // BLS12-381 Fr modulus (order of G1/G2 groups)
    // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    uint256 internal constant MOD = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    /// @dev add modulo Fr
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, b, MOD);
    }

    /// @dev sub modulo Fr
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return addmod(a, MOD - (b % MOD), MOD);
        }
    }

    /// @dev mul modulo Fr
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, MOD);
    }

    /// @dev modular exponentiation via precompile 0x05
    function modexp(uint256 base, uint256 exponent, uint256 modulus) internal view returns (uint256 result) {
        bytes memory input = abi.encodePacked(uint256(32), uint256(32), uint256(32), bytes32(base), bytes32(exponent), bytes32(modulus));
        (bool ok, bytes memory out) = address(0x05).staticcall(input);
        require(ok && out.length == 32, "modexp failed");
        return uint256(bytes32(out));
    }

    /// @dev modular inverse a^(MOD-2) mod MOD (MOD is prime)
    function inv(uint256 a) internal view returns (uint256) {
        require(a != 0, "inv 0");
        return modexp(a, MOD - 2, MOD);
    }
}


