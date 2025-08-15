// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Minimal BLS12-381 precompile helpers (EIP-2537)
/// @notice Raw staticcalls to G1ADD (0x0b) and G1MSM (0x0c). Inputs are uncompressed bytes.
library Bls12381 {
    address internal constant G1ADD = address(0x0b);
    address internal constant G1MSM = address(0x0c);

    error BlsPrecompileFailed();

    /// @notice Call G1 addition precompile with 2 concatenated 128-byte points.
    /// @param a 128-byte uncompressed G1 point (x||y)
    /// @param b 128-byte uncompressed G1 point (x||y)
    /// @return c 128-byte uncompressed G1 point result
    function g1add(bytes memory a, bytes memory b) internal view returns (bytes memory c) {
        require(a.length == 128 && b.length == 128, "bad G1 len");
        bytes memory input = bytes.concat(a, b);
        (bool ok, bytes memory out) = G1ADD.staticcall(input);
        if (!ok || out.length != 128) revert BlsPrecompileFailed();
        return out;
    }

    /// @notice Call G1 MSM precompile with concatenated pairs: (128-byte point || 32-byte scalar)
    /// @param input concatenated pairs for k>=1; length must be 160*k
    /// @return out128 128-byte uncompressed G1 point result of MSM
    function g1msm(bytes memory input) internal view returns (bytes memory out128) {
        require(input.length % 160 == 0 && input.length > 0, "bad MSM len");
        (bool ok, bytes memory out) = G1MSM.staticcall(input);
        if (!ok || out.length != 128) revert BlsPrecompileFailed();
        return out;
    }

    /// @notice Utilities to help build MSM calldata.
    function concatMSM(bytes[] memory points128, uint256[] memory scalars)
        internal
        pure
        returns (bytes memory out)
    {
        require(points128.length == scalars.length, "len mismatch");
        uint256 k = points128.length;
        out = new bytes(160 * k);
        uint256 o = 0;
        for (uint256 i = 0; i < k; i++) {
            bytes memory p = points128[i];
            require(p.length == 128, "bad G1 pt");
            // copy 128-byte point
            for (uint256 j = 0; j < 128; j++) {
                out[o + j] = p[j];
            }
            o += 128;
            // append 32-byte big-endian scalar
            bytes32 s = bytes32(scalars[i]);
            for (uint256 j = 0; j < 32; j++) {
                out[o + j] = s[j];
            }
            o += 32;
        }
    }
}
