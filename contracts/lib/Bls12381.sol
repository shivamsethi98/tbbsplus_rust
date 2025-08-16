// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Minimal BLS12-381 precompile helpers (EIP-2537)
/// @notice Raw staticcalls to G1ADD (0x0b) and G1MSM (0x0c). Inputs are uncompressed bytes.
library Bls12381 {
    address internal constant G1ADD = address(0x0b);
    address internal constant G1MSM = address(0x0c);

    error BlsPrecompileFailed();
    error BadLen();

    // BLS12-381 base field modulus Fq, big-endian 48 bytes
    function fqModulusBE48() internal pure returns (bytes memory m) {
        // 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
        m = hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    }

    function _isZero48(bytes memory be48) private pure returns (bool) {
        if (be48.length != 48) revert BadLen();
        for (uint256 i = 0; i < 48; i++) { if (be48[i] != 0) return false; }
        return true;
    }

    // Compute (modulus - y) mod modulus for 48-byte big-endian values; returns 0 if y == 0
    function _modSub48(bytes memory y) private pure returns (bytes memory z) {
        if (y.length != 48) revert BadLen();
        if (_isZero48(y)) { return new bytes(48); }
        bytes memory m = fqModulusBE48();
        z = new bytes(48);
        int256 borrow = 0;
        for (int256 i = 47; i >= 0; i--) {
            uint256 mi = uint8(m[uint256(i)]);
            uint256 yi = uint8(y[uint256(i)]);
            int256 diff = int256(mi) - int256(yi) - borrow;
            if (diff < 0) { diff += 256; borrow = 1; } else { borrow = 0; }
            z[uint256(i)] = bytes1(uint8(uint256(diff)));
        }
    }

    /// @notice Negate a G1 point (x, y) -> (x, -y mod Fq) in the 128-byte uncompressed format used by precompiles
    function g1neg(bytes memory p) internal pure returns (bytes memory out128) {
        if (p.length != 128) revert BadLen();
        out128 = new bytes(128);
        // copy x (0..63)
        for (uint256 i = 0; i < 64; i++) { out128[i] = p[i]; }
        // extract y as 48-byte BE from last 48 bytes (positions 80..127), first 16 bytes of y segment are zero padding
        bytes memory y48 = new bytes(48);
        for (uint256 j = 0; j < 48; j++) { y48[j] = p[80 + j]; }
        bytes memory yNeg = _modSub48(y48);
        // write zero padding for y (64..79) and then yNeg (80..127)
        for (uint256 k = 64; k < 80; k++) { out128[k] = 0x00; }
        for (uint256 j2 = 0; j2 < 48; j2++) { out128[80 + j2] = yNeg[j2]; }
    }

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
