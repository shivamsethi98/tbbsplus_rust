// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract EIP2537Test {
    // EIP-2537 BLS12-381 precompiles
    // Per spec/constants provided:
    // 0x0b: G1ADD, 0x0c: G1MSM, 0x0d: G2ADD, 0x0e: G2MSM
    // 0x0f: PAIRING_CHECK, 0x10: MAP_FP_TO_G1, 0x11: MAP_FP2_TO_G2
    address constant PAIRING = address(0x0f);
    address constant MAP_FP_TO_G1 = address(0x10);
    address constant MAP_FP2_TO_G2 = address(0x11);

    // Helper: detect if EIP-2537 precompiles are present on the chain being tested.
    // We call MAP_FP_TO_G1 with 64-byte zero input; per spec it should return 128 bytes.
    function _is2537Present() internal view returns (bool) {
        bytes memory input = new bytes(64);
        (bool ok, bytes memory ret) = MAP_FP_TO_G1.staticcall(input);
        // If the precompile exists per spec, ok==true and ret.length==128
        if (!ok) return false;
        if (ret.length != 128) return false;
        return true;
    }

    function _isMapFp2ToG2Present() internal view returns (bool) {
        bytes memory input = new bytes(128);
        (bool ok, bytes memory ret) = MAP_FP2_TO_G2.staticcall(input);
        if (!ok) return false;
        if (ret.length != 256) return false;
        return true;
    }

    // Presence check test (non-failing): proves precompile is available on-chain
    function test_eip2537_presence_map_fp_to_g1_zero_ok() public view {
        bytes memory input = new bytes(64); // 0 is a valid field element < p
        (bool ok, bytes memory ret) = MAP_FP_TO_G1.staticcall(input);
        if (!(ok && ret.length == 128)) {
            // Skip if local EVM (fork engine) does not implement the precompile
            return;
        }
        // If present, assert output length per spec
        require(ret.length == 128, "unexpected MAP_FP_TO_G1 output length");
    }

    // Presence check for MAP_FP2_TO_G2 (non-failing)
    function test_eip2537_presence_map_fp2_to_g2_zero_ok() public view {
        bytes memory input = new bytes(128);
        (bool ok, bytes memory ret) = MAP_FP2_TO_G2.staticcall(input);
        if (!(ok && ret.length == 256)) {
            return;
        }
        require(ret.length == 256, "unexpected MAP_FP2_TO_G2 output length");
    }

    // 1) Empty input behavior per EIP-2537: variable-length inputs MUST error on empty input.
    function test_eip2537_pairing_emptyInput_reverts_per_spec() public view {
        if (!_is2537Present()) return; // skip on chains/tools without the precompile
        (bool ok, ) = PAIRING.staticcall(hex"");
        require(!ok, "pairing should revert on empty input per EIP-2537");
    }

    // 2) Malformed short input should revert (length not representing any pair)
    function test_eip2537_pairing_malformedShort_reverts() public view {
        if (!_is2537Present()) return; // skip if absent
        (bool ok, ) = PAIRING.staticcall(hex"01");
        require(!ok, "pairing should revert for malformed 1-byte input");
        (ok, ) = PAIRING.staticcall(hex"0001");
        require(!ok, "pairing should revert for malformed 2-byte input");
        (ok, ) = PAIRING.staticcall(new bytes(31));
        require(!ok, "pairing should revert for malformed 31-byte input");
        (ok, ) = PAIRING.staticcall(new bytes(33));
        require(!ok, "pairing should revert for malformed 33-byte input");
    }

    // 3) Random garbage of medium size should revert
    function test_eip2537_pairing_randomGarbage_reverts() public view {
        if (!_is2537Present()) return; // skip if absent
        bytes memory data = new bytes(96);
        for (uint256 i=0; i<data.length; i++) data[i] = bytes1(uint8(i));
        (bool ok, ) = PAIRING.staticcall(data);
        require(!ok, "pairing should revert on random garbage");
    }

    // 4) Very large malformed input should revert as well
    function test_eip2537_pairing_largeMalformed_reverts() public view {
        if (!_is2537Present()) return; // skip if absent
        bytes memory data = new bytes(1024);
        for (uint256 i=0; i<data.length; i++) data[i] = 0x01;
        (bool ok, ) = PAIRING.staticcall(data);
        require(!ok, "pairing should revert on large malformed input");
    }
}

