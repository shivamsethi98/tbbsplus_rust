// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Bls12381} from "../contracts/lib/Bls12381.sol";
import {BbsPlusPokVerify} from "../contracts/BbsPlusPokVerify.sol";
import {BbsPlusPokVerifyWrapper} from "../contracts/test/BbsPlusPokVerifyWrapper.sol";

// Minimal cheatcode interface (subset used here)
interface Vm {
    function envOr(string calldata key, string calldata defaultValue) external view returns (string memory);
    function readFile(string calldata path) external view returns (string memory);
    function parseJson(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonString(string calldata json, string calldata key) external pure returns (string memory);
    function parseUint(string calldata) external pure returns (uint256);
    function parseBytes(string calldata) external pure returns (bytes memory);
}

contract BbsPlusPokFromRustFoundryTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    event log(string);

    function _precompileAvailable() internal view returns (bool) {
        bytes memory z = new bytes(128);
        try this._probeG1Add(z, z) returns (bytes memory) {
            return true;
        } catch {
            return false;
        }
    }

    function _probeG1Add(bytes memory a, bytes memory b) external view returns (bytes memory) {
        return Bls12381.g1add(a, b);
    }

    function testVerifyFromRustJson() external {
        string memory path = vm.envOr("RUST_POK_JSON", string(""));
        if (bytes(path).length == 0) {
            emit log("RUST_POK_JSON not set; skipping");
            return;
        }
        if (!_precompileAvailable()) {
            emit log("EIP-2537 precompiles unavailable in this EVM; skipping (Foundry)");
            return;
        }

        string memory json = vm.readFile(path);

        uint256 mc = abi.decode(vm.parseJson(json, ".messageCount"), (uint256));

        // Points as hex strings -> bytes
        string memory g1Str = vm.parseJsonString(json, ".g1");
        bytes memory g1 = vm.parseBytes(g1Str);
        string memory h0Str = vm.parseJsonString(json, ".h0");
        bytes memory h0 = vm.parseBytes(h0Str);

        // H is string[] of 0x-hex
        string[] memory Hs = abi.decode(vm.parseJson(json, ".H"), (string[]));
        bytes[] memory H = new bytes[](Hs.length);
        for (uint256 i = 0; i < Hs.length; i++) {
            H[i] = vm.parseBytes(Hs[i]);
        }

        string memory APrimeStr = vm.parseJsonString(json, ".APrime");
        string memory ABarStr = vm.parseJsonString(json, ".ABar");
        string memory dStr = vm.parseJsonString(json, ".d");
        bytes memory APrime = vm.parseBytes(APrimeStr);
        bytes memory ABar = vm.parseBytes(ABarStr);
        bytes memory d = vm.parseBytes(dStr);

        string memory T1Str = vm.parseJsonString(json, ".T1");
        string memory T2Str = vm.parseJsonString(json, ".T2");
        bytes memory T1 = vm.parseBytes(T1Str);
        bytes memory T2 = vm.parseBytes(T2Str);

        uint256[] memory revealedIdx256 = abi.decode(vm.parseJson(json, ".revealedIdx"), (uint256[]));
        string[] memory revealedValsStr = abi.decode(vm.parseJson(json, ".revealedVals"), (string[]));
        uint256[] memory revealedVals = new uint256[](revealedValsStr.length);
        for (uint256 i = 0; i < revealedValsStr.length; i++) {
            revealedVals[i] = vm.parseUint(revealedValsStr[i]);
        }

        string memory challengeStr = vm.parseJsonString(json, ".challenge");
        uint256 challenge = vm.parseUint(challengeStr);

        string memory respAStr = vm.parseJsonString(json, ".respA");
        string memory respH0Str = vm.parseJsonString(json, ".respH0");
        string memory respR3Str = vm.parseJsonString(json, ".respR3");
        string memory respSPrimeStr = vm.parseJsonString(json, ".respSPrime");
        uint256 respA = vm.parseUint(respAStr);
        uint256 respH0 = vm.parseUint(respH0Str);
        uint256 respR3 = vm.parseUint(respR3Str);
        uint256 respSPrime = vm.parseUint(respSPrimeStr);

        string[] memory respMsgsStr = abi.decode(vm.parseJson(json, ".respMsgs"), (string[]));
        uint256[] memory respMsgs = new uint256[](respMsgsStr.length);
        for (uint256 i = 0; i < respMsgsStr.length; i++) {
            respMsgs[i] = vm.parseUint(respMsgsStr[i]);
        }

        // Cast revealed idx to uint32[]
        uint32[] memory idx = new uint32[](revealedIdx256.length);
        for (uint256 i = 0; i < revealedIdx256.length; i++) {
            idx[i] = uint32(revealedIdx256[i]);
        }

        BbsPlusPokVerify.VerificationContext memory ctx = BbsPlusPokVerify.VerificationContext({
            messageCount: uint32(mc),
            g1: g1,
            h0: h0,
            H: H
        });
        BbsPlusPokVerify.PublicSignatureParts memory sig = BbsPlusPokVerify.PublicSignatureParts({
            APrime: APrime,
            ABar: ABar,
            d: d
        });
        BbsPlusPokVerify.Revealed memory revealed = BbsPlusPokVerify.Revealed({
            idx: idx,
            vals: revealedVals
        });
        BbsPlusPokVerify.Proof1 memory p1 = BbsPlusPokVerify.Proof1({
            T1: T1,
            respA: respA,
            respH0: respH0
        });
        BbsPlusPokVerify.Proof2 memory p2 = BbsPlusPokVerify.Proof2({
            T2: T2,
            respMsgs: respMsgs,
            respR3: respR3,
            respSPrime: respSPrime
        });

        BbsPlusPokVerifyWrapper wrapper = new BbsPlusPokVerifyWrapper();
        bool ok = wrapper.verify(sig, ctx, revealed, challenge, p1, p2);
        require(ok, "BBS+ PoK verify failed");
    }
}
