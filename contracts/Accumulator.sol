// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Params} from "./Params.sol";
import {Bls12381} from "./lib/Bls12381.sol";
import {Verify} from "./Verify.sol";

interface ICredentialRegistryLike {
    function accumulatorManagers(address who) external view returns (bool);
}

/// @title Positive accumulator anchor and witnesses (single opener v1)
/// @notice Stores per-credential accumulator anchor (Delta in G1) and membership witnesses
///         produced off-chain by the opener. Verifies membership on-chain via pairing.
contract Accumulator {
    Params public immutable params;
    ICredentialRegistryLike public immutable registry;

    constructor(Params _params, ICredentialRegistryLike _registry) {
        params = _params;
        registry = _registry;
    }

    modifier onlyOpener() {
        require(registry.accumulatorManagers(msg.sender), "not opener");
        _;
    }

    // key: keccak256(name)
    function _key(string memory name) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(name));
    }

    // Per-name accumulator anchor Delta in G1 (128 bytes)
    mapping(bytes32 => bytes) private deltas;
    // Per-name mapping from element e (Fr) to membership witness (G1, 128 bytes)
    mapping(bytes32 => mapping(uint256 => bytes)) private witnesses;

    event AccumulatorUpdated(string indexed name, bytes delta);
    event WitnessAvailable(string indexed name, uint256 indexed e, bytes witness, bytes delta);

    /// @notice Set or update accumulator anchor for credential `name`
    function setDelta(string calldata name, bytes calldata delta128) external onlyOpener {
        require(delta128.length == 128, "bad delta len");
        bytes32 k = _key(name);
        deltas[k] = delta128;
        emit AccumulatorUpdated(name, delta128);
    }

    /// @notice Publish membership witness for element `e` under credential `name`
    function publishWitness(string calldata name, uint256 e, bytes calldata witness128) external onlyOpener {
        require(witness128.length == 128, "bad wit len");
        bytes32 k = _key(name);
        witnesses[k][e] = witness128;
        emit WitnessAvailable(name, e, witness128, deltas[k]);
    }

    function getDelta(string calldata name) external view returns (bytes memory) {
        return deltas[_key(name)];
    }

    function getWitness(string calldata name, uint256 e) external view returns (bytes memory) {
        return witnesses[_key(name)][e];
    }

    /// @notice Verify membership e \in Acc(name) with witness; uses Params openerPkG2 as pkAcc
    /// @dev Checks e(Delta, g2) == e(witness, g2^e * pkAcc)
    function verifyMembership(
        string calldata name,
        uint256 e,
        bytes calldata witness128
    ) external view returns (bool) {
        bytes memory delta = deltas[_key(name)];
        if (delta.length != 128 || witness128.length != 128) return false;
        ( , , bytes memory g2base) = params.getG1H0G2ByName(name);
        bytes memory pkAcc = params.getOpenerPkG2ByName(name);
        if (g2base.length != 256 || pkAcc.length != 256) return false;
        // Build pkAcc + e*g2
        uint256[] memory s = new uint256[](1); s[0] = e;
        bytes[] memory g2arr = new bytes[](1); g2arr[0] = g2base;
        bytes memory eg2 = Bls12381.g2msm(Bls12381.concatMSM_G2(g2arr, s));
        bytes memory rhs_g2 = Bls12381.g2add(pkAcc, eg2);
        // e(Delta, g2) * e(-witness, pkAcc + e*g2) == 1
        return Verify.verifyPairing(delta, g2base, Bls12381.g1neg(witness128), rhs_g2);
    }
}


