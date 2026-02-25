// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Params} from "./Params.sol";
import {Bls12381} from "./lib/Bls12381.sol";
import {Verify} from "./Verify.sol";

interface ICredentialRegistryLike {
    function accumulatorManagers(address who) external view returns (bool);
}




/// @title Positive accumulator anchor (witness-free v2)
/// @notice Stores per-credential accumulator anchor (Delta in G1). Membership witnesses
///         are computed off-chain by users from event logs. Verifies membership on-chain via pairing.
contract Accumulator {
    Params public immutable params;
    ICredentialRegistryLike public immutable registry;
    address public serviceProvider;

    constructor(Params _params, ICredentialRegistryLike _registry) {
        params = _params;
        registry = _registry;
    }

    modifier onlyOpener() {
        require(registry.accumulatorManagers(msg.sender), "not opener");
        _;
    }

    modifier onlyServiceProvider() {
        require(msg.sender == serviceProvider, "not sp");
        _;
    }

    // key: keccak256(name)
    function _key(string memory name) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(name));
    }

    // Per-name accumulator anchor Delta in G1 (128 bytes)
    mapping(bytes32 => bytes) private deltas;
    // Per-name mapping from keccak256(A128) to element e (revocation tag)
    mapping(bytes32 => mapping(bytes32 => uint256)) private AhashToE;
    // Per-name revocation flags for element e
    mapping(bytes32 => mapping(uint256 => bool)) private revoked;

    event AccumulatorUpdated(string indexed name, bytes delta);
    event MemberAdded(string indexed name, uint256 indexed e);
    event MappingPublished(string indexed name, uint256 indexed userId, bytes32 Ahash, uint256 e);

    modifier onlyRegistry() {
        require(msg.sender == address(registry), "only registry");
        _;
    }
    event MemberRevoked(string indexed name, uint256 indexed e, bytes newDelta);
    event OpenRequested(string indexed name, address indexed requester, bytes T1, bytes T2);
    event Opened(string indexed name, bytes A);
    event RevokeRequested(string indexed name, uint256 indexed e);

    function setServiceProvider(address sp) external onlyOpener {
        require(sp != address(0), "bad sp");
        serviceProvider = sp;
    }

    /// @notice Set or update accumulator anchor for credential `name`
    function setDelta(string calldata name, bytes calldata delta128) external onlyOpener {
        require(delta128.length == 128, "bad delta len");
        bytes32 k = _key(name);
        deltas[k] = delta128;
        emit AccumulatorUpdated(name, delta128);
    }

    /// @notice Add a new member: update delta and emit MemberAdded event
    /// @dev Users derive their initial witness W_e = V_old from the previous AccumulatorUpdated event
    function addMember(string calldata name, uint256 e, bytes calldata newDelta128) external onlyOpener {
        require(newDelta128.length == 128, "bad delta len");
        require(e != 0, "bad e");
        bytes32 k = _key(name);
        deltas[k] = newDelta128;
        emit MemberAdded(name, e);
        emit AccumulatorUpdated(name, newDelta128);
    }

    /// @notice Add multiple members in a single transaction with one delta update.
    /// @dev The caller provides the final accumulator delta after all members are added.
    ///      Gas savings: single storage write for delta + single AccumulatorUpdated event,
    ///      instead of N writes and N events. Each member still gets an individual MemberAdded event.
    /// @param name Credential name
    /// @param es Array of N member elements (revocation tags)
    /// @param newDelta128 Final accumulator anchor after adding all members (128-byte G1 point)
    function addMembers(
        string calldata name,
        uint256[] calldata es,
        bytes calldata newDelta128
    ) external onlyOpener {
        require(newDelta128.length == 128, "bad delta len");
        uint256 n = es.length;
        require(n > 0, "empty batch");
        bytes32 k = _key(name);
        for (uint256 j = 0; j < n; j++) {
            require(es[j] != 0, "bad e");
            emit MemberAdded(name, es[j]);
        }
        deltas[k] = newDelta128;
        emit AccumulatorUpdated(name, newDelta128);
    }

    function getDelta(string calldata name) external view returns (bytes memory) {
        return deltas[_key(name)];
    }

    /// Internal helper to populate A->e mapping and emit event
    function _publishMapping(
        string calldata name,
        uint256 userId,
        bytes calldata A128,
        uint256 e
    ) internal {
        require(A128.length == 128, "bad A len");
        bytes32 k = _key(name);
        bytes32 ah = keccak256(A128);
        uint256 existing = AhashToE[k][ah];
        if (existing == 0) {
            AhashToE[k][ah] = e;
        }
        emit MappingPublished(name, userId, ah, e);
    }

    /// @notice Registry can populate A->e mapping immediately after verification
    function publishMappingFromRegistry(
        string calldata name,
        uint256 userId,
        bytes calldata A128,
        uint256 e
    ) external onlyRegistry {
        _publishMapping(name, userId, A128, e);
    }

    /// @notice Lookup e by A for a credential name. Returns 0 if not found
    function getEByA(string calldata name, bytes calldata A128) external view returns (uint256) {
        if (A128.length != 128) return 0;
        bytes32 k = _key(name);
        return AhashToE[k][keccak256(A128)];
    }

    /// @notice Mark element `e` as revoked and update accumulator anchor to `newDelta128`
    function deleteMember(string calldata name, uint256 e, bytes calldata newDelta128) external onlyOpener {
        require(newDelta128.length == 128, "bad delta len");
        bytes32 k = _key(name);
        require(!revoked[k][e], "already revoked");
        deltas[k] = newDelta128;
        revoked[k][e] = true;
        emit MemberRevoked(name, e, newDelta128);
        emit AccumulatorUpdated(name, newDelta128);
    }

    /// @notice Check if element `e` has been revoked for credential `name`
    function isRevoked(string calldata name, uint256 e) external view returns (bool) {
        return revoked[_key(name)][e];
    }

    /// @notice Consumers can request credential opening by submitting encryption (T1, T2)
    function requestOpen(
        string calldata name,
        bytes calldata T1,
        bytes calldata T2
    ) external onlyServiceProvider {
        require(T1.length == 128 && T2.length == 128, "bad T len");
        emit OpenRequested(name, msg.sender, T1, T2);
    }

    /// @notice Opener may publish the recovered A for transparency/auditing
    function publishOpenResult(string calldata name, bytes calldata A128) external onlyOpener {
        require(A128.length == 128, "bad A len");
        emit Opened(name, A128);
    }

    /// @notice Service provider can request revocation directly by e (after opening off-chain)
    function requestRevokeByE(string calldata name, uint256 e) external onlyServiceProvider {
        require(e != 0, "bad e");
        emit RevokeRequested(name, e);
    }

    /// @notice Verify membership e \in Acc(name) with witness supplied as calldata
    /// @dev Checks e(witness, g2^e * pkAcc) == e(Delta, g2). Witness is NOT read from storage.
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


