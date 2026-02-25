// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

contract Params {
    address private owner;
    constructor() { owner = msg.sender; }

    modifier onlyOwner { require(msg.sender == owner, "only owner"); _; }

    // name => id (immutable once set)
    mapping(string => uint256) private nameToId;
    uint256 private nextId = 1;

    // Minimal params kept for now
    struct CredParams {
        uint256 messageCount;
        // Threshold config
        uint256 t;
        uint256 n;
        // Optional: public attribute encoding (opaque for now)
        uint256[] public_m_encoding;
        // H vector length (event will carry points in SetupPublicParams)
        uint256 hLen;
    // Optional: BLS12-381 G2 public key (uncompressed 256-byte x.c0||x.c1||y.c0||y.c1)
    bytes pkG2;
    // Optional: BLS12-381 G1 generator (128B) and h0 (128B) and G2 base (256B) for pairing & commitments
    bytes g1;
    bytes h0;
    bytes g2Base;
    // H vector of G1 points, 128-byte uncompressed each, length == messageCount
    bytes[] H;
    // Opener keys for encryption/accumulator: Ybar in G1 (128B) and opener pkG2 (256B)
    bytes openerYbarG1;
    bytes openerPkG2;
    // Batch sizes for aggregators (0 = no batching / single-user fallback)
    uint256 batchSizeReq;
    uint256 batchSizePres;
    }
    mapping(uint256 => CredParams) private paramsById;

    // Compact params blob layout (byte offsets) for slicing input blob in setupAll
    // 0..127: g1 (128B), 128..255: h0 (128B), 256..511: g2Base (256B),
    // 512..767: pkG2 (256B), 768..895: openerYbarG1 (128B), 896..1151: openerPkG2 (256B)
    mapping(uint256 => bytes32) private dataHash;

    event ParamsSet(string indexed name, uint256 indexed id, uint256 messageCount, uint256 t, uint256 n);

    // Slice helper: returns blob[start:start+len]
    function _slice(bytes memory blob, uint256 start, uint256 len) private pure returns (bytes memory out) {
        require(start + len <= blob.length, "oob");
        out = new bytes(len);
        assembly {
            let src := add(add(blob, 0x20), start)
            let dst := add(out, 0x20)
            for { let i := 0 } lt(i, len) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
    }


    /// @notice One-shot setup for a credential suite. Initializes all core params in a single transaction
    /// @dev Preserves existing getters so off-chain and on-chain consumers remain compatible.
    function setupAll(
        string memory name,
        uint256 messageCount,
        uint256 t,
        uint256 n,
        uint256[] memory public_m_encoding,
        uint256 batchSizeReq,
        uint256 batchSizePres,
        bytes calldata blob,
        uint16[] calldata indices,
        bytes[] calldata commitmentsG2
    ) external onlyOwner {
        require(bytes(name).length > 0, "bad name");
        require(t > 0 && n >= t, "bad threshold");
        // Expect blob length to match exact encoding size (fixed fields only, excludes H[])
        uint256 expected = 128 + 128 + 256 + 256 + 128 + 256; // 1152 bytes
        require(blob.length == expected, "bad blob len");
        require(indices.length == commitmentsG2.length, "len mismatch");
        for (uint256 i = 0; i < commitmentsG2.length; i++) { require(commitmentsG2[i].length == 256, "bad g2 len"); }

        uint256 id = nameToId[name];
        bool isNew = false;
        if (id == 0) { id = nextId++; nameToId[name] = id; isNew = true; }
        CredParams storage cp = paramsById[id];
        // If already initialized, enforce consistency
        if (cp.messageCount != 0) { require(cp.messageCount == messageCount, "mcount mismatch"); }
        cp.messageCount = messageCount;
        if (cp.t != 0) { require(cp.t == t, "t mismatch"); }
        cp.t = t;
        if (cp.n != 0) { require(cp.n == n, "n mismatch"); }
        cp.n = n;
        cp.public_m_encoding = public_m_encoding;
        cp.batchSizeReq = batchSizeReq;
        cp.batchSizePres = batchSizePres;
        // hLen is maintained by setHByName; do not overwrite here

        // Persist compact blob directly into storage fields; keep cp.H set via setHByName
        bytes memory _blob = blob; // move to memory
        dataHash[id] = keccak256(_blob);
        cp.g1 = _slice(_blob, 0, 128);
        cp.h0 = _slice(_blob, 128, 128);
        cp.g2Base = _slice(_blob, 256, 256);
        cp.pkG2 = _slice(_blob, 512, 256);
        cp.openerYbarG1 = _slice(_blob, 768, 128);
        cp.openerPkG2 = _slice(_blob, 896, 256);

        // Set opener commitments
        for (uint256 k = 0; k < indices.length; k++) {
            openerCommitmentsG2[id][indices[k]] = commitmentsG2[k];
        }

        emit ParamsSet(name, id, messageCount, t, n);
        emit ParamsG1H0G2Set(name);
        if (indices.length > 0) { emit OpenerCommitmentsSet(name, indices); }
    }

    // no-op

    // Global issuer registry and optional libp2p multiaddrs
    mapping(address => bool) public issuerAllowed;
    mapping(address => uint16) public issuerIndex; // 1..n index used by off-chain/relay
    mapping(address => string[]) private issuerMultiaddrs; // optional libp2p multiaddrs per issuer
    address[] private issuersList; // enumerate allowlisted issuers (may contain removed entries marked disallowed)
    event IssuerSet(address indexed issuer, uint16 idx, bool allowed);
    event IssuerMultiaddrsSet(address indexed issuer, string[] addrs);

    // --- Opener roster and commitments (per-credential commitments, global roster like issuers) ---
    mapping(address => bool) public openerAllowed;
    mapping(address => uint16) public openerIndex; // 1..n index
    mapping(address => string[]) private openerMultiaddrs;
    address[] private openersList;
    event OpenerSet(address indexed opener, uint16 idx, bool allowed);
    event OpenerMultiaddrsSet(address indexed opener, string[] addrs);
    // Per-credential (by id) opener index -> G2 commitment bytes (256B)
    mapping(uint256 => mapping(uint16 => bytes)) private openerCommitmentsG2;
    event OpenerCommitmentsSet(string indexed name, uint16[] indices);


    function getMapCredentials(string memory name) external view returns (uint256) {
        return nameToId[name];
    }

    function getParamsByName(string memory name) external view returns (CredParams memory) {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        return paramsById[id];
    }

    function getParamsById(uint256 id) external view returns (CredParams memory) {
        require(id != 0 && id < nextId, "bad id");
        return paramsById[id];
    }

    // Set pkG2 for an existing credential set; removed in favor of setupAll
    // function setPkG2(string memory name, bytes calldata pkG2) external onlyOwner { ... }

    function getPkG2ByName(string memory name) external view returns (bytes memory) {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        return paramsById[id].pkG2;
    }

    // --- Opener keys (Ybar in G1, opener pk in G2) ---
    // function setOpenerKeys(string memory name, bytes calldata ybarG1, bytes calldata pkG2) external onlyOwner { ... }

    function getOpenerYbarByName(string memory name) external view returns (bytes memory) {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        return paramsById[id].openerYbarG1;
    }

    function getOpenerPkG2ByName(string memory name) external view returns (bytes memory) {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        return paramsById[id].openerPkG2;
    }

    event ParamsG1H0G2Set(string indexed name);
    // function setG1H0G2(string memory name, bytes calldata g1, bytes calldata h0, bytes calldata g2Base) external onlyOwner { ... }

    function getG1H0G2ByName(string memory name) external view returns (bytes memory g1, bytes memory h0, bytes memory g2Base) {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        CredParams storage cp = paramsById[id];
        return (cp.g1, cp.h0, cp.g2Base);
    }

    event HSet(string indexed name, uint256 count);
    function setHByName(string memory name, bytes[] calldata H) external onlyOwner {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        // Ensure each point is 128 bytes
        for (uint256 i = 0; i < H.length; i++) {
            require(H[i].length == 128, "bad H pt len");
        }
        CredParams storage cp = paramsById[id];
        delete cp.H;
        for (uint256 j = 0; j < H.length; j++) {
            cp.H.push(H[j]);
        }
        cp.hLen = H.length;
        emit HSet(name, H.length);
    }

    function getHByName(string memory name) external view returns (bytes[] memory H) {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        CredParams storage cp = paramsById[id];
        return cp.H;
    }

    // --- Batch size config ---
    function getBatchSizesByName(string memory name) external view returns (uint256, uint256) {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        CredParams storage cp = paramsById[id];
        return (cp.batchSizeReq, cp.batchSizePres);
    }

    function setBatchSizes(string memory name, uint256 reqSize, uint256 presSize) external onlyOwner {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        paramsById[id].batchSizeReq = reqSize;
        paramsById[id].batchSizePres = presSize;
    }

    // --- Opener admin (roster and multiaddrs) ---
    function setOpener(address opener, uint16 idx, bool allowed) external onlyOwner {
        require(idx > 0, "bad idx");
        openerAllowed[opener] = allowed;
        openerIndex[opener] = idx;
        bool seen = false;
        for (uint256 i = 0; i < openersList.length; i++) {
            if (openersList[i] == opener) { seen = true; break; }
        }
        if (!seen) { openersList.push(opener); }
        emit OpenerSet(opener, idx, allowed);
    }

    function setOpenerMultiaddrs(address opener, string[] calldata addrs) external onlyOwner {
        delete openerMultiaddrs[opener];
        for (uint256 i = 0; i < addrs.length; i++) {
            openerMultiaddrs[opener].push(addrs[i]);
        }
        emit OpenerMultiaddrsSet(opener, addrs);
    }

    function getOpenerMultiaddrs(address opener) external view returns (string[] memory) {
        return openerMultiaddrs[opener];
    }

    function getOpeners() external view returns (address[] memory) {
        return openersList;
    }

    // --- Opener commitments per-credential ---
    // function setOpenerCommitments(string memory name, uint16[] calldata indices, bytes[] calldata commitmentsG2) external onlyOwner { ... }

    function getOpenerCommitment(string memory name, uint16 idx) external view returns (bytes memory) {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        return openerCommitmentsG2[id][idx];
    }

    // Issuer registry ops
    function setIssuer(address issuer, uint16 idx, bool allowed) external onlyOwner {
        require(idx > 0, "bad idx");
        issuerAllowed[issuer] = allowed;
        issuerIndex[issuer] = idx;
        // Add to list if first time seen
        bool seen = false;
        for (uint256 i = 0; i < issuersList.length; i++) {
            if (issuersList[i] == issuer) { seen = true; break; }
        }
        if (!seen) { issuersList.push(issuer); }
        emit IssuerSet(issuer, idx, allowed);
    }

    function setIssuerMultiaddrs(address issuer, string[] calldata addrs) external onlyOwner {
        delete issuerMultiaddrs[issuer];
        for (uint256 i = 0; i < addrs.length; i++) {
            issuerMultiaddrs[issuer].push(addrs[i]);
        }
        emit IssuerMultiaddrsSet(issuer, addrs);
    }

    function getIssuerMultiaddrs(address issuer) external view returns (string[] memory) {
        return issuerMultiaddrs[issuer];
    }

    function getIssuers() external view returns (address[] memory) {
        return issuersList;
    }

    /// @notice Return the keccak256 hash of the fixed params blob stored via SSTORE2 for `name`
    function getDataHashByName(string memory name) external view returns (bytes32) {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        return dataHash[id];
    }
}
