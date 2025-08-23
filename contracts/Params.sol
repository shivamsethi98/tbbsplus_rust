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
    }
    mapping(uint256 => CredParams) private paramsById;

    event ParamsSet(string indexed name, uint256 indexed id, uint256 messageCount, uint256 t, uint256 n);

    // Global issuer registry and optional libp2p multiaddrs
    mapping(address => bool) public issuerAllowed;
    mapping(address => uint16) public issuerIndex; // 1..n index used by off-chain/relay
    mapping(address => string[]) private issuerMultiaddrs; // optional libp2p multiaddrs per issuer
    address[] private issuersList; // enumerate allowlisted issuers (may contain removed entries marked disallowed)
    event IssuerSet(address indexed issuer, uint16 idx, bool allowed);
    event IssuerMultiaddrsSet(address indexed issuer, string[] addrs);

    function setParamsOnce(
        string memory name,
        uint256 messageCount,
        uint256 t,
        uint256 n,
        uint256[] memory public_m_encoding,
        uint256 hLen
    ) external onlyOwner {
        require(nameToId[name] == 0, "exists");
        require(bytes(name).length > 0, "bad name");
        require(t > 0 && n >= t, "bad threshold");
        uint256 id = nextId++;
        nameToId[name] = id;
        paramsById[id] = CredParams({
            messageCount: messageCount,
            t: t,
            n: n,
            public_m_encoding: public_m_encoding,
            hLen: hLen,
            pkG2: new bytes(0),
            g1: new bytes(0),
            h0: new bytes(0),
            g2Base: new bytes(0),
            H: new bytes[](0),
            openerYbarG1: new bytes(0),
            openerPkG2: new bytes(0)
        });
        emit ParamsSet(name, id, messageCount, t, n);
    }

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

    // Set pkG2 for an existing credential set; can be called later once key is known.
    function setPkG2(string memory name, bytes calldata pkG2) external onlyOwner {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        require(pkG2.length == 256, "bad pk len");
        paramsById[id].pkG2 = pkG2;
    }

    function getPkG2ByName(string memory name) external view returns (bytes memory) {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        return paramsById[id].pkG2;
    }

    // --- Opener keys (Ybar in G1, opener pk in G2) ---
    function setOpenerKeys(string memory name, bytes calldata ybarG1, bytes calldata pkG2) external onlyOwner {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        require(ybarG1.length == 128 && pkG2.length == 256, "bad opener lens");
        paramsById[id].openerYbarG1 = ybarG1;
        paramsById[id].openerPkG2 = pkG2;
    }

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
    function setG1H0G2(string memory name, bytes calldata g1, bytes calldata h0, bytes calldata g2Base) external onlyOwner {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        require(g1.length == 128 && h0.length == 128 && g2Base.length == 256, "bad lens");
        paramsById[id].g1 = g1;
        paramsById[id].h0 = h0;
        paramsById[id].g2Base = g2Base;
        emit ParamsG1H0G2Set(name);
    }

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
}
