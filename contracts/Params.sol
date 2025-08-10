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
    }
    mapping(uint256 => CredParams) private paramsById;

    event ParamsSet(string indexed name, uint256 indexed id, uint256 messageCount, uint256 t, uint256 n);

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
            hLen: hLen
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
}
