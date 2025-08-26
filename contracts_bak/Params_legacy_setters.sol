// SPDX-License-Identifier: GPL-3.0
// NOTE: This file is a backup of legacy setter functions removed from the active Params.sol.
// It is intentionally placed outside the Hardhat sources path to avoid compilation.
// Keep for reference/migration; do not import or compile.

/*
pragma solidity >=0.7.0 <0.9.0;

abstract contract ParamsLegacySettersBackup {
    // These functions belonged to the original Params contract. They were replaced by setupAll.
    // They are preserved here verbatim for future reference.

    event ParamsG1H0G2Set(string indexed name);
    event HSet(string indexed name, uint256 count);
    event OpenerCommitmentsSet(string indexed name, uint16[] indices);

    struct CredParams {
        uint256 messageCount;
        uint256 t;
        uint256 n;
        uint256[] public_m_encoding;
        uint256 hLen;
        bytes pkG2;
        bytes g1;
        bytes h0;
        bytes g2Base;
        bytes[] H;
        bytes openerYbarG1;
        bytes openerPkG2;
    }

    mapping(string => uint256) internal nameToId;
    mapping(uint256 => CredParams) internal paramsById;
    mapping(uint256 => mapping(uint16 => bytes)) internal openerCommitmentsG2;

    function setPkG2(string memory name, bytes calldata pkG2) external /*onlyOwner {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        require(pkG2.length == 256, "bad pk len");
        paramsById[id].pkG2 = pkG2;
    }

    function setOpenerKeys(string memory name, bytes calldata ybarG1, bytes calldata pkG2) external /*onlyOwner {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        require(ybarG1.length == 128 && pkG2.length == 256, "bad opener lens");
        paramsById[id].openerYbarG1 = ybarG1;
        paramsById[id].openerPkG2 = pkG2;
    }

    function setG1H0G2(string memory name, bytes calldata g1, bytes calldata h0, bytes calldata g2Base) external /*onlyOwner {
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        require(g1.length == 128 && h0.length == 128 && g2Base.length == 256, "bad lens");
        paramsById[id].g1 = g1;
        paramsById[id].h0 = h0;
        paramsById[id].g2Base = g2Base;
        emit ParamsG1H0G2Set(name);
    }

    function setHByName(string memory name, bytes[] calldata H) external /*onlyOwner*
        require(id != 0, "not found");
        for (uint256 i = 0; i < H.length; i++) { require(H[i].length == 128, "bad H pt len"); }
        CredParams storage cp = paramsById[id];
        delete cp.H;
        for (uint256 j = 0; j < H.length; j++) { cp.H.push(H[j]); }
        cp.hLen = H.length;
        emit HSet(name, H.length);
    }

    function setOpenerCommitments(
        string memory name,
        uint16[] calldata indices,
        bytes[] calldata commitmentsG2
    ) external /*onlyOwner*h == commitmentsG2.length, "len mismatch");
        uint256 id = nameToId[name];
        require(id != 0, "not found");
        for (uint256 i = 0; i < indices.length; i++) {
            require(commitmentsG2[i].length == 256, "bad g2 len");
            openerCommitmentsG2[id][indices[i]] = commitmentsG2[i];
        }
        emit OpenerCommitmentsSet(name, indices);
    }
}
*/

