// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../BbsPlusPokVerify.sol";

contract BbsPlusPokVerifyWrapper {
    using BbsPlusPokVerify for BbsPlusPokVerify.PublicSignatureParts;

    function verify(
        BbsPlusPokVerify.PublicSignatureParts memory sig,
        BbsPlusPokVerify.VerificationContext memory ctx,
        BbsPlusPokVerify.Revealed memory revealed,
        uint256 challenge,
        BbsPlusPokVerify.Proof1 memory p1,
        BbsPlusPokVerify.Proof2 memory p2
    ) external view returns (bool) {
        return BbsPlusPokVerify.verify(sig, ctx, revealed, challenge, p1, p2);
    }
}
