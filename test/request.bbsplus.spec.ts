import { expect } from "chai";
import { ethers } from "hardhat";

describe("RequestCredential BBS+", function () {
  it("emits SigReqBBSPlus on broadcast", async () => {
    const [client] = await ethers.getSigners();
    const Request = await ethers.getContractFactory("RequestCredential");
    const request = await Request.connect(client).deploy();
    await request.waitForDeployment();

    const sid = 1n;
    const name = "ANON_CRED";
    const commitmentB: [bigint, bigint] = [0n, 0n];
    const revealedIdx: number[] = [0, 2];
    const revealedVals: bigint[] = [123n, 456n];
    const proof = ethers.randomBytes(32);
    const context = ethers.toUtf8Bytes("demo");

    await expect(
      request
        .connect(client)
        .broadcastSigReqBBSPlus(
          sid,
          name,
          commitmentB,
          revealedIdx,
          revealedVals,
          proof,
          context
        )
    )
      .to.emit(request, "SigReqBBSPlus")
      .withArgs(
        client.address,
        sid,
        name,
        commitmentB,
        revealedIdx,
        revealedVals,
        proof,
        context
      );
  });
});
