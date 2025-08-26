import { expect } from "chai";
import { ethers } from "hardhat";

describe("Issue allowlisting", function () {
  it("only allowlisted issuers can emit blind sign", async () => {
    const [owner, issuer1, client, rando] = await ethers.getSigners();

    const Params = await ethers.getContractFactory("Params");
    const params = await Params.connect(owner).deploy();
    await params.waitForDeployment();
  // Initialize minimal params via setupAll (fixed fields with zeroed blob); H set optional for this test
  const zeros = (n: number) => "0x" + "00".repeat(n);
  const blob = ethers.concat([
    zeros(128), // g1
    zeros(128), // h0
    zeros(256), // g2Base
    zeros(256), // pkG2
    zeros(128), // openerYbar
    zeros(256), // openerPkG2
  ]);
  await (
    await (params as any).connect(owner).setupAll(
      "ANON_CRED", 5, 2, 3, [1, 2], blob, [], []
    )
  ).wait();

    const Issue = await ethers.getContractFactory("Issue");
    const issue = await Issue.connect(owner).deploy(await params.getAddress());
    await issue.waitForDeployment();

    // Non-allowlisted should revert
    await expect(
      issue.connect(rando).SendBlindSign("ANON_CRED", client.address, [3, 4], [5, 6])
    ).to.be.revertedWith("not issuer");

    // Allowlist issuer1
    await issue.connect(owner).addIssuer(issuer1.address);

    // Now it should pass and emit
    const id = await params.getMapCredentials("ANON_CRED");
    await expect(
      issue.connect(issuer1).SendBlindSign("ANON_CRED", client.address, [3, 4], [5, 6])
    )
      .to.emit(issue, "emitIssue")
      .withArgs(id, client.address, issuer1.address, [3, 4], [5, 6]);
  });
});
