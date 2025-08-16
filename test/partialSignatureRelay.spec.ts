import { expect } from "chai";
import { ethers } from "hardhat";

describe("PartialSignatureRelay", function () {
  it("allowlists issuers, relays partials, prevents dups", async () => {
    const [owner, issuer1, issuer2, client] = await ethers.getSigners();

    const Params = await ethers.getContractFactory("Params");
    const params = await Params.connect(owner).deploy();
    await params.waitForDeployment();
    await params
      .connect(owner)
      .setParamsOnce("ANON_CRED", 5, 2, 3, [1, 2], 6);

    const Relay = await ethers.getContractFactory("PartialSignatureRelay");
    const relay = await Relay.connect(owner).deploy(await params.getAddress());
    await relay.waitForDeployment();

    // not allowlisted should revert
    await expect(
      relay.connect(issuer1).submitPartialShare("ANON_CRED", 1, 1, ethers.randomBytes(64))
    ).to.be.revertedWith("not issuer");

    // allowlist issuer1 with idx 1
    await expect(relay.connect(owner).setIssuer(issuer1.address, 1, true))
      .to.emit(relay, "IssuerSet")
      .withArgs(issuer1.address, 1, true);

    // idx mismatch should revert
    await expect(
      relay.connect(issuer1).submitPartialShare("ANON_CRED", 1, 2, ethers.randomBytes(64))
    ).to.be.revertedWith("idx mismatch");

    // proper submit should emit event
    const payload = ethers.randomBytes(96);
    await expect(
      relay.connect(issuer1).submitPartialShare("ANON_CRED", 1, 1, payload)
    )
      .to.emit(relay, "PartialShare")
      .withArgs(await params.getMapCredentials("ANON_CRED"), "ANON_CRED", 1n, issuer1.address, 1, payload);

    // duplicate should revert
    await expect(
      relay.connect(issuer1).submitPartialShare("ANON_CRED", 1, 1, payload)
    ).to.be.revertedWith("dup share");

    // another issuer can be added with a different idx
    await relay.connect(owner).setIssuer(issuer2.address, 2, true);
    await expect(
      relay.connect(issuer2).submitPartialShare("ANON_CRED", 1, 2, ethers.randomBytes(96))
    ).to.emit(relay, "PartialShare");
  });
});
