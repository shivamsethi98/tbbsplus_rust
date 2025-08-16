import { expect } from "chai";
import { ethers } from "hardhat";

describe("AC flow v1 (events-only)", function () {
  it("sets params, broadcasts req, allowlists issuer, and emits share", async () => {
    const [owner, issuer1, client] = await ethers.getSigners();

    const Params = await ethers.getContractFactory("Params");
    const params = await Params.connect(owner).deploy();
    await params.waitForDeployment();

    // set params once
    await expect(
      params.connect(owner).setParamsOnce(
        "ANON_CRED",
        5, // messageCount
        2, // t
        3, // n
        [1, 2], // public_m_encoding (dummy)
        6 // hLen
      )
    ).to.emit(params, "ParamsSet");

    const id = await params.getMapCredentials("ANON_CRED");
    expect(id).to.not.equal(0n);

    const Request = await ethers.getContractFactory("RequestCredential");
    const req = await Request.connect(owner).deploy();
    await req.waitForDeployment();

    // broadcast request
    await expect(
      req.connect(client).broadcastSigReq(
        1, // sid
        "ANON_CRED",
        1001, // sigid
        [11, 22, 33], // attributes
        1, // no_of_private_attribute
        [1, 2], // B_dash
        [9, 8, 7], // k
        123456 // c
      )
    ).to.emit(req, "SigReqBroadcast");

    const Issue = await ethers.getContractFactory("Issue");
    const issue = await Issue.connect(owner).deploy(await params.getAddress());
    await issue.waitForDeployment();

    // allowlist issuer1
    await expect(issue.connect(owner).addIssuer(issuer1.address))
      .to.emit(issue, "IssuerUpdated")
      .withArgs(issuer1.address, true);

    // issuer sends blind sign (event-only)
    await expect(
      issue.connect(issuer1).SendBlindSign("ANON_CRED", client.address, [3, 4], [5, 6])
    )
      .to.emit(issue, "emitIssue")
      .withArgs(id, client.address, issuer1.address, [3, 4], [5, 6]);
  });
});
