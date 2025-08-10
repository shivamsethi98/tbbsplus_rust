import { ethers } from "hardhat";

async function main() {
  const [owner, issuer1, client] = await ethers.getSigners();
  const credName = "IITH_UG_AC";

  // Deploy Params and set immutable params once
  const Params = await ethers.getContractFactory("Params");
  const params = await Params.connect(owner).deploy();
  await params.waitForDeployment();
  await (await params
    .connect(owner)
    .setParamsOnce(credName, 5, 2, 3, [1, 2], 6)).wait();

  // Deploy RequestCredential and PartialSignatureRelay
  const Request = await ethers.getContractFactory("RequestCredential");
  const request = await Request.connect(owner).deploy();
  await request.waitForDeployment();

  const Relay = await ethers.getContractFactory("PartialSignatureRelay");
  const relay = await Relay.connect(owner).deploy(await params.getAddress());
  await relay.waitForDeployment();

  // Allowlist issuer1 with index 1
  await (await relay.connect(owner).setIssuer(issuer1.address, 1, true)).wait();

  // Listen for BBS+ request; issuer relays a dummy share on-chain
  request.on(
    "SigReqBBSPlus",
    async (
      clientAddr,
      sid,
      name,
      _commitmentB,
      revealedIdx,
      revealedVals,
      _proof,
      _context
    ) => {
      console.log("SigReqBBSPlus:", { clientAddr, sid, name, revealedIdx, revealedVals });
      const payload = ethers.randomBytes(64);
  const tx = await relay.connect(issuer1).submitPartialShare(credName, sid, 1, payload);
      await tx.wait();
      console.log("Submitted partial share from", issuer1.address);
    }
  );

  // Also listen for the relay event just to confirm end-to-end
  await new Promise<void>(async (resolve) => {
    relay.once(
      "PartialShare",
      (id, name, sid, issuer, idx, payload) => {
        console.log("PartialShare:", { id, name, sid, issuer, idx, payloadLen: (payload as string).length });
        resolve();
      }
    );

    // Trigger a request from the client
  const commitmentB: [bigint, bigint] = [0n, 0n];
  const revealedIdx: number[] = [0, 2];
  const revealedVals: bigint[] = [123n, 456n];
    const proof = ethers.randomBytes(32);
    const context = ethers.toUtf8Bytes("demo");

    await (
      await request
        .connect(client)
  .broadcastSigReqBBSPlus(1n, credName, commitmentB, revealedIdx, revealedVals, proof, context)
    ).wait();
  });
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
