import { expect } from "chai";
import { ethers } from "hardhat";

const ZERO128 = "0x" + "00".repeat(128);

async function precompilesPresent(): Promise<boolean> {
  const MAP1 = "0x0000000000000000000000000000000000000010";
  const input = "0x" + "00".repeat(64);
  try {
    const res = await ethers.provider.call({ to: MAP1, data: input });
    console.log("PRESENT", res);
    return res !== "0x" && res.length === 2 + 128 * 2;
  } catch {
    return false;
  }
}

describe("BBS+ PoK verify (no pairings) minimal", function () {
  it("verifies trivial infinity case via MSM on fork", async function () {
    if (!(await precompilesPresent())) {
      this.skip();
      return;
    }
    // REQUIRE: run on a mainnet fork (FORK=1) so EIP-2537 precompiles are available
    const Wrapper = await ethers.getContractFactory("BbsPlusPokVerifyWrapper");
    const wrapper = await Wrapper.deploy();
    await wrapper.waitForDeployment();

    const messageCount = 2;
    const H = [ZERO128, ZERO128];
    const ctx = {
      messageCount,
      g1: ZERO128,
      h0: ZERO128,
      H,
    };

    const sig = {
      APrime: ZERO128,
      ABar: ZERO128,
      d: ZERO128,
    };

    const revealed = {
      idx: [0],
      vals: [0],
    };

    const p1 = {
      T1: ZERO128,
      respA: 0,
      respH0: 0,
    };

    const p2 = {
      T2: ZERO128,
      respMsgs: [0], // undisclosed count = 1
      respR3: 0,
      respSPrime: 0,
    };

    const ok = await wrapper.verify(sig, ctx, revealed, 0, p1, p2);
    expect(ok).to.equal(true);
  });
});
