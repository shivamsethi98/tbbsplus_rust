import { expect } from "chai";
import { ethers } from "hardhat";
import { zeroPadValue } from "ethers";
import fs from "fs";

describe("VerifyWrapper DLEQ", () => {
  it("accepts a valid Chaum–Pedersen DLEQ vector", async () => {
    const jsonPath = process.env.DLEQ_JSON || "./dleq.json";
    const vec = JSON.parse(fs.readFileSync(jsonPath, "utf8"));

  const VerifyFactory = await ethers.getContractFactory("VerifyWrapper");
  const verify = await VerifyFactory.deploy();

    const ok = await verify.verifyDLEQ_G1(
      vec.g1, vec.t1, vec.ybar, vec.t2prime, vec.u1, vec.u2, vec.z, vec.c
    );
    expect(ok).to.eq(true);

    // Negative: tamper z
  const badZ = zeroPadValue("0x01", 32);
    const bad = await verify.verifyDLEQ_G1(
      vec.g1, vec.t1, vec.ybar, vec.t2prime, vec.u1, vec.u2,
      badZ,
      vec.c
    );
    expect(bad).to.eq(false);
  });
});
