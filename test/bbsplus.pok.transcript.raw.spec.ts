import { expect } from "chai";
import { ethers } from "hardhat";

describe("BBS+ PoK transcript raw challenge", function () {
  it("cRaw( transcript ) matches off-chain keccak", async () => {
    const Wrapper = await ethers.getContractFactory("contracts/test/BbsPlusPokTranscriptWrapper.sol:BbsPlusPokTranscriptWrapper");
    const wrapper = await Wrapper.deploy();

    const transcript = ethers.hexlify(ethers.randomBytes(256));
    const on = await wrapper.cRaw(transcript);

    const off = BigInt(ethers.keccak256(transcript)) % BigInt("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    expect(on).to.equal(off);
  });
});
