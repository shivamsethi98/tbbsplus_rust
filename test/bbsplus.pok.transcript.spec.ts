import { expect } from "chai";
import { ethers } from "hardhat";

// Typescript mirror of BbsPlusPokTranscript.computeChallenge ordering
function keccakFr(hexNo0x: string): bigint {
  // BLS12-381 Fr modulus
  const r = BigInt("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
  const h = ethers.keccak256("0x" + hexNo0x);
  const n = BigInt(h);
  return n % r;
}

function u32ToBE4(n: number): string {
  const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b.toString("hex");
}
function u256ToBE32(n: bigint): string {
  let h = n.toString(16); if (h.length > 64) throw new Error("overflow");
  h = h.padStart(64, "0"); return h;
}

function packInputs(
  paramsHash: string,
  pkHash: string,
  contextHash: string,
  sid: bigint,
  messageCount: number,
  revealedIdx: number[],
  revealedVals: bigint[],
  APrime: string,
  ABar: string,
  d: string,
  T1: string,
  T2: string,
): string {
  if (revealedIdx.length !== revealedVals.length) throw new Error("len mismatch");
  let s = Buffer.from("BPOK").toString("hex");
  s += paramsHash.slice(2);
  s += pkHash.slice(2);
  s += contextHash.slice(2);
  s += u256ToBE32(sid);
  s += u32ToBE4(messageCount);
  for (let i = 0; i < revealedIdx.length; i++) {
    s += u32ToBE4(revealedIdx[i]);
    s += u256ToBE32(revealedVals[i]);
  }
  for (const b of [APrime, ABar, d, T1, T2]) s += b.slice(2);
  return s;
}

describe("BBS+ PoK transcript challenge (no pairings)", function () {
  it("matches on-chain computeChallenge", async () => {
  const Wrapper = await ethers.getContractFactory("contracts/test/BbsPlusPokTranscriptWrapper.sol:BbsPlusPokTranscriptWrapper");
  const h = await Wrapper.deploy();

    const paramsHash = ethers.keccak256(Buffer.from("params"));
    const pkHash = ethers.keccak256(Buffer.from("pk"));
    const contextHash = ethers.ZeroHash;
    const sid = 123n;
    const messageCount = 5;
    const revealedIdx = [1, 3];
    const revealedVals = [42n, 9001n];
    // Dummy group bytes; for end-to-end we’ll use real encodings later
    const APrime = "0x" + "11".repeat(96);
    const ABar = "0x" + "22".repeat(96);
    const d = "0x" + "33".repeat(48);
    const T1 = "0x" + "44".repeat(96);
    const T2 = "0x" + "55".repeat(96);

    const packed = packInputs(
      paramsHash, pkHash, contextHash, sid, messageCount,
      revealedIdx, revealedVals, APrime, ABar, d, T1, T2,
    );
    const off = keccakFr(packed);

    const on = await h.c([
      paramsHash, pkHash, contextHash, sid, messageCount,
      revealedIdx, revealedVals, APrime, ABar, d, T1, T2,
    ]);

    expect(on).to.equal(off);
  });
});
