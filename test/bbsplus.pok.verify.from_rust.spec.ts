import { expect } from "chai";
import { ethers } from "hardhat";
import path from "path";
import { loadPokJson, RustPokJson } from "./helpers/loadPokJson";

async function precompilesPresent(): Promise<boolean> {
  // Probe MAP_FP_TO_G1 (0x10) with 64 bytes of zeros. If present, returns 128-byte point
  const MAP1 = "0x0000000000000000000000000000000000000010";
  const input = "0x" + "00".repeat(64);
  try {
    const res = await ethers.provider.call({ to: MAP1, data: input });
    return res !== "0x" && res.length === 2 + 128 * 2;
  } catch {
    return false;
  }
}

function toBytes128(x: string): string {
  if (!x.startsWith("0x")) throw new Error("bytes must be 0x-prefixed");
  const len = (x.length - 2) / 2;
  if (len !== 128) throw new Error(`expected 128 bytes, got ${len}`);
  return x;
}

function toU256(x: string): bigint {
  if (x.startsWith("0x")) return BigInt(x);
  return BigInt(x);
}

describe("BBS+ PoK verify (from Rust JSON)", function () {
  it("verifies proof from RUST_POK_JSON if provided", async function () {
    if (!(await precompilesPresent())) {
      // eslint-disable-next-line no-console
      console.log("[skip] EIP-2537 precompiles unavailable on this network; skipping PoK verify test");
      this.skip();
      return;
    }
    const jsonPath = process.env.RUST_POK_JSON;
    if (!jsonPath) {
      // eslint-disable-next-line no-console
      console.log("[skip] RUST_POK_JSON not set; skipping PoK verify test");
      this.skip();
      return;
    }
  const fp = path.resolve(jsonPath);
  const j: RustPokJson = loadPokJson(fp);

    const Wrapper = await ethers.getContractFactory("BbsPlusPokVerifyWrapper");
    const wrapper = await Wrapper.deploy();
    await wrapper.waitForDeployment();

    const ctx = {
      messageCount: j.messageCount,
      g1: toBytes128(j.g1),
      h0: toBytes128(j.h0),
      H: j.H.map(toBytes128),
    };
    const sig = {
      APrime: toBytes128(j.APrime),
      ABar: toBytes128(j.ABar),
      d: toBytes128(j.d),
    };
    const revealed = {
      idx: j.revealedIdx,
      vals: j.revealedVals.map(toU256),
    };
    const p1 = {
      T1: toBytes128(j.T1),
      respA: toU256(j.respA),
      respH0: toU256(j.respH0),
    };
    const p2 = {
      T2: toBytes128(j.T2),
      respMsgs: j.respMsgs.map(toU256),
      respR3: toU256(j.respR3),
      respSPrime: toU256(j.respSPrime),
    };
    const challenge = toU256(j.challenge);

    const ok = await wrapper.verify(sig, ctx, revealed, challenge, p1, p2);
    expect(ok).to.equal(true);
  });
});
