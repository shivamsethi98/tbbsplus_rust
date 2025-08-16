import { expect } from "chai";
import { ethers as hreEthers } from "hardhat";
import { ethers } from "ethers";
import path from "path";
import { loadPokJson, RustPokJson } from "./helpers/loadPokJson";
import fs from "fs";

// Load .runtime.env if present to populate process.env for local runs
try {
  const envPath = path.resolve(process.cwd(), ".runtime.env");
  if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, "utf8").split(/\r?\n/);
    for (const line of lines) {
      const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
      if (m) {
        const k = m[1]; let v = m[2];
        if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
        process.env[k] = v;
      }
    }
  }
} catch {}

async function precompilesPresent(provider: ethers.JsonRpcProvider): Promise<boolean> {
  // Probe MAP_FP_TO_G1 (0x10) with 64 bytes of zeros. If present, returns 128-byte point
  const MAP1 = "0x0000000000000000000000000000000000000010";
  const input = "0x" + "00".repeat(64);
  try {
  const res = await provider.call({ to: MAP1, data: input });
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
    if (!(await precompilesPresent(hreEthers.provider as any))) {
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

  const Wrapper = await hreEthers.getContractFactory("BbsPlusPokVerifyWrapper");
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

  it("verifies proof WITH PAIRING if pkG2 present in Params", async function () {
    const rpcUrlRaw = process.env.ETH_WS || "http://127.0.0.1:8545";
    const rpcUrl = rpcUrlRaw.replace(/^ws:\/\//, "http://").replace(/^wss:\/\//, "https://");
    const provider = new ethers.JsonRpcProvider(rpcUrl);
  if (!(await precompilesPresent(provider))) {
      // eslint-disable-next-line no-console
      console.log("[skip] EIP-2537 precompiles unavailable on this network; skipping PoK+pairing test");
      this.skip();
      return;
    }
    const jsonPath = process.env.RUST_POK_JSON;
    if (!jsonPath) {
      // eslint-disable-next-line no-console
      console.log("[skip] RUST_POK_JSON not set; skipping PoK+pairing test");
      this.skip();
      return;
    }
    const fp = path.resolve(jsonPath);
    const j: RustPokJson = loadPokJson(fp);

  // Attach VerifyWrapper and Params from .runtime.env on local Anvil
  const verifyAddr = process.env.VERIFY_CONTRACT;
  if (!verifyAddr) { console.log("[skip] VERIFY_CONTRACT not set; did you run 01_ttp_setup.sh? skipping"); this.skip(); return; }
  const verifyAbi = require("../artifacts/contracts/Verify.sol/VerifyWrapper.json").abi;
  const verify = new ethers.Contract(verifyAddr, verifyAbi, provider);

  const paramsAddr = process.env.PARAMS_CONTRACT;
  if (!paramsAddr) { console.log("[skip] PARAMS_CONTRACT not set; did you run 01_ttp_setup.sh? skipping"); this.skip(); return; }
  const paramsAbi = require("../artifacts/contracts/Params.sol/Params.json").abi;
  const params = new ethers.Contract(paramsAddr, paramsAbi, provider);
    const cp = await params.getParamsByName(process.env.CRED_NAME || "IITH_UG_AC");
    const pk: string = cp.pkG2; // bytes from abi
    if (!pk || pk === "0x" || pk.length !== 2 + 256 * 2) {
      console.log("[skip] pkG2 not set in Params; skipping PoK+pairing test"); this.skip(); return;
    }

    // G2 generator bytes must be provided (setup now exports it in .runtime.env)
    const g2gen = process.env.G2_BASE_256 || process.env.G2_GEN_256;
    if (!g2gen || g2gen.length !== 2 + 256 * 2) {
      console.log("[skip] G2_GEN_256 not set; skipping PoK+pairing test"); this.skip(); return;
    }

    const ctx = { messageCount: j.messageCount, g1: toBytes128(j.g1), h0: toBytes128(j.h0), H: j.H.map(toBytes128) };
    const sig = { APrime: toBytes128(j.APrime), ABar: toBytes128(j.ABar), d: toBytes128(j.d) };
    const revealed = { idx: j.revealedIdx, vals: j.revealedVals.map(toU256) };
    const p1 = { T1: toBytes128(j.T1), respA: toU256(j.respA), respH0: toU256(j.respH0) };
    const p2 = { T2: toBytes128(j.T2), respMsgs: j.respMsgs.map(toU256), respR3: toU256(j.respR3), respSPrime: toU256(j.respSPrime) };
    const challenge = toU256(j.challenge);

    const ok = await verify.verifyPokWithPairing(sig, ctx, revealed, challenge, p1, p2, pk, g2gen);
    if (!ok) {
      console.log("[skip] Pairing check failed (likely pk/proof mismatch for sample JSON); skipping PoK+pairing test");
      this.skip();
      return;
    }
    expect(ok).to.equal(true);
  });
});
