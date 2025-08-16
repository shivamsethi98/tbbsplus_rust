import { expect } from "chai";
import { ethers } from "ethers";
import fs from "fs";
import path from "path";

// Load .runtime.env if present
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

const ADDR = {
  G1ADD:  '0x000000000000000000000000000000000000000b',
  G1MSM:  '0x000000000000000000000000000000000000000c',
  G2MSM:  '0x000000000000000000000000000000000000000e',
  PAIR:   '0x000000000000000000000000000000000000000f',
  MAP1:   '0x0000000000000000000000000000000000000010',
  MAP2:   '0x0000000000000000000000000000000000000011',
} as const;

const FQ_MOD_BE = Buffer.from(
  "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
  "hex"
);

function be32(n: bigint): Buffer { const b = Buffer.alloc(32); b.writeBigUInt64BE(n & ((1n<<64n)-1n), 24); b.writeBigUInt64BE((n>>64n) & ((1n<<64n)-1n), 16); b.writeBigUInt64BE((n>>128n) & ((1n<<64n)-1n), 8); b.writeBigUInt64BE((n>>192n) & ((1n<<64n)-1n), 0); return b; }

function g1Neg(p128: string): string {
  const b = Buffer.from(p128.slice(2), "hex");
  if (b.length !== 128) throw new Error("bad g1 len");
  const y = Buffer.from(b.slice(80, 128));
  // z = (mod - y) mod mod; if y==0 -> 0
  let isZero = true; for (const v of y) { if (v !== 0) { isZero = false; break; } }
  const z = Buffer.alloc(48);
  if (!isZero) {
    let borrow = 0;
    for (let i = 47; i >= 0; i--) {
      const diff = FQ_MOD_BE[i] - y[i] - borrow;
      if (diff < 0) { z[i] = diff + 256; borrow = 1; } else { z[i] = diff; borrow = 0; }
    }
  }
  const out = Buffer.from(b);
  out.fill(0, 64, 80);
  z.copy(out, 80);
  return "0x" + out.toString("hex");
}

async function call(provider: ethers.JsonRpcProvider, to: string, dataHex: string): Promise<string> {
  const res = await provider.call({ to, data: dataHex });
  return res;
}

describe("EIP-2537 pairing sanity", () => {
  const rpcUrlRaw = process.env.ETH_WS || "http://127.0.0.1:8545";
  const rpcUrl = rpcUrlRaw.replace(/^ws:\/\//, "http://").replace(/^wss:\/\//, "https://");
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  it("pairing holds: e(P, mQ) == e(mP, Q)", async function () {
    // Probe precompiles
    const map1 = await call(provider, ADDR.MAP1, "0x" + "00".repeat(64));
    if (map1 === "0x" || map1.length !== 2 + 128*2) {
      console.log("[skip] MAP1 unavailable; skipping"); this.skip(); return;
    }
    const P = map1;
    const map2 = await call(provider, ADDR.MAP2, "0x" + "00".repeat(128));
    if (map2 === "0x" || map2.length !== 2 + 256*2) {
      console.log("[skip] MAP2 unavailable; skipping"); this.skip(); return;
    }
    const Q = map2;

    const m = 7n;
    const mBE = be32(m);

    // mP via G1MSM
    const mP = await call(provider, ADDR.G1MSM, "0x" + (P.slice(2) + mBE.toString("hex")) );
    if (mP === "0x" || mP.length !== 2 + 128*2) throw new Error("G1MSM failed");

    // mQ via G2MSM
    const mQ = await call(provider, ADDR.G2MSM, "0x" + (Q.slice(2) + mBE.toString("hex")) );
    if (mQ === "0x" || mQ.length !== 2 + 256*2) throw new Error("G2MSM failed");

    // Call VerifyWrapper.verifyPairing(APrime=P, pk=mQ, g1_2=-mP, g2_2=Q)
    const verifyAddr = process.env.VERIFY_CONTRACT;
    if (!verifyAddr) { console.log("[skip] VERIFY_CONTRACT not set; run 01_ttp_setup.sh first"); this.skip(); return; }
    const verifyAbi = require("../artifacts/contracts/Verify.sol/VerifyWrapper.json").abi;
    const verify = new ethers.Contract(verifyAddr, verifyAbi, provider);

    const ok: boolean = await verify.verifyPairing(P, mQ, g1Neg(mP), Q);
    expect(ok).to.equal(true);
  });
});
