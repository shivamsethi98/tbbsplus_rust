import { expect } from "chai";
import { ethers } from "ethers";
import fs from "fs";
import path from "path";

// Load .runtime.env
try {
  const envPath = path.resolve(process.cwd(), ".runtime.env");
  if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, "utf8").split(/\r?\n/);
    for (const line of lines) { const m = line.match(/^([A-Z0-9_]+)=(.*)$/); if (m) { const k=m[1]; let v=m[2]; if (v.startsWith('"')&&v.endsWith('"')) v=v.slice(1,-1); process.env[k]=v; } }
  }
} catch {}

function toBytes128(x: string): string { if (!x.startsWith("0x")) throw new Error("bytes must be 0x"); const len=(x.length-2)/2; if (len!==128) throw new Error(`expected 128 bytes, got ${len}`); return x; }
function toU256(x: string): bigint { return x.startsWith("0x")? BigInt(x) : BigInt(x); }

describe("BBS+ PoK verify WITH pairing (TTP key)", function () {
  it("generates PoK JSON with TTP key and verifies on-chain with pairing", async function () {
    const rpcUrlRaw = process.env.ETH_WS || "http://127.0.0.1:8545";
    const rpcUrl = rpcUrlRaw.replace(/^ws:\/\//, "http://").replace(/^wss:\/\//, "https://");
    const provider = new ethers.JsonRpcProvider(rpcUrl);

    const verifyAddr = process.env.VERIFY_CONTRACT; if (!verifyAddr) { this.skip(); return; }
    const paramsAddr = process.env.PARAMS_CONTRACT; if (!paramsAddr) { this.skip(); return; }
    const verifyAbi = require("../artifacts/contracts/Verify.sol/VerifyWrapper.json").abi;
    const paramsAbi = require("../artifacts/contracts/Params.sol/Params.json").abi;
    const verify = new ethers.Contract(verifyAddr, verifyAbi, provider);
    const params = new ethers.Contract(paramsAddr, paramsAbi, provider);
    const cp = await params.getParamsByName(process.env.CRED_NAME || "ANON_CRED");
    const pk: string = cp.pkG2;
    if (!pk || pk === "0x" || pk.length !== 2 + 256*2) { this.skip(); return; }

    // Generate PoK JSON deterministic with TTP secret
    const out = ".runtime/pok.json";
    const cmd = `OUT=${out} CRED_NAME=${process.env.CRED_NAME||"ANON_CRED"} MESSAGE_COUNT=${process.env.MESSAGE_COUNT||"5"} THRESHOLD=${process.env.THRESHOLD||"3"} TOTAL=${process.env.TOTAL||"4"} cargo run --quiet --bin export_pok_json_ttp`;
    const { execSync } = require("child_process");
    execSync(cmd, { stdio: "inherit", cwd: path.resolve(process.cwd()) });
  const j = JSON.parse(fs.readFileSync(out, "utf8"));
  const g2base = j.g2 as string; if (!g2base || g2base.length !== 2 + 256*2) { this.skip(); return; }

  const ctx = { messageCount: j.messageCount, g1: toBytes128(j.g1), h0: toBytes128(j.h0), H: j.H.map(toBytes128) };
  const sig = { APrime: toBytes128(j.APrime), ABar: toBytes128(j.ABar), d: toBytes128(j.d) };
    const revealed = { idx: j.revealedIdx, vals: j.revealedVals.map(toU256) };
    const p1 = { T1: toBytes128(j.T1), respA: toU256(j.respA), respH0: toU256(j.respH0) };
    const p2 = { T2: toBytes128(j.T2), respMsgs: j.respMsgs.map(toU256), respR3: toU256(j.respR3), respSPrime: toU256(j.respSPrime) };
    const challenge = toU256(j.challenge);

  // First, PoK only should pass
  const okPok: boolean = await verify.verifyPok(sig, ctx, revealed, challenge, p1, p2);
  expect(okPok).to.equal(true);
    // Sanity: pk in Params equals emitted PK_G2_HEX (if present)
    try {
      const pkHexFile = fs.existsSync('.runtime.pk_g2.hex') ? fs.readFileSync('.runtime.pk_g2.hex', 'utf8').trim() : process.env.PK_G2_HEX;
      if (pkHexFile && typeof pkHexFile === 'string') {
        if (pkHexFile.toLowerCase() !== pk.toLowerCase()) {
          // eslint-disable-next-line no-console
          console.log('[warn] pkG2 on-chain != emitted PK_G2_HEX');
        }
      }
    } catch {}

    // Try raw pairing in both equivalent orders for diagnostics
  const ok1: boolean = await verify.verifyPairing(sig.APrime, pk, negateG1(sig.ABar), g2base);
  const ok2: boolean = await verify.verifyPairing(sig.ABar, g2base, negateG1(sig.APrime), pk);
    // eslint-disable-next-line no-console
    console.log(`[diag] pairing ok1=${ok1} ok2=${ok2}`);
    // Extra: check raw signature relation with pk (e(A, g2) == e(g1 + h0*s + sum(h_i*m_i), pk) where e is in exponent);
    // We can't recompute RHS on-chain easily here, but at least check A vs pk pairing sanity
    if (j.sigA) {
  const okSigPair = await verify.verifyPairing(j.sigA, g2base, negateG1(j.g1), pk);
      // eslint-disable-next-line no-console
      console.log(`[diag] raw sig pairing (A,g2) * (-g1,pk) == 1 ? ${okSigPair}`);
    }
  const okPair: boolean = await verify.verifyPokWithPairing(sig, ctx, revealed, challenge, p1, p2, pk, g2base);
    expect(okPair).to.equal(true);
  });
});

function negateG1(p128: string): string {
  const FQ_MOD_BE = Buffer.from(
    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    'hex'
  );
  const b = Buffer.from(p128.slice(2), 'hex');
  if (b.length !== 128) throw new Error('bad g1 len');
  const y = Buffer.from(b.slice(80, 128));
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
  return '0x' + out.toString('hex');
}
