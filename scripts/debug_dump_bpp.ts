import { ethers } from "hardhat";

function keccak(b: Uint8Array) {
  return ethers.keccak256(b);
}

function to32be(x: bigint): Uint8Array {
  const b = ethers.zeroPadValue(ethers.toBeHex(x), 32);
  return ethers.getBytes(b);
}

function concatMSM(points128: string[], scalars: bigint[]): string {
  if (points128.length !== scalars.length) throw new Error("len mismatch");
  const parts: Uint8Array[] = [];
  for (let i = 0; i < points128.length; i++) {
    const p = ethers.getBytes(points128[i]);
    if (p.length !== 128) throw new Error("bad point len");
    parts.push(p);
    parts.push(to32be(scalars[i]));
  }
  return ethers.hexlify(ethers.concat(parts));
}

async function g1msm(pairsHex: string): Promise<string> {
  const pairAddr = "0x000000000000000000000000000000000000000c";
  // staticcall should return 128 bytes on success
  const out = await ethers.provider.send("eth_call", [
    { to: pairAddr, data: pairsHex },
    "latest",
  ]);
  return out; // 0x... 128-byte result
}

async function g1add(a128: string, b128: string): Promise<string> {
  const addAddr = "0x000000000000000000000000000000000000000b";
  const data = ethers.hexlify(ethers.concat([ethers.getBytes(a128), ethers.getBytes(b128)]));
  const out = await ethers.provider.send("eth_call", [{ to: addAddr, data }, "latest"]);
  return out;
}

async function main() {
  const name = process.env.CRED_NAME || "ANON_CRED";
  const sid = BigInt(process.env.SID || "1");
  const registryAddr = process.env.REGISTRY_CONTRACT as string;
  const paramsAddr = process.env.PARAMS_CONTRACT as string;
  if (!registryAddr || !paramsAddr) throw new Error("need REGISTRY_CONTRACT, PARAMS_CONTRACT in env");

  const registry = await ethers.getContractAt("CredentialRegistry", registryAddr);
  const params = await ethers.getContractAt("Params", paramsAddr);

  const [A, e, s, status] = (await (registry as any).getSignature(name, sid)) as [string, bigint, bigint, number];
  console.log("status:", status, "e:", e.toString(), "s:", s.toString());
  const [Bp, idx, vals] = (await (registry as any).getRequestData(name, sid)) as [string, number[], bigint[]];
  console.log("B' len:", ethers.getBytes(Bp).length, "revealed count:", idx.length);
  const [g1, h0, g2base] = await (params as any).getG1H0G2ByName(name);
  const pkG2 = await (params as any).getPkG2ByName(name);
  console.log("g1 len:", ethers.getBytes(g1).length, "h0 len:", ethers.getBytes(h0).length);

  const [BppOn, g1PlusBppOn] = (await (registry as any).debugComputeBpp(name, sid)) as [string, string];
  console.log("B'' len:", ethers.getBytes(BppOn).length, "g1+B'' len:", ethers.getBytes(g1PlusBppOn).length);

  // Off-chain reconstruction using precompiles
  const h0s = await g1msm(concatMSM([h0], [s]));
  const Bp_plus_h0s = await g1add(Bp, h0s);
  let sumRevealed = "0x" + "00".repeat(128);
  if (idx.length > 0) {
    const H: string[] = (await (params as any).getHByName(name)) as string[];
    const pts: string[] = [];
    const scs: bigint[] = [];
    for (let i = 0; i < idx.length; i++) {
      pts.push(H[idx[i]]);
      scs.push(vals[i]);
    }
    sumRevealed = await g1msm(concatMSM(pts, scs));
  }
  const BppOff = await g1add(Bp_plus_h0s, sumRevealed);
  const g1PlusBppOff = await g1add(g1, BppOff);

  const hashesOff = {
    BppOffHash: keccak(ethers.getBytes(BppOff)),
    g1BppOffHash: keccak(ethers.getBytes(g1PlusBppOff)),
  };
  const hashesOn = {
    BppHash: keccak(ethers.getBytes(BppOn)),
    g1BppHash: keccak(ethers.getBytes(g1PlusBppOn)),
  };
  console.log("compare:", { hashesOn, hashesOff });

  // Pairing precompile diagnostics using A, pkG2, g1+B'', g2Base
  const pairAddr = "0x000000000000000000000000000000000000000f";
  const input = ethers.hexlify(
    ethers.concat([
      ethers.getBytes(A),
      ethers.getBytes(pkG2),
      ethers.getBytes(g1PlusBppOn),
      ethers.getBytes(g2base),
    ])
  );
  const out = await ethers.provider.send("eth_call", [{ to: pairAddr, data: input }, "latest"]);
  console.log("pairing(out):", out);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
