import { ethers } from "hardhat";

async function main() {
  const name = process.env.CRED_NAME || "ANON_CRED";
  const paramsAddr = process.env.PARAMS_CONTRACT!;
  const pkHex = process.env.PK_G2_HEX;
  if (!pkHex || !pkHex.startsWith("0x")) throw new Error("PK_G2_HEX must be 0x-hex bytes (256 bytes)");
  const pkBytes = pkHex;
  if (((pkBytes.length - 2) / 2) !== 256) throw new Error(`pk len ${ (pkBytes.length-2)/2 } != 256`);
  const [owner] = await ethers.getSigners();
  const Params = await ethers.getContractFactory("Params");
  const params = Params.attach(paramsAddr).connect(owner);
  await (params as any).setPkG2(name, pkBytes);
  console.log("pkG2 set for", name);
}

main().catch((e)=>{ console.error(e); process.exit(1); });
