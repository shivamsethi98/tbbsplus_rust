import { ethers } from "hardhat";

async function main() {
  const paramsAddr = process.env.PARAMS_CONTRACT;
  const credName = process.env.CRED_NAME;
  const hList = process.env.H_LIST_128; // comma-separated 0x... strings
  if (!paramsAddr || !credName || !hList) {
    throw new Error("PARAMS_CONTRACT, CRED_NAME, H_LIST_128 env vars are required");
  }
  const Hhex = hList.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  if (Hhex.length === 0) {
    throw new Error("H_LIST_128 parsed to empty list");
  }
  const Params = await ethers.getContractFactory("Params");
  const params = Params.attach(paramsAddr);
  const Hbytes = Hhex.map((h) => ethers.getBytes(h));
  for (const b of Hbytes) {
    if (b.length !== 128) throw new Error("H element not 128 bytes");
  }
  const [owner] = await ethers.getSigners();
  await (await (params as any).connect(owner).setHByName(credName, Hbytes)).wait();
  console.error(`Params.setHByName set ${Hbytes.length} points`);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });


