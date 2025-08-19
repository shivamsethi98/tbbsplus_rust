import { ethers } from "hardhat";

async function main() {
  const credName = process.env.CRED_NAME || "ANON_CRED";
  const paramsAddr = process.env.PARAMS_CONTRACT;
  const g1Hex = process.env.G1_128;
  const h0Hex = process.env.H0_128;
  const g2BaseHex = process.env.G2_BASE_256;

  if (!paramsAddr) throw new Error("PARAMS_CONTRACT missing");
  if (!g1Hex || !h0Hex || !g2BaseHex) throw new Error("G1_128/H0_128/G2_BASE_256 missing");

  const [owner] = await ethers.getSigners();
  const Params = await ethers.getContractFactory("Params");
  const params = Params.attach(paramsAddr);

  await (
    await (params as any)
      .connect(owner)
      .setG1H0G2(credName, ethers.getBytes(g1Hex), ethers.getBytes(h0Hex), ethers.getBytes(g2BaseHex))
  ).wait();
  console.log(`setG1H0G2 done for ${credName} at ${paramsAddr}`);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });


