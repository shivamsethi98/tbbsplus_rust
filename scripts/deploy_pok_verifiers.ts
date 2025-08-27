import { ethers } from "hardhat";

async function main() {
  const Verify = await ethers.getContractFactory("VerifyWrapper");
  const verify = await Verify.deploy();
  await verify.waitForDeployment();
  console.log("export VERIFY_CONTRACT=" + await verify.getAddress());
}

main().catch((e) => { console.error(e); process.exit(1); });
