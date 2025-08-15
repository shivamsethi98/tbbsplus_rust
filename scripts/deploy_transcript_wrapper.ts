import { ethers } from "hardhat";

async function main() {
  const Wrapper = await ethers.getContractFactory("contracts/test/BbsPlusPokTranscriptWrapper.sol:BbsPlusPokTranscriptWrapper");
  const wrapper = await Wrapper.deploy();
  await wrapper.waitForDeployment();
  const addr = await wrapper.getAddress();
  console.log(`WRAP_ADDR=${addr}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
