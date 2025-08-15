import { ethers } from "hardhat";

async function main() {
  const Wrapper = await ethers.getContractFactory("BbsPlusPokVerifyWrapper");
  const wrapper = await Wrapper.deploy();
  await wrapper.waitForDeployment();
  console.log("export POK_VERIFY_WRAPPER=" + await wrapper.getAddress());

  const Transcript = await ethers.getContractFactory("BbsPlusPokTranscriptWrapper");
  const transcript = await Transcript.deploy();
  await transcript.waitForDeployment();
  console.log("export POK_TRANSCRIPT_WRAPPER=" + await transcript.getAddress());

  const Verify = await ethers.getContractFactory("VerifyWrapper");
  const verify = await Verify.deploy();
  await verify.waitForDeployment();
  console.log("export VERIFY_CONTRACT=" + await verify.getAddress());
}

main().catch((e) => { console.error(e); process.exit(1); });
