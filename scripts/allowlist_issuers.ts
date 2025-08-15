import { ethers } from "hardhat";
async function main() {
  const signers = await ethers.getSigners();
  const owner = signers[0];
  const paramsAddr = process.env.PARAMS_CONTRACT!;
  const Params = await ethers.getContractFactory("Params");
  const params = Params.attach(paramsAddr).connect(owner) as any;
  for (let i = 1; i <= 3; i++) {
    const issuer = signers[i].address;
    await (await params.setIssuer(issuer, i, true)).wait();
    console.log(`Issuer ${i}: ${issuer}`);
  }
}
main().then(()=>process.exit(0)).catch((e)=>{console.error(e);process.exit(1)});
