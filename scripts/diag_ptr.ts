import { ethers } from "hardhat";

async function main() {
  const name = process.env.CRED_NAME || "ANON_CRED";
  const addr = process.env.PARAMS_CONTRACT as string;
  const Params = await ethers.getContractFactory("Params");
  const params = Params.attach(addr) as any;
  const [ptr, size] = await params.getDataPtrByName(name);
  console.log("ptr=", ptr, "size=", size.toString());
}

main().catch((e) => { console.error(e); process.exit(1); });


