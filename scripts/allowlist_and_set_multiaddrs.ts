import { ethers } from "hardhat";
(async () => {
  const signers = await ethers.getSigners();
  const owner = signers[0];
  const paramsAddr = process.env.PARAMS_CONTRACT!;
  const Params = await ethers.getContractFactory("Params");
  const params = Params.attach(paramsAddr).connect(owner) as any;
  const t = Number(process.env.THRESHOLD || 3);
  const basePort = Number(process.env.BASE_PORT || 9900);
  for (let i = 1; i <= t; i++) {
    const issuer = signers[i].address;
    await (await params.setIssuer(issuer, i, true)).wait();
    const addrs = [`/ip4/127.0.0.1/tcp/${basePort + i - 1}`];
    await (await params.setIssuerMultiaddrs(issuer, addrs)).wait();
    console.log(`Issuer ${i}: ${issuer} -> ${addrs[0]}`);
  }
})();
