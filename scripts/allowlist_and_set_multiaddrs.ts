import { ethers } from "hardhat";
(async () => {
  const [owner] = await ethers.getSigners();
  const paramsAddr = process.env.PARAMS_CONTRACT!;
  const Params = await ethers.getContractFactory("Params");
  const params = Params.attach(paramsAddr).connect(owner) as any;
  const t = Number(process.env.THRESHOLD || 3);
  const basePort = Number(process.env.BASE_PORT || 9900);
  const MNEMONIC = process.env.MNEMONIC || "digital humor toss grant absorb fold dry dynamic crew wagon cute hint";

  for (let i = 1; i <= t; i++) {
    const path = `m/44'/60'/0'/0/${i}`;
    const wallet = (ethers as any).HDNodeWallet
      ? (ethers as any).HDNodeWallet.fromPhrase(MNEMONIC, undefined, path)
      : (ethers.Wallet.fromPhrase(MNEMONIC) as any).derivePath(path);
    const issuer: string = wallet.address;
    await (await params.setIssuer(issuer, i, true)).wait();
    const addrs = [`/ip4/127.0.0.1/tcp/${basePort + i - 1}`];
    await (await params.setIssuerMultiaddrs(issuer, addrs)).wait();
    console.log(`Issuer ${i}: ${issuer} -> ${addrs[0]} (path ${path})`);
  }

  // Also allowlist opener as accumulator manager in CredentialRegistry (owner-only)
  const regAddr = process.env.REGISTRY_CONTRACT!;
  const Registry = await ethers.getContractFactory("CredentialRegistry");
  const registry = Registry.attach(regAddr).connect(owner) as any;
  const openerAddr = process.env.OPENER_ADDR || (process.env.OPENER_PK ? new ethers.Wallet(process.env.OPENER_PK).address : undefined);
  if (openerAddr) {
    await (await registry.setAccumulatorManager(openerAddr, true)).wait();
    console.log(`Opener allowlisted: ${openerAddr}`);
  } else {
    console.warn("[warn] OPENER_ADDR/OPENER_PK not set; opener not allowlisted");
  }
})();
