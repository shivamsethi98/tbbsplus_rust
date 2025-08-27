import { ethers } from 'hardhat';
import { loadEnv } from '../utils/env';
import fs from 'fs';

async function main() {
  const { provider } = loadEnv();
  const out: any = { network: await provider.getNetwork(), ts: Date.now(), contracts: {} };

  const Params = await ethers.getContractFactory('Params');
  const params = await Params.deploy();
  const rP = await params.deploymentTransaction()!.wait();
  out.contracts['Params'] = { address: await params.getAddress(), gasUsed: rP?.gasUsed?.toString() };

  const Registry = await ethers.getContractFactory('CredentialRegistry');
  const registry = await Registry.deploy(await params.getAddress());
  const rR = await registry.deploymentTransaction()!.wait();
  out.contracts['CredentialRegistry'] = { address: await registry.getAddress(), gasUsed: rR?.gasUsed?.toString() };

  const Request = await ethers.getContractFactory('RequestCredential');
  const request = await Request.deploy();
  const rQ = await request.deploymentTransaction()!.wait();
  out.contracts['RequestCredential'] = { address: await request.getAddress(), gasUsed: rQ?.gasUsed?.toString() };

  const Acc = await ethers.getContractFactory('Accumulator');
  const acc = await Acc.deploy(await params.getAddress(), await registry.getAddress());
  const rA = await acc.deploymentTransaction()!.wait();
  out.contracts['Accumulator'] = { address: await acc.getAddress(), gasUsed: rA?.gasUsed?.toString() };

  const Verify = await ethers.getContractFactory('VerifyWrapper');
  const verify = await Verify.deploy();
  const rV = await verify.deploymentTransaction()!.wait();
  out.contracts['VerifyWrapper'] = { address: await verify.getAddress(), gasUsed: rV?.gasUsed?.toString() };

  const path = `metrics/results/deploy_gas.${out.network.chainId}.${out.ts}.json`;
  fs.mkdirSync('metrics/results', { recursive: true });
  fs.writeFileSync(path, JSON.stringify(out, null, 2));
  console.log('saved', path);
}

main().catch((e) => { console.error(e); process.exit(1); });


