import { ethers } from 'hardhat';
import { loadEnv, readRuntime } from '../utils/env';
import { sendAndMeasure } from '../utils/measure';
import fs from 'fs';

async function main() {
  const rt = readRuntime();
  const { provider } = loadEnv();
  const name = process.env.CRED_NAME || rt.CRED_NAME || 'ANON_CRED';
  const accAddr = rt.ACC_CONTRACT;
  if (!accAddr) throw new Error('ACC_CONTRACT missing');
  const e = process.env.E || '7';

  const Acc = await ethers.getContractFactory('Accumulator');
  const acc = Acc.attach(accAddr) as any;

  // Expect delta and witness inputs via env files or prior computations; here we just read current delta for sizeof sanity
  const delta = await acc.getDelta(name);
  const witness = await acc.getWitness(name, e);

  const out: any = { scenario: 'registerInfo', name, e, ts: Date.now(), chainId: (await provider.getNetwork()).chainId.toString() };

  if (delta && delta.length === 128) {
    const nm = await sendAndMeasure(acc.setDelta(name, delta), provider);
    out.setDelta = nm;
  }
  if (witness && witness.length === 128) {
    const nm2 = await sendAndMeasure(acc.publishWitness(name, e, witness), provider);
    out.publishWitness = nm2;
  }

  fs.mkdirSync('metrics/results', { recursive: true });
  const path = `metrics/results/registerInfo.${out.chainId}.${out.ts}.json`;
  fs.writeFileSync(path, JSON.stringify(out, null, 2));
  console.log('saved', path);
}

main().catch((e) => { console.error(e); process.exit(1); });


