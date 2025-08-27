import hre from 'hardhat';
import { loadEnv, readRuntime } from '../utils/env';
import { sendAndMeasure } from '../utils/measure';
import fs from 'fs';

async function main() {
  const rt = readRuntime();
  const { provider } = loadEnv();
  const name = process.env.CRED_NAME || rt.CRED_NAME || 'ANON_CRED';
  const registryAddr = rt.REGISTRY_CONTRACT;
  if (!registryAddr) throw new Error('REGISTRY_CONTRACT missing');

  const Registry = await hre.ethers.getContractFactory('CredentialRegistry');
  const registry = Registry.attach(registryAddr) as any;

  const sid = Number(process.env.SID || rt.SID || 1);
  // If auto-confirm path already ran, measure a no-op confirm (will revert). Instead, measure Aggregated->Confirmed by events.
  // Here we attempt confirm; if it reverts with bad status, we fallback to just report last Confirmed timestamp.
  let m: any;
  try {
    m = await sendAndMeasure(registry.confirmCredential(name, sid), provider);
  } catch (e:any) {
    console.log('[info] confirmCredential failed (likely already confirmed). Reporting no tx metrics.');
    m = { hash: null, wallMs: 0, gasUsed: null, gasPrice: null, costWei: null, block: null };
  }

  const out = { scenario: 'verifyCred', name, sid, ...m, ts: Date.now(), chainId: (await provider.getNetwork()).chainId.toString() };
  fs.mkdirSync('metrics/results', { recursive: true });
  const path = `metrics/results/verifyCred.${out.chainId}.${out.sid}.${out.ts}.json`;
  fs.writeFileSync(path, JSON.stringify(out, null, 2));
  console.log('saved', path);
}

main().catch((e) => { console.error(e); process.exit(1); });

