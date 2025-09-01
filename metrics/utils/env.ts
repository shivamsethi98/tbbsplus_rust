import 'dotenv/config';
import { JsonRpcProvider, WebSocketProvider, Wallet } from 'ethers';
import fs from 'fs';

function getArg(name: string): string | undefined {
  const prefixes = [`--${name}=`, `--${name.toLowerCase()}=`];
  for (const a of process.argv.slice(2)) {
    for (const p of prefixes) {
      if (a.startsWith(p)) return a.substring(p.length);
    }
  }
  return undefined;
}

export function cliOverrides() {
  const rpc = getArg('rpc');
  const chainId = getArg('chainId');
  const pk = getArg('pk');
  const name = getArg('name');
  const sid = getArg('sid');
  const threshold = getArg('threshold');
  const total = getArg('total');
  const messageCount = getArg('messageCount');
  return { rpc, chainId, pk, name, sid, threshold, total, messageCount };
}

export function loadEnv() {
  const cli = cliOverrides();
  const rpc = cli.rpc || process.env.ETH_WS || process.env.SEPOLIA_URL || 'http://127.0.0.1:8545';
  const provider = rpc.startsWith('ws') ? new WebSocketProvider(rpc) : new JsonRpcProvider(rpc);
  const chainId = Number(cli.chainId || process.env.CHAIN_ID || 31337);
  const pk = cli.pk || process.env.OWNER_PK || process.env.PRIVATE_KEY;
  const signer = pk ? new Wallet(pk, provider) : undefined;
  return { provider, signer, chainId };
}

export function readRuntime() {
  const path = '.runtime.env';
  if (!fs.existsSync(path)) return {} as any;
  const out: any = {};
  const lines = fs.readFileSync(path, 'utf8').split(/\r?\n/);
  for (const l of lines) {
    const m = l.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

