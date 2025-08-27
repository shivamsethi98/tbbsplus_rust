import 'dotenv/config';
import { JsonRpcProvider, WebSocketProvider, Wallet } from 'ethers';
import fs from 'fs';

export function loadEnv() {
  const rpc = process.env.ETH_WS || process.env.SEPOLIA_URL || 'http://127.0.0.1:8545';
  const provider = rpc.startsWith('ws') ? new WebSocketProvider(rpc) : new JsonRpcProvider(rpc);
  const chainId = Number(process.env.CHAIN_ID || 31337);
  const pk = process.env.OWNER_PK || process.env.PRIVATE_KEY;
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

