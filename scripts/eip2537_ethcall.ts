/*
  Minimal eth_call helper for EIP-2537 precompiles.
  Usage:
    ETH_RPC_URL=<rpc> npx ts-node scripts/eip2537_ethcall.ts map1
    ETH_RPC_URL=<rpc> npx ts-node scripts/eip2537_ethcall.ts map2
    ETH_RPC_URL=<rpc> npx ts-node scripts/eip2537_ethcall.ts pair-empty

  Addresses per EIP-2537:
    0x0b G1ADD, 0x0c G1MSM, 0x0d G2ADD, 0x0e G2MSM, 0x0f PAIRING,
    0x10 MAP_FP_TO_G1, 0x11 MAP_FP2_TO_G2
*/
import 'dotenv/config';
import { JsonRpcProvider } from 'ethers';

const ADDR = {
  PAIR:  '0x000000000000000000000000000000000000000f',
  MAP1:  '0x0000000000000000000000000000000000000010',
  MAP2:  '0x0000000000000000000000000000000000000011',
} as const;

function zeroHexBytes(n: number): string {
  return '0x' + '00'.repeat(n);
}

async function main() {
  const rpc = process.env.ETH_RPC_URL || process.env.SEPOLIA_URL || process.env.HOODI_URL;
  if (!rpc) throw new Error('Set ETH_RPC_URL (or SEPOLIA_URL/HOODI_URL)');
  const provider = new JsonRpcProvider(rpc);

  const op = (process.argv[2] || '').toLowerCase();
  if (!['map1','map2','pair-empty'].includes(op)) {
    console.error('usage: ts-node scripts/eip2537_ethcall.ts <map1|map2|pair-empty>');
    process.exit(1);
  }

  let to: string;
  let data: string;
  if (op === 'map1') {
    to = ADDR.MAP1; data = zeroHexBytes(64);
  } else if (op === 'map2') {
    to = ADDR.MAP2; data = zeroHexBytes(128);
  } else {
    to = ADDR.PAIR; data = '0x';
  }

  try {
    const res = await provider.call({ to, data });
    console.log(JSON.stringify({ ok: true, to, inputLen: (data.length-2)/2, resultLen: (res.length-2)/2, result: res }));
  } catch (e: any) {
    console.log(JSON.stringify({ ok: false, to, error: e?.message || String(e) }));
  }
}

main();
