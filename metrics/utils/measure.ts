import { ContractTransactionResponse, AbstractProvider } from 'ethers';

export async function sendAndMeasure(txp: Promise<ContractTransactionResponse>, provider: AbstractProvider) {
  const t0 = Date.now();
  const tx = await txp;
  const r = await tx.wait();
  const t1 = Date.now();
  const gasUsed = r?.gasUsed;
  const effGasPrice = (r as any)?.effectiveGasPrice ?? null;
  const costWei = gasUsed && effGasPrice ? gasUsed * effGasPrice : null;
  let oracle: any = null;
  const apiKey = process.env.ETHERSCAN_API_KEY;
  const chainId = (await provider.getNetwork()).chainId.toString();
  try {
    const doFetch: any = (globalThis as any).fetch;
    if (apiKey && doFetch && (chainId === '11155111' || chainId === '1')) {
      const base = chainId === '11155111' ? 'https://api-sepolia.etherscan.io' : 'https://api.etherscan.io';
      const url = `${base}/api?module=gastracker&action=gasoracle&apikey=${apiKey}`;
      const res = await doFetch(url);
      const j = await res.json();
      if (j && j.status === '1' && j.result) oracle = j.result;
    }
  } catch {}
  return {
    hash: tx.hash,
    startMs: t0,
    endMs: t1,
    wallMs: t1 - t0,
    gasUsed: gasUsed?.toString(),
    effectiveGasPrice: effGasPrice?.toString?.(),
    costWei: costWei?.toString?.(),
    block: r?.blockNumber,
    gasOracle: oracle,
  };
}

