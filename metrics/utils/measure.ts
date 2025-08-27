import { ContractTransactionResponse, AbstractProvider } from 'ethers';

export async function sendAndMeasure(txp: Promise<ContractTransactionResponse>, provider: AbstractProvider) {
  const t0 = Date.now();
  const tx = await txp;
  const r = await tx.wait();
  const t1 = Date.now();
  const gasUsed = r?.gasUsed;
  const txFull = await provider.getTransaction(tx.hash);
  const effGasPrice = txFull?.gasPrice;
  const costWei = gasUsed && effGasPrice ? gasUsed * effGasPrice : null;
  return { hash: tx.hash, startMs: t0, endMs: t1, wallMs: t1 - t0, gasUsed: gasUsed?.toString(), gasPrice: effGasPrice?.toString(), costWei: costWei?.toString(), block: r?.blockNumber };
}

