import { ethers } from "hardhat";
import fs from "fs";
import path from "path";

async function appendDeployMetrics(contract: string, tx: any) {
  try {
    const metricsFile = process.env.DEPLOY_METRICS_FILE || "metrics/results/deploy.ndjson";
    const dir = path.dirname(metricsFile);
    fs.mkdirSync(dir, { recursive: true });
    const rcpt = await tx.wait();
    const gasUsed = rcpt?.gasUsed?.toString?.() ?? String(rcpt?.gasUsed ?? "0");
    const eff = rcpt?.effectiveGasPrice?.toString?.() ?? String(rcpt?.effectiveGasPrice ?? "0");
    let costWei = "0";
    try { costWei = (BigInt(gasUsed) * BigInt(eff)).toString(); } catch {}
    const obj = { scenario: `deploy_${contract}`, contract, hash: tx?.hash, blockNumber: rcpt?.blockNumber, gasUsed, effectiveGasPrice: eff, costWei };
    fs.appendFileSync(metricsFile, JSON.stringify(obj) + "\n");
  } catch (e) { console.warn("appendDeployMetrics failed", contract, e); }
}

async function main() {
  const Verify = await ethers.getContractFactory("VerifyWrapper");
  const verify = await Verify.deploy();
  await verify.waitForDeployment();
  if (verify.deploymentTransaction()) await appendDeployMetrics("VerifyWrapper", verify.deploymentTransaction());
  console.log("export VERIFY_CONTRACT=" + await verify.getAddress());
}

main().catch((e) => { console.error(e); process.exit(1); });
