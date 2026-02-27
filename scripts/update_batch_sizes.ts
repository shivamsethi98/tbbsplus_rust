/**
 * update_batch_sizes.ts — Update on-chain batch sizes without a TTP rerun.
 *
 * Usage:
 *   PARAMS_CONTRACT=0x... BATCH_SIZE_REQ=4 BATCH_SIZE_PRES=4 \
 *     npx hardhat run scripts/update_batch_sizes.ts --network localhost
 *
 * Environment variables:
 *   PARAMS_CONTRACT   — deployed Params contract address (required, or read from .runtime.env)
 *   CRED_NAME         — credential name (default: ANON_CRED)
 *   BATCH_SIZE_REQ    — request batch size (default: 1)
 *   BATCH_SIZE_PRES   — presentation batch size (default: 1)
 */
import { ethers } from "hardhat";
import * as dotenv from "dotenv";
import * as fs from "fs";

async function main() {
  // Load .runtime.env if present so PARAMS_CONTRACT is available without extra env
  if (fs.existsSync(".runtime.env")) {
    dotenv.config({ path: ".runtime.env" });
  }

  const credName: string = process.env.CRED_NAME ?? "ANON_CRED";
  const batchSizeReq: number = parseInt(process.env.BATCH_SIZE_REQ ?? "1", 10);
  const batchSizePres: number = parseInt(process.env.BATCH_SIZE_PRES ?? "1", 10);
  const paramsAddr: string | undefined = process.env.PARAMS_CONTRACT;

  if (!paramsAddr) {
    throw new Error("PARAMS_CONTRACT env var required (or set in .runtime.env)");
  }

  const [signer] = await ethers.getSigners();
  const params = await ethers.getContractAt("Params", paramsAddr, signer);

  console.log(`Setting batch sizes for "${credName}": req=${batchSizeReq}  pres=${batchSizePres}`);
  const tx = await params.setBatchSizes(credName, batchSizeReq, batchSizePres);
  const receipt = await tx.wait();
  console.log(`Done — tx: ${tx.hash}  (block ${receipt?.blockNumber})`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
