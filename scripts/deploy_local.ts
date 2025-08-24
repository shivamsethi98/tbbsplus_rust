import { ethers } from "hardhat";

async function main() {
  const [owner] = await ethers.getSigners();
  const credName = process.env.CRED_NAME || "ANON_CRED";
  const messageCount = Number(process.env.MESSAGE_COUNT || 5);
  const t = Number(process.env.THRESHOLD || 3);
  const n = Number(process.env.TOTAL || 4);

  const Params = await ethers.getContractFactory("Params");
  const params = await Params.connect(owner).deploy();
  await params.waitForDeployment();
  await (
    await (params as any).connect(owner).setParamsOnce(
      credName,
      messageCount,
      t,
      n,
      [1, 2],
      messageCount
    )
  ).wait();

  const Registry = await ethers.getContractFactory("CredentialRegistry");
  const registry = await Registry.connect(owner).deploy(await params.getAddress());
  await registry.waitForDeployment();

  const Request = await ethers.getContractFactory("RequestCredential");
  const request = await Request.connect(owner).deploy();
  await request.waitForDeployment();

  // Wire Request <-> Registry:
  // 1) Allow RequestCredential to record request data into the registry
  await (await (registry as any).connect(owner).setRequestContract(await request.getAddress())).wait();
  // 2) Let RequestCredential know the registry so it can forward request metadata post-PoK
  await (await (request as any).connect(owner).setRegistry(await registry.getAddress())).wait();

  const Relay = await ethers.getContractFactory("PartialSignatureRelay");
  const relay = await Relay.connect(owner).deploy(await params.getAddress());
  await relay.waitForDeployment();

  // Deploy Accumulator with Params and Registry
  const Accumulator = await ethers.getContractFactory("Accumulator");
  const accumulator = await Accumulator.connect(owner).deploy(
    await params.getAddress(),
    await registry.getAddress()
  );
  await accumulator.waitForDeployment();

  // Gate: set opener account as accumulatorManager on the registry
  // Prefer explicit OPENER_ADDR, else derive from OPENER_PK, else fallback to owner
  const OPENER_PK = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
  const openerAddr = new ethers.Wallet(OPENER_PK).address;
  await (await (registry as any).connect(owner).setAccumulatorManager(openerAddr, true)).wait();

  // Set Service Provider on Accumulator (callable by opener)
  const spAddr = process.env.SP_ADDR || "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720";
  try {
    const openerSigner = await ethers.getSigner(openerAddr);
    await (await (accumulator as any).connect(openerSigner).setServiceProvider(spAddr)).wait();
  } catch (e) {
    console.warn("setServiceProvider failed:", e);
  }

  console.log(`export REQ_CONTRACT=${await request.getAddress()}`);
  console.log(`export RELAY_CONTRACT=${await relay.getAddress()}`);
  console.log(`export REGISTRY_CONTRACT=${await registry.getAddress()}`);
  console.log(`export PARAMS_CONTRACT=${await params.getAddress()}`);
  console.log(`export ACC_CONTRACT=${await accumulator.getAddress()}`);
  console.log(`export OPENER_ADDR=${openerAddr}`);
  console.log(`export SP_ADDR=${spAddr}`);
  console.log(`export CHAIN_ID=31337`);
  console.log(`export ETH_WS=ws://127.0.0.1:8545`);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });

