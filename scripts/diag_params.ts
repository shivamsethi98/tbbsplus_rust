import { ethers } from "hardhat";

async function main() {
  const name = process.env.CRED_NAME || "ANON_CRED";
  const addr = process.env.PARAMS_CONTRACT as string;
  if (!addr) throw new Error("PARAMS_CONTRACT missing");
  const Params = await ethers.getContractFactory("Params");
  const params = Params.attach(addr) as any;
  const id = await params.getMapCredentials(name);
  console.log("[diag] id=", id.toString());
  const cp = await params.getParamsByName(name);
  console.log("[diag] m=", cp.messageCount.toString(), " t=", cp.t.toString(), " n=", cp.n.toString());
  const dh = await params.getDataHashByName(name);
  console.log("[diag] dataHash=", dh);
  try {
    const [g1, h0, g2] = await params.getG1H0G2ByName(name);
    console.log("[diag] g1/h0/g2 len:", g1.length, h0.length, g2.length);
  } catch (e:any) {
    console.log("[diag] getG1H0G2ByName error:", e?.message || e);
  }
  try {
    const H: string[] = await params.getHByName(name);
    console.log("[diag] H.len=", H.length);
  } catch (e:any) {
    console.log("[diag] getHByName error:", e?.message || e);
  }
  try {
    const pk = await params.getPkG2ByName(name);
    console.log("[diag] pkG2 len:", pk.length);
  } catch (e:any) {
    console.log("[diag] getPkG2ByName error:", e?.message || e);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });


