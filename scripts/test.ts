const reg = await ethers.getContractAt("CredentialRegistry", process.env.REGISTRY_CONTRACT);
await (await reg.confirmCredential(process.env.CRED_NAME, Number(process.env.SID||"3"))).wait();