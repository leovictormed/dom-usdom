export async function runStatus78Cycle({runExecutor,resolveSigner,runSigner,maxCycles=16}) {
  if (![runExecutor,resolveSigner,runSigner].every(v=>typeof v==='function') || !Number.isSafeInteger(maxCycles) || maxCycles<1 || maxCycles>64) throw new TypeError('invalid status78 cycle configuration');
  for (let cycle=0; cycle<maxCycles; cycle++) {
    const status=await runExecutor();
    if (!Number.isInteger(status) || status<0 || status>255) throw new Error('executor returned invalid status');
    if (status===0 || status===80) return status;
    if (status!==78) return status;
    const signer=await resolveSigner();
    if (signer===null) return 78;
    if (typeof signer!=='string' || !/^[a-z][a-z0-9-]*(?::[A-Za-z0-9]+)?$/.test(signer)) throw new Error('ambiguous or invalid signer resolution');
    const signerStatus=await runSigner(signer);
    if (!Number.isInteger(signerStatus) || signerStatus<0 || signerStatus>255) throw new Error('signer returned invalid status');
    if (signerStatus!==0) return signerStatus;
  }
  return 80;
}
