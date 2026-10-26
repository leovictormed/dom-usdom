const decimal=value=>typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value);
const raw32=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const address=value=>typeof value==='string'&&/^0x[0-9a-fA-F]{40}$/.test(value);
export function validateClosedMainnetDepositEvidence({baseline,baselineSha256,execution,packageValue}) {
  if(!packageValue||packageValue.ethereumChainId!=='1'||packageValue.amountBaseUnits!=='1000000'
      ||packageValue.broadcastAuthorized!==false||packageValue.releaseConfigSha256===undefined) {
    throw new Error('closed deposit package binding is required');
  }
  if(!baseline||baseline.schema!=='usdom-closed-mainnet-deposit-financial-baseline-v1'
      ||baseline.chainId!=='1'||baseline.observedAt!=='finalized'||baseline.rpcCount!==2
      ||!raw32(baseline.packageSha256)||!address(baseline.funder)||!address(baseline.token)
      ||!address(baseline.reserve)||!raw32(baselineSha256)
      ||baseline.allowanceBaseUnits!=='0'
      ||!['funderBalanceBaseUnits','reserveBalanceBaseUnits','totalDepositedBaseUnits','outstandingBaseUnits']
        .every(field=>decimal(baseline[field]))) throw new Error('closed deposit financial baseline is invalid');
  if(baseline.funder.toLowerCase()!==packageValue.funder.toLowerCase()
      ||baseline.token.toLowerCase()!==packageValue.token.toLowerCase()
      ||baseline.reserve.toLowerCase()!==packageValue.reserve.toLowerCase()) {
    throw new Error('closed deposit financial baseline belongs to another package');
  }
  const pairs=[['funderBalanceBefore','funderBalanceAfter',-1_000_000n],
    ['reserveBalanceBefore','reserveBalanceAfter',1_000_000n],
    ['totalDepositedBefore','totalDepositedAfter',1_000_000n],
    ['outstandingBefore','outstandingAfter',1_000_000n]];
  if(!execution||execution.schema!=='usdom-closed-mainnet-deposit-execution-v1'
      ||execution.packageSha256!==baseline.packageSha256||execution.financialBaselineSha256!==baselineSha256
      ||execution.chainId!=='1'||execution.steps!==3||execution.amountBaseUnits!=='1000000'
      ||execution.allowanceBefore!=='0'||execution.allowanceAfter!=='0'||execution.outputLast!==true) {
    throw new Error('closed deposit execution identity is invalid');
  }
  const baselineFields=['funderBalanceBaseUnits','reserveBalanceBaseUnits','totalDepositedBaseUnits','outstandingBaseUnits'];
  for(let index=0;index<pairs.length;index++) {
    const [before,after,delta]=pairs[index];
    if(!decimal(execution[before])||!decimal(execution[after])
        ||execution[before]!==baseline[baselineFields[index]]
        ||BigInt(execution[after])!==BigInt(execution[before])+delta) {
      throw new Error('closed deposit exact financial delta is invalid');
    }
  }
  return execution;
}
