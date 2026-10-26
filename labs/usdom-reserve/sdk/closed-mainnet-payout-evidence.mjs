const decimal=value=>typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value);
const raw32=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const address=value=>typeof value==='string'&&/^0x[0-9a-fA-F]{40}$/.test(value);
const hash32=value=>typeof value==='string'&&/^0x[0-9a-fA-F]{64}$/.test(value);
export function validateClosedMainnetPayoutEvidence({baseline,baselineSha256,execution,packageValue}) {
  if(!packageValue||packageValue.ethereumChainId!=='1'||packageValue.amountBaseUnits!=='1000000'
      ||packageValue.broadcastAuthorized!==false) {
    throw new Error('closed redemption package binding is required');
  }
  if(!baseline||baseline.schema!=='usdom-closed-mainnet-redemption-payout-baseline-v1'
      ||baseline.chainId!=='1'||baseline.observedAt!=='finalized'||baseline.rpcCount!==2
      ||!decimal(baseline.snapshotBlockNumber)||!hash32(baseline.snapshotBlockHash)
      ||!raw32(baseline.packageSha256)||!address(baseline.token)||!address(baseline.recipient)
      ||!address(baseline.reserve)
      ||!['recipientBalanceBaseUnits','reserveBalanceBaseUnits','totalReleasedBaseUnits','outstandingBaseUnits','totalProvedDebtBaseUnits'].every(field=>decimal(baseline[field]))
      ||baseline.totalProvedDebtBaseUnits!=='1000000'
      ||!raw32(baselineSha256)) {
    throw new Error('closed redemption payout baseline is invalid');
  }
  if(baseline.reserve.toLowerCase()!==packageValue.reserve.toLowerCase()
      ||baseline.recipient.toLowerCase()!==packageValue.recipient.toLowerCase()) {
    throw new Error('closed redemption payout baseline belongs to another package');
  }
  if(!execution||execution.schema!=='usdom-closed-mainnet-redemption-execution-v1'
      ||execution.packageSha256!==baseline.packageSha256
      ||execution.payoutBaselineSha256!==baselineSha256
      ||execution.token?.toLowerCase()!==baseline.token.toLowerCase()
      ||execution.recipient?.toLowerCase()!==baseline.recipient.toLowerCase()
      ||execution.recipientBalanceBefore!==baseline.recipientBalanceBaseUnits
      ||!decimal(execution.recipientBalanceAfter)
      ||BigInt(execution.recipientBalanceAfter)!==BigInt(execution.recipientBalanceBefore)+1_000_000n
      ||execution.reserveBalanceBefore!==baseline.reserveBalanceBaseUnits
      ||execution.totalReleasedBefore!==baseline.totalReleasedBaseUnits
      ||execution.outstandingBefore!==baseline.outstandingBaseUnits
      ||execution.totalProvedDebtBefore!==baseline.totalProvedDebtBaseUnits
      ||!decimal(execution.reserveBalanceAfter)||!decimal(execution.totalReleasedAfter)||!decimal(execution.outstandingAfter)
      ||!decimal(execution.totalProvedDebtAfter)
      ||BigInt(execution.reserveBalanceAfter)!==BigInt(execution.reserveBalanceBefore)-1_000_000n
      ||BigInt(execution.totalReleasedAfter)!==BigInt(execution.totalReleasedBefore)+1_000_000n
      ||BigInt(execution.outstandingAfter)!==BigInt(execution.outstandingBefore)-1_000_000n
      ||BigInt(execution.totalProvedDebtAfter)!==BigInt(execution.totalProvedDebtBefore)-1_000_000n
      ||execution.chainId!=='1'||execution.steps!==2
      ||execution.burnId!==packageValue.burnId||execution.requestId!==packageValue.requestId
      ||execution.amountBaseUnits!=='1000000'||execution.finalizedAcrossRpcCount!==2
      ||!decimal(execution.snapshotBlockNumber)||!hash32(execution.snapshotBlockHash)
      ||execution.outputLast!==true) throw new Error('closed redemption payout delta is invalid');
  return execution;
}
