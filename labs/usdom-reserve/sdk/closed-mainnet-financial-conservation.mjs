const decimal=value=>typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value);
const hex32=value=>typeof value==='string'&&/^0x[0-9a-fA-F]{64}$/.test(value);

export function validateClosedMainnetFinancialConservation({depositPackage,depositExecution,
  issuanceIndex,redemptionPackage,redemptionExecution}) {
  if(depositPackage?.amountBaseUnits!=='1000000'||!hex32(depositPackage.depositId)
      ||depositExecution?.amountBaseUnits!=='1000000'||depositExecution.allowanceBefore!=='0'
      ||depositExecution.allowanceAfter!=='0'||depositExecution.steps!==3
      ||issuanceIndex?.schema!=='usdom-finalized-deposit-witness-v1'
      ||issuanceIndex.amount_base_units!=='1000000'
      ||issuanceIndex.deposit_id?.toLowerCase()!==depositPackage.depositId.toLowerCase()
      ||issuanceIndex.witness_verified!==true||issuanceIndex.relation_executed!==true
      ||issuanceIndex.broadcasts!==false||issuanceIndex.mines!==false
      ||redemptionPackage?.amountBaseUnits!=='1000000'
      ||redemptionExecution?.amountBaseUnits!=='1000000'||redemptionExecution.steps!==2
      ||redemptionExecution.burnId!==redemptionPackage.burnId
      ||redemptionExecution.requestId!==redemptionPackage.requestId
      ||redemptionExecution.finalizedAcrossRpcCount!==2) {
    throw new Error('closed pilot does not bind one exact deposit, issuance, burn and payout');
  }
  for(const value of [depositExecution.reserveBalanceAfter,depositExecution.outstandingAfter,
    redemptionExecution.reserveBalanceBefore,redemptionExecution.reserveBalanceAfter,
    redemptionExecution.outstandingBefore,redemptionExecution.outstandingAfter,
    redemptionExecution.totalProvedDebtBefore,redemptionExecution.totalProvedDebtAfter]) {
    if(!decimal(value)) throw new Error('closed pilot monetary value is not canonical');
  }
  if(depositExecution.reserveBalanceAfter!==redemptionExecution.reserveBalanceBefore
      ||depositExecution.outstandingAfter!==redemptionExecution.outstandingBefore
      ||BigInt(redemptionExecution.reserveBalanceAfter)!==BigInt(depositExecution.reserveBalanceAfter)-1_000_000n
      ||BigInt(redemptionExecution.outstandingAfter)!==BigInt(depositExecution.outstandingAfter)-1_000_000n
      ||redemptionExecution.totalProvedDebtBefore!=='1000000'
      ||redemptionExecution.totalProvedDebtAfter!=='0') {
    throw new Error('closed pilot violates exact collateral or permanent-debt conservation');
  }
  return {schema:'usdom-closed-mainnet-financial-conservation/v1',amountBaseUnits:'1000000',
    allowanceBefore:'0',allowanceAfter:'0',conserved:true,
    permanentDebtBeforePayout:'1000000',permanentDebtAfterPayout:'0'};
}
