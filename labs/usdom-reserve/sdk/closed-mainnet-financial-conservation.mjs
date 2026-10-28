import {validateFinalizedDepositWitnessIndex} from './finalized-deposit-issuance.mjs';

const decimal=value=>typeof value==='string'&&value.length<=78
  &&/^(0|[1-9][0-9]*)$/.test(value)&&BigInt(value)<1n<<256n;
const hex32=value=>typeof value==='string'&&/^0x[0-9a-fA-F]{64}$/.test(value);

export function validateClosedMainnetFinancialConservation({depositPackage,depositExecution,
  issuanceIndex,redemptionPackage,redemptionExecution}) {
  validateFinalizedDepositWitnessIndex(issuanceIndex);
  if(depositPackage?.amountBaseUnits!=='1000000'||!hex32(depositPackage.depositId)
      ||depositExecution?.amountBaseUnits!=='1000000'||depositExecution.allowanceBefore!=='0'
      ||depositExecution.allowanceAfter!=='0'||depositExecution.steps!==3
      ||!Array.isArray(depositExecution.transactionHashes)||depositExecution.transactionHashes.length!==3
      ||issuanceIndex.deposit_id?.toLowerCase()!==depositPackage.depositId.toLowerCase()
      ||issuanceIndex.funder?.toLowerCase()!==depositPackage.funder?.toLowerCase()
      ||issuanceIndex.receiving_commitment?.toLowerCase()
        !==depositPackage.receivingCommitment?.toLowerCase()
      ||issuanceIndex.release_config_sha256!==depositPackage.releaseConfigSha256
      ||issuanceIndex.source_transaction_hash?.toLowerCase()
        !==depositExecution.transactionHashes[2]?.toLowerCase()
      ||redemptionPackage?.amountBaseUnits!=='1000000'
      ||redemptionExecution?.amountBaseUnits!=='1000000'||redemptionExecution.steps!==2
      ||redemptionExecution.burnId!==redemptionPackage.burnId
      ||redemptionExecution.requestId!==redemptionPackage.requestId
      ||redemptionExecution.finalizedAcrossRpcCount!==2) {
    throw new Error('closed pilot does not bind one exact deposit, issuance, burn and payout');
  }
  for(const value of [depositExecution.reserveBalanceBefore,depositExecution.reserveBalanceAfter,
    depositExecution.totalDepositedBefore,depositExecution.totalDepositedAfter,
    depositExecution.outstandingBefore,depositExecution.outstandingAfter,
    redemptionExecution.recipientBalanceBefore,redemptionExecution.recipientBalanceAfter,
    redemptionExecution.reserveBalanceBefore,redemptionExecution.reserveBalanceAfter,
    redemptionExecution.totalReleasedBefore,redemptionExecution.totalReleasedAfter,
    redemptionExecution.outstandingBefore,redemptionExecution.outstandingAfter,
    redemptionExecution.totalProvedDebtBefore,redemptionExecution.totalProvedDebtAfter]) {
    if(!decimal(value)) throw new Error('closed pilot monetary value is not canonical');
  }
  if(BigInt(depositExecution.reserveBalanceAfter)!==BigInt(depositExecution.reserveBalanceBefore)+1_000_000n
      ||BigInt(depositExecution.totalDepositedAfter)!==BigInt(depositExecution.totalDepositedBefore)+1_000_000n
      ||BigInt(depositExecution.outstandingAfter)!==BigInt(depositExecution.outstandingBefore)+1_000_000n
      ||depositExecution.reserveBalanceAfter!==redemptionExecution.reserveBalanceBefore
      ||depositExecution.outstandingAfter!==redemptionExecution.outstandingBefore
      ||BigInt(redemptionExecution.recipientBalanceAfter)!==BigInt(redemptionExecution.recipientBalanceBefore)+1_000_000n
      ||BigInt(redemptionExecution.reserveBalanceAfter)!==BigInt(depositExecution.reserveBalanceAfter)-1_000_000n
      ||BigInt(redemptionExecution.totalReleasedAfter)!==BigInt(redemptionExecution.totalReleasedBefore)+1_000_000n
      ||BigInt(redemptionExecution.outstandingAfter)!==BigInt(depositExecution.outstandingAfter)-1_000_000n
      ||BigInt(depositExecution.totalDepositedAfter)-BigInt(redemptionExecution.totalReleasedBefore)
        !==BigInt(redemptionExecution.outstandingBefore)
      ||BigInt(depositExecution.totalDepositedAfter)-BigInt(redemptionExecution.totalReleasedAfter)
        !==BigInt(redemptionExecution.outstandingAfter)
      ||redemptionExecution.totalProvedDebtBefore!=='1000000'
      ||redemptionExecution.totalProvedDebtAfter!=='0') {
    throw new Error('closed pilot violates exact collateral or permanent-debt conservation');
  }
  return {schema:'usdom-closed-mainnet-financial-conservation/v1',amountBaseUnits:'1000000',
    allowanceBefore:'0',allowanceAfter:'0',conserved:true,
    permanentDebtBeforePayout:'1000000',permanentDebtAfterPayout:'0'};
}
