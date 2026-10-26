const DECIMAL=/^(0|[1-9][0-9]*)$/;
export const PILOT_DEPOSIT_TRANSACTION_CAP_WEI=50_000_000_000_000_000n;
export const PILOT_REDEMPTION_TRANSACTION_CAP_WEI=100_000_000_000_000_000n;
export const PILOT_DEPOSIT_CUMULATIVE_CAP_WEI=150_000_000_000_000_000n;
export const PILOT_REDEMPTION_CUMULATIVE_CAP_WEI=200_000_000_000_000_000n;
export const PILOT_TOTAL_CUMULATIVE_CAP_WEI=350_000_000_000_000_000n;

function costs(values,count,perTransaction,label) {
  if(!Array.isArray(values)||values.length>count||values.some(value=>!DECIMAL.test(value))) {
    throw new Error(`${label} pilot cost list is malformed`);
  }
  const parsed=values.map(BigInt);
  if(parsed.some(value=>value===0n||value>perTransaction)) {
    throw new Error(`${label} pilot per-transaction ETH cap exceeded`);
  }
  return parsed;
}

export function validateClosedMainnetPilotBudget({depositMaximumCosts,redemptionMaximumCosts}) {
  const deposit=costs(depositMaximumCosts,3,PILOT_DEPOSIT_TRANSACTION_CAP_WEI,'deposit');
  const redemption=costs(redemptionMaximumCosts,2,PILOT_REDEMPTION_TRANSACTION_CAP_WEI,'redemption');
  const depositTotal=deposit.reduce((sum,value)=>sum+value,0n);
  const redemptionTotal=redemption.reduce((sum,value)=>sum+value,0n);
  if(depositTotal>PILOT_DEPOSIT_CUMULATIVE_CAP_WEI
      ||redemptionTotal>PILOT_REDEMPTION_CUMULATIVE_CAP_WEI
      ||depositTotal+redemptionTotal>PILOT_TOTAL_CUMULATIVE_CAP_WEI) {
    throw new Error('closed-mainnet cumulative ETH budget exceeded');
  }
  return Object.freeze({schema:'usdom-closed-mainnet-pilot-budget-v1',
    depositMaximumCostWei:depositTotal.toString(),redemptionMaximumCostWei:redemptionTotal.toString(),
    totalMaximumCostWei:(depositTotal+redemptionTotal).toString()});
}
