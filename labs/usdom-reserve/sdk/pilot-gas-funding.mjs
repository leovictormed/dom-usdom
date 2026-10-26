const decimal=value=>typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value);
export function validatePilotGasFunding({balanceA,balanceB,maximumCost}) {
  if(!decimal(balanceA)||!decimal(balanceB)||!decimal(maximumCost)) throw new Error('gas funding values must be canonical wei');
  if(balanceA!==balanceB) throw new Error('RPC gas balances disagree');
  if(BigInt(maximumCost)===0n||BigInt(balanceA)<BigInt(maximumCost)) throw new Error('insufficient ETH for worst-case pilot gas');
  return {balanceWei:balanceA,maximumCostWei:maximumCost,surplusWei:(BigInt(balanceA)-BigInt(maximumCost)).toString()};
}
