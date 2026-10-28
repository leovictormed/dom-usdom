const decimal=value=>typeof value==='string'&&value.length<=78
  &&/^(0|[1-9][0-9]*)$/.test(value)&&BigInt(value)<1n<<256n;
export function validatePilotGasFunding({balanceA,balanceB,maximumCost}) {
  if(!decimal(balanceA)||!decimal(balanceB)||!decimal(maximumCost)) throw new Error('gas funding values must be canonical wei');
  if(balanceA!==balanceB) throw new Error('RPC gas balances disagree');
  if(BigInt(maximumCost)===0n||BigInt(balanceA)<BigInt(maximumCost)) throw new Error('insufficient ETH for worst-case pilot gas');
  return {balanceWei:balanceA,maximumCostWei:maximumCost,surplusWei:(BigInt(balanceA)-BigInt(maximumCost)).toString()};
}

export const PILOT_PAYER_WORST_CASE_WEI=Object.freeze({
  safeDeployer:'300000000000000000',
  contractDeployer:'1000000000000000000',
  depositFunder:'150000000000000000',
  redemptionRelayer:'200000000000000000',
  safeRecoveryRelayerAllRoles:'750000000000000000',
});

/** Exact upper envelopes by payer. Addresses may coincide only when execution
 * is strictly sequential; the caller must then sum every applicable envelope. */
export function requiredPilotPayerFunding(payers) {
  const roles=Object.keys(PILOT_PAYER_WORST_CASE_WEI);
  if(!payers||typeof payers!=='object'||Array.isArray(payers)
      ||JSON.stringify(Object.keys(payers).sort())!==JSON.stringify(roles.sort())) {
    throw new Error('pilot payer map is incomplete');
  }
  const totals=new Map();
  for(const role of roles) {
    const address=payers[role];
    if(typeof address!=='string'||!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error(`${role} payer is invalid`);
    const normalized=address.toLowerCase();
    totals.set(normalized,(totals.get(normalized)??0n)+BigInt(PILOT_PAYER_WORST_CASE_WEI[role]));
  }
  return Object.freeze([...totals].sort(([a],[b])=>a.localeCompare(b)).map(([address,maximumCostWei])=>
    Object.freeze({address,maximumCostWei:maximumCostWei.toString()})));
}
