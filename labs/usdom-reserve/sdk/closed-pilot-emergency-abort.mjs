const phases=['before-approve','after-approve','after-deposit','after-issuance','after-burn','after-queue','after-payout'];
export function closedPilotEmergencyAbortPlan(phase) {
  if(!phases.includes(phase)) throw new Error('unknown closed-pilot abort phase');
  const allowanceMayRemain=phase==='after-approve';
  const debtMayExist=['after-burn','after-queue'].includes(phase);
  return Object.freeze({schema:'usdom-closed-pilot-emergency-abort/v1',phase,
    immediate:Object.freeze(['guardian-safe-pause','guardian-safe-close-deposits']),
    allowance:Object.freeze(allowanceMayRemain
      ?['funder-revoke-allowance-after-pause-confirmed']:['verify-allowance-zero']),
    recovery:Object.freeze(debtMayExist
      ?['verify-permanent-debt','resume-after-governance-delay','renew-existing-debt-lease','execute-existing-debt']
      :['verify-no-unpaid-permanent-debt']),
    prohibited:Object.freeze(['new-deposit','new-first-proof-queue','collateral-sweep','deposit-refund','generic-blind-signing']),
  });
}
