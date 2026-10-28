const OPERATIONS=new Set([
  'check-closed-mainnet-deposit-evidence','check-closed-mainnet-payout-evidence',
  'check-closed-mainnet-redemption','check-closed-mainnet-redemption-release',
  'closed-mainnet-burn-block',
  'closed-mainnet-deposit-prepare','closed-mainnet-deposit-check',
  'closed-mainnet-deposit-raw-check','closed-mainnet-phase-check',
  'closed-mainnet-genesis-initialize','closed-mainnet-issuance-submit',
  'closed-mainnet-issuance-mine','finalized-burn-submission-prepare',
  'finalized-burn-evidence-materialize','mainnet-preflight','mainnet-readiness',
]);

/**
 * Produce the only failure shape that pilot entry points may write to an
 * observable stream.  The Error is deliberately accepted but never inspected:
 * messages, causes and stacks may contain RPC URLs, raw transactions, witnesses
 * or identifiers that would join the deposit and redemption phases.
 */
export function pilotFailureRecord(operation,_error) {
  if(!OPERATIONS.has(operation)) throw new Error('unsupported pilot diagnostic operation');
  return Object.freeze({
    schema:'usdom-pilot-safe-diagnostic/v1',ok:false,operation,
    code:'PILOT_OPERATION_REJECTED',
  });
}

export function pilotFailureLine(operation,error) {
  return `${JSON.stringify(pilotFailureRecord(operation,error))}\n`;
}

export function writePilotFailure(operation,error,{stream=process.stderr}={}) {
  stream.write(pilotFailureLine(operation,error));
}

export function releaseFailureRecord(operation,_error) {
  if(typeof operation!=='string'||!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(operation)
      ||operation.length>96) throw new Error('invalid release diagnostic operation');
  return Object.freeze({
    schema:'usdom-release-safe-diagnostic/v1',ok:false,operation,
    code:'RELEASE_OPERATION_REJECTED',
  });
}

export function releaseFailureLine(operation,error) {
  return `${JSON.stringify(releaseFailureRecord(operation,error))}\n`;
}

export function writeReleaseFailure(operation,error,{stream=process.stderr}={}) {
  stream.write(releaseFailureLine(operation,error));
}
