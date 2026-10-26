import {BoundedMainnetPreflightProvider} from './mainnet-preflight-rpc.mjs';
import {
  collectRecoverableSafeControlRecovery,collectRecoverableSafeControlSnapshot,
} from './safe-control-observation.mjs';
import {
  SafeRecoveryNotFinalizedError,observeFinalizedSafeRecoveryExecution,
} from './safe-control-recovery-execution.mjs';
import {prepareRecoverableSafeRecoveryPlan} from './safe-control-recovery-plan.mjs';
import {bindRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';

function fail(message) { throw new Error(message); }

export function reconcileRecoverableSafeControlSnapshots(snapshots) {
  if(!Array.isArray(snapshots)||snapshots.length<2||snapshots.length>5) {
    fail('two to five recoverable Safe snapshots are required');
  }
  const canonical=snapshots.map(value=>JSON.stringify(value));
  if(canonical.some(value=>value!==canonical[0])) fail('cataloged RPCs disagree on recoverable Safe controls');
  return snapshots[0];
}

export async function collectRecoverableSafeControlSnapshotConsensus({packageDocument,sources,
  providerFactory=url=>new BoundedMainnetPreflightProvider(url),
  collectSnapshot=collectRecoverableSafeControlSnapshot}={}) {
  if(!Array.isArray(sources)||sources.length<2||sources.length>5) {
    fail('two to five cataloged RPC sources are required');
  }
  const snapshots=[];
  try {
    for(const source of sources) {
      const provider=providerFactory(source.url);
      try {
        const options={packageDocument,rpcUrl:source.url,expectedNonce:'0',providerFactory:()=>provider};
        const before=await collectSnapshot(options);
        const after=await collectSnapshot(options);
        if(JSON.stringify(before)!==JSON.stringify(after)) {
          fail('recoverable Safe snapshot changed during source recheck');
        }
        snapshots.push(before);
      } finally { provider.destroy?.(); }
    }
    return bindRpcConsensusEvidence(reconcileRecoverableSafeControlSnapshots(snapshots),sources,'snapshotHash');
  } catch(error) {
    let message=String(error?.message??error);
    for(const source of sources) message=message.split(source.url).join('[redacted RPC URL]');
    throw new Error(message);
  }
}

export async function collectRecoverableSafeControlRecoveryConsensus({packageDocument,baselineSnapshot,
  transitionsByRole,transactions,sources,
  providerFactory=url=>new BoundedMainnetPreflightProvider(url),
  collectRecovery=collectRecoverableSafeControlRecovery}={}) {
  if(!Array.isArray(sources)||sources.length<2||sources.length>5) {
    fail('two to five cataloged RPC sources are required');
  }
  const reports=[];
  try {
    for(const source of sources) {
      const provider=providerFactory(source.url);
      try {
        const options={packageDocument,baselineSnapshot,transitionsByRole,transactions,
          rpcUrl:source.url,providerFactory:()=>provider};
        const before=await collectRecovery(options),after=await collectRecovery(options);
        if(JSON.stringify(before)!==JSON.stringify(after)) {
          fail('recoverable Safe recovery changed during source recheck');
        }
        reports.push(before);
      } finally { provider.destroy?.(); }
    }
    return bindRpcConsensusEvidence(reconcileRecoverableSafeControlSnapshots(reports),sources,'recoveryHash');
  } catch(error) {
    let message=String(error?.message??error);
    for(const source of sources) message=message.split(source.url).join('[redacted RPC URL]');
    throw new Error(message);
  }
}

export async function observeFinalizedSafeRecoveryExecutionConsensus({plan,transactionPackage,role,sources,
  providerFactory=url=>new BoundedMainnetPreflightProvider(url),
  observeExecution=observeFinalizedSafeRecoveryExecution}={}) {
  if(!Array.isArray(sources)||sources.length<2||sources.length>5) {
    fail('two to five cataloged RPC sources are required');
  }
  const observations=[];
  try {
    for(const source of sources) {
      const provider=providerFactory(source.url);
      try {
        const options={plan,transactionPackage,role,rpcUrl:source.url,providerFactory:()=>provider};
        const before=await observeExecution(options),after=await observeExecution(options);
        if(JSON.stringify(before)!==JSON.stringify(after)) {
          fail('finalized Safe execution changed during source recheck');
        }
        observations.push(before);
      } finally { provider.destroy?.(); }
    }
    return bindRpcConsensusEvidence(reconcileRecoverableSafeControlSnapshots(observations),sources);
  } catch(error) {
    let message=String(error?.message??error);
    for(const source of sources) message=message.split(source.url).join('[redacted RPC URL]');
    if(error instanceof SafeRecoveryNotFinalizedError) throw new SafeRecoveryNotFinalizedError(message);
    throw new Error(message);
  }
}

export async function prepareRecoverableSafeRecoveryPlanConsensus({packageDocument,baselineSnapshot,
  transitionsByRole,sources,providerFactory=url=>new BoundedMainnetPreflightProvider(url),
  preparePlan=prepareRecoverableSafeRecoveryPlan}={}) {
  if(!Array.isArray(sources)||sources.length<2||sources.length>5) {
    fail('two to five cataloged RPC sources are required');
  }
  const plans=[];
  try {
    for(const source of sources) {
      const provider=providerFactory(source.url);
      try {
        const options={packageDocument,baselineSnapshot,transitionsByRole,
          rpcUrl:source.url,providerFactory:()=>provider};
        const before=await preparePlan(options),after=await preparePlan(options);
        if(JSON.stringify(before)!==JSON.stringify(after)) {
          fail('recoverable Safe plan changed during source recheck');
        }
        plans.push(before);
      } finally { provider.destroy?.(); }
    }
    return bindRpcConsensusEvidence(reconcileRecoverableSafeControlSnapshots(plans),sources,'planHash');
  } catch(error) {
    let message=String(error?.message??error);
    for(const source of sources) message=message.split(source.url).join('[redacted RPC URL]');
    throw new Error(message);
  }
}
