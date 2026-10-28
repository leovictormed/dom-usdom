const hash=/^0x[0-9a-fA-F]{64}$/;
const nonzero=value=>hash.test(value??'')&&!/^0x0{64}$/i.test(value);

const pair=(value,a,b)=>[value?.[a],value?.[b]];
const empty=values=>values.every(value=>value===null);
const pinned=values=>values.every(nonzero);

/** Classify only complete, monotonic artifact-binding states. Mixed hash pairs
 * are never recoverable input because they cannot identify one build. */
export function classifyProductionReleaseArtifactStage(release) {
  if(!release||typeof release!=='object'||Array.isArray(release)) {
    throw new Error('production release stage input is invalid');
  }
  const reserve=pair(release,'reserveRuntimeCodeHash','reserveInitcodeHash');
  const registry=pair(release,'checkpointRegistryRuntimeCodeHash','checkpointRegistryInitcodeHash');
  if(empty(reserve)&&empty(registry)) return 'bootstrap';
  if(empty(reserve)&&pinned(registry)) return 'registry';
  if(pinned(reserve)&&pinned(registry)) return 'final';
  throw new Error('production release contains a partial or non-monotonic artifact stage');
}

export function assertProductionReleaseStageTransition(before,after) {
  const order=['bootstrap','registry','final'];
  const left=classifyProductionReleaseArtifactStage(before);
  const right=classifyProductionReleaseArtifactStage(after);
  if(order.indexOf(right)<order.indexOf(left)||order.indexOf(right)>order.indexOf(left)+1) {
    throw new Error(`invalid production release stage transition: ${left} -> ${right}`);
  }
  return Object.freeze({before:left,after:right});
}
