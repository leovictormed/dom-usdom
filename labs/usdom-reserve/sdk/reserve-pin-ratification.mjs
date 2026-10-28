import {createHash} from 'node:crypto';
import {materializeProductionSolidityPins} from './production-solidity-pins.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';

export const RESERVE_PIN_RATIFICATION_SCHEMA='usdom-reserve-production-pin-ratification-proposal/v1';
const constants=Object.freeze([
  'PRODUCTION_VERIFIER_CODE_HASH','PRODUCTION_VERIFIER_CONFIG_HASH',
  'PRODUCTION_RESERVE_PREACTIVATION_CONFIG_HASH',
]);
const sha=value=>createHash('sha256').update(value).digest('hex');
const bytes=value=>Buffer.isBuffer(value)?value:Buffer.from(value);
const manifestInputs=Object.freeze({
  'contracts/USDOMProofReserve.sol':'reserveSourceBytes',
  'config/rebuild-v3-critical-source-inventory.json':'criticalSourceInventoryBytes',
  'config/mainnet-toolchain-lock.json':'toolchainLockBytes',
});

function authenticateManifest(sourceManifestBytes,inputs) {
  let text;
  try {text=new TextDecoder('utf-8',{fatal:true}).decode(bytes(sourceManifestBytes));}
  catch {throw new Error('source manifest is not canonical UTF-8');}
  if(!text.endsWith('\n')||Buffer.from(text,'utf8').length!==bytes(sourceManifestBytes).length) {
    throw new Error('source manifest is not canonical UTF-8');
  }
  const entries=new Map(); let previous='';
  for(const line of text.slice(0,-1).split('\n')) {
    const match=/^([0-9a-f]{64})  ([^\0\r\n]+)$/.exec(line);
    if(!match||match[2].startsWith('/')||match[2].split('/').includes('..')
        ||match[2]<=previous||entries.has(match[2])) {
      throw new Error('source manifest is not canonical and uniquely sorted');
    }
    previous=match[2]; entries.set(match[2],match[1]);
  }
  for(const [name,field] of Object.entries(manifestInputs)) {
    if(entries.get(name)!==sha(bytes(inputs[field]))) {
      throw new Error(`${name} differs from the authenticated source manifest`);
    }
  }
}

function pin(source,name) {
  const match=source.match(new RegExp(`bytes32\\s+(?:public|private)\\s+constant\\s+${name}\\s*=\\s*(0x[0-9a-fA-F]{64})\\s*;`));
  if(!match) throw new Error(`${name} is absent from the candidate source`);
  return match[1].toLowerCase();
}

function reviewPatch(before,after) {
  const changed=[];
  for(const name of constants) {
    const pattern=new RegExp(`^.*bytes32\\s+(?:public|private)\\s+constant\\s+${name}\\s*=.*$`,'m');
    const oldLine=before.match(pattern)?.[0],newLine=after.match(pattern)?.[0];
    if(!oldLine||!newLine||oldLine===newLine) throw new Error(`${name} did not produce one reviewable change`);
    changed.push(`@@ ${name} @@\n-${oldLine}\n+${newLine}`);
  }
  return `--- a/contracts/USDOMProofReserve.sol\n+++ b/contracts/USDOMProofReserve.sol\n${changed.join('\n')}\n`;
}

/** Build a review-only proposal. This function never writes Solidity and never
 * changes production authorization. Its byte descriptors make release,
 * current source, compiler artifact, global manifest, critical inventory and
 * toolchain lock independently re-openable by the verifier. */
export function buildReservePinRatificationProposal({releaseConfig,releaseConfigBytes,
  reserveSourceBytes,finalizedBurnVerifierArtifactBytes,finalizedBurnVerifierConfigBytes,
  sourceManifestBytes,criticalSourceInventoryBytes,toolchainLockBytes}={}) {
  const parsedRelease=parseStrictJsonBytes(bytes(releaseConfigBytes),
    {label:'reserve pin release config',maxBytes:4*1024*1024,maxDepth:64});
  if(JSON.stringify(parsedRelease)!==JSON.stringify(releaseConfig)) {
    throw new Error('release config object differs from its authority bytes');
  }
  let source;
  try { source=new TextDecoder('utf-8',{fatal:true}).decode(bytes(reserveSourceBytes)); }
  catch { throw new Error('reserve source is not canonical UTF-8'); }
  if(!Buffer.from(source,'utf8').equals(bytes(reserveSourceBytes))) {
    throw new Error('reserve source UTF-8 roundtrip differs from its authority bytes');
  }
  for(const name of constants) {
    if(!new RegExp(`${name}\\s*=\\s*bytes32\\(0\\)\\s*;`).test(source)) {
      throw new Error(`${name} must remain deliberately zero before ratification`);
    }
  }
  if(bytes(releaseConfigBytes).length===0||bytes(finalizedBurnVerifierArtifactBytes).length===0
      ||bytes(finalizedBurnVerifierConfigBytes).length===0||bytes(sourceManifestBytes).length===0
      ||bytes(criticalSourceInventoryBytes).length===0||bytes(toolchainLockBytes).length===0) {
    throw new Error('ratification proposal inputs must be nonempty');
  }
  authenticateManifest(sourceManifestBytes,{reserveSourceBytes,criticalSourceInventoryBytes,
    toolchainLockBytes});
  const candidate=materializeProductionSolidityPins({releaseConfig:parsedRelease,reserveSource:source,
    component:'reserve'}).reserveSource;
  const pins=Object.fromEntries(constants.map(name=>[name,pin(candidate,name)]));
  const patch=reviewPatch(source,candidate);
  return Object.freeze({schema:RESERVE_PIN_RATIFICATION_SCHEMA,status:'proposal-only',
    productionPinsActivated:false,requiresExternalRatification:true,
    contract:'contracts/USDOMProofReserve.sol',pins,
    inputs:Object.freeze({releaseConfigSha256:sha(bytes(releaseConfigBytes)),
      currentReserveSourceSha256:sha(bytes(reserveSourceBytes)),
      candidateReserveSourceSha256:sha(Buffer.from(candidate)),
      finalizedBurnVerifierArtifactSha256:sha(bytes(finalizedBurnVerifierArtifactBytes)),
      finalizedBurnVerifierConfigSha256:sha(bytes(finalizedBurnVerifierConfigBytes)),
      sourceManifestSha256:sha(bytes(sourceManifestBytes)),
      criticalSourceInventorySha256:sha(bytes(criticalSourceInventoryBytes)),
      toolchainLockSha256:sha(bytes(toolchainLockBytes))}),
    reviewPatch:patch,reviewPatchSha256:sha(Buffer.from(patch))});
}

export function verifyReservePinRatificationProposal({proposal,...inputs}={}) {
  if(!proposal||proposal.schema!==RESERVE_PIN_RATIFICATION_SCHEMA
      ||proposal.status!=='proposal-only'||proposal.productionPinsActivated!==false
      ||proposal.requiresExternalRatification!==true) {
    throw new Error('reserve pin ratification proposal has invalid authority state');
  }
  const expected=buildReservePinRatificationProposal(inputs);
  if(JSON.stringify(proposal)!==JSON.stringify(expected)) {
    throw new Error('reserve pin ratification proposal differs from current release/source/toolchain inputs');
  }
  return true;
}

/** Recover the unique pre-pin source from an already-installed candidate so a
 * crash-safe retry can revalidate the original proposal. No other installed
 * source or proposal is accepted. */
export function restoreReservePinRatificationBaseline({proposal,candidateSourceBytes}={}) {
  const candidateBytes=bytes(candidateSourceBytes);
  if(!proposal?.inputs||sha(candidateBytes)!==proposal.inputs.candidateReserveSourceSha256) {
    throw new Error('installed reserve source differs from the ratified candidate');
  }
  let source;
  try {source=new TextDecoder('utf-8',{fatal:true}).decode(candidateBytes);}
  catch {throw new Error('installed reserve source is not canonical UTF-8');}
  for(const name of constants) {
    const value=proposal?.pins?.[name];
    if(!/^0x[0-9a-f]{64}$/.test(value??'')) throw new Error(`ratified ${name} is invalid`);
    const declaration=new RegExp(`(bytes32\\s+(?:public|private)\\s+constant\\s+${name}\\s*=\\s*)${value}(\\s*;)`,'g');
    const matches=[...source.matchAll(declaration)];
    if(matches.length!==1) throw new Error(`installed ${name} differs from the ratified pin`);
    source=source.replace(declaration,(_match,prefix,suffix)=>`${prefix}bytes32(0)${suffix}`);
  }
  const baseline=Buffer.from(source,'utf8');
  if(sha(baseline)!==proposal.inputs.currentReserveSourceSha256) {
    throw new Error('restored reserve baseline differs from the ratified source');
  }
  return baseline;
}
