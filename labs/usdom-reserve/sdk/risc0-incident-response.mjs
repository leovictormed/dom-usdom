import {
  Interface,
  getAddress,
  isAddress,
  keccak256,
  toUtf8Bytes,
} from 'ethers';
import {assessRiscZeroMainnetHealth} from './risc0-health.mjs';
import {validateRiscZeroHealthSourceCatalog} from './risc0-health-source-catalog.mjs';

export const RISC0_INCIDENT_RESPONSE_SCHEMA='usdom-risc0-incident-response/v4';
export const RISC0_INCIDENT_RESPONSE_REPORT_SCHEMA='usdom-risc0-incident-response-report/v4';

const reserveInterface=new Interface([
  'function pauseQueueEpoch(uint64 expectedQueueEpoch,uint64 expectedPilotAuthorizationGeneration)',
]);
const checkpointInterface=new Interface([
  'function haltPermanently()',
]);
const hashPattern=/^0x[0-9a-fA-F]{64}$/;
const uintPattern=/^(0|[1-9][0-9]*)$/;
const zeroAddress='0x0000000000000000000000000000000000000000';
const observationIntegrityBlockers=new Set([
  'risc0_reference_invalid',
  'risc0_observation_scope_invalid',
  'risc0_observation_schema_invalid',
  'risc0_verifier_observation_schema_invalid',
  'risc0_estop_observation_schema_invalid',
  'risc0_estop_state_invalid',
  'risc0_wrong_chain',
  'risc0_wrong_genesis',
  'risc0_finalized_block_number_invalid',
  'risc0_finalized_block_hash_invalid',
  'risc0_finalized_snapshot_changed',
]);

function fail(message) {
  throw new Error(message);
}

function exactObject(value,keys,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    fail(`${label} must contain exact fields`);
  }
  return value;
}

function address(value,label) {
  if(typeof value!=='string' || !isAddress(value) || getAddress(value)===zeroAddress) {
    fail(`${label} must be a nonzero address`);
  }
  return getAddress(value);
}

function hash(value,label) {
  if(typeof value!=='string' || !hashPattern.test(value)
      || value.toLowerCase()==='0x'+'00'.repeat(32)) {
    fail(`${label} must be a nonzero bytes32`);
  }
  return value.toLowerCase();
}

function uint(value,label,bits=256) {
  const maxDigits={64:20,256:78}[bits];
  if(maxDigits===undefined||typeof value!=='string'||value.length>maxDigits
      ||!uintPattern.test(value)) fail(`${label} must be a canonical uint`);
  const result=BigInt(value);
  if(result>=2n**BigInt(bits)) fail(`${label} exceeds uint${bits}`);
  return result;
}

function target(value,label) {
  exactObject(value,['address','runtimeCodeHash'],label);
  return {address:address(value.address,`${label} address`),
    runtimeCodeHash:hash(value.runtimeCodeHash,`${label} runtime code hash`)};
}

function snapshot(value) {
  exactObject(value,['ethereumChainId','reserve','checkpointRegistry'],'response snapshot');
  const ethereumChainId=uint(value.ethereumChainId,'response chain ID');
  if(ethereumChainId===0n) fail('response chain ID is zero');
  exactObject(value.reserve,['address','runtimeCodeHash','queueEpoch','pilotAuthorizationGeneration','paused','resumeReadyAt'],'reserve snapshot');
  exactObject(value.checkpointRegistry,['address','runtimeCodeHash','halted'],'checkpoint snapshot');
  if(typeof value.reserve.paused!=='boolean' || typeof value.checkpointRegistry.halted!=='boolean') {
    fail('response snapshot booleans are invalid');
  }
  const reserveTarget=target({address:value.reserve.address,
    runtimeCodeHash:value.reserve.runtimeCodeHash},'reserve');
  const checkpointTarget=target({address:value.checkpointRegistry.address,
    runtimeCodeHash:value.checkpointRegistry.runtimeCodeHash},'checkpoint registry');
  const resumeReadyAt=uint(value.reserve.resumeReadyAt,'resume ready timestamp',64);
  const pilotAuthorizationGeneration=uint(value.reserve.pilotAuthorizationGeneration,'pilot authorization generation',64);
  if(pilotAuthorizationGeneration===(1n<<64n)-1n) fail('pilot authorization generation exhausted');
  if(!value.reserve.paused && resumeReadyAt!==0n) fail('unpaused reserve has a scheduled resume');
  return {
    ethereumChainId:ethereumChainId.toString(),
    reserve:{...reserveTarget,queueEpoch:uint(value.reserve.queueEpoch,'queue epoch',64).toString(),
      pilotAuthorizationGeneration:pilotAuthorizationGeneration.toString(),
      paused:value.reserve.paused,resumeReadyAt:resumeReadyAt.toString()},
    checkpointRegistry:{...checkpointTarget,halted:value.checkpointRegistry.halted},
  };
}

function expectedTargets(value) {
  exactObject(value,['reserve','checkpointRegistry'],'expected response targets');
  return {reserve:target(value.reserve,'expected reserve'),
    checkpointRegistry:target(value.checkpointRegistry,'expected checkpoint registry')};
}

function sameTarget(left,right,label) {
  if(left.address!==right.address || left.runtimeCodeHash!==right.runtimeCodeHash) {
    fail(`${label} does not match the approved release target`);
  }
}

function action(role,to,data,precondition,postcondition) {
  return {role,to,value:'0',data:data.toLowerCase(),dataHash:keccak256(data),precondition,postcondition};
}

function planHash(value) {
  return keccak256(toUtf8Bytes(JSON.stringify(value)));
}

function sourceIdentity(value,label) {
  exactObject(value,['sourceId','operatorId','providerId','infrastructureId','endpointHash'],label);
  for(const [field,fieldLabel] of [['sourceId','source'],['operatorId','operator'],
    ['providerId','provider'],['infrastructureId','infrastructure']]) {
    if(typeof value[field]!=='string' || !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(value[field])) {
      fail(`${label} ${fieldLabel} identity is invalid`);
    }
  }
  return {sourceId:value.sourceId,operatorId:value.operatorId,providerId:value.providerId,
    infrastructureId:value.infrastructureId,
    endpointHash:hash(value.endpointHash,`${label} endpoint hash`)};
}

function healthSources(values,approvedCatalog) {
  if(!Array.isArray(values) || values.length<1 || values.length>4) {
    fail('one to four upstream health sources are required');
  }
  const catalog=validateRiscZeroHealthSourceCatalog(approvedCatalog);
  const approved=catalog.sources;
  const approvedById=new Map(approved.map(value=>[value.sourceId,value]));
  const normalized=values.map((value,index)=>{
    exactObject(value,['sourceId','operatorId','providerId','infrastructureId','endpointHash','observation'],
      `health source ${index}`);
    const identity=sourceIdentity({sourceId:value.sourceId,operatorId:value.operatorId,
      providerId:value.providerId,infrastructureId:value.infrastructureId,
      endpointHash:value.endpointHash},`health source ${index}`);
    const expected=approvedById.get(identity.sourceId);
    if(!expected || JSON.stringify(identity)!==JSON.stringify(expected)) {
      fail(`health source ${index} is not an approved release source`);
    }
    return {...identity,observation:value.observation};
  }).sort((left,right)=>left.sourceId<right.sourceId?-1:left.sourceId>right.sourceId?1:0);
  if(new Set(normalized.map(({sourceId})=>sourceId)).size!==normalized.length) {
    fail('upstream health source identities must be distinct');
  }
  return {catalogHash:catalog.catalogHash,observed:normalized};
}

/** Builds unsigned control-plane actions from one strict upstream health
 * assessment. An unavailable or malformed observation can pause the reserve,
 * but cannot irreversibly halt checkpointing. A structurally authenticated
 * finalized observation with an upstream identity or stop-state mismatch is a
 * confirmed incident and produces both independent guardian actions. */
export function buildRiscZeroIncidentResponsePlan({reference,sources,approvedSourceCatalog,responseSnapshot,
  approvedTargets}) {
  const observed=snapshot(responseSnapshot);
  const approved=expectedTargets(approvedTargets);
  sameTarget(observed.reserve,approved.reserve,'reserve');
  sameTarget(observed.checkpointRegistry,approved.checkpointRegistry,'checkpoint registry');
  const {catalogHash:approvedSourceCatalogHash,observed:inputs}=
    healthSources(sources,approvedSourceCatalog);
  const assessments=inputs.map(({observation})=>assessRiscZeroMainnetHealth({reference,observation}));
  const observationsIdentical=inputs.every(({observation})=>
    JSON.stringify(observation)===JSON.stringify(inputs[0].observation));
  const allHealthy=observationsIdentical && assessments.every(({healthy})=>healthy);
  const sourceOperatorsDistinct=new Set(inputs.map(({operatorId})=>operatorId)).size===inputs.length;
  const sourceEndpointsDistinct=new Set(inputs.map(({endpointHash})=>endpointHash)).size===inputs.length;
  const allTrustedIncidents=inputs.length>=2 && sourceOperatorsDistinct && sourceEndpointsDistinct
    && observationsIdentical && assessments.every(assessment=>!assessment.healthy
      && !assessment.blockers.some(({code})=>observationIntegrityBlockers.has(code)));
  const classification=allHealthy?'healthy':allTrustedIncidents
    ?'confirmed-upstream-incident':'unconfirmed-health-failure';
  const blockerCodes=[...new Set(assessments.flatMap(assessment=>
    assessment.blockers.map(({code})=>code)))].sort();
  const actions=[];
  // Re-submit the generation-bound pause when a resume is pending. Calling
  // pauseQueueEpoch on an already paused reserve cancels resumeReadyAt, so an
  // upstream incident cannot be bypassed by a previously scheduled resume.
  if(classification!=='healthy' && (!observed.reserve.paused || observed.reserve.resumeReadyAt!=='0')) {
    actions.push(action('reserveGuardian',observed.reserve.address,
      reserveInterface.encodeFunctionData('pauseQueueEpoch',[observed.reserve.queueEpoch,observed.reserve.pilotAuthorizationGeneration]),
      {queueEpoch:observed.reserve.queueEpoch,pilotAuthorizationGeneration:observed.reserve.pilotAuthorizationGeneration,paused:observed.reserve.paused,
        resumeReadyAt:observed.reserve.resumeReadyAt},{paused:true,resumeReadyAt:'0',pilotAuthorizationGeneration:(BigInt(observed.reserve.pilotAuthorizationGeneration)+1n).toString()}));
  }
  if(classification==='confirmed-upstream-incident' && !observed.checkpointRegistry.halted) {
    actions.push(action('checkpointGuardian',observed.checkpointRegistry.address,
      checkpointInterface.encodeFunctionData('haltPermanently'),{halted:false},{halted:true}));
  }
  const commonAssessment=observationsIdentical?assessments[0]:null;
  const body={schema:RISC0_INCIDENT_RESPONSE_SCHEMA,classification,
    approvedSourceCatalogHash,
    observedUpstreamSources:inputs.map(({sourceId,operatorId,endpointHash})=>
      ({sourceId,operatorId,endpointHash})),
    upstreamFinalizedBlockNumber:commonAssessment?.finalizedBlockNumber??null,
    upstreamFinalizedBlockHash:commonAssessment?.finalizedBlockHash??null,
    responseChainId:observed.ethereumChainId,assessment:{healthy:classification==='healthy',
      observationsIdentical,sourceOperatorsDistinct,sourceEndpointsDistinct,
      blockerCount:blockerCodes.length,blockerCodes},snapshot:observed,actions};
  return {...body,planHash:planHash(body)};
}

function validatePlan(plan) {
  exactObject(plan,['schema','classification','approvedSourceCatalogHash','observedUpstreamSources',
    'upstreamFinalizedBlockNumber','upstreamFinalizedBlockHash',
    'responseChainId','assessment','snapshot','actions','planHash'],'incident response plan');
  if(plan.schema!==RISC0_INCIDENT_RESPONSE_SCHEMA) fail('incident response schema mismatch');
  if(!['healthy','confirmed-upstream-incident','unconfirmed-health-failure'].includes(plan.classification)) {
    fail('incident response classification is invalid');
  }
  const body={schema:plan.schema,classification:plan.classification,
    approvedSourceCatalogHash:plan.approvedSourceCatalogHash,
    observedUpstreamSources:plan.observedUpstreamSources,
    upstreamFinalizedBlockNumber:plan.upstreamFinalizedBlockNumber,
    upstreamFinalizedBlockHash:plan.upstreamFinalizedBlockHash,responseChainId:plan.responseChainId,
    assessment:plan.assessment,snapshot:plan.snapshot,actions:plan.actions};
  if(hash(plan.planHash,'plan hash')!==planHash(body)) fail('incident response plan hash mismatch');
  const normalized=snapshot(plan.snapshot);
  if(normalized.ethereumChainId!==uint(plan.responseChainId,'response chain ID').toString()) {
    fail('response chain identity mismatch');
  }
  if(!Array.isArray(plan.actions) || plan.actions.length>2) fail('incident response actions are invalid');
  return normalized;
}

/** Executes a previously bound response plan through independent transaction
 * adapters. The adapters may be Safe orchestration modules; this function has
 * no key handling and never treats proposal creation as inclusion. */
export async function executeRiscZeroIncidentResponse({plan,reference,sources,approvedSourceCatalog,
  approvedTargets,
  reserve,checkpointRegistry,reserveGuardian,checkpointGuardian}) {
  const observed=validatePlan(plan);
  const rebuilt=buildRiscZeroIncidentResponsePlan({reference,sources,approvedSourceCatalog,
    responseSnapshot:observed,approvedTargets});
  if(JSON.stringify(rebuilt)!==JSON.stringify(plan)) {
    fail('incident response plan does not match the authenticated observation');
  }
  if(plan.classification==='healthy') {
    if(plan.actions.length!==0) fail('healthy response plan contains actions');
    return {schema:RISC0_INCIDENT_RESPONSE_REPORT_SCHEMA,planHash:plan.planHash,
      status:'healthy',transactions:[]};
  }
  const provider=reserve.runner?.provider??reserve.runner;
  const checkpointProvider=checkpointRegistry.runner?.provider??checkpointRegistry.runner;
  if(!provider || provider!==checkpointProvider) fail('response contracts must share one provider');
  if((await provider.getNetwork()).chainId!==BigInt(observed.ethereumChainId)) fail('response chain mismatch');
  if(getAddress(await reserve.getAddress())!==observed.reserve.address
      || getAddress(await checkpointRegistry.getAddress())!==observed.checkpointRegistry.address) {
    fail('response contract address mismatch');
  }
  const [reserveCode,checkpointCode]=await Promise.all([
    provider.getCode(observed.reserve.address),provider.getCode(observed.checkpointRegistry.address),
  ]);
  if(keccak256(reserveCode)!==observed.reserve.runtimeCodeHash
      || keccak256(checkpointCode)!==observed.checkpointRegistry.runtimeCodeHash) {
    fail('response contract runtime identity mismatch');
  }
  const transactions=[];
  for(const responseAction of plan.actions) {
    exactObject(responseAction,['role','to','value','data','dataHash','precondition','postcondition'],
      'response action');
    if(responseAction.value!=='0' || keccak256(responseAction.data)!==responseAction.dataHash) {
      fail('response action commitment mismatch');
    }
    let adapter;
    if(responseAction.role==='reserveGuardian') {
      if(responseAction.to!==observed.reserve.address
          || responseAction.data.toLowerCase()!==reserveInterface.encodeFunctionData(
            'pauseQueueEpoch',[observed.reserve.queueEpoch,observed.reserve.pilotAuthorizationGeneration]).toLowerCase()) {
        fail('reserve response action mismatch');
      }
      if(await reserve.queueEpoch()!==BigInt(observed.reserve.queueEpoch)
          || await reserve.pilotAuthorizationGeneration()!==BigInt(observed.reserve.pilotAuthorizationGeneration)
          || await reserve.paused()!==observed.reserve.paused
          || await reserve.resumeReadyAt()!==BigInt(observed.reserve.resumeReadyAt)) {
        fail('reserve response precondition changed');
      }
      adapter=reserveGuardian;
      if(getAddress(await reserve.guardian())!==getAddress(await adapter.getAddress())) {
        fail('reserve guardian mismatch');
      }
    } else if(responseAction.role==='checkpointGuardian') {
      if(plan.classification!=='confirmed-upstream-incident'
          || responseAction.to!==observed.checkpointRegistry.address
          || responseAction.data.toLowerCase()!==checkpointInterface.encodeFunctionData(
            'haltPermanently').toLowerCase()) {
        fail('checkpoint response action mismatch');
      }
      if(await checkpointRegistry.halted()) fail('checkpoint response precondition changed');
      adapter=checkpointGuardian;
      if(getAddress(await checkpointRegistry.guardian())!==getAddress(await adapter.getAddress())) {
        fail('checkpoint guardian mismatch');
      }
    } else fail('unknown response role');
    const transaction=await adapter.sendTransaction({to:responseAction.to,value:0n,data:responseAction.data});
    const receipt=await transaction.wait();
    if(receipt?.status!==1) fail(`${responseAction.role} response transaction failed`);
    transactions.push({role:responseAction.role,transactionHash:receipt.hash,
      blockNumber:String(receipt.blockNumber)});
  }
  if(!await reserve.paused()) fail('reserve pause was not confirmed');
  if(await reserve.resumeReadyAt()!==0n) fail('reserve scheduled resume was not cancelled');
  if(plan.classification==='confirmed-upstream-incident' && !await checkpointRegistry.halted()) {
    fail('checkpoint halt was not confirmed');
  }
  return {schema:RISC0_INCIDENT_RESPONSE_REPORT_SCHEMA,planHash:plan.planHash,
    status:plan.classification==='confirmed-upstream-incident'?'contained':'reserve-paused',transactions};
}
