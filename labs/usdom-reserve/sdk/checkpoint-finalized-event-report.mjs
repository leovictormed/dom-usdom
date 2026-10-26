import {Interface,getAddress,keccak256,toUtf8Bytes} from 'ethers';
import {CHECKPOINT_EVENT_TOPIC0} from './checkpoint-registry.mjs';

export const CHECKPOINT_FINALIZED_EVENT_OBSERVATION_SCHEMA=
  'usdom-checkpoint-finalized-event-observation-v2';
export const CHECKPOINT_FINALIZED_EVENT_REPORT_SCHEMA='usdom-checkpoint-finalized-event-report-v2';
const iface=new Interface([
  'event Checkpoint(bytes32 indexed bridgeDomain,uint32 indexed domNetworkMagic,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 checkpointConfigHash)',
]);
const hash=/^0x[0-9a-f]{64}$/;
const data=/^0x(?:[0-9a-f]{2})*$/;
const address=/^0x[0-9a-fA-F]{40}$/;
const commit=/^[0-9a-f]{40}$/;
const identifier=/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const topFields=['schema','releaseId','sourceCommit','sourceTag','ethereumChainId','transactionHash',
  'blockNumber','blockHash','blockTimestamp','sourceSetCommitment','observations'];
const sourceFields=['operatorId','originKeccak256','chainId','transactionHash','receiptStatus',
  'blockNumber','blockHash','blockTimestamp','finalizedHeadNumber','finalizedHeadHash',
  'snapshotBlockHashAfter','registryRuntimeCodeHash','checkpointEventCount','log','state'];
const logFields=['address','logIndex','topics','data'];
const stateFields=['checkpointConfigHash','halted','gracefullyShutdown','latestIssuanceClosed',
  'latestHeight','latestBlock','latestStateRoot','latestContextHash','latestTotalDifficulty',
  'latestTotalIssued','latestTotalBurned','checkpointCount','candidateStatementHash'];
const reportFields=['schema','status','releaseId','sourceCommit','sourceTag','ethereumChainId','registry',
  'registryRuntimeCodeHash','checkpointConfigHash','transactionHash','blockNumber','blockHash',
  'blockTimestamp','sourceSetCommitment','sourceCount','checkpoint','registryState','observations','rule'];

function fail(message) { throw new Error(message); }
function exact(value,fields,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==fields.length
      ||fields.some(field=>!(field in value))) fail(`${label} must use the exact supported schema`);
}
function bytes32(value,label,{zero=false}={}) {
  if(!hash.test(value??'')||(!zero&&BigInt(value)===0n)) fail(`${label} must be lowercase bytes32`);
  return value;
}
function uint(value,bits,label,{nonzero=false}={}) {
  const maxDigits=bits===64?20:bits===128?39:78;
  if(typeof value!=='string'||value.length>maxDigits||!/^(0|[1-9][0-9]*)$/.test(value)) {
    fail(`${label} must be canonical decimal`);
  }
  const parsed=BigInt(value);
  if((nonzero&&parsed===0n)||parsed>=(1n<<BigInt(bits))) fail(`${label} is outside uint${bits}`);
  return parsed;
}
function addr(value,label) {
  if(!address.test(value??'')||BigInt(value)===0n) fail(`${label} must be nonzero address`);
  return getAddress(value);
}
function stable(value) {
  if(Array.isArray(value)) return value.map(stable);
  if(value&&typeof value==='object') return Object.fromEntries(
    Object.keys(value).sort().map(key=>[key,stable(value[key])]),
  );
  return value;
}

export function buildCheckpointFinalizedEventReport({releaseEvidence,releaseConfig,observation}={}) {
  if(!releaseEvidence||releaseEvidence.schema!==1||!identifier.test(releaseEvidence.releaseId??'')
      ||!identifier.test(releaseEvidence.sourceTag??'')||!commit.test(releaseEvidence.sourceCommit??'')) {
    fail('release provenance is invalid');
  }
  if(!releaseConfig||releaseConfig.ethereumChainId!=='1') fail('Ethereum mainnet release is required');
  exact(observation,topFields,'checkpoint finalized event observation');
  if(observation.schema!==CHECKPOINT_FINALIZED_EVENT_OBSERVATION_SCHEMA
      ||observation.releaseId!==releaseEvidence.releaseId
      ||observation.sourceCommit!==releaseEvidence.sourceCommit
      ||observation.sourceTag!==releaseEvidence.sourceTag||observation.ethereumChainId!=='1') {
    fail('finalized event observation release binding differs');
  }
  const block=uint(observation.blockNumber,256,'blockNumber',{nonzero:true});
  const timestamp=uint(observation.blockTimestamp,64,'blockTimestamp',{nonzero:true});
  bytes32(observation.transactionHash,'transactionHash'); bytes32(observation.blockHash,'blockHash');
  bytes32(observation.sourceSetCommitment,'sourceSetCommitment');
  if(!Array.isArray(observation.observations)||observation.observations.length<2
      ||observation.observations.length>5) fail('two to five independent finalized RPC observations are required');
  const ids=new Set(),origins=new Set();
  let decoded,state;
  for(const [index,source] of observation.observations.entries()) {
    exact(source,sourceFields,`RPC observation ${index+1}`);
    if(typeof source.operatorId!=='string'||!identifier.test(source.operatorId)||ids.has(source.operatorId)) {
      fail('RPC operator identities must be canonical and distinct');
    }
    ids.add(source.operatorId);
    const origin=bytes32(source.originKeccak256,'originKeccak256');
    if(origins.has(origin)) fail('RPC origins must be distinct'); origins.add(origin);
    if(source.chainId!=='1'||source.transactionHash!==observation.transactionHash
        ||source.receiptStatus!=='1'||uint(source.blockNumber,256,'source blockNumber')!==block
        ||source.blockHash!==observation.blockHash
        ||uint(source.blockTimestamp,64,'source blockTimestamp')!==timestamp
        ||source.registryRuntimeCodeHash!==releaseConfig.checkpointRegistryRuntimeCodeHash
        ||source.checkpointEventCount!=='1') fail('independent finalized receipt observations disagree');
    if(uint(source.finalizedHeadNumber,256,'finalizedHeadNumber')<block
        ||bytes32(source.finalizedHeadHash,'finalizedHeadHash')===source.blockHash
          && source.finalizedHeadNumber!==source.blockNumber
        ||bytes32(source.snapshotBlockHashAfter,'snapshotBlockHashAfter')!==source.blockHash) {
      fail('receipt block was not stable below the finalized head');
    }
    exact(source.log,logFields,'checkpoint event log');
    if(addr(source.log.address,'event address')!==addr(releaseConfig.checkpointRegistry,'registry')
        ||uint(source.log.logIndex,64,'logIndex')<0n||!Array.isArray(source.log.topics)
        ||source.log.topics.length!==3||source.log.topics[0]!==CHECKPOINT_EVENT_TOPIC0
        ||!source.log.topics.every(topic=>hash.test(topic))||!data.test(source.log.data)) {
      fail('checkpoint event log framing is invalid');
    }
    let current;
    try { current=iface.decodeEventLog('Checkpoint',source.log.data,source.log.topics); }
    catch { fail('checkpoint event ABI decoding failed'); }
    const decodedCurrent={bridgeDomain:current.bridgeDomain.toLowerCase(),
      domNetworkMagic:current.domNetworkMagic.toString(),domHeight:current.domHeight.toString(),
      domBlock:current.domBlock.toLowerCase(),domStateRoot:current.domStateRoot.toLowerCase(),
      checkpointConfigHash:current.checkpointConfigHash.toLowerCase()};
    if(decoded&&JSON.stringify(decoded)!==JSON.stringify(decodedCurrent)) {
      fail('independent RPCs returned different checkpoint events');
    }
    decoded=decodedCurrent;
    exact(source.state,stateFields,'checkpoint registry finalized state');
    for(const field of ['checkpointConfigHash','latestBlock','latestStateRoot','latestContextHash',
      'candidateStatementHash']) bytes32(source.state[field],`state ${field}`,{zero:field==='candidateStatementHash'});
    uint(source.state.latestHeight,64,'state latestHeight');
    uint(source.state.latestTotalDifficulty,256,'state latestTotalDifficulty',{nonzero:true});
    const totalIssued=uint(source.state.latestTotalIssued,128,'state latestTotalIssued');
    const totalBurned=uint(source.state.latestTotalBurned,128,'state latestTotalBurned');
    uint(source.state.checkpointCount,64,'state checkpointCount',{nonzero:true});
    if(typeof source.state.halted!=='boolean'||typeof source.state.gracefullyShutdown!=='boolean'
        ||typeof source.state.latestIssuanceClosed!=='boolean'||totalBurned>totalIssued
        ||source.state.halted!==false||source.state.halted&&source.state.gracefullyShutdown
        ||source.state.gracefullyShutdown&&(!source.state.latestIssuanceClosed||totalBurned!==totalIssued)
        ||source.state.candidateStatementHash!=='0x'+'00'.repeat(32)) {
      fail('registry did not finish in a canonical finalized lifecycle state');
    }
    if(state&&JSON.stringify(stable(state))!==JSON.stringify(stable(source.state))) {
      fail('independent RPCs returned different finalized registry state');
    }
    state=source.state;
  }
  const canonical=[...observation.observations].sort((left,right)=>left.operatorId.localeCompare(right.operatorId));
  if(observation.observations.some((source,index)=>source.operatorId!==canonical[index].operatorId)) {
    fail('RPC observations must use canonical operator order');
  }
  const expectedSources=keccak256(toUtf8Bytes(
    `USDOM_CHECKPOINT_FINALIZED_EVENT_RPC_SOURCES_V2\n${canonical.map(source=>
      `${source.operatorId}\u0000${source.originKeccak256}`).join('\n')}`));
  if(expectedSources!==observation.sourceSetCommitment) fail('RPC source set commitment differs');
  if(decoded.bridgeDomain!==releaseConfig.domDomain
      ||decoded.domNetworkMagic!==releaseConfig.checkpointDomNetworkMagic
      ||decoded.checkpointConfigHash!==releaseConfig.checkpointRegistryConfigHash
      ||state.checkpointConfigHash!==releaseConfig.checkpointRegistryConfigHash
      ||state.latestHeight!==decoded.domHeight||state.latestBlock!==decoded.domBlock
      ||state.latestStateRoot!==decoded.domStateRoot) fail('finalized checkpoint differs from release or registry state');
  return Object.freeze({schema:CHECKPOINT_FINALIZED_EVENT_REPORT_SCHEMA,status:'finalized',
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',registry:getAddress(releaseConfig.checkpointRegistry),
    registryRuntimeCodeHash:releaseConfig.checkpointRegistryRuntimeCodeHash,
    checkpointConfigHash:releaseConfig.checkpointRegistryConfigHash,
    transactionHash:observation.transactionHash,blockNumber:observation.blockNumber,
    blockHash:observation.blockHash,blockTimestamp:observation.blockTimestamp,
    sourceSetCommitment:observation.sourceSetCommitment,sourceCount:canonical.length.toString(),
    checkpoint:decoded,registryState:structuredClone(state),observations:structuredClone(canonical),
    rule:'A checkpoint is finalized only when independent finalized RPC snapshots agree on one successful receipt, one ABI-valid Checkpoint event, exact registry runtime/config and matching post-state.',
  });
}

export function serializeCheckpointFinalizedEventReport(report) {
  return Buffer.from(`${JSON.stringify(stable(report),null,2)}\n`);
}

export function validateCheckpointFinalizedEventReport({report,releaseEvidence,releaseConfig}={}) {
  exact(report,reportFields,'checkpoint finalized event report');
  if(report.schema!==CHECKPOINT_FINALIZED_EVENT_REPORT_SCHEMA||report.status!=='finalized') {
    fail('checkpoint finalized event report status or schema is invalid');
  }
  const observation={schema:CHECKPOINT_FINALIZED_EVENT_OBSERVATION_SCHEMA,
    releaseId:report.releaseId,sourceCommit:report.sourceCommit,sourceTag:report.sourceTag,
    ethereumChainId:report.ethereumChainId,transactionHash:report.transactionHash,
    blockNumber:report.blockNumber,blockHash:report.blockHash,blockTimestamp:report.blockTimestamp,
    sourceSetCommitment:report.sourceSetCommitment,observations:structuredClone(report.observations)};
  const expected=buildCheckpointFinalizedEventReport({releaseEvidence,releaseConfig,observation});
  if(JSON.stringify(stable(report))!==JSON.stringify(stable(expected))) {
    fail('checkpoint finalized event report is not canonical and release-bound');
  }
  return true;
}
