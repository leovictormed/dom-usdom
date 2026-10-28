import {Interface,keccak256,toUtf8Bytes} from 'ethers';
import {isIP} from 'node:net';
import {CHECKPOINT_EVENT_TOPIC0} from './checkpoint-registry.mjs';
import {buildCheckpointFinalizedEventReport,CHECKPOINT_FINALIZED_EVENT_OBSERVATION_SCHEMA}
  from './checkpoint-finalized-event-report.mjs';
import {createBoundedJsonRpcProvider} from './checkpoint-bootstrap-ratification-collector.mjs';
import {validateAuthenticatedCheckpointSubmission} from './checkpoint-submission.mjs';

export const CHECKPOINT_FINALIZED_EVENT_RPC_CATALOG_SCHEMA=
  'usdom-checkpoint-finalized-event-rpc-catalog-v1';
const hash=/^0x[0-9a-fA-F]{64}$/;
const quantity=/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/;
const operator=/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;
const ETHEREUM_MAINNET_GENESIS=
  '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';
const registry=new Interface([
  'event Checkpoint(bytes32 indexed bridgeDomain,uint32 indexed domNetworkMagic,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 checkpointConfigHash)',
  'event CheckpointFinalizedV2(bytes32 indexed statementHash,bytes32 domContextHash,uint256 domTotalDifficulty,uint128 totalIssued,uint128 totalBurned,bool issuanceClosed,uint256 checkpointCount)',
  'function checkpointConfigHash() view returns (bytes32)',
  'function halted() view returns (bool)',
  'function gracefullyShutdown() view returns (bool)',
  'function latestIssuanceClosed() view returns (bool)',
  'function latestHeight() view returns (uint64)',
  'function latestBlock() view returns (bytes32)',
  'function latestStateRoot() view returns (bytes32)',
  'function latestContextHash() view returns (bytes32)',
  'function latestTotalDifficulty() view returns (uint256)',
  'function latestTotalIssued() view returns (uint128)',
  'function latestTotalBurned() view returns (uint128)',
  'function checkpointCount() view returns (uint64)',
  'function candidate() view returns (bytes32 statementHash,uint64 height,uint64 readyAt,bytes32 blockHash,bytes32 stateRoot,bytes32 contextHash,uint256 totalDifficulty,uint128 totalIssued,uint128 totalBurned,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp)',
  'function finalizeCheckpoint()',
]);
const FINALIZE_CHECKPOINT_CALLDATA=registry.encodeFunctionData('finalizeCheckpoint');

function fail(message) { throw new Error(message); }
function exact(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    fail(`${label} schema is invalid`);
  }
}
function endpoint(value,label) {
  let parsed; try { parsed=new URL(value); } catch { fail(`${label} must be an absolute HTTPS URL`); }
  if(parsed.protocol!=='https:'||parsed.username||parsed.password||parsed.hash||parsed.search
      ||parsed.pathname!=='/'||parsed.hostname.endsWith('.')||parsed.hostname==='localhost'
      ||parsed.hostname.endsWith('.localhost')||parsed.hostname.endsWith('.local')
      ||isIP(parsed.hostname)!==0||!parsed.hostname.includes('.')) {
    fail(`${label} must be a canonical public root HTTPS origin`);
  }
  return parsed;
}
function catalogRows(catalog) {
  exact(catalog,['schema','sources'],'finalized-event RPC catalog');
  if(catalog.schema!==CHECKPOINT_FINALIZED_EVENT_RPC_CATALOG_SCHEMA||!Array.isArray(catalog.sources)
      ||catalog.sources.length<2||catalog.sources.length>5) fail('finalized-event catalog requires two to five sources');
  const values=catalog.sources.map((row,index)=>{
    exact(row,['operatorId','originKeccak256'],`finalized-event source ${index+1}`);
    if(!operator.test(row.operatorId??'')||!/^0x[0-9a-f]{64}$/.test(row.originKeccak256??'')
        ||BigInt(row.originKeccak256)===0n) fail(`finalized-event source ${index+1} is invalid`);
    return {...row};
  });
  if(new Set(values.map(v=>v.operatorId)).size!==values.length
      ||new Set(values.map(v=>v.originKeccak256)).size!==values.length) fail('catalog sources must be distinct');
  const sorted=[...values].sort((a,b)=>a.operatorId<b.operatorId?-1:a.operatorId>b.operatorId?1:0);
  if(values.some((v,i)=>v.operatorId!==sorted[i].operatorId)) fail('catalog sources must be sorted');
  return values;
}
export function buildCheckpointFinalizedEventRpcCatalog(sources) {
  if(!Array.isArray(sources)||sources.length<2||sources.length>5) fail('two to five RPC sources are required');
  const hostnames=[];
  const result={schema:CHECKPOINT_FINALIZED_EVENT_RPC_CATALOG_SCHEMA,sources:sources.map((source,index)=>{
    exact(source,['operatorId','url'],`runtime source ${index+1}`);
    if(!operator.test(source.operatorId??'')) fail(`runtime source ${index+1} operator is invalid`);
    const url=endpoint(source.url,`runtime source ${index+1} URL`);
    hostnames.push(url.hostname.toLowerCase());
    return {operatorId:source.operatorId,
      originKeccak256:keccak256(toUtf8Bytes(url.origin.toLowerCase()))};
  }).sort((a,b)=>a.operatorId<b.operatorId?-1:a.operatorId>b.operatorId?1:0)};
  if(new Set(hostnames).size!==hostnames.length) fail('RPC source hostnames must be pairwise distinct');
  catalogRows(result); return result;
}
export function validateCheckpointFinalizedEventRpcCatalog(catalog) { catalogRows(catalog); return true; }
function q(value,label) {
  if(!quantity.test(value??'')) fail(`${label} is not a canonical JSON-RPC quantity`);
  return BigInt(value);
}
function h(value,label) {
  if(!hash.test(value??'')||BigInt(value)===0n) fail(`${label} is not nonzero bytes32`);
  return value.toLowerCase();
}
async function call(provider,to,name,blockTag) {
  const result=await provider.send('eth_call',[{to,data:registry.encodeFunctionData(name)},blockTag]);
  try { return registry.decodeFunctionResult(name,result); }
  catch { fail(`${name} returned malformed ABI data`); }
}
async function observe({row,url,transactionHash,releaseConfig,submission,fetchImpl,timeoutMs,maxBytes}) {
  const provider=createBoundedJsonRpcProvider(url,{fetchImpl,timeoutMs,maxBytes});
  const [chainId,genesis,transaction,receipt,finalized]=await Promise.all([
    provider.send('eth_chainId',[]),provider.send('eth_getBlockByNumber',['0x0',false]),
    provider.send('eth_getTransactionByHash',[transactionHash]),
    provider.send('eth_getTransactionReceipt',[transactionHash]),
    provider.send('eth_getBlockByNumber',['finalized',false]),
  ]);
  if(chainId!=='0x1'||genesis?.number!=='0x0'
      ||String(genesis?.hash??'').toLowerCase()!==ETHEREUM_MAINNET_GENESIS
      ||!transaction||!receipt||!finalized) fail(`${row.operatorId} returned incomplete or non-mainnet chain data`);
  if(String(transaction.hash).toLowerCase()!==transactionHash
      ||String(transaction.to).toLowerCase()!==String(releaseConfig.checkpointRegistry).toLowerCase()
      ||String(transaction.input).toLowerCase()!==FINALIZE_CHECKPOINT_CALLDATA
      ||q(transaction.value,'transaction value')!==0n
      ||q(transaction.blockNumber,'transaction blockNumber')!==q(receipt.blockNumber,'receipt blockNumber')
      ||h(transaction.blockHash,'transaction blockHash')!==h(receipt.blockHash,'receipt blockHash')) {
    fail(`${row.operatorId} transaction differs from the exact zero-value checkpoint finalization call`);
  }
  if(String(receipt.transactionHash).toLowerCase()!==transactionHash||receipt.status!=='0x1') {
    fail(`${row.operatorId} receipt is absent, foreign or failed`);
  }
  const blockNumber=q(receipt.blockNumber,'receipt blockNumber');
  const blockHash=h(receipt.blockHash,'receipt blockHash');
  const finalizedNumber=q(finalized.number,'finalized blockNumber');
  const finalizedHash=h(finalized.hash,'finalized blockHash');
  if(finalizedNumber<blockNumber) fail(`${row.operatorId} receipt is not finalized`);
  const tag=`0x${blockNumber.toString(16)}`;
  const block=await provider.send('eth_getBlockByNumber',[tag,false]);
  if(!block||q(block.number,'receipt block number')!==blockNumber||h(block.hash,'receipt block hash')!==blockHash) {
    fail(`${row.operatorId} receipt block differs`);
  }
  const blockTimestamp=q(block.timestamp,'receipt block timestamp');
  if(!Array.isArray(receipt.logs)) fail(`${row.operatorId} receipt logs are invalid`);
  const matches=receipt.logs.filter(log=>String(log.address).toLowerCase()
    ===String(releaseConfig.checkpointRegistry).toLowerCase()
    &&Array.isArray(log.topics)&&String(log.topics[0]).toLowerCase()===CHECKPOINT_EVENT_TOPIC0.toLowerCase());
  if(matches.length!==1) fail(`${row.operatorId} receipt must contain exactly one Checkpoint event`);
  const finalizedTopic=registry.getEvent('CheckpointFinalizedV2').topicHash.toLowerCase();
  const finalizationMatches=receipt.logs.filter(log=>String(log.address).toLowerCase()
    ===String(releaseConfig.checkpointRegistry).toLowerCase()
    &&Array.isArray(log.topics)&&String(log.topics[0]).toLowerCase()===finalizedTopic);
  if(finalizationMatches.length!==1) fail(`${row.operatorId} receipt must contain exactly one CheckpointFinalizedV2 event`);
  const event=matches[0];
  if(!Array.isArray(event.topics)||event.topics.length!==3||!event.topics.every(topic=>hash.test(topic))
      ||!/^0x(?:[0-9a-fA-F]{2})*$/.test(event.data??'')
      ||h(event.transactionHash,'event transactionHash')!==transactionHash
      ||h(event.blockHash,'event blockHash')!==blockHash
      ||q(event.blockNumber,'event blockNumber')!==blockNumber
      ||event.removed!==false) fail(`${row.operatorId} event framing is invalid`);
  const logIndex=q(event.logIndex,'event logIndex');
  const transactionIndex=q(event.transactionIndex,'event transactionIndex');
  const finalizationEvent=finalizationMatches[0];
  if(!Array.isArray(finalizationEvent.topics)||finalizationEvent.topics.length!==2
      ||!finalizationEvent.topics.every(topic=>hash.test(topic))
      ||!/^0x(?:[0-9a-fA-F]{2})*$/.test(finalizationEvent.data??'')
      ||h(finalizationEvent.transactionHash,'finalization transactionHash')!==transactionHash
      ||h(finalizationEvent.blockHash,'finalization blockHash')!==blockHash
      ||q(finalizationEvent.blockNumber,'finalization blockNumber')!==blockNumber
      ||finalizationEvent.removed!==false
      ||q(finalizationEvent.transactionIndex,'finalization transactionIndex')!==transactionIndex) {
    fail(`${row.operatorId} finalization event framing is invalid`);
  }
  const finalizationLogIndex=q(finalizationEvent.logIndex,'finalization logIndex');
  if(finalizationLogIndex<=logIndex) {
    fail(`${row.operatorId} CheckpointFinalizedV2 must follow the legacy Checkpoint event`);
  }
  const [code,...values]=await Promise.all([
    provider.send('eth_getCode',[releaseConfig.checkpointRegistry,tag]),
    ...['checkpointConfigHash','halted','gracefullyShutdown','latestIssuanceClosed','latestHeight','latestBlock','latestStateRoot',
      'latestContextHash','latestTotalDifficulty','latestTotalIssued','latestTotalBurned','checkpointCount','candidate'].map(name=>
      call(provider,releaseConfig.checkpointRegistry,name,tag)),
  ]);
  if(!/^0x(?:[0-9a-fA-F]{2})+$/.test(code??'')) fail(`${row.operatorId} registry code is invalid`);
  const codeHash=keccak256(code).toLowerCase();
  const [config,halted,gracefullyShutdown,latestIssuanceClosed,height,latestBlock,stateRoot,contextHash,
    totalDifficulty,totalIssued,totalBurned,count,candidate]=values;
  const [transactionAfter,receiptAfter,blockAfter,finalizedAfter,codeAfter,...valuesAfter]=await Promise.all([
    provider.send('eth_getTransactionByHash',[transactionHash]),
    provider.send('eth_getTransactionReceipt',[transactionHash]),provider.send('eth_getBlockByNumber',[tag,false]),
    provider.send('eth_getBlockByNumber',['finalized',false]),
    provider.send('eth_getCode',[releaseConfig.checkpointRegistry,tag]),
    ...['checkpointConfigHash','halted','gracefullyShutdown','latestIssuanceClosed','latestHeight','latestBlock','latestStateRoot',
      'latestContextHash','latestTotalDifficulty','latestTotalIssued','latestTotalBurned','checkpointCount','candidate'].map(name=>
      call(provider,releaseConfig.checkpointRegistry,name,tag)),
  ]);
  const normalized=value=>value.map(item=>typeof item==='bigint'?item.toString():String(item).toLowerCase());
  if(!transactionAfter||String(transactionAfter.hash).toLowerCase()!==transactionHash
      ||String(transactionAfter.to).toLowerCase()!==String(transaction.to).toLowerCase()
      ||String(transactionAfter.input).toLowerCase()!==String(transaction.input).toLowerCase()
      ||transactionAfter.value!==transaction.value||transactionAfter.blockNumber!==transaction.blockNumber
      ||transactionAfter.blockHash!==transaction.blockHash
      ||!receiptAfter||h(receiptAfter.blockHash,'rechecked receipt blockHash')!==blockHash
      ||receiptAfter.status!=='0x1'||String(receiptAfter.transactionHash).toLowerCase()!==transactionHash
      ||JSON.stringify(receiptAfter.logs)!==JSON.stringify(receipt.logs)
      ||!blockAfter||h(blockAfter.hash,'rechecked blockHash')!==blockHash
      ||q(blockAfter.number,'rechecked block number')!==blockNumber
      ||q(blockAfter.timestamp,'rechecked block timestamp')!==blockTimestamp
      ||!finalizedAfter||q(finalizedAfter.number,'rechecked finalized blockNumber')!==finalizedNumber
      ||h(finalizedAfter.hash,'rechecked finalized blockHash')!==finalizedHash
      ||String(codeAfter).toLowerCase()!==String(code).toLowerCase()
      ||valuesAfter.some((value,index)=>JSON.stringify(normalized(value))
        !==JSON.stringify(normalized(values[index])))) {
    fail(`${row.operatorId} receipt snapshot changed during collection`);
  }
  return {operatorId:row.operatorId,originKeccak256:row.originKeccak256,chainId:'1',transactionHash,
    receiptStatus:'1',blockNumber:blockNumber.toString(),blockHash,
    blockTimestamp:blockTimestamp.toString(),finalizedHeadNumber:finalizedNumber.toString(),
    finalizedHeadHash:finalizedHash,snapshotBlockHashAfter:blockHash,registryRuntimeCodeHash:codeHash,
    checkpointEventCount:'1',log:{address:releaseConfig.checkpointRegistry,
      logIndex:logIndex.toString(),transactionIndex:transactionIndex.toString(),
      transactionHash,blockNumber:blockNumber.toString(),blockHash,removed:false,
      topics:event.topics.map(v=>v.toLowerCase()),
      data:event.data.toLowerCase()},
    finalizationLog:{address:releaseConfig.checkpointRegistry,logIndex:finalizationLogIndex.toString(),
      transactionIndex:transactionIndex.toString(),transactionHash,blockNumber:blockNumber.toString(),
      blockHash,removed:false,topics:finalizationEvent.topics.map(v=>v.toLowerCase()),
      data:finalizationEvent.data.toLowerCase()},state:{checkpointConfigHash:String(config[0]).toLowerCase(),
      halted:Boolean(halted[0]),gracefullyShutdown:Boolean(gracefullyShutdown[0]),
      latestIssuanceClosed:Boolean(latestIssuanceClosed[0]),latestHeight:height[0].toString(),
      latestBlock:String(latestBlock[0]).toLowerCase(),
      latestStateRoot:String(stateRoot[0]).toLowerCase(),latestContextHash:String(contextHash[0]).toLowerCase(),
      latestTotalDifficulty:totalDifficulty[0].toString(),latestTotalIssued:totalIssued[0].toString(),
      latestTotalBurned:totalBurned[0].toString(),checkpointCount:count[0].toString(),
      candidateStatementHash:String(candidate[0]).toLowerCase()}};
}

export async function collectCheckpointFinalizedEventObservation({catalog,rpcSources,transactionHash,
  releaseEvidence,releaseConfig,submission,fetchImpl=globalThis.fetch,timeoutMs=10_000,maxBytes=256*1024}={}) {
  const rows=catalogRows(catalog);
  if(!hash.test(transactionHash??'')||BigInt(transactionHash)===0n) fail('transactionHash must be nonzero bytes32');
  transactionHash=transactionHash.toLowerCase();
  // The finalized-event transaction calls finalizeCheckpoint(), while the
  // authenticated package proves the candidate whose statement is emitted.
  // Validating the package here prevents an arbitrary JSON statementHash from
  // being relabelled as the proof-authorized candidate.
  validateAuthenticatedCheckpointSubmission(submission);
  if(submission.ethereumChainId!=='1'||submission.value!=='0'
      ||String(submission.to).toLowerCase()!==String(releaseConfig.checkpointRegistry).toLowerCase()
      ||!hash.test(submission.statementHash??'')||BigInt(submission.statementHash)===0n
      ||!/^0x(?:[0-9a-fA-F]{2})+$/.test(submission.data??'')) {
    fail('authenticated checkpoint submission transaction binding is invalid');
  }
  if(!Array.isArray(rpcSources)||rpcSources.length!==rows.length) fail('runtime sources must match catalog');
  const runtime=new Map();
  const runtimeHostnames=[];
  rpcSources.forEach((source,index)=>{
    exact(source,['operatorId','url'],`runtime source ${index+1}`);
    const url=endpoint(source.url,`runtime source ${index+1} URL`);
    runtimeHostnames.push(url.hostname.toLowerCase());
    if(runtime.has(source.operatorId)) fail('runtime operators must be distinct');
    runtime.set(source.operatorId,{url:url.href,
      originKeccak256:keccak256(toUtf8Bytes(url.origin.toLowerCase()))});
  });
  if(new Set(runtimeHostnames).size!==runtimeHostnames.length) {
    fail('runtime RPC source hostnames must be pairwise distinct');
  }
  const observations=[];
  for(const row of rows) {
    const source=runtime.get(row.operatorId);
    if(!source||source.originKeccak256!==row.originKeccak256) fail('runtime source differs from catalog');
    observations.push(await observe({row,url:source.url,transactionHash,releaseConfig,submission,fetchImpl,
      timeoutMs,maxBytes}));
  }
  const first=observations[0];
  if(observations.some(value=>value.blockNumber!==first.blockNumber||value.blockHash!==first.blockHash
      ||value.blockTimestamp!==first.blockTimestamp)) fail('RPC sources disagree on receipt block');
  const sourceSetCommitment=keccak256(toUtf8Bytes(
    `USDOM_CHECKPOINT_FINALIZED_EVENT_RPC_SOURCES_V2\n${rows.map(row=>
      `${row.operatorId}\u0000${row.originKeccak256}`).join('\n')}`));
  const observation={schema:CHECKPOINT_FINALIZED_EVENT_OBSERVATION_SCHEMA,
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',transactionHash,
    statementHash:submission.statementHash.toLowerCase(),
    blockNumber:first.blockNumber,blockHash:first.blockHash,blockTimestamp:first.blockTimestamp,
    sourceSetCommitment,observations};
  buildCheckpointFinalizedEventReport({releaseEvidence,releaseConfig,observation});
  return observation;
}
