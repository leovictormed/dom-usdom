import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {Interface,keccak256,toUtf8Bytes} from 'ethers';
import {buildCheckpointFinalizedEventReport,serializeCheckpointFinalizedEventReport,
  validateCheckpointFinalizedEventReport} from '../../sdk/checkpoint-finalized-event-report.mjs';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';

const h=byte=>'0x'+byte.repeat(64);
const registry='0x1000000000000000000000000000000000000001';
const releaseEvidence={schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1'};
const releaseConfig={ethereumChainId:'1',checkpointRegistry:registry,
  checkpointRegistryRuntimeCodeHash:h('1'),checkpointRegistryConfigHash:h('2'),domDomain:h('3'),
  checkpointDomNetworkMagic:'1146047821'};
const iface=new Interface([
  'event Checkpoint(bytes32 indexed bridgeDomain,uint32 indexed domNetworkMagic,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 checkpointConfigHash)',
  'event CheckpointFinalizedV2(bytes32 indexed statementHash,bytes32 domContextHash,uint256 domTotalDifficulty,uint128 totalIssued,uint128 totalBurned,bool issuanceClosed,uint256 checkpointCount)',
]);

function fixture() {
  const encoded=iface.encodeEventLog(iface.getEvent('Checkpoint'),
    [releaseConfig.domDomain,releaseConfig.checkpointDomNetworkMagic,'1001',h('4'),h('5'),
      releaseConfig.checkpointRegistryConfigHash]);
  const state={checkpointConfigHash:h('2'),halted:false,gracefullyShutdown:false,latestIssuanceClosed:false,latestHeight:'1001',latestBlock:h('4'),
    latestStateRoot:h('5'),latestContextHash:h('6'),latestTotalDifficulty:'1000000',latestTotalIssued:'100',latestTotalBurned:'20',
    checkpointCount:'1',candidateStatementHash:'0x'+'00'.repeat(32)};
  const finalized=iface.encodeEventLog(iface.getEvent('CheckpointFinalizedV2'),
    [h('a'),h('6'),'1000000','100','20',false,'1']);
  const observations=[1,2].map(index=>({operatorId:`operator-${index}`,
    originKeccak256:keccak256(toUtf8Bytes(`https://rpc${index}.example`)),chainId:'1',
    transactionHash:h('7'),receiptStatus:'1',blockNumber:'20000000',blockHash:h('8'),
    blockTimestamp:'1800000000',finalizedHeadNumber:'20000010',finalizedHeadHash:h('9'),
    snapshotBlockHashAfter:h('8'),registryRuntimeCodeHash:h('1'),checkpointEventCount:'1',
    log:{address:registry,logIndex:'2',transactionIndex:'1',transactionHash:h('7'),
      blockNumber:'20000000',blockHash:h('8'),removed:false,
      topics:encoded.topics.map(value=>value.toLowerCase()),
      data:encoded.data.toLowerCase()},finalizationLog:{address:registry,logIndex:'3',
      transactionIndex:'1',transactionHash:h('7'),blockNumber:'20000000',blockHash:h('8'),
      removed:false,topics:finalized.topics.map(value=>value.toLowerCase()),
      data:finalized.data.toLowerCase()},state:{...state}}));
  const sourceSetCommitment=keccak256(toUtf8Bytes(
    `USDOM_CHECKPOINT_FINALIZED_EVENT_RPC_SOURCES_V2\n${observations.map(value=>
      `${value.operatorId}\u0000${value.originKeccak256}`).join('\n')}`));
  return {releaseEvidence:{...releaseEvidence},releaseConfig:{...releaseConfig},observation:{
    schema:'usdom-checkpoint-finalized-event-observation-v3',releaseId:'release-1',
    sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1',ethereumChainId:'1',transactionHash:h('7'),
    statementHash:h('a'),
    blockNumber:'20000000',blockHash:h('8'),blockTimestamp:'1800000000',sourceSetCommitment,
    observations}};
}

function syncFinalizationLog(source) {
  const finalized=iface.encodeEventLog(iface.getEvent('CheckpointFinalizedV2'),[
    h('a'),source.state.latestContextHash,source.state.latestTotalDifficulty,
    source.state.latestTotalIssued,source.state.latestTotalBurned,
    source.state.latestIssuanceClosed,source.state.checkpointCount]);
  source.finalizationLog.topics=finalized.topics.map(value=>value.toLowerCase());
  source.finalizationLog.data=finalized.data.toLowerCase();
}

test('builds and validates one exact finalized checkpoint event report',()=>{
  const input=fixture(); const report=buildCheckpointFinalizedEventReport(input);
  assert.equal(report.status,'finalized'); assert.equal(report.sourceCount,'2');
  assert.equal(report.checkpoint.domHeight,'1001'); assert.equal(report.checkpoint.domBlock,h('4'));
  assert.equal(report.finalization.statementHash,h('a'));
  assert.equal(report.finalization.domContextHash,h('6'));
  assert.equal(validateCheckpointFinalizedEventReport({...input,report}),true);
  assert.deepEqual(JSON.parse(serializeCheckpointFinalizedEventReport(report)),report);
});

test('distinguishes authenticated graceful closure from emergency halt',()=>{
  const closed=fixture();
  for(const source of closed.observation.observations) Object.assign(source.state,{
    gracefullyShutdown:true,latestIssuanceClosed:true,latestTotalIssued:'100',latestTotalBurned:'100',
  });
  for(const source of closed.observation.observations) syncFinalizationLog(source);
  const report=buildCheckpointFinalizedEventReport(closed);
  assert.equal(report.registryState.gracefullyShutdown,true);
  assert.equal(report.registryState.halted,false);
  for(const mutate of [
    state=>{state.latestIssuanceClosed=false;},
    state=>{state.latestTotalBurned='99';},
    state=>{state.halted=true;},
  ]) {
    const invalid=fixture();
    for(const source of invalid.observation.observations) {
      Object.assign(source.state,{gracefullyShutdown:true,latestIssuanceClosed:true,
        latestTotalIssued:'100',latestTotalBurned:'100'});
      mutate(source.state);
      syncFinalizationLog(source);
    }
    assert.throws(()=>buildCheckpointFinalizedEventReport(invalid),/canonical finalized lifecycle state/);
  }
});

test('rejects receipt, block, runtime and post-state disagreement',()=>{
  for(const mutate of [
    value=>{value.observation.observations[1].receiptStatus='0';},
    value=>{value.observation.observations[1].blockHash=h('9');},
    value=>{value.observation.observations[1].registryRuntimeCodeHash=h('9');},
    value=>{value.observation.observations[1].finalizedHeadNumber='19999999';},
    value=>{value.observation.observations[1].finalizedHeadNumber='20000000';},
    value=>{value.observation.observations[1].finalizedHeadHash=h('8');},
    value=>{value.observation.observations[1].snapshotBlockHashAfter=h('9');},
    value=>{value.observation.observations[1].state.latestContextHash=h('9');},
    value=>{value.observation.observations[1].state.candidateStatementHash=h('9');},
  ]) {
    const input=fixture(); mutate(input);
    assert.throws(()=>buildCheckpointFinalizedEventReport(input),
      /(disagree|different|canonical finalized lifecycle state|stable below the finalized head)/);
  }
});

test('rejects oversized decimal evidence before numeric conversion',()=>{
  for(const mutate of [
    value=>{value.observation.blockNumber='9'.repeat(100000);},
    value=>{value.observation.blockTimestamp='9'.repeat(100000);},
    value=>{value.observation.observations[0].state.latestTotalIssued='9'.repeat(100000);},
  ]) {
    const input=fixture(); mutate(input);
    assert.throws(()=>buildCheckpointFinalizedEventReport(input),/canonical decimal/);
  }
});

test('rejects receipt and finalized-head block positions outside uint64',()=>{
  const outside=(1n<<64n).toString();
  for(const mutate of [
    value=>{value.observation.blockNumber=outside;},
    value=>{value.observation.observations[0].blockNumber=outside;},
    value=>{value.observation.observations[0].finalizedHeadNumber=outside;},
  ]) {
    const input=fixture(); mutate(input);
    assert.throws(()=>buildCheckpointFinalizedEventReport(input),/outside uint64/);
  }
});

test('rejects malformed, foreign or duplicate Checkpoint logs',()=>{
  for(const mutate of [
    value=>{value.observation.observations[0].checkpointEventCount='2';},
    value=>{value.observation.observations[0].log.address='0x2000000000000000000000000000000000000002';},
    value=>{value.observation.observations[0].log.topics[0]=h('9');},
    value=>{value.observation.observations[0].log.data='0x01';},
  ]) {
    const input=fixture(); mutate(input);
    assert.throws(()=>buildCheckpointFinalizedEventReport(input),/(disagree|framing|decoding)/);
  }
});

test('rejects missing, foreign, reordered or state-divergent finalization events',()=>{
  for(const mutate of [
    value=>{delete value.observation.observations[0].finalizationLog;},
    value=>{value.observation.observations[0].finalizationLog.address=
      '0x2000000000000000000000000000000000000002';},
    value=>{value.observation.observations[0].finalizationLog.logIndex='1';},
    value=>{value.observation.observations[0].finalizationLog.removed=true;},
    value=>{value.observation.observations[0].finalizationLog.transactionHash=h('9');},
    value=>{value.observation.observations[0].finalizationLog.data='0x01';},
    value=>{
      const divergent=iface.encodeEventLog(iface.getEvent('CheckpointFinalizedV2'),
        [h('a'),h('6'),'1000001','100','20',false,'1']);
      value.observation.observations[0].finalizationLog.data=divergent.data.toLowerCase();
    },
  ]) {
    const input=fixture(); mutate(input);
    assert.throws(()=>buildCheckpointFinalizedEventReport(input),
      /(exact supported schema|framing|decoding|different|differs from release)/);
  }
});

test('binds the finalized statement to the authenticated submission',()=>{
  const input=fixture(); input.observation.statementHash=h('9');
  assert.throws(()=>buildCheckpointFinalizedEventReport(input),
    /statement differs from the authenticated submission/);
});

test('rejects event/release mismatch, untrusted sources and forged reports',()=>{
  const mismatch=fixture(); mismatch.releaseConfig.domDomain=h('9');
  assert.throws(()=>buildCheckpointFinalizedEventReport(mismatch),/differs from release/);
  const duplicate=fixture(); duplicate.observation.observations[1].originKeccak256=
    duplicate.observation.observations[0].originKeccak256;
  assert.throws(()=>buildCheckpointFinalizedEventReport(duplicate),/origins must be distinct/);
  const sourceSet=fixture(); sourceSet.observation.sourceSetCommitment=h('9');
  assert.throws(()=>buildCheckpointFinalizedEventReport(sourceSet),/source set commitment differs/);
  const input=fixture(); const report=structuredClone(buildCheckpointFinalizedEventReport(input));
  report.registryState.checkpointCount='999';
  assert.throws(()=>validateCheckpointFinalizedEventReport({...input,report}),/not canonical/);
  const forged=structuredClone(buildCheckpointFinalizedEventReport(input));
  forged.finalization.statementHash=h('9');
  assert.throws(()=>validateCheckpointFinalizedEventReport({...input,report:forged}),
    /statement differs from the authenticated submission/);
});

test('preparer rechecks release and finalized observation before output',async()=>{
  const source=await readFile(new URL(
    '../../scripts/prepare-checkpoint-finalized-event-report.mjs',import.meta.url),'utf8');
  assert.match(source,/const before=await Promise\.all\(paths\.map\(read\)\)/);
  assert.match(source,/const after=await Promise\.all\(paths\.map\(read\)\)/);
  assert.match(source,/after\.some\(\(bytes,index\)=>!bytes\.equals\(before\[index\]\)\)/);
  assert.match(source,/parseStrictJsonBytes\(bytes/);
  assert.doesNotMatch(source,/bytes\.toString\(['"]utf8['"]\)/);
  assert.match(source,/before\.map\(\(bytes,index\)=>\s*parse\(paths\[index\],bytes\)\)/);
  for(const name of ['mainnet-release-evidence','proof-reserve','finalized-event-observation']) {
    assert.match(source,new RegExp(name));
  }
});

test('finalized-event JSON authority rejects duplicate escaped keys and invalid UTF-8',()=>{
  for(const bytes of [
    Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) assert.throws(()=>parseStrictJsonBytes(bytes,{label:'checkpoint finalized event',
    maxBytes:2*1024*1024,maxDepth:24}),/duplicate (?:object )?key|invalid UTF-8/);
});
