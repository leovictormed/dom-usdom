import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {keccak256,toUtf8Bytes} from 'ethers';
import {buildCheckpointBootstrapRatificationReport,checkpointBootstrapRatificationDigest,
  serializeCheckpointBootstrapRatificationReport,validateCheckpointBootstrapRatificationReport}
  from '../../sdk/checkpoint-bootstrap-ratification-report.mjs';

const h=byte=>'0x'+byte.repeat(64);
const releaseEvidence={schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1'};
const releaseConfig={ethereumChainId:'1',governance:'0x1000000000000000000000000000000000000001',
  governanceCodeHash:h('1'),reserveConfigHash:h('2'),checkpointRegistryConfigHash:h('3'),
  activationScheduleCommitment:h('4'),nativeEthereumTrustedCheckpoint:h('5'),domDomain:h('6'),
  checkpointDomNetworkMagic:'1146047821',checkpointDomChainId:h('7'),checkpointFirstV4Height:'1001',
  checkpointIntervalBlocks:'360',checkpointConfirmationDepthBlocks:'30',
  checkpointChallengePeriodSeconds:'172800',checkpointInitialHeight:'1000',
  checkpointInitialBlock:h('8'),checkpointInitialContextHash:h('9'),
  checkpointInitialTotalDifficulty:'100000'};
const checkpointConsensus={schema:'usdom-ethereum-checkpoint-consensus-v1',network:'ethereum-mainnet',
  checkpointEpoch:'500000',checkpointSlot:'16000000',checkpointRoot:h('5'),sourceCount:'3',
  sourceSetCommitment:h('a'),observedAtUnix:'1000'};
const nativeFacts={schema:'usdom-native-preactivation-facts-v1',
  nativeEthereumTrustedCheckpoint:h('5'),domDomain:h('6'),checkpointDomNetworkMagic:'1146047821',
  checkpointDomChainId:h('7'),checkpointFirstV4Height:'1001',checkpointIntervalBlocks:'360',
  checkpointConfirmationDepthBlocks:'30',checkpointChallengePeriodSeconds:'172800',
  checkpointInitialHeight:'1000',checkpointInitialBlock:h('8'),checkpointInitialContextHash:h('9'),
  checkpointInitialTotalDifficulty:'100000'};

function fixture() {
  const approvals=[1,2].map(index=>({operatorId:`operator-${index}`,
    originKeccak256:keccak256(toUtf8Bytes(`https://rpc${index}.example`)),snapshotBlockNumber:'20000000',
    snapshotBlockHash:h('b'),snapshotBlockTimestamp:'1100',governanceCodeHash:h('1'),
    eip1271MagicValue:'0x1626ba7e',observedAtUnix:String(1100+index)}));
  const sourceSetCommitment=keccak256(toUtf8Bytes(
    `USDOM_CHECKPOINT_RATIFICATION_RPC_SOURCES_V1\n${approvals.map(value=>
      `${value.operatorId}\u0000${value.originKeccak256}`).join('\n')}`));
  const ratificationDigest=checkpointBootstrapRatificationDigest({releaseEvidence,releaseConfig,
    checkpointConsensus,nativeFacts});
  return {releaseEvidence:{...releaseEvidence},releaseConfig:{...releaseConfig},
    checkpointConsensus:{...checkpointConsensus},nativeFacts:{...nativeFacts},observation:{
      schema:'usdom-checkpoint-bootstrap-ratification-observation-v1',releaseId:'release-1',
      sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1',ethereumChainId:'1',
      governance:releaseConfig.governance,ratificationDigest,snapshotBlockNumber:'20000000',
      snapshotBlockHash:h('b'),snapshotBlockTimestamp:'1100',sourceSetCommitment,approvals}};
}

test('builds and validates an exact finalized EIP-1271 bootstrap ratification',()=>{
  const input=fixture();
  const report=buildCheckpointBootstrapRatificationReport(input);
  assert.equal(report.status,'ratified');
  assert.equal(report.approvalCount,'2');
  assert.equal(report.ethereumCheckpointRoot,h('5'));
  assert.equal(validateCheckpointBootstrapRatificationReport({...input,report}),true);
  assert.deepEqual(JSON.parse(serializeCheckpointBootstrapRatificationReport(report)),report);
});

test('rejects release, checkpoint and DOM identity drift',()=>{
  for(const mutate of [
    value=>{value.observation.sourceCommit='b'.repeat(40);},
    value=>{value.releaseConfig.nativeEthereumTrustedCheckpoint=h('f');},
    value=>{value.nativeFacts.domDomain=h('f');},
    value=>{value.nativeFacts.checkpointInitialHeight='999';},
    value=>{value.checkpointConsensus.checkpointSlot='16000001';},
  ]) {
    const input=fixture(); mutate(input);
    assert.throws(()=>buildCheckpointBootstrapRatificationReport(input),
      /(binding differs|trusted checkpoint differs|identity differs|differs from release|insufficient)/);
  }
});

test('rejects RPC disagreement, EIP-1271 failure, duplicate origin and forged source commitment',()=>{
  const cases=[
    value=>{value.observation.approvals[1].snapshotBlockHash=h('c');},
    value=>{value.observation.approvals[1].governanceCodeHash=h('c');},
    value=>{value.observation.approvals[1].eip1271MagicValue='0xffffffff';},
    value=>{value.observation.approvals[1].originKeccak256=
      value.observation.approvals[0].originKeccak256;},
    value=>{value.observation.sourceSetCommitment=h('d');},
  ];
  for(const mutate of cases) {
    const input=fixture(); mutate(input);
    assert.throws(()=>buildCheckpointBootstrapRatificationReport(input),
      /(disagree|origins must be distinct|source set commitment differs)/);
  }
});

test('rejects stale observation and noncanonical or forged reports',()=>{
  const stale=fixture(); stale.observation.approvals[0].observedAtUnix='87501';
  assert.throws(()=>buildCheckpointBootstrapRatificationReport(stale),/stale/);
  const input=fixture(); const report=structuredClone(buildCheckpointBootstrapRatificationReport(input));
  report.approvals[0].eip1271MagicValue='0xffffffff';
  assert.throws(()=>validateCheckpointBootstrapRatificationReport({...input,report}),/disagree/);
  const extra=structuredClone(buildCheckpointBootstrapRatificationReport(input)); extra.reviewed=true;
  assert.throws(()=>validateCheckpointBootstrapRatificationReport({...input,report:extra}),/exact supported schema/);
});

test('rejects oversized decimal evidence before numeric conversion',()=>{
  for(const mutate of [
    value=>{value.checkpointConsensus.checkpointEpoch='9'.repeat(100000);},
    value=>{value.checkpointConsensus.sourceCount='9'.repeat(100000);},
    value=>{value.observation.snapshotBlockTimestamp='9'.repeat(100000);},
  ]) {
    const input=fixture(); mutate(input);
    assert.throws(()=>buildCheckpointBootstrapRatificationReport(input),/canonical decimal/);
  }
});

test('fixed preparer rechecks every ratification input before output',async()=>{
  const source=await readFile(new URL(
    '../../scripts/prepare-checkpoint-bootstrap-ratification-report.mjs',import.meta.url),'utf8');
  assert.match(source,/const before=await Promise\.all\(paths\.map\(read\)\)/);
  assert.match(source,/const after=await Promise\.all\(paths\.map\(read\)\)/);
  assert.match(source,/after\.some\(\(bytes,index\)=>!bytes\.equals\(before\[index\]\)\)/);
  for(const name of ['mainnet-release-evidence','proof-reserve','ethereum-checkpoint-consensus',
    'native-preactivation-facts','ratification-observation']) assert.match(source,new RegExp(name));
});
