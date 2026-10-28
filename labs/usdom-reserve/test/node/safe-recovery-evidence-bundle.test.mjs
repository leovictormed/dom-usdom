import test from 'node:test';
import assert from 'node:assert/strict';
import {_safeRecoveryEvidenceBundleInternals,validateSafeRecoveryEvidenceBundleShape}
  from '../../sdk/safe-recovery-evidence-bundle.mjs';
import {rpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';

const sha=character=>character.repeat(64);
const hash=character=>`0x${character.repeat(64)}`;
const valid={schema:'usdom-safe-recovery-evidence-bundle/v2',ethereumChainId:'1',
  packageDocumentSha256:sha('1'),packageHash:hash('2'),baselineDocumentSha256:sha('3'),
  planDocumentSha256:sha('4'),replacementProofsDocumentSha256:sha('c'),
  transactionPackageDocumentSha256:sha('5'),rpcCatalogSha256:sha('6'),
  executions:['governance','reserveGuardian','checkpointGuardian'].map((role,index)=>({
    role,documentSha256:sha(String(index+7)),transactionHash:hash(String(index+1)),
  })),reportDocumentSha256:sha('a'),recoveryHash:hash('b')};

test('Safe recovery aggregate evidence has one exact canonical shape',()=>{
  assert.equal(validateSafeRecoveryEvidenceBundleShape(valid),valid);
});

test('Safe recovery aggregate evidence rejects schema and binding mutations',()=>{
  for(const mutate of [
    value=>{value.extra=true;},value=>{delete value.planDocumentSha256;},
    value=>{value.schema='usdom-safe-recovery-evidence-bundle/v1';},
    value=>{delete value.replacementProofsDocumentSha256;},
    value=>{value.replacementProofsDocumentSha256=sha('0');},
    value=>{value.ethereumChainId=1;},value=>{value.rpcCatalogSha256='0x'+sha('6');},
    value=>{value.executions[0].extra=true;},value=>{delete value.executions[0].documentSha256;},
    value=>{value.executions[0].role='reserveGuardian';},
    value=>{value.executions[1].transactionHash=value.executions[1].transactionHash.toUpperCase();},
    value=>{value.executions[1].transactionHash=hash('0');},
    value=>{value.executions[1].documentSha256=sha('0');},
    value=>{value.recoveryHash=hash('0');},
    value=>{value.executions.pop();},
  ]) {
    const changed=structuredClone(valid); mutate(changed);
    assert.throws(()=>validateSafeRecoveryEvidenceBundleShape(changed));
  }
});

test('Safe recovery bundle rejects semantic authority detached from document bytes',()=>{
  const value={role:'governance'};
  assert.doesNotThrow(()=>_safeRecoveryEvidenceBundleInternals.bindJson(value,
    Buffer.from('{"role":"governance"}\n'),'fixture'));
  assert.throws(()=>_safeRecoveryEvidenceBundleInternals.bindJson(value,
    Buffer.from('{"role":"checkpointGuardian"}\n'),'fixture'),/bytes differ/);
});

test('Safe recovery bundle binds the RPC catalog preimage to recovery consensus',()=>{
  const originA=hash('1'),originB=hash('2');
  const row=(operatorId,providerId,infrastructureId,originKeccak256)=>({operatorId,providerId,
    infrastructureId,originKeccak256,tlsPolicy:'node-default-ca-hostname-expiry-origin-pinned-v1',
    clockPolicy:'utc-wall-clock-sane-v1',clientPolicy:'ethereum-execution-client-stable-v1'});
  const catalog={schema:'usdom-mainnet-preflight-rpc-catalog-v2',sources:[
    row('operator-a','provider-a','infrastructure-a',originA),
    row('operator-b','provider-b','infrastructure-b',originB),
  ]};
  const rpcConsensus=rpcConsensusEvidence([
    {sourceId:'operator-a',originKeccak256:originA},
    {sourceId:'operator-b',originKeccak256:originB},
  ]);
  const bytes=Buffer.from(`${JSON.stringify(catalog)}\n`);
  assert.doesNotThrow(()=>_safeRecoveryEvidenceBundleInternals.bindRpcCatalog(bytes,rpcConsensus));
  const substituted=structuredClone(catalog);
  substituted.sources[1].originKeccak256=hash('3');
  assert.throws(()=>_safeRecoveryEvidenceBundleInternals.bindRpcCatalog(
    Buffer.from(JSON.stringify(substituted)),rpcConsensus),/differs from recovery consensus/);
  assert.throws(()=>_safeRecoveryEvidenceBundleInternals.bindRpcCatalog(
    Buffer.from('{"schema":"unrelated","sources":[]}'),rpcConsensus));
});

test('Safe recovery bundle rejects a valid-looking plan detached from package, baseline or report',()=>{
  const addresses=Array.from({length:12},(_,index)=>
    `0x${(index+1).toString(16).padStart(40,'0')}`);
  const roles=['governance','reserveGuardian','checkpointGuardian'];
  const consensus=rpcConsensusEvidence([
    {sourceId:'operator-a',originKeccak256:hash('1')},
    {sourceId:'operator-b',originKeccak256:hash('2')},
  ]);
  const controls=roles.map((role,index)=>({role,safe:addresses[index]}));
  const before=roles.map((role,index)=>({role,address:addresses[index],nonce:'0',
    owners:addresses.slice(3+index*3,6+index*3)}));
  const transitions=Object.fromEntries(roles.map((role,index)=>[role,{
    lostOwner:before[index].owners[0],replacementOwner:addresses[index],
  }]));
  // Use distinct replacement identities outside the fixture's owner sets.
  roles.forEach((role,index)=>{ transitions[role].replacementOwner=
    `0x${(100+index).toString(16).padStart(40,'0')}`; });
  const rolePlans=roles.map((role,index)=>({role,safe:addresses[index],
    oldOwner:before[index].owners[0],newOwner:transitions[role].replacementOwner,
    previousOwner:'0x0000000000000000000000000000000000000001',
    requiredSigners:before[index].owners.slice(1).sort((a,b)=>BigInt(a)<BigInt(b)?-1:1),
    safeTransaction:{nonce:'0'},safeTxHash:hash(String(index+3))}));
  const base={packageDocument:{controls},baseline:{packageHash:hash('a'),snapshotHash:hash('b'),
    finalizedBlockNumber:'10',roles:before,rpcConsensus:structuredClone(consensus)},
  plan:{packageHash:hash('a'),baselineSnapshotHash:hash('b'),planHash:hash('c'),
    finalizedBlockNumber:'11',transitionsByRole:structuredClone(transitions),roles:rolePlans,
    rpcConsensus:structuredClone(consensus)},
  transactionPackage:{planHash:hash('c')},executions:roles.map((role,index)=>({role,
    safeTxHash:rolePlans[index].safeTxHash,transactionHash:hash(String(index+6)),
    blockNumber:String(12+index),transactionIndex:'0',finalizedObservationBlockNumber:String(15+index)})),
  report:{packageHash:hash('a'),baselineSnapshotHash:hash('b'),
    transitionsByRole:structuredClone(transitions),
    afterSnapshot:{finalizedBlockNumber:'20',roles:structuredClone(before)},
    rpcConsensus:structuredClone(consensus),
    recoveries:roles.map((role,index)=>({role,safeTxHash:rolePlans[index].safeTxHash,
      transactionHash:hash(String(index+6)),blockNumber:String(12+index),transactionIndex:'0'}))}};
  assert.doesNotThrow(()=>_safeRecoveryEvidenceBundleInternals.bindRecoverySourceGraph(base));
  for(const mutate of [
    value=>{value.plan.packageHash=hash('d');},
    value=>{value.plan.baselineSnapshotHash=hash('d');},
    value=>{value.transactionPackage.planHash=hash('d');},
    value=>{value.plan.transitionsByRole.governance.replacementOwner=addresses[11];},
    value=>{value.plan.rpcConsensus.sources[0].operatorId='operator-z';},
    value=>{value.plan.roles[0].requiredSigners.reverse();},
    value=>{value.plan.roles[0].safeTransaction.nonce='1';},
    value=>{value.executions[0].transactionHash=hash('e');},
    value=>{value.report.recoveries[0].blockNumber='11';},
    value=>{value.executions[1].blockNumber='12';value.executions[1].transactionIndex='0';},
    value=>{value.executions[1].finalizedObservationBlockNumber='14';},
  ]) {
    const changed=structuredClone(base); mutate(changed);
    assert.throws(()=>_safeRecoveryEvidenceBundleInternals.bindRecoverySourceGraph(changed));
  }
});
