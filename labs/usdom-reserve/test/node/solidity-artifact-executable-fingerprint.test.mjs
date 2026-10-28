import test from 'node:test';
import assert from 'node:assert/strict';
import {solidityArtifactExecutableFingerprint} from '../../sdk/solidity-artifact-executable-fingerprint.mjs';

const artifact=()=>({abi:[{type:'constructor',inputs:[]}],bytecode:{object:'0x6000'},
 deployedBytecode:{object:'0x6001'},metadata:{compiler:{version:'one'}},buildInfo:'volatile'});

test('executable artifact fingerprint ignores irrelevant build metadata',()=>{
 const first=artifact(),second=structuredClone(first);
 second.metadata.compiler.version='two';second.buildInfo='rewritten concurrently';second.extra={x:1};
 assert.equal(solidityArtifactExecutableFingerprint(first),
  solidityArtifactExecutableFingerprint(second));
});

test('executable artifact fingerprint detects ABI, creation and runtime mutations',()=>{
 const baseline=solidityArtifactExecutableFingerprint(artifact());
 for(const mutate of [v=>v.abi[0].inputs.push({name:'x',type:'uint256'}),
  v=>v.bytecode.object='0x6002',v=>v.deployedBytecode.object='0x6003']) {
  const changed=artifact();mutate(changed);
  assert.notEqual(solidityArtifactExecutableFingerprint(changed),baseline);
 }
});
