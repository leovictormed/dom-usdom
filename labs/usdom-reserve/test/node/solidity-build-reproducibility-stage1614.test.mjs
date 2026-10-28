import assert from 'node:assert/strict';
import test from 'node:test';
import {assertSolidityBuildsEqual,PRODUCTION_SOLIDITY_CONTRACTS,
  solidityArtifactFingerprint} from '../../sdk/solidity-build-reproducibility.mjs';
import {requireReleaseArtifact} from '../../sdk/deployment-artifact-evidence.mjs';

const hash='0x'+'11'.repeat(32);
function artifact() { return {abi:[{type:'function',name:'f',inputs:[]}],storageLayout:{storage:[],types:{}},
 bytecode:{object:'0x6000'},deployedBytecode:{object:'0x6001'},metadata:{sources:{'contracts/A.sol':{keccak256:hash}}}}; }

test('fingerprint commits initcode, runtime, ABI, storage layout and every source hash',()=>{
 const base=solidityArtifactFingerprint(artifact());
 for(const mutate of [
  x=>{x.bytecode.object='0x6002';},x=>{x.deployedBytecode.object='0x6002';},
  x=>{x.abi[0].name='g';},x=>{x.storageLayout.storage.push({slot:'0'});},
  x=>{x.metadata.sources['contracts/A.sol'].keccak256='0x'+'22'.repeat(32);},
 ]) { const changed=artifact(); mutate(changed); assert.notDeepEqual(solidityArtifactFingerprint(changed),base); }
});

test('comparison rejects any semantic drift in any production contract',()=>{
 const first=Object.fromEntries(PRODUCTION_SOLIDITY_CONTRACTS.map(name=>[name,solidityArtifactFingerprint(artifact())]));
 assert.equal(assertSolidityBuildsEqual(first,structuredClone(first)),true);
 for(const name of PRODUCTION_SOLIDITY_CONTRACTS) {
  const changed=structuredClone(first); changed[name].abiSha256='0'.repeat(64);
  assert.throws(()=>assertSolidityBuildsEqual(first,changed),new RegExp(name));
 }
});

test('artifacts without storage layout or canonical source hashes fail closed',()=>{
 const missing=artifact(); delete missing.storageLayout;
 assert.throws(()=>solidityArtifactFingerprint(missing),/storage layout/);
 const bad=artifact(); bad.metadata.sources['contracts/A.sol'].keccak256='0x01';
 assert.throws(()=>solidityArtifactFingerprint(bad),/source hash/);
});

test('deployment rejects stale, substituted and ambiguous canonical artifact evidence',()=>{
 const sha='a'.repeat(64),path='out/USDOMProofReserve.sol/USDOMProofReserve.json';
 const evidence={reserveArtifact:{path,sha256:sha}};
 assert.equal(requireReleaseArtifact(evidence,'reserveArtifact',path,sha),true);
 for(const changed of [
  {},{reserveArtifact:{path,sha256:'b'.repeat(64)}},
  {reserveArtifact:{path:'out/old.json',sha256:sha}},
  {reserveArtifact:{path,sha256:sha,legacy:true}},
 ]) assert.throws(()=>requireReleaseArtifact(changed,'reserveArtifact',path,sha),/hash-address/);
});
