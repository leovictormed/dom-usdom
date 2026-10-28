import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {auditReserveArtifact} from '../../sdk/reserve-artifact-safety.mjs';

const artifactUrl=new URL('../../out/USDOMProofReserve.sol/USDOMProofReserve.json',import.meta.url);
const root=new URL('../../',import.meta.url).pathname;
const artifact=JSON.parse(await readFile(artifactUrl));
const checkerSource=readFileSync(new URL('../../scripts/check-reserve-artifact-safety.mjs',import.meta.url),'utf8');

test('canonical reserve artifact has a closed ABI and safe executable opcode surface',()=>{
  const result=auditReserveArtifact(artifact,{root});
  assert.deepEqual([result.runtimeBytes,result.creationBytes,result.functionCount,result.eventCount,result.errorCount],
    [20_339,26_553,91,20,34]);
  assert.ok(result.executableBytes>19_000);
  assert.ok(result.immutableReferenceCount>0);
});

test('artifact audit rejects selector, ABI, metadata, immutable, link and opcode substitution',()=>{
  const mutations=[
    value=>{value.methodIdentifiers['pause()']=value.methodIdentifiers['closeDeposits()'];},
    value=>{value.abi=value.abi.filter(item=>!(item.type==='event'&&item.name==='Released'));},
    value=>{value.metadata.settings.viaIR=false; value.rawMetadata=JSON.stringify(value.metadata);},
    value=>{value.deployedBytecode.immutableReferences[Object.keys(value.deployedBytecode.immutableReferences)[0]][0].length=31;},
    value=>{value.bytecode.linkReferences={x:{L:[{start:0,length:20}]}};},
    value=>{const bytes=Buffer.from(value.deployedBytecode.object.slice(2),'hex'); bytes[100]=0xf4;
      value.deployedBytecode.object=`0x${bytes.toString('hex')}`;},
  ];
  for(const mutate of mutations) {
    const changed=structuredClone(artifact); mutate(changed);
    assert.throws(()=>auditReserveArtifact(changed,{root}));
  }
});

test('forbidden runtime opcode is diagnosed before the bytecode identity mismatch',()=>{
  const changed=structuredClone(artifact);
  const bytes=Buffer.from(changed.deployedBytecode.object.slice(2),'hex');
  bytes[100]=0xf4;
  changed.deployedBytecode.object=`0x${bytes.toString('hex')}`;
  assert.throws(()=>auditReserveArtifact(changed,{root}),/unexpected DELEGATECALL opcode at 100/);
});

test('artifact ingress and embedded metadata reject ambiguous or linked authorities',()=>{
  const changed=structuredClone(artifact);
  changed.rawMetadata=changed.rawMetadata.replace('{','{"compiler":null,');
  assert.throws(()=>auditReserveArtifact(changed,{root}),/raw metadata is malformed/);
  assert.match(checkerSource,/constants\.O_RDONLY\|constants\.O_NOFOLLOW\|constants\.O_CLOEXEC/);
  assert.match(checkerSource,/stat\.size>4\*1024\*1024/);
  assert.match(checkerSource,/parseStrictJson\(bytes\.toString\('utf8'\)/);
  assert.doesNotMatch(checkerSource,/JSON\.parse\(readFileSync/);
});
