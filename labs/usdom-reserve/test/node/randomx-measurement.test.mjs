import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {blake2b} from '@noble/hashes/blake2b';
import {concat,getBytes,keccak256,toUtf8Bytes} from 'ethers';
import {
  inspectAuthenticatedRandomxExport,inspectCanonicalRandomxStatement,
} from '../../sdk/randomx-measurement.mjs';

function structurallyValidStatement() {
  const value=Buffer.alloc(384);
  value.write('UDCRXST1',0,'ascii');
  value.writeUInt16BE(1,8); value.writeUInt16BE(1,10); value.writeUInt32BE(0xa1b2c3d4,12);
  value.fill(0x11,16,48); value.writeBigUInt64BE(1n,48); value.writeBigUInt64BE(0n,56);
  value.fill(0x12,64,96);
  value.writeUInt32LE(4,96); value.writeBigUInt64LE(1n,96+36);
  value.writeUInt32LE(0x1f00ffff,96+180);
  value[320]=0; value.fill(0x01,321,352);
  value[352]=0; value[353]=0xff; value[354]=0xff;
  return value;
}

function commit(domain,value) {
  return keccak256(concat([toUtf8Bytes(domain),getBytes(value)]));
}

function authenticatedFixture() {
  const statement=structurallyValidStatement();
  const preimage=statement.subarray(96,320);
  const header=Buffer.alloc(256);
  preimage.copy(header,0,0,4); preimage.copy(header,12,4,36);
  preimage.copy(header,4,36,44); preimage.copy(header,44,44,224);
  statement.copy(header,224,320,352);
  const packageBytes=Buffer.alloc(18+256+1);
  packageBytes.write('USDOMBL4',0,'ascii'); packageBytes.writeUInt16BE(1,8);
  packageBytes.writeUInt32BE(256,10); packageBytes.writeUInt32BE(1,14);
  header.copy(packageBytes,18); packageBytes[274]=1;
  const privateInput=Buffer.alloc(12+12+packageBytes.length+1+1);
  privateInput.write('UDCSPI01',0,'ascii'); privateInput.writeUInt16BE(1,8);
  privateInput.writeUInt16BE(1,10); privateInput.writeUInt32BE(packageBytes.length,12);
  privateInput.writeUInt32BE(1,16); privateInput.writeUInt32BE(1,20);
  packageBytes.copy(privateInput,24); privateInput[24+packageBytes.length]=1;
  privateInput[25+packageBytes.length]=1;
  const privateInputCommitment=commit('DOM:checkpoint-segment-private-input:v1',privateInput);
  const transition=Buffer.alloc(2320);
  transition.write('UDCSTN04',0,'ascii'); transition.writeUInt16BE(4,8);
  transition.writeUInt16BE(1,10);
  Buffer.from(privateInputCommitment.slice(2),'hex').copy(transition,12);
  transition.writeBigUInt64BE(10n,52); // previous issued, low 64 bits
  transition.writeBigUInt64BE(2n,68);  // previous burned, low 64 bits
  transition.writeBigUInt64BE(10n,84); // new issued, low 64 bits
  transition.writeBigUInt64BE(3n,100); // new burned, low 64 bits
  transition[108]=0; transition[109]=1;
  const policyInput=Buffer.from('UDCSPOL1-authenticated-policy-fixture');
  const nativeOpening=Buffer.from('UDCSNS01-authenticated-opening-fixture');
  const inspected=inspectCanonicalRandomxStatement(statement);
  const report={
    schema:'usdom-authenticated-randomx-statement-export-v1',
    portableSegmentExecuted:true,randomxRelationExecuted:false,generatesProof:false,mines:false,
    sourceBlockCount:1,selectedBlockIndex:0,blockHeight:inspected.blockHeight,
    blockHash:`0x${Buffer.from(blake2b(header,{dkLen:32})).toString('hex')}`,
    transitionCommitment:commit('DOM:checkpoint-segment-transition:v4',transition),
    privateInputCommitment,
    policyInputCommitment:commit('DOM:checkpoint-segment-policy-input:v1',policyInput),
    nativeOpeningCommitment:commit(
      'DOM:checkpoint-segment-native-state-opening:v1',nativeOpening,
    ),
    statementCommitment:inspected.journal,
    statementPath:'evidence/randomx-canonical-statement.bin',
    reportPath:'evidence/randomx-canonical-statement-export.json',
  };
  return {statement,report,sources:{transition,privateInput,policyInput,nativeOpening}};
}

test('measurement statement parser binds canonical framing, schedule, target and journal',()=>{
  const input=structurallyValidStatement();
  const result=inspectCanonicalRandomxStatement(input);
  assert.equal(result.networkMagic,String(0xa1b2c3d4));
  assert.equal(result.blockHeight,'1');
  assert.equal(result.seedHeight,'0');
  assert.match(result.statementSha256,/^[0-9a-f]{64}$/);
  assert.match(result.journal,/^0x[0-9a-f]{64}$/);
  for(const mutate of [
    value=>value[0]^=1,value=>value.writeBigUInt64BE(0n,48),
    value=>value.writeUInt32LE(3,96),value=>value.writeBigUInt64LE(2n,96+36),
    value=>value[352]^=1,value=>value.fill(0xff,320,352),
    value=>{ value.writeUInt32LE(0x207fffff,96+180); value.fill(0,352,384);
      value[352]=0xff; value[353]=0xff; value[354]=0x7f; },
    value=>{ value.writeUInt32LE(0x03000001,96+180); value.fill(0,352,384);
      value[381]=1; },
  ]) {
    const changed=Buffer.from(input); mutate(changed);
    assert.throws(()=>inspectCanonicalRandomxStatement(changed));
  }
});

test('authenticated export binds exact source commitments and terminal package header',()=>{
  const fixture=authenticatedFixture();
  const result=inspectAuthenticatedRandomxExport(
    fixture.report,fixture.sources,fixture.statement,
  );
  assert.equal(result.blockHeight,'1');
  assert.equal(result.sourceBlockCount,1);
  assert.equal(result.blockHash,fixture.report.blockHash);

  const changedSource={...fixture.sources,policyInput:Buffer.from(fixture.sources.policyInput)};
  changedSource.policyInput[8]^=1;
  assert.throws(()=>inspectAuthenticatedRandomxExport(
    fixture.report,changedSource,fixture.statement,
  ),/commitment mismatch/);
  assert.throws(()=>inspectAuthenticatedRandomxExport(
    {...fixture.report,unexpected:true},fixture.sources,fixture.statement,
  ),/schema/);
  assert.throws(()=>inspectAuthenticatedRandomxExport(
    {...fixture.report,blockHash:`0x${'11'.repeat(32)}`},fixture.sources,fixture.statement,
  ),/block hash mismatch/);
  for(const blockHeight of ['9'.repeat(100000),(1n<<64n).toString()]) {
    assert.throws(()=>inspectAuthenticatedRandomxExport(
      {...fixture.report,blockHeight},fixture.sources,fixture.statement,
    ),/report values are invalid/);
  }
  for(const transition of [
    fixture.sources.transition.subarray(0,2319),
    (()=>{ const value=Buffer.from(fixture.sources.transition); value.writeUInt16BE(3,8); return value; })(),
    (()=>{ const value=Buffer.from(fixture.sources.transition); value.writeBigUInt64BE(11n,68); return value; })(),
    (()=>{ const value=Buffer.from(fixture.sources.transition); value[108]=1; value[109]=0; return value; })(),
    (()=>{ const value=Buffer.from(fixture.sources.transition); value[109]=2; return value; })(),
  ]) {
    assert.throws(()=>inspectAuthenticatedRandomxExport(
      fixture.report,{...fixture.sources,transition},fixture.statement,
    ),/transition (framing is|economics are) invalid/);
  }
});

test('plan CLI reports authenticated input availability consistently and executes nothing',()=>{
  const script=fileURLToPath(new URL('../../scripts/plan-randomx-measurement.mjs',import.meta.url));
  const result=spawnSync(process.execPath,[script],{encoding:'utf8'});
  assert.ok(result.status===0||result.status===1,result.stderr);
  const report=JSON.parse(result.stdout);
  assert.equal(report.mode,'plan-only');
  assert.equal(report.executesGuest,false);
  assert.equal(report.generatesProof,false);
  assert.equal(report.mines,false);
  assert.equal(report.readyForAuthorizedExecution,result.status===0);
  if(result.status===0) {
    assert.notEqual(report.statement,null); assert.notEqual(report.authenticatedExport,null);
    assert.deepEqual(report.blockers,[]);
  } else {
    assert.equal(report.readyForAuthorizedExecution,false);
    assert(report.blockers.includes('canonical_statement_unavailable')
      ||report.blockers.includes('authenticated_export_unavailable')
      ||report.blockers.some(value=>value.startsWith('artifact_unavailable:')));
  }
  const extra=spawnSync(process.execPath,[script,'ignored-input.bin'],{encoding:'utf8'});
  assert.equal(extra.status,2);
  assert.equal(extra.stdout,'');
  assert.match(extra.stderr,/Usage:/);
});
