import test from 'node:test';
import assert from 'node:assert/strict';
import {AbiCoder,Interface,keccak256} from 'ethers';
import {
 EIP1271_MAGIC_VALUE,buildNativeReleaseAttestation,collectNativeAttestationApprovals,
 nativeReleaseAttestationDigest,nativeReleaseAttestationTypedData,validNativeAttestationSignature,
} from '../../sdk/native-release-attestation.mjs';
import {collectNativeAttestationApprovalConsensus} from '../../sdk/release-authorization-rpc.mjs';

const address=byte=>'0x'+byte.repeat(20);
const hash=byte=>'0x'+byte.repeat(32);
const releaseConfig={ethereumChainId:'1',governance:address('11'),governanceCodeHash:hash('22'),
 reserveConfigHash:hash('44'),checkpointRegistryConfigHash:hash('33')};
const attestation={approvedBy:releaseConfig.governance,checkpointRegistryConfigHash:hash('33'),
 completedAt:'1792492800',kind:'native-privacy-trusted-setup',releaseId:'release-1',
 reserveConfigHash:hash('44'),schema:1,signature:'0x1234',sourceCommit:'a'.repeat(40),
 subjectCommitment:hash('55')};
const blockHash=hash('66');
const code='0x60016000';
const validReturn=AbiCoder.defaultAbiCoder().encode(['bytes4'],[EIP1271_MAGIC_VALUE]);
const sources=[{sourceId:'operator-a',originKeccak256:hash('81')},
 {sourceId:'operator-b',originKeccak256:hash('82')}];

function provider({result=validReturn,endingHash=blockHash,callError=false}={}) {
 const calls=[];
 return {calls,async send(method,params) {
  calls.push([method,params]);
  if(method==='eth_chainId') return '0x1';
  if(method==='eth_getBlockByNumber') {
   if(params[0]==='finalized') return {number:'0x14fb180',hash:blockHash,
    timestamp:'0x'+BigInt(1792492900).toString(16)};
   return {number:'0x14fb180',hash:endingHash,timestamp:'0x'+BigInt(1792492900).toString(16)};
  }
  if(method==='eth_getCode') return code;
  if(method==='eth_call') {
   if(callError) throw new Error('rejected');
   return result;
  }
  throw new Error(`unexpected method ${method}`);
 }};
}

test('native attestation EIP-712 digest binds every release and ceremony field',()=>{
 const baseline=nativeReleaseAttestationDigest(attestation,releaseConfig);
 assert.equal(baseline,'0x91b04fcdbe134586333bc4be67ce25bcb5e8e78f44a9b56fdaf9faa23f8186f6');
 const mutations=[
  [{...attestation,kind:'native-wallet-custody'},releaseConfig],
  [{...attestation,releaseId:'release-2'},releaseConfig],
  [{...attestation,sourceCommit:'b'.repeat(40)},releaseConfig],
  [{...attestation,reserveConfigHash:hash('45')},releaseConfig],
  [{...attestation,checkpointRegistryConfigHash:hash('34')},releaseConfig],
  [{...attestation,completedAt:'1792492801'},releaseConfig],
  [{...attestation,subjectCommitment:hash('56')},releaseConfig],
  [{...attestation,approvedBy:address('12')},{...releaseConfig,governance:address('12')}],
  [attestation,{...releaseConfig,ethereumChainId:'2'}],
 ];
 for(const [changed,config] of mutations) {
  assert.notEqual(nativeReleaseAttestationDigest(changed,config),baseline);
 }
 assert.equal(nativeReleaseAttestationDigest({...attestation,signature:'0xabcd'},releaseConfig),baseline);
});

test('native attestation builder derives the exact release-bound signing request',()=>{
 const releaseEvidence={releaseId:attestation.releaseId,sourceCommit:attestation.sourceCommit};
 const built=buildNativeReleaseAttestation({kind:attestation.kind,releaseEvidence,releaseConfig,
  completedAt:attestation.completedAt,subjectCommitment:attestation.subjectCommitment});
 assert.deepEqual(built.attestation,{...attestation,signature:null});
 assert.equal(built.digest,nativeReleaseAttestationDigest(built.attestation,releaseConfig));
 const typed=nativeReleaseAttestationTypedData(built.attestation,releaseConfig);
 assert.equal(typed.domain.verifyingContract,releaseConfig.governance);
 const signed=buildNativeReleaseAttestation({kind:attestation.kind,releaseEvidence,releaseConfig,
  completedAt:attestation.completedAt,subjectCommitment:attestation.subjectCommitment,
  signature:attestation.signature});
 assert.equal(signed.digest,built.digest);
 assert.throws(()=>buildNativeReleaseAttestation({kind:'unsupported',releaseEvidence,releaseConfig,
  completedAt:attestation.completedAt,subjectCommitment:attestation.subjectCommitment}),/unsupported/);
});

test('finalized collector uses exact governance code, fixed block and EIP-1271 result',async()=>{
 const rpc=provider();
 const observation=await collectNativeAttestationApprovals({provider:rpc,releaseConfig,
  attestations:{nativePrivacyTrustedSetup:attestation}});
 assert.deepEqual(observation,{approvals:{nativePrivacyTrustedSetup:{
  digest:nativeReleaseAttestationDigest(attestation,releaseConfig),valid:true,
 }},chainId:'1',finalizedBlockHash:blockHash,finalizedBlockNumber:'22000000',
 finalizedBlockTimestamp:'1792492900',
 governance:releaseConfig.governance,governanceCodeHash:keccak256(code),snapshotBlockHashAfter:blockHash});
 const approvalCall=rpc.calls.find(([method])=>method==='eth_call');
 assert.equal(approvalCall[1][0].to,releaseConfig.governance);
 assert.equal(approvalCall[1][1],'0x14fb180');
 const decoded=new Interface([
  'function isValidSignature(bytes32 digest,bytes signature) view returns (bytes4)',
 ]).decodeFunctionData('isValidSignature',approvalCall[1][0].data);
 assert.equal(decoded.digest,nativeReleaseAttestationDigest(attestation,releaseConfig));
 assert.equal(decoded.signature,attestation.signature);
 assert(rpc.calls.some(([method,params])=>method==='eth_getCode' && params[1]==='0x14fb180'));
});

test('collector records rejection, call failure and ending-snapshot changes fail closed',async()=>{
 for(const options of [{result:'0x1626ba7e'},{result:'0xffffffff'+'00'.repeat(28)},
  {result:validReturn+'00'},{callError:true}]) {
  const observation=await collectNativeAttestationApprovals({provider:provider(options),releaseConfig,
   attestations:{nativePrivacyTrustedSetup:attestation}});
  assert.equal(observation.approvals.nativePrivacyTrustedSetup.valid,false);
 }
 const changed=await collectNativeAttestationApprovals({provider:provider({endingHash:hash('67')}),releaseConfig,
  attestations:{nativePrivacyTrustedSetup:attestation}});
 assert.equal(changed.snapshotBlockHashAfter,hash('67'));
});

test('native attestation signatures are canonical, nonempty and bounded',async()=>{
 assert.equal(validNativeAttestationSignature('0x1234'),true);
 for(const value of [null,'','0x','0x1','0xzz']) assert.equal(validNativeAttestationSignature(value),false);
 const oversized='0x'+'11'.repeat(65_537);
 assert.equal(validNativeAttestationSignature(oversized),false);
 await assert.rejects(collectNativeAttestationApprovals({provider:provider(),releaseConfig,
  attestations:{nativePrivacyTrustedSetup:{...attestation,signature:'0x'}}}),/signature is malformed/);
});

test('native attestation consensus rechecks every approval across independent RPCs',async()=>{
 const config={...releaseConfig,governanceCodeHash:keccak256(code)};
 const observation=await collectNativeAttestationApprovalConsensus({providers:[provider(),provider()],
  releaseConfig:config,attestations:{nativePrivacyTrustedSetup:attestation},sources});
 assert.equal(observation.approvals.nativePrivacyTrustedSetup.valid,true);
 assert.equal(observation.rpcConsensus.sourceCount,'2');
 await assert.rejects(()=>collectNativeAttestationApprovalConsensus({providers:[provider(),
  provider({endingHash:hash('67')})],releaseConfig:config,
  attestations:{nativePrivacyTrustedSetup:attestation},sources}),/invalid or unstable/);
 await assert.rejects(()=>collectNativeAttestationApprovalConsensus({providers:[provider(),provider()],
  releaseConfig:config,attestations:{nativePrivacyTrustedSetup:attestation},sources:[sources[0]]}),
 /source identities must match/);
});
