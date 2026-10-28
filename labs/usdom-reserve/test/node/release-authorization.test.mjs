import test from 'node:test';
import assert from 'node:assert/strict';
import {AbiCoder,Interface,keccak256} from 'ethers';
import {
  RELEASE_AUTHORIZATION_DOMAIN_VERSION,buildReleaseAuthorization,
  collectReleaseAuthorizationApproval,releaseAuthorizationDigest,releaseAuthorizationTypedData,
  releaseEvidenceCommitment,validateReleaseAuthorizationFreshness,
} from '../../sdk/release-authorization.mjs';
import {EIP1271_MAGIC_VALUE,validEip1271Signature} from '../../sdk/finalized-eip1271-approval.mjs';
import {collectReleaseAuthorizationAnchor,collectReleaseAuthorizationApprovalConsensus,
 validateReleaseSigningNetworkObservation}
  from '../../sdk/release-authorization-rpc.mjs';

const address=byte=>'0x'+byte.repeat(20);
const hash=byte=>'0x'+byte.repeat(32);
test('EIP-1271 opaque bytes have one canonical lowercase JSON representation',()=>{
 assert.equal(validEip1271Signature('0xabcd'),true);
 assert.equal(validEip1271Signature('0xABCD'),false);
});
const raw=byte=>byte.repeat(32);
const implementation=address('12');
const releaseConfig={ethereumChainId:'1',governance:address('11'),governanceCodeHash:hash('22'),
 governanceImplementation:implementation,governanceImplementationCodeHash:keccak256('0x60016000'),
 reserveConfigHash:hash('33'),checkpointRegistryConfigHash:hash('44'),
 governanceOwners:[address('61'),address('62'),address('63')],
 guardianOwners:[address('64'),address('65'),address('66')],
 checkpointGuardianOwners:[address('67'),address('68'),address('69')]};
const releaseEvidence={schema:1,releaseId:'usdom-v1.2.3',sourceCommit:'a'.repeat(40),
 sourceTag:'usdom-v1.2.3',reserveArtifact:{
  path:'out/USDOMProofReserve.sol/USDOMProofReserve.json',sha256:raw('71')},
 residualRiskAcceptanceReport:{path:'evidence/residual-risk.json',sha256:raw('55')}};
const operatorIntent={schema:1,undefined:[]};
const authorization={accepted:true,releaseId:releaseEvidence.releaseId,
 sourceCommit:releaseEvidence.sourceCommit,sourceTag:releaseEvidence.sourceTag,
 releaseEvidenceCommitment:releaseEvidenceCommitment(releaseEvidence),
 reserveConfigHash:releaseConfig.reserveConfigHash,
 checkpointRegistryConfigHash:releaseConfig.checkpointRegistryConfigHash,
 reportSha256:releaseEvidence.residualRiskAcceptanceReport.sha256,
 acceptingAuthority:releaseConfig.governance,acceptedAt:'1792492800',productionApproved:true,
 deployAuthorized:true,realFundsAuthorized:true,signature:'0x1234',rule:'exact release only'};
const blockHash=hash('66');
const code='0x60016000';
const validReturn=AbiCoder.defaultAbiCoder().encode(['bytes4'],[EIP1271_MAGIC_VALUE]);
const sources=[{sourceId:'operator-a',originKeccak256:hash('81')},
 {sourceId:'operator-b',originKeccak256:hash('82')}];

function provider({result=validReturn,chainId='0x1',endingHash=blockHash,implementationCode=code,
 singleton=implementation,singletonAfter=singleton,governanceCodeAfter=code,
 finalizedNumber='0x14fb180',finalizedTimestamp='0x'+BigInt(1792492900).toString(16)}={}) {
 const calls=[];
 let storageReads=0;
 let governanceCodeReads=0;
 return {calls,async send(method,params) {
  calls.push([method,params]);
  if(method==='eth_chainId') return chainId;
  if(method==='eth_getBlockByNumber') {
   if(params[0]==='finalized') return {number:finalizedNumber,hash:blockHash,
    timestamp:finalizedTimestamp};
   return {number:finalizedNumber,hash:endingHash,timestamp:finalizedTimestamp};
  }
  if(method==='eth_getCode') return params[0].toLowerCase()===implementation.toLowerCase()
   ?implementationCode:(governanceCodeReads++===0?code:governanceCodeAfter);
  if(method==='eth_getStorageAt') {
   const selected=storageReads++===0?singleton:singletonAfter;
   return '0x'+'00'.repeat(12)+selected.slice(2);
  }
  if(method==='eth_call') return result;
  throw new Error(`unexpected method ${method}`);
 }};
}

test('release authorization digest binds authority, scope, report and exact release',()=>{
 assert.equal(RELEASE_AUTHORIZATION_DOMAIN_VERSION,'4');
 assert.equal(releaseAuthorizationTypedData(authorization,releaseConfig).message.governanceOwnersHash,
  keccak256(AbiCoder.defaultAbiCoder().encode(['address[]'],[releaseConfig.governanceOwners])));
 const baseline=releaseAuthorizationDigest(authorization,releaseConfig);
 const mutations=[
  [{...authorization,releaseId:'usdom-v1.2.4'},releaseConfig],
  [{...authorization,sourceCommit:'b'.repeat(40)},releaseConfig],
  [{...authorization,reportSha256:raw('56')},releaseConfig],
  [{...authorization,acceptedAt:'1792492801'},releaseConfig],
  [{...authorization,acceptingAuthority:address('12')},{...releaseConfig,governance:address('12')}],
  [authorization,{...releaseConfig,ethereumChainId:'2'}],
  [authorization,{...releaseConfig,governanceOwners:[address('60'),address('62'),address('63')]}],
 ];
 for(const [changed,config] of mutations) {
  assert.notEqual(releaseAuthorizationDigest(changed,config),baseline);
 }
 assert.equal(releaseAuthorizationDigest(authorization,{...releaseConfig,
  governanceOwners:[address('63'),address('62'),address('61')]}),baseline);
 assert.notEqual(releaseAuthorizationDigest({...authorization,sourceTag:'usdom-v1.2.4'},releaseConfig),baseline);
 assert.notEqual(releaseAuthorizationDigest({...authorization,
  releaseEvidenceCommitment:hash('72')},releaseConfig),baseline);
 assert.throws(()=>releaseAuthorizationDigest({...authorization,reserveConfigHash:hash('34')},releaseConfig),
  /reserveConfigHash differs from the release/);
 assert.throws(()=>releaseAuthorizationDigest({...authorization,checkpointRegistryConfigHash:hash('45')},releaseConfig),
  /checkpointRegistryConfigHash differs from the release/);
 for(const field of ['productionApproved','deployAuthorized','realFundsAuthorized']) {
  assert.throws(()=>releaseAuthorizationDigest({...authorization,[field]:false},releaseConfig),
    new RegExp(`${field} must be true`));
 }
 assert.equal(releaseAuthorizationDigest({...authorization,signature:'0xabcd'},releaseConfig),baseline);
 assert.throws(()=>releaseAuthorizationDigest(authorization,{...releaseConfig,governanceOwners:null}),
  /exactly three addresses/);
 assert.throws(()=>releaseAuthorizationDigest(authorization,{...releaseConfig,
  governanceOwners:[address('61'),address('61'),address('63')]}),/distinct nonzero/);
});

test('release authorization rejects oversized integers before EIP-712 conversion',()=>{
 assert.throws(()=>releaseAuthorizationDigest({...authorization,
  acceptedAt:'9'.repeat(100000)},releaseConfig),/acceptedAt/);
 assert.throws(()=>releaseAuthorizationDigest(authorization,{...releaseConfig,
  ethereumChainId:'9'.repeat(100000)}),/ethereumChainId/);
 assert.throws(()=>releaseAuthorizationDigest(authorization,{...releaseConfig,
  ethereumChainId:(1n<<256n).toString()}),/uint256/);
});

test('release evidence commitment is canonical, acyclic and path-safe',()=>{
 const reordered={reserveArtifact:{sha256:raw('71'),
  path:'out/USDOMProofReserve.sol/USDOMProofReserve.json'},
  sourceTag:'usdom-v1.2.3',sourceCommit:'a'.repeat(40),releaseId:'usdom-v1.2.3',schema:1,
  residualRiskAcceptanceReport:{sha256:raw('55'),path:'evidence/residual-risk.json'}};
 assert.equal(releaseEvidenceCommitment(reordered),releaseEvidenceCommitment(releaseEvidence));
 for(const pathValue of ['../outside.json','evidence/../outside.json','/tmp/outside.json',
  'evidence//report.json','evidence/./report.json','evidence\\report.json',
  'config/production-requirements.json','out/arbitrary.json','evidence/report\nforged.json',
  'evidence/réport.json']) {
  assert.throws(()=>releaseEvidenceCommitment({...releaseEvidence,
   reserveArtifact:{...releaseEvidence.reserveArtifact,path:pathValue}}),/invalid hash-addressed document/);
 }
 const cycle=structuredClone(releaseEvidence); cycle.self=cycle;
 assert.throws(()=>releaseEvidenceCommitment(cycle),/contains a cycle/);
 assert.throws(()=>releaseEvidenceCommitment({...releaseEvidence,extra:undefined}),/non-JSON value/);
 assert.throws(()=>releaseEvidenceCommitment({...releaseEvidence,extra:Number.NaN}),/noncanonical number/);
 assert.throws(()=>releaseEvidenceCommitment({...releaseEvidence,
  releaseEvidenceCommitment:hash('99')}),/cannot contain releaseEvidenceCommitment/);
 assert.throws(()=>releaseEvidenceCommitment({...releaseEvidence,
  reserveArtifact:{...releaseEvidence.reserveArtifact,sha256:'0'.repeat(64)}}),/nonzero SHA-256/);
});

test('release authorization rejects coordinated zero identity placeholders',()=>{
 for(const changed of [
  {...authorization,sourceCommit:'0'.repeat(40)},
  {...authorization,releaseEvidenceCommitment:hash('00')},
  {...authorization,reportSha256:'0'.repeat(64)},
  {...authorization,reserveConfigHash:hash('00')},
  {...authorization,checkpointRegistryConfigHash:hash('00')},
 ]) {
  const config={...releaseConfig};
  if(changed.reserveConfigHash===hash('00')) config.reserveConfigHash=hash('00');
  if(changed.checkpointRegistryConfigHash===hash('00')) {
   config.checkpointRegistryConfigHash=hash('00');
  }
  assert.throws(()=>releaseAuthorizationDigest(changed,config));
 }
 assert.throws(()=>buildReleaseAuthorization({
  releaseEvidence:{...releaseEvidence,residualRiskAcceptanceReport:{
   ...releaseEvidence.residualRiskAcceptanceReport,sha256:'0'.repeat(64)}},
  releaseConfig,operatorIntent,acceptedAt:'1792492800',
 }),/hash-addressed residual-risk report is required/);
});

test('builder creates one signing request without mutating authorization inputs',()=>{
 const evidence=structuredClone(releaseEvidence),intent=structuredClone(operatorIntent);
 const unsigned=buildReleaseAuthorization({releaseEvidence:evidence,releaseConfig,
  operatorIntent:intent,acceptedAt:'1792492800'});
 assert.equal(unsigned.authorization.signature,null);
 assert.equal(unsigned.digest,releaseAuthorizationDigest(unsigned.authorization,releaseConfig));
 assert.deepEqual(evidence,releaseEvidence);
 assert.deepEqual(intent,operatorIntent);
 const signed=buildReleaseAuthorization({releaseEvidence,releaseConfig,operatorIntent,
  acceptedAt:'1792492800',signature:'0x1234'});
 assert.equal(signed.digest,unsigned.digest);
 assert.equal(signed.authorization.signature,'0x1234');
 const changedEvidence=structuredClone(releaseEvidence);
 changedEvidence.reserveArtifact.sha256=raw('72');
 const changedArtifact=buildReleaseAuthorization({releaseEvidence:changedEvidence,releaseConfig,
  operatorIntent,acceptedAt:'1792492800'});
 assert.notEqual(changedArtifact.digest,unsigned.digest);
 assert.notEqual(changedArtifact.authorization.releaseEvidenceCommitment,
  unsigned.authorization.releaseEvidenceCommitment);
 assert.throws(()=>buildReleaseAuthorization({releaseEvidence,releaseConfig,
  operatorIntent:{...operatorIntent,undefined:['governance']},acceptedAt:'1792492800'}),
 /parameters remain undefined/);
});

test('collector checks release authorization through finalized EIP-1271 state',async()=>{
 const rpc=provider();
 const observation=await collectReleaseAuthorizationApproval({provider:rpc,releaseConfig,authorization});
 assert.deepEqual(observation,{approvals:{releaseAuthorization:{
  digest:releaseAuthorizationDigest(authorization,releaseConfig),valid:true,
 }},chainId:'1',finalizedBlockHash:blockHash,finalizedBlockNumber:'22000000',
 finalizedBlockTimestamp:'1792492900',governance:releaseConfig.governance,
 governanceCodeHash:keccak256(code),snapshotBlockHashAfter:blockHash});
 const call=rpc.calls.find(([method])=>method==='eth_call');
 const decoded=new Interface([
  'function isValidSignature(bytes32 digest,bytes signature) view returns (bytes4)',
 ]).decodeFunctionData('isValidSignature',call[1][0].data);
 assert.equal(decoded.digest,releaseAuthorizationDigest(authorization,releaseConfig));
 assert.equal(decoded.signature,authorization.signature);
 await assert.rejects(collectReleaseAuthorizationApproval({provider:provider({chainId:'0x2'}),
  releaseConfig,authorization}),/chain ID differs/);
});

test('collector rejects Safe proxy implementation substitution and finalized TOCTOU',async()=>{
 for(const rpc of [provider({singleton:address('13')}),provider({implementationCode:'0x6002'}),
  provider({singletonAfter:address('13')}),provider({governanceCodeAfter:'0x6002'})]) {
  await assert.rejects(()=>collectReleaseAuthorizationApproval({provider:rpc,releaseConfig,authorization}),
   /implementation/);
 }
});

test('authorization RPC consensus rechecks one identical finalized anchor and approval',async()=>{
 const config={...releaseConfig,governanceCodeHash:keccak256(code)};
 const anchor=await collectReleaseAuthorizationAnchor({providers:[provider(),provider()],
  releaseConfig:config,sources});
 assert.equal(anchor.blockHash,blockHash);
 assert.equal(anchor.governanceCodeHash,keccak256(code));
 assert.equal(anchor.rpcConsensus.sourceCount,'2');
 const observation=await collectReleaseAuthorizationApprovalConsensus({providers:[provider(),provider()],
  releaseConfig:config,authorization,sources});
 assert.equal(observation.approvals.releaseAuthorization.valid,true);
 assert.equal(observation.rpcConsensus.sourceCount,'2');
 await assert.rejects(()=>collectReleaseAuthorizationAnchor({providers:[provider(),
  provider({endingHash:hash('77')})],releaseConfig:config,sources}),/anchor changed/);
 await assert.rejects(()=>collectReleaseAuthorizationAnchor({providers:[provider(),
  provider({singleton:address('13')})],releaseConfig:config,sources}),/implementation/);
 await assert.rejects(()=>collectReleaseAuthorizationAnchor({providers:[provider(),
  provider({implementationCode:'0x6002'})],releaseConfig:config,sources}),/implementation/);
 await assert.rejects(()=>collectReleaseAuthorizationApprovalConsensus({providers:[provider(),
  provider({endingHash:hash('77')})],releaseConfig:config,authorization,sources}),/invalid or unstable/);
 await assert.rejects(()=>collectReleaseAuthorizationApprovalConsensus({providers:[provider(),provider()],
  releaseConfig:config,authorization,sources:[sources[0]]}),/source identities must match/);
});

test('authorization expires and current EIP-1271 state remains authoritative',async()=>{
 const fresh={...authorization,acceptedAt:'1792492800'};
 assert.deepEqual(validateReleaseAuthorizationFreshness({authorization:fresh,
  observation:{finalizedBlockTimestamp:'1792579200'}}),{
  acceptedAt:'1792492800',finalizedBlockTimestamp:'1792579200'});
 assert.throws(()=>validateReleaseAuthorizationFreshness({authorization:fresh,
  observation:{finalizedBlockTimestamp:'1792579201'}}),/stale/);
 assert.throws(()=>validateReleaseAuthorizationFreshness({authorization:fresh,
  observation:{finalizedBlockTimestamp:'1792492799'}}),/later than finalized/);
 const config={...releaseConfig,governanceCodeHash:keccak256(code)};
 await assert.rejects(()=>collectReleaseAuthorizationApprovalConsensus({
  providers:[provider({finalizedTimestamp:'0x'+BigInt(1792579201).toString(16)}),
    provider({finalizedTimestamp:'0x'+BigInt(1792579201).toString(16)})],
  releaseConfig:config,authorization:fresh,sources,
 }),/stale/);
 await assert.rejects(()=>collectReleaseAuthorizationApprovalConsensus({
  providers:[provider({result:'0x'}),provider({result:'0x'})],
  releaseConfig:config,authorization:fresh,sources,
 }),/invalid or unstable/);
});

test('presign observation preserves governance, RPC identities and monotonic finality',async()=>{
 const config={...releaseConfig,governanceCodeHash:keccak256(code)};
 const authorized=await collectReleaseAuthorizationAnchor({providers:[provider(),provider()],
  releaseConfig:config,sources});
 const observed={...structuredClone(authorized),blockNumber:'22000001',
  blockHash:hash('91'),blockTimestamp:'1792492901'};
 assert.equal(validateReleaseSigningNetworkObservation({authorized,observed}).blockNumber,'22000001');
 for(const changed of [
  {...observed,governance:address('12')},
  {...observed,governanceCodeHash:hash('92')},
  {...observed,blockNumber:'21999999'},
  {...observed,rpcConsensus:{...observed.rpcConsensus,sourceCount:'3'}},
 ]) assert.throws(()=>validateReleaseSigningNetworkObservation({authorized,observed:changed}),
  /differs from signing authorization/);
 for(const blockNumber of ['9'.repeat(100_000),(1n<<64n).toString(),'022000001','-1']) {
  assert.throws(()=>validateReleaseSigningNetworkObservation({authorized,
   observed:{...observed,blockNumber}}),/block number is invalid/);
 }
});

test('authorization anchor rejects oversized or noncanonical RPC quantities before conversion',async()=>{
 const config={...releaseConfig,governanceCodeHash:keccak256(code)};
 for(const mutation of [
  {chainId:`0x${'f'.repeat(100_000)}`},
  {finalizedNumber:`0x${'f'.repeat(100_000)}`},
  {finalizedTimestamp:`0x${'f'.repeat(100_000)}`},
  {finalizedNumber:`0x${(1n<<64n).toString(16)}`},
  {finalizedTimestamp:`0x${(1n<<64n).toString(16)}`},
  {finalizedNumber:'0x014fb180'},
 ]) {
  await assert.rejects(()=>collectReleaseAuthorizationAnchor({
   providers:[provider(mutation),provider(mutation)],releaseConfig:config,sources,
  }),/RPC finalized anchor is invalid/);
 }
});
