import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {
 proofReserveDeploymentConfigHash,proofReservePreActivationConfigHash,
 safeOwnersCommitment,validateConfiguration, validateProofConfiguration,
} from '../../sdk/configuration.mjs';
const address=n=>'0x'+n.toString(16).padStart(40,'0');
const fixture=()=>({chainId:'31337',token:address(1),governance:address(2),guardian:address(3),domDomain:'0x'+'01'.repeat(32),notaries:[address(4),address(5),address(6)],threshold:3,withdrawalDelay:'21600',governanceDelay:'172800',maxOutstanding:'1000000',outflowCapacity:'10000'});
const proofFixture=()=>({
 productionReady:false,ethereumChainId:'31337',token:address(1),verifier:address(2),
 verifierCodeHash:'0x'+'11'.repeat(32),verifierConfigHash:'0x'+'22'.repeat(32),
 checkpointRegistry:address(5),checkpointRegistryRuntimeCodeHash:'0x'+'23'.repeat(32),
 checkpointRegistryConfigHash:'0x'+'24'.repeat(32),domDomain:'0x'+'33'.repeat(32),
 activationScheduleCommitment:'0x'+'35'.repeat(32),governance:address(3),guardian:address(4),
 withdrawalDelaySeconds:'21600',governanceDelaySeconds:'172800',
 maxOutstandingBaseUnits:'1000000',outflowCapacityBaseUnitsPerDay:'10000',realFundsAuthorized:false,
});
const deploymentFixture=()=>({
 ethereumChainId:'1',reserve:address(9),token:'0xdAC17F958D2ee523a2206206994597C13D831ec7',
 tokenCodeHash:'0x'+'10'.repeat(32),verifier:address(8),verifierCodeHash:'0x'+'20'.repeat(32),
 verifierConfigHash:'0x'+'30'.repeat(32),checkpointRegistry:address(5),
 checkpointRegistryRuntimeCodeHash:'0x'+'31'.repeat(32),checkpointRegistryConfigHash:'0x'+'32'.repeat(32),domDomain:'0x'+'40'.repeat(32),
 activationScheduleCommitment:'0x'+'42'.repeat(32),governance:address(7),
 governanceCodeHash:'0x'+'50'.repeat(32),governanceImplementation:address(17),
 governanceImplementationCodeHash:'0x'+'51'.repeat(32),guardian:address(6),guardianCodeHash:'0x'+'60'.repeat(32),
 governanceOwnersCommitment:'0x'+'52'.repeat(32),
 guardianImplementation:address(16),guardianImplementationCodeHash:'0x'+'61'.repeat(32),
 guardianOwnersCommitment:'0x'+'62'.repeat(32),
 withdrawalDelaySeconds:'86400',governanceDelaySeconds:'172800',
 maxOutstandingBaseUnits:'100000000000',outflowCapacityBaseUnitsPerDay:'2000000000',
});
test('Safe owner commitment canonicalizes order and rejects ambiguous owner sets',()=>{
 const owners=[address(20),address(21),address(22)];
 assert.match(safeOwnersCommitment(owners),/^0x[0-9a-f]{64}$/);
 assert.equal(safeOwnersCommitment(owners),safeOwnersCommitment([...owners].reverse()));
 assert.throws(()=>safeOwnersCommitment(owners.slice(0,2)),/exactly three/);
 assert.throws(()=>safeOwnersCommitment([owners[0],owners[0],owners[2]]),/distinct/);
});
test('missing production configuration is rejected',async()=>{
 const config=JSON.parse(await readFile(new URL('../../config/production.unconfigured.json',import.meta.url),'utf8'));
 assert.throws(()=>validateConfiguration(config));
});
test('configuration checks quorum, integer precision, distinct roles and bounds',()=>{
 assert.equal(validateConfiguration(fixture()).threshold,3);
 for(const change of [{threshold:2},{notaries:[address(4),address(4),address(6)]},{guardian:address(2)},{maxOutstanding:1000},{withdrawalDelay:'1'},{outflowCapacity:'1000001'},{domDomain:'0x'+'00'.repeat(32)}]) assert.throws(()=>validateConfiguration({...fixture(),...change}));
 for(const field of ['withdrawalDelay','governanceDelay','maxOutstanding','outflowCapacity']) {
  assert.throws(()=>validateConfiguration({...fixture(),[field]:(1n<<64n).toString()}),/range/);
 }
});
test('quorum prototype refuses Ethereum mainnet even with the intended USDT token',()=>{
 assert.throws(()=>validateConfiguration({...fixture(),chainId:'1'}),/refuses Ethereum mainnet/);
 assert.throws(()=>validateConfiguration({...fixture(),chainId:'1',token:'0xdAC17F958D2ee523a2206206994597C13D831ec7'}),/refuses Ethereum mainnet/);
 assert.equal(validateConfiguration(fixture()).chainId,31337n);
});
test('missing proof-reserve production configuration is rejected',async()=>{
 const config=JSON.parse(await readFile(new URL('../../config/proof-reserve.unconfigured.json',import.meta.url),'utf8'));
 assert.throws(()=>validateProofConfiguration(config));
});
test('proof-reserve configuration validates exact local bounds and immutable identities',()=>{
 const config=validateProofConfiguration(proofFixture());
 assert.equal(config.ethereumChainId,31337n);
 assert.equal(config.withdrawalDelaySeconds,21600n);
 for(const change of [
  {extra:true},{productionReady:true},{realFundsAuthorized:true},{verifier:address(1)},
  {guardian:address(3)},{verifierCodeHash:'0x'+'00'.repeat(32)},{verifierConfigHash:null},
  {domDomain:'0x'+'00'.repeat(32)},
  {activationScheduleCommitment:null},{withdrawalDelaySeconds:'21599'},
  {governanceDelaySeconds:'2592001'},{maxOutstandingBaseUnits:'0'},
  {outflowCapacityBaseUnitsPerDay:'1000001'},
 ]) assert.throws(()=>validateProofConfiguration({...proofFixture(),...change}));
 for(const field of ['withdrawalDelaySeconds','governanceDelaySeconds','maxOutstandingBaseUnits',
  'outflowCapacityBaseUnitsPerDay']) {
  assert.throws(()=>validateProofConfiguration({...proofFixture(),[field]:(1n<<64n).toString()}),/range/);
 }
});
test('proof-reserve tooling cannot declare Ethereum mainnet ready before a ratified release',()=>{
 const mainnet={...proofFixture(),ethereumChainId:'1',token:'0xdAC17F958D2ee523a2206206994597C13D831ec7'};
 assert.throws(()=>validateProofConfiguration(mainnet),/production verifier release unavailable/);
 assert.throws(()=>validateProofConfiguration({...mainnet,token:address(1)}),/intended USDT/);
 assert.throws(()=>validateProofConfiguration({...mainnet,productionReady:true}),/cannot assert production readiness/);
});
test('proof-reserve deployment commitment binds every immutable release field',()=>{
 const expected='0x94c07dd41ae21ae82155f03557da9e9242d54fe3dfb544f42f1475f33a2c7e84';
 const result=proofReserveDeploymentConfigHash(deploymentFixture());
 assert.equal(result.identityHash,'0x69c6713e2e6e23c18f23465289dcde809c181f69451fbea7dbe124256c79e1f5');
 assert.equal(result.policyHash,'0x3185e841c8953089d224c176ba77159bf0b48c1cf8ca715c5e522bdfaea59149');
 assert.equal(result.reserveConfigHash,expected);
 assert.match(result.reservePreActivationConfigHash,/^0x[0-9a-f]{64}$/);
 const {activationScheduleCommitment: _activation,...preActivationInput}=deploymentFixture();
 assert.equal(proofReservePreActivationConfigHash(preActivationInput).reservePreActivationConfigHash,
  result.reservePreActivationConfigHash);
 const mutations={
  reserve:address(10),token:address(11),tokenCodeHash:'0x'+'11'.repeat(32),verifier:address(12),
  verifierCodeHash:'0x'+'21'.repeat(32),verifierConfigHash:'0x'+'31'.repeat(32),
  checkpointRegistry:address(15),checkpointRegistryRuntimeCodeHash:'0x'+'32'.repeat(32),
  checkpointRegistryConfigHash:'0x'+'33'.repeat(32),domDomain:'0x'+'43'.repeat(32),
  activationScheduleCommitment:'0x'+'45'.repeat(32),governance:address(13),guardian:address(14),
  governanceCodeHash:'0x'+'51'.repeat(32),guardianCodeHash:'0x'+'61'.repeat(32),
  governanceImplementation:address(18),governanceImplementationCodeHash:'0x'+'52'.repeat(32),
  governanceOwnersCommitment:'0x'+'53'.repeat(32),
  guardianImplementation:address(19),guardianImplementationCodeHash:'0x'+'62'.repeat(32),
  guardianOwnersCommitment:'0x'+'63'.repeat(32),
  withdrawalDelaySeconds:'86401',governanceDelaySeconds:'172801',maxOutstandingBaseUnits:'100000000001',
  outflowCapacityBaseUnitsPerDay:'2000000001',ethereumChainId:'31337',
 };
 for(const [key,value] of Object.entries(mutations)) {
  const changed=proofReserveDeploymentConfigHash({...deploymentFixture(),[key]:value});
  assert.notEqual(changed.reserveConfigHash,expected,key);
  if(key==='activationScheduleCommitment') {
   assert.equal(changed.reservePreActivationConfigHash,result.reservePreActivationConfigHash,key);
  } else assert.notEqual(changed.reservePreActivationConfigHash,result.reservePreActivationConfigHash,key);
 }
 for(const change of [{extra:true},{reserve:address(8)},{tokenCodeHash:'0x'+'00'.repeat(32)},
  {withdrawalDelaySeconds:'21599'},{outflowCapacityBaseUnitsPerDay:'100000000001'}]) {
  assert.throws(()=>proofReserveDeploymentConfigHash({...deploymentFixture(),...change}));
 }
});
