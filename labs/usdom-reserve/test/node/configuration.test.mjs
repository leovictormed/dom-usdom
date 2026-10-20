import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {
 proofReserveDeploymentConfigHash, validateConfiguration, validateProofConfiguration,
} from '../../sdk/configuration.mjs';
const address=n=>'0x'+n.toString(16).padStart(40,'0');
const fixture=()=>({chainId:'31337',token:address(1),governance:address(2),guardian:address(3),domDomain:'0x'+'01'.repeat(32),notaries:[address(4),address(5),address(6)],threshold:3,withdrawalDelay:'21600',governanceDelay:'172800',maxOutstanding:'1000000',outflowCapacity:'10000'});
const proofFixture=()=>({
 productionReady:false,ethereumChainId:'31337',token:address(1),verifier:address(2),
 verifierCodeHash:'0x'+'11'.repeat(32),verifierConfigHash:'0x'+'22'.repeat(32),
 domDomain:'0x'+'33'.repeat(32),
 activationScheduleCommitment:'0x'+'35'.repeat(32),governance:address(3),guardian:address(4),
 withdrawalDelaySeconds:'21600',governanceDelaySeconds:'172800',
 maxOutstandingBaseUnits:'1000000',outflowCapacityBaseUnitsPerDay:'10000',realFundsAuthorized:false,
});
const deploymentFixture=()=>({
 ethereumChainId:'1',reserve:address(9),token:'0xdAC17F958D2ee523a2206206994597C13D831ec7',
 tokenCodeHash:'0x'+'10'.repeat(32),verifier:address(8),verifierCodeHash:'0x'+'20'.repeat(32),
 verifierConfigHash:'0x'+'30'.repeat(32),domDomain:'0x'+'40'.repeat(32),
 activationScheduleCommitment:'0x'+'42'.repeat(32),governance:address(7),
 governanceCodeHash:'0x'+'50'.repeat(32),guardian:address(6),guardianCodeHash:'0x'+'60'.repeat(32),
 withdrawalDelaySeconds:'86400',governanceDelaySeconds:'172800',
 maxOutstandingBaseUnits:'100000000000',outflowCapacityBaseUnitsPerDay:'2000000000',
});
test('missing production configuration is rejected',async()=>{
 const config=JSON.parse(await readFile(new URL('../../config/production.unconfigured.json',import.meta.url),'utf8'));
 assert.throws(()=>validateConfiguration(config));
});
test('configuration checks quorum, integer precision, distinct roles and bounds',()=>{
 assert.equal(validateConfiguration(fixture()).threshold,3);
 for(const change of [{threshold:2},{notaries:[address(4),address(4),address(6)]},{guardian:address(2)},{maxOutstanding:1000},{withdrawalDelay:'1'},{outflowCapacity:'1000001'},{domDomain:'0x'+'00'.repeat(32)}]) assert.throws(()=>validateConfiguration({...fixture(),...change}));
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
});
test('proof-reserve tooling cannot declare Ethereum mainnet ready before a ratified release',()=>{
 const mainnet={...proofFixture(),ethereumChainId:'1',token:'0xdAC17F958D2ee523a2206206994597C13D831ec7'};
 assert.throws(()=>validateProofConfiguration(mainnet),/production verifier release unavailable/);
 assert.throws(()=>validateProofConfiguration({...mainnet,token:address(1)}),/intended USDT/);
 assert.throws(()=>validateProofConfiguration({...mainnet,productionReady:true}),/cannot assert production readiness/);
});
test('proof-reserve deployment commitment binds every immutable release field',()=>{
 const expected='0x41cff47d4837956bb9202d2267ed106b146b00f76b4c23b1c92b2c1c4be9ca94';
 const result=proofReserveDeploymentConfigHash(deploymentFixture());
 assert.equal(result.identityHash,'0x5ad60f5954d204b4f647d33f7062348b996b2e35279d73717c111b9ffefdcf2f');
 assert.equal(result.policyHash,'0x1e25521a3eff1018a9f65fb94e5b6f35069b5a3145c5e86f464f2c8dbe769eb8');
 assert.equal(result.reserveConfigHash,expected);
 for(const [key,value] of Object.entries({
  reserve:address(10),token:address(11),tokenCodeHash:'0x'+'11'.repeat(32),verifier:address(12),
  verifierCodeHash:'0x'+'21'.repeat(32),verifierConfigHash:'0x'+'31'.repeat(32),
  domDomain:'0x'+'43'.repeat(32),
  activationScheduleCommitment:'0x'+'45'.repeat(32),governance:address(13),guardian:address(14),
  governanceCodeHash:'0x'+'51'.repeat(32),guardianCodeHash:'0x'+'61'.repeat(32),
  withdrawalDelaySeconds:'86401',governanceDelaySeconds:'172801',maxOutstandingBaseUnits:'100000000001',
  outflowCapacityBaseUnitsPerDay:'2000000001',ethereumChainId:'31337',
 })) assert.notEqual(proofReserveDeploymentConfigHash({...deploymentFixture(),[key]:value}).reserveConfigHash,expected,key);
 for(const change of [{extra:true},{reserve:address(8)},{tokenCodeHash:'0x'+'00'.repeat(32)},
  {withdrawalDelaySeconds:'21599'},{outflowCapacityBaseUnitsPerDay:'100000000001'}]) {
  assert.throws(()=>proofReserveDeploymentConfigHash({...deploymentFixture(),...change}));
 }
});
