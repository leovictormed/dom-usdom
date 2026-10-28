import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {AbiCoder,concat,keccak256} from 'ethers';
import {deriveReserveArtifactBinding,deriveReserveInitcodeHash} from '../../sdk/compiled-runtime.mjs';
import {proofReserveDeploymentConfigHash} from '../../sdk/configuration.mjs';

const root=new URL('../../',import.meta.url),artifact=JSON.parse(readFileSync(new URL('out/USDOMProofReserve.sol/USDOMProofReserve.json',root)));
const address=n=>'0x'+n.toString(16).padStart(40,'0'),hash=n=>'0x'+n.toString(16).padStart(64,'0');
const tuple='tuple(address token,address verifier,address checkpointRegistry,bytes32 domDomain,bytes32 activationScheduleCommitment,address governance,address guardian,uint64 withdrawalDelay,uint64 governanceDelay,uint64 maxOutstanding,uint64 outflowCapacity,bool pilotRestricted)';
const fields=['token','verifier','checkpointRegistry','domDomain','activationScheduleCommitment','governance','guardian','withdrawalDelay','governanceDelay','maxOutstanding','outflowCapacity','pilotRestricted'];
const release={ethereumChainId:'1',reserve:address(99),token:address(1),tokenCodeHash:hash(2),verifier:address(3),verifierCodeHash:hash(4),verifierConfigHash:hash(5),checkpointRegistry:address(6),checkpointRegistryRuntimeCodeHash:hash(7),checkpointRegistryConfigHash:hash(8),domDomain:hash(9),activationScheduleCommitment:hash(10),governance:address(11),governanceCodeHash:hash(12),governanceImplementation:address(13),governanceImplementationCodeHash:hash(14),governanceOwnersCommitment:hash(15),guardian:address(16),guardianCodeHash:hash(17),guardianImplementation:address(18),guardianImplementationCodeHash:hash(19),guardianOwnersCommitment:hash(20),withdrawalDelaySeconds:'21600',governanceDelaySeconds:'172800',maxOutstandingBaseUnits:'100000000000',outflowCapacityBaseUnitsPerDay:'2000000000'};
const constructorValue={token:release.token,verifier:release.verifier,checkpointRegistry:release.checkpointRegistry,domDomain:release.domDomain,activationScheduleCommitment:release.activationScheduleCommitment,governance:release.governance,guardian:release.guardian,withdrawalDelay:release.withdrawalDelaySeconds,governanceDelay:release.governanceDelaySeconds,maxOutstanding:release.maxOutstandingBaseUnits,outflowCapacity:release.outflowCapacityBaseUnitsPerDay,pilotRestricted:true};
const coder=AbiCoder.defaultAbiCoder(),creation=artifact.bytecode.object;
const sourceContents=Object.fromEntries(Object.keys(artifact.metadata.sources).map(path=>[path,readFileSync(new URL(path,root))]));

test('ethers, cast and solc constructor ABI produce one exact reserve initcode',()=>{
 const constructor=artifact.abi.find(value=>value.type==='constructor');
 assert.deepEqual(constructor.inputs[0].components.map(value=>value.name),fields);
 assert.equal(constructor.inputs[0].type,'tuple');
 const ethersEncoded=coder.encode([tuple],[constructorValue]);
 const cast=spawnSync('/home/leonardov/.foundry/bin/cast',['abi-encode','f(address,address,address,bytes32,bytes32,address,address,uint64,uint64,uint64,uint64,bool)',...fields.map(field=>String(constructorValue[field]))],{encoding:'utf8'});
 assert.equal(cast.status,0,cast.stderr);
 assert.equal(cast.stdout.trim().toLowerCase(),ethersEncoded.toLowerCase());
 const derived=deriveReserveInitcodeHash({artifact,releaseConfig:release,sourceContents});
 assert.equal(derived.initcode,concat([creation,ethersEncoded]));
 assert.equal(derived.initcodeHash,keccak256(concat([creation,cast.stdout.trim()])));
});

test('artifact binding makes config, immutable runtime and constructor initcode concordant',()=>{
 const configuration=proofReserveDeploymentConfigHash({...release});
 const bound=deriveReserveArtifactBinding({artifact,releaseConfig:{...release,reserveConfigHash:configuration.reserveConfigHash},sourceContents});
 assert.equal(bound.reserveConfigHash,configuration.reserveConfigHash);
 assert.equal(bound.initcodeHash,deriveReserveInitcodeHash({artifact,releaseConfig:release,sourceContents}).initcodeHash);
 assert.equal(bound.runtimeSize,(artifact.deployedBytecode.object.length-2)/2);
 assert.match(bound.runtimeCodeHash,/^0x[0-9a-f]{64}$/);
});

test('every constructor component changes initcode and the pre-pilot tuple is rejected',()=>{
 const canonical=coder.encode([tuple],[constructorValue]),base=keccak256(concat([creation,canonical]));
 const mutations={token:address(21),verifier:address(22),checkpointRegistry:address(23),domDomain:hash(24),activationScheduleCommitment:hash(25),governance:address(26),guardian:address(27),withdrawalDelay:'21601',governanceDelay:'172801',maxOutstanding:'100000000001',outflowCapacity:'2000000001',pilotRestricted:false};
 for(const [field,value] of Object.entries(mutations)) assert.notEqual(base,keccak256(concat([creation,coder.encode([tuple],[{...constructorValue,[field]:value}])])),field);
 const legacy='tuple(address token,address verifier,address checkpointRegistry,bytes32 domDomain,bytes32 activationScheduleCommitment,address governance,address guardian,uint64 withdrawalDelay,uint64 governanceDelay,uint64 maxOutstanding,uint64 outflowCapacity)';
 const {[fields.at(-1)]:_removed,...oldValue}=constructorValue;
 const oldEncoding=coder.encode([legacy],[oldValue]);
 assert.equal((oldEncoding.length-2)/2,11*32);
 assert.equal((canonical.length-2)/2,12*32);
 assert.notEqual(keccak256(concat([creation,oldEncoding])),base);
 assert.equal(coder.encode([tuple],[oldValue]),coder.encode([tuple],[{...oldValue,pilotRestricted:false}]));
});
