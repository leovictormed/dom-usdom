#!/usr/bin/env node
// Deterministic local-only measurement. It imports the authenticated Anvil
// fixture and never accepts an RPC URL, key, raw transaction or network input.
import {createHash} from 'node:crypto';
import {constants} from 'node:fs';
import {mkdir,mkdtemp,open,readFile,rm,stat} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {ContractFactory,keccak256,toUtf8Bytes} from 'ethers';
import {auditedDeploymentCreateGasCeiling,auditedDeploymentGasLimit,
  MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT}
  from '../sdk/mainnet-deployment-execution.mjs';
import {localEvm} from '../test/node/helpers/evm.mjs';
import {ANVIL_PATH,ANVIL_SHA256} from '../test/node/helpers/pinned-anvil.mjs';
import {solidityArtifactExecutableFingerprint}
  from '../sdk/solidity-artifact-executable-fingerprint.mjs';
import {assertProductionSolidityMetadata,assertReproducibleBuildEnvironment,
  productionFoundryBuildArguments,reproducibleFoundryChildEnvironment,snapshotProductionSolc}
  from '../sdk/reproducible-build-environment.mjs';
import {snapshotExecutablePath,assertExecutableUnchanged} from '../sdk/stable-executable.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const artifactPaths={
  finalizedBurnVerifier:'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json',
  checkpointVerifier:'out/DOMCheckpointRiscZeroVerifier.sol/DOMCheckpointRiscZeroVerifier.json',
  checkpointRegistry:'out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json',
  reserve:'out/USDOMProofReserve.sol/USDOMProofReserve.json',
};
const supportPaths={
  riscZero:'out/DOMFinalizedBurnRiscZeroVerifier.t.sol/MockRiscZeroVerifierV3.json',
  token:'out/Mocks.sol/HostileToken.json',singleton:'out/Mocks.sol/MockGovernance.json',
  control:'out/Mocks.sol/MockMutableSingletonControl.json',
};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
let buildRoot,captures=[];
async function load(relative) {
  const target=path.join(buildRoot,relative),handle=await open(target,constants.O_RDONLY|constants.O_NOFOLLOW);
  const before=await handle.stat({bigint:true}),named=await stat(target,{bigint:true});
  if(!before.isFile()||before.nlink!==1n||before.size<2n||before.size>64n*1024n*1024n
      ||before.dev!==named.dev||before.ino!==named.ino){await handle.close();throw new Error(`unsafe isolated artifact: ${relative}`)}
  const bytes=await handle.readFile(),after=await handle.stat({bigint:true});
  if(before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size
      ||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||BigInt(bytes.length)!==before.size){await handle.close();throw new Error(`isolated artifact changed while captured: ${relative}`)}
  const artifact=JSON.parse(bytes);
  assertProductionSolidityMetadata(artifact);
  captures.push({relative,target,handle,before});
  return {relative,bytes,executableSha256:solidityArtifactExecutableFingerprint(artifact),artifact};
}
async function oneRun(artifacts,support) {
  const cleanups=[];
  const rpc=await localEvm({after:fn=>cleanups.push(fn)});
  try {
    const signer=await rpc.provider.getSigner(0);
    async function deploy(build,args=[]) {
      const contract=await new ContractFactory(build.artifact.abi,
        build.artifact.bytecode.object,signer).deploy(...args);
      const receipt=await contract.deploymentTransaction().wait();
      if(receipt?.status!==1) throw new Error('local deployment failed');
      return {contract,receipt};
    }
    const riscZero=await deploy(support.riscZero,['0x73c457ba']);
    const singleton=await deploy(support.singleton);
    const governance=await deploy(support.control,[await singleton.contract.getAddress()]);
    const reserveGuardian=await deploy(support.control,[await singleton.contract.getAddress()]);
    const checkpointGuardian=await deploy(support.control,[await singleton.contract.getAddress()]);
    await (await governance.contract.setOwners('0x0000000000000000000000000000000000000101',
      '0x0000000000000000000000000000000000000102','0x0000000000000000000000000000000000000103')).wait();
    await (await reserveGuardian.contract.setOwners('0x0000000000000000000000000000000000000201',
      '0x0000000000000000000000000000000000000202','0x0000000000000000000000000000000000000203')).wait();
    await (await checkpointGuardian.contract.setOwners('0x0000000000000000000000000000000000000301',
      '0x0000000000000000000000000000000000000302','0x0000000000000000000000000000000000000303')).wait();
    const token=await deploy(support.token);
    const imageId=keccak256(toUtf8Bytes('USD0M LOCAL GAS IMAGE'));
    const finalized=await deploy(artifacts.finalizedBurnVerifier,
      [await riscZero.contract.getAddress(),imageId]);
    const checkpoint=await deploy(artifacts.checkpointVerifier,
      [await riscZero.contract.getAddress(),keccak256(toUtf8Bytes('USD0M LOCAL CHECKPOINT GAS IMAGE'))]);
    const bridgeDomain=keccak256(toUtf8Bytes('USD0M LOCAL GAS DOMAIN'));
    const activation=keccak256(toUtf8Bytes('USD0M LOCAL GAS ACTIVATION'));
    const initialState=keccak256(toUtf8Bytes('USD0M LOCAL GAS STATE'));
    const registry=await deploy(artifacts.checkpointRegistry,[{
      bridgeDomain,domNetworkMagic:0xA1B2C3D4,
      domChainId:keccak256(toUtf8Bytes('USD0M LOCAL GAS CHAIN')),firstV4Height:101n,
      activationEmptyStateRoot:initialState,activationScheduleCommitment:activation,
      checkpointInterval:360,confirmationDepth:30,challengePeriod:86400,
      verifier:await checkpoint.contract.getAddress(),guardian:await checkpointGuardian.contract.getAddress(),
      initialHeight:100n,initialBlock:keccak256(toUtf8Bytes('USD0M LOCAL GAS BLOCK')),
      initialStateRoot:initialState,initialContextHash:keccak256(toUtf8Bytes('USD0M LOCAL GAS CONTEXT')),
      initialTotalDifficulty:1_000_000n,
    }]);
    const reserve=await deploy(artifacts.reserve,[{
      token:await token.contract.getAddress(),verifier:await finalized.contract.getAddress(),
      checkpointRegistry:await registry.contract.getAddress(),domDomain:bridgeDomain,
      activationScheduleCommitment:activation,governance:await governance.contract.getAddress(),
      guardian:await reserveGuardian.contract.getAddress(),withdrawalDelay:86400,
      governanceDelay:172800,maxOutstanding:100_000_000_000n,outflowCapacity:2_000_000_000n,
      pilotRestricted:true,
    }]);
    const measured={finalizedBurnVerifier:finalized,checkpointVerifier:checkpoint,
      checkpointRegistry:registry,reserve};
    const result={};
    for(const [name,value] of Object.entries(measured)) {
      const transaction=value.contract.deploymentTransaction();
      const runtime=await rpc.provider.getCode(await value.contract.getAddress());
      result[name]={artifactPath:artifacts[name].relative,
        artifactExecutableSha256:artifacts[name].executableSha256,
        initcodeSha256:sha(Buffer.from(transaction.data.slice(2),'hex')),
        initcodeBytes:(transaction.data.length-2)/2,runtimeCodeHash:keccak256(runtime),
        runtimeBytes:(runtime.length-2)/2,gasUsed:value.receipt.gasUsed.toString(),
        auditedCreateGasCeiling:auditedDeploymentCreateGasCeiling(name).toString(),
        measuredMargin:(auditedDeploymentCreateGasCeiling(name)-value.receipt.gasUsed).toString(),
        plannedGasLimit:auditedDeploymentGasLimit(name,transaction.data).toString()};
      if(value.receipt.gasUsed>auditedDeploymentCreateGasCeiling(name)) {
        throw new Error(`${name} exceeds its audited CREATE gas ceiling`);
      }
    }
    return result;
  } finally {
    for(const cleanup of cleanups.reverse()) await cleanup();
  }
}

assertReproducibleBuildEnvironment(process.env);
const forge=await snapshotExecutablePath(path.join(process.env.HOME,'.foundry/bin/forge')),
 solc=await snapshotProductionSolc(process.env);
const temporary=await mkdtemp(path.join(os.tmpdir(),'usdom-local-deployment-gas-'));
buildRoot=temporary;const output=path.join(temporary,'out'),cache=path.join(temporary,'cache'),configHome=path.join(temporary,'config');
await mkdir(configHome,{mode:0o700});
const buildArguments=productionFoundryBuildArguments('contracts/USDOMProofReserve.sol',output,cache,root,solc.path);
buildArguments.splice(1,1,'contracts/USDOMProofReserve.sol','contracts/DOMCheckpointRegistry.sol',
 'contracts/DOMCheckpointRiscZeroVerifier.sol','contracts/DOMFinalizedBurnRiscZeroVerifier.sol');
const supportBuildArguments=productionFoundryBuildArguments('test/solidity/USDOMProofReserve.t.sol',output,cache,root,solc.path);
supportBuildArguments.splice(1,1,'test/solidity/DOMFinalizedBurnRiscZeroVerifier.t.sol','test/solidity/Mocks.sol');
const ignoredIndex=supportBuildArguments.indexOf('6335');
supportBuildArguments.splice(ignoredIndex+1,0,'--ignored-error-codes','3860','--ignored-error-codes','5574');
supportBuildArguments.splice(supportBuildArguments.indexOf('-D'),2);
supportBuildArguments.splice(supportBuildArguments.indexOf('--force'),1);
let artifactEntries,supportEntries,first,second;
try {
 await runPinnedExecutable(forge,buildArguments,{cwd:root,maxBuffer:64*1024*1024,timeout:10*60*1000,
  env:reproducibleFoundryChildEnvironment(process.env,configHome)});
 await runPinnedExecutable(forge,supportBuildArguments,{cwd:root,maxBuffer:64*1024*1024,timeout:10*60*1000,
  env:reproducibleFoundryChildEnvironment(process.env,configHome)});
 [artifactEntries,supportEntries]=await Promise.all([
  Promise.all(Object.entries(artifactPaths).map(async([key,value])=>[key,await load(value)])),
  Promise.all(Object.entries(supportPaths).map(async([key,value])=>[key,await load(value)])),
 ]);
 const artifacts=Object.fromEntries(artifactEntries),support=Object.fromEntries(supportEntries);
 first=await oneRun(artifacts,support);second=await oneRun(artifacts,support);
 for(const capture of captures){const after=await capture.handle.stat({bigint:true}),named=await stat(capture.target,{bigint:true});if(capture.before.dev!==after.dev||capture.before.ino!==after.ino||capture.before.size!==after.size||capture.before.mtimeNs!==after.mtimeNs||capture.before.ctimeNs!==after.ctimeNs||after.dev!==named.dev||after.ino!==named.ino)throw new Error(`isolated artifact set changed: ${capture.relative}`)}
 await assertExecutableUnchanged(forge);await assertExecutableUnchanged(solc);
} finally {for(const capture of captures)await capture.handle.close();await rm(temporary,{recursive:true,force:true});}
const artifacts=Object.fromEntries(artifactEntries),support=Object.fromEntries(supportEntries);
if(JSON.stringify(first)!==JSON.stringify(second)) throw new Error('local deployment gas measurement is not reproducible');
const measuredGas=Object.values(first).reduce((sum,value)=>sum+BigInt(value.gasUsed),0n);
const plannedGas=Object.values(first).reduce((sum,value)=>sum+BigInt(value.plannedGasLimit),0n);
if(plannedGas>MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT) {
  throw new Error('current deployment plan exceeds the aggregate gas policy');
}
const report={schema:'usdom-local-deployment-gas-measurement/v2',network:'anvil-local-chain-31337',
  node:{path:'node',sha256:sha(await readFile(process.execPath)),version:process.version},
  anvil:{path:ANVIL_PATH,sha256:ANVIL_SHA256},runs:2,
  supportArtifacts:Object.fromEntries(Object.entries(support).map(([name,value])=>[name,{
    artifactPath:value.relative,artifactExecutableSha256:value.executableSha256,
  }])),contracts:first,
  aggregate:{measuredGas:measuredGas.toString(),plannedGasLimit:plannedGas.toString(),
    sequenceGasLimit:MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT.toString(),
    policyMargin:(MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT-plannedGas).toString()},
  limitations:['local chain bypasses chain-id-1 production-pin branches',
    'support contracts are deterministic test doubles; no mainnet RPC or external deployment occurred']};
process.stdout.write(`${JSON.stringify(report,null,2)}\n`);
