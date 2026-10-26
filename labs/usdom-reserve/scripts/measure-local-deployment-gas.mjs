#!/usr/bin/env node
// Deterministic local-only measurement. It imports the authenticated Anvil
// fixture and never accepts an RPC URL, key, raw transaction or network input.
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {ContractFactory,keccak256,toUtf8Bytes} from 'ethers';
import {auditedDeploymentCreateGasCeiling,auditedDeploymentGasLimit,
  MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT}
  from '../sdk/mainnet-deployment-execution.mjs';
import {localEvm} from '../test/node/helpers/evm.mjs';
import {ANVIL_PATH,ANVIL_SHA256} from '../test/node/helpers/pinned-anvil.mjs';

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
async function load(relative) {
  const bytes=await readFile(path.join(root,relative));
  return {relative,bytes,sha256:sha(bytes),artifact:JSON.parse(bytes)};
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
    }]);
    const measured={finalizedBurnVerifier:finalized,checkpointVerifier:checkpoint,
      checkpointRegistry:registry,reserve};
    const result={};
    for(const [name,value] of Object.entries(measured)) {
      const transaction=value.contract.deploymentTransaction();
      const runtime=await rpc.provider.getCode(await value.contract.getAddress());
      result[name]={artifactPath:artifacts[name].relative,artifactSha256:artifacts[name].sha256,
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

const [artifactEntries,supportEntries]=await Promise.all([
  Promise.all(Object.entries(artifactPaths).map(async([key,value])=>[key,await load(value)])),
  Promise.all(Object.entries(supportPaths).map(async([key,value])=>[key,await load(value)])),
]);
const artifacts=Object.fromEntries(artifactEntries),support=Object.fromEntries(supportEntries);
const first=await oneRun(artifacts,support),second=await oneRun(artifacts,support);
if(JSON.stringify(first)!==JSON.stringify(second)) throw new Error('local deployment gas measurement is not reproducible');
const measuredGas=Object.values(first).reduce((sum,value)=>sum+BigInt(value.gasUsed),0n);
const plannedGas=Object.values(first).reduce((sum,value)=>sum+BigInt(value.plannedGasLimit),0n);
if(plannedGas>MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT) {
  throw new Error('current deployment plan exceeds the aggregate gas policy');
}
const report={schema:'usdom-local-deployment-gas-measurement/v1',network:'anvil-local-chain-31337',
  node:{path:process.execPath,sha256:sha(await readFile(process.execPath)),version:process.version},
  anvil:{path:ANVIL_PATH,sha256:ANVIL_SHA256},runs:2,
  supportArtifacts:Object.fromEntries(Object.entries(support).map(([name,value])=>[name,{
    artifactPath:value.relative,artifactSha256:value.sha256,
  }])),contracts:first,
  aggregate:{measuredGas:measuredGas.toString(),plannedGasLimit:plannedGas.toString(),
    sequenceGasLimit:MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT.toString(),
    policyMargin:(MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT-plannedGas).toString()},
  limitations:['local chain bypasses chain-id-1 production-pin branches',
    'support contracts are deterministic test doubles; no mainnet RPC or external deployment occurred']};
process.stdout.write(`${JSON.stringify(report,null,2)}\n`);
