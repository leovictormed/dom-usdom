import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {Wallet,getCreateAddress,keccak256} from 'ethers';
import {buildMainnetDeploymentCompletion,_mainnetDeploymentCompletionInternals}
  from '../../sdk/mainnet-deployment-completion.mjs';
import {buildMainnetDeploymentPackage} from '../../sdk/deployment-package.mjs';
import {auditedDeploymentGasLimit,MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS,
  validateMainnetDeploymentRawTransaction} from '../../sdk/mainnet-deployment-execution.mjs';

const root=new URL('../../',import.meta.url);
const read=file=>readFile(new URL(file,root),'utf8');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const jsonBytes=value=>Buffer.from(JSON.stringify(value));
const h=value=>`0x${value.repeat(64)}`;

async function completionAuthority() {
  const wallet=new Wallet('0x0123456789012345678901234567890123456789012345678901234567890123');
  const names=['finalizedBurnVerifier','checkpointVerifier','checkpointRegistry','reserve'];
  const data='0x60006000f3',runtime=h('2');
  const plans=Object.fromEntries(names.map((name,index)=>[name,{from:wallet.address,
    nonce:String(7+index),expectedContract:getCreateAddress({from:wallet.address,nonce:7+index}),
    expectedInitcodeHash:keccak256(data),expectedRuntimeCodeHash:runtime,data}]));
  const packageValue=buildMainnetDeploymentPackage({releaseConfigSha256:'33'.repeat(32),
    observationDocumentSha256:'44'.repeat(32),observationHash:h('5'),plans,
    approvedArtifacts:Object.fromEntries(names.map(name=>[name,{expectedContract:plans[name].expectedContract,
      expectedInitcodeHash:plans[name].expectedInitcodeHash,expectedRuntimeCodeHash:runtime}]))});
  const packageBytes=jsonBytes(packageValue),packageSha256=sha(packageBytes);
  let maxFee=1n; for(let index=0;index<12;index++) maxFee=(maxFee*9n+7n)/8n;
  maxFee+=MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS;
  const stages=[];
  for(let index=0;index<4;index++) {
    const planned=packageValue.transactions[index],gasLimit=auditedDeploymentGasLimit(planned.name,data);
    const rawTransaction=await wallet.signTransaction({type:2,chainId:1,nonce:7+index,to:null,
      value:0,data,gasLimit,maxFeePerGas:maxFee,
      maxPriorityFeePerGas:MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS,accessList:[]});
    const handoff={schema:'usdom-mainnet-deployment-ledger-handoff-v1',chainId:'1',
      releaseConfigSha256:packageValue.releaseConfigSha256,packageSha256,
      rpcCatalogSha256:'66'.repeat(32),observationDocumentSha256:packageValue.observationDocumentSha256,
      observationHash:packageValue.observationHash,transaction:planned};
    const decoded=validateMainnetDeploymentRawTransaction({raw:rawTransaction,packageValue,
      packageBytes,packageSha256,handoff,index:String(index)});
    const rawTransactionBytes=Buffer.from(`${rawTransaction}\n`);
    const raw={...decoded,chainId:'1',releaseConfigSha256:packageValue.releaseConfigSha256,
      packageSha256,rpcCatalogSha256:handoff.rpcCatalogSha256,
      observationDocumentSha256:packageValue.observationDocumentSha256,
      observationHash:packageValue.observationHash,rawSha256:sha(rawTransactionBytes)};
    const blockNumber=index<2?'0x10':`0x${(15+index).toString(16)}`;
    const blockHash=index<2?h('a'):h(String(index));
    const receipt={schema:'usdom-mainnet-deployment-receipt-v1',transactionHash:raw.transactionHash,
      blockNumber,blockHash,transactionIndex:`0x${(index+1).toString(16)}`,status:'0x1',
      from:raw.from,to:null,contractAddress:raw.expectedContract,gasUsed:'0x5208',
      effectiveGasPrice:'0x1',actualCost:'21000'};
    const finalizedBlockNumber=`0x${(32+index).toString(16)}`,finalizedBlockHash=h('f');
    const completion={schema:'usdom-mainnet-deployment-evidence-v1',index:String(index),
      name:planned.name,chainId:'1',releaseConfigSha256:raw.releaseConfigSha256,
      packageSha256,rpcCatalogSha256:raw.rpcCatalogSha256,
      observationDocumentSha256:raw.observationDocumentSha256,observationHash:raw.observationHash,
      transactionHash:raw.transactionHash,from:raw.from,nonce:raw.nonce,rawSha256:raw.rawSha256,
      initcodeHash:planned.initcodeHash,expectedContract:planned.expectedContract,
      runtimeCodeHash:planned.expectedRuntimeCodeHash,receiptBlockNumber:blockNumber,receiptBlockHash:blockHash,
      finalizedBlockNumber,finalizedBlockHash};
    const anchor={schema:'usdom-mainnet-deployment-fee-anchor-v1',index:String(index),name:planned.name,
      chainId:'1',packageSha256,observationDocumentSha256:raw.observationDocumentSha256,
      observationHash:raw.observationHash,finalizedBlockNumber:blockNumber,finalizedBlockHash:blockHash,
      maximumBaseFeePerGas:'1',gasLimit:raw.gasLimit,maxFeePerGas:raw.maxFeePerGas};
    stages.push({raw,receipt,completion,anchor,rawTransactionBytes,rawBytes:jsonBytes(raw),
      receiptBytes:jsonBytes(receipt),completionBytes:jsonBytes(completion),anchorBytes:jsonBytes(anchor)});
  }
  return {packageValue,packageBytes,stages};
}

test('deployment phase executes all four ordered CREATE stages before postdeployment preflight',async()=>{
  const generator=await read('scripts/generate-closed-mainnet-phase-command.sh');
  const phase=generator.slice(generator.indexOf('  execute-mainnet-deployment-secret)'),
    generator.indexOf('  prepare-native-wallet-secret)'));
  assert.match(phase,/for index in 0 1/);
  assert.match(phase,/for index in 2 3/);
  assert.ok(phase.indexOf('execute:mainnet-deployment')<phase.indexOf('materialize-mainnet-deployment-completion.mjs'));
  assert.ok(phase.indexOf('for index in 0 1')<phase.indexOf('materialize:mainnet-predeployment-attestation'));
  assert.ok(phase.indexOf('materialize:mainnet-predeployment-attestation')<phase.indexOf('for index in 2 3'));
  assert.ok(phase.indexOf('materialize-mainnet-deployment-completion.mjs')<phase.indexOf('materialize:mainnet-cold-start-attestation'));
  assert.match(phase,/check:mainnet-cold-start/);
});

test('aggregate completion binds package order, raw CREATE, receipts and finality evidence',async()=>{
  const sdk=await read('sdk/mainnet-deployment-completion.mjs');
  for(const token of ['validateMainnetDeploymentPackage','validateMainnetDeploymentRawTransaction',
    'validateDeploymentStageLink','stages.length!==4','planned.nonce',
    'planned.expectedContract','planned.expectedRuntimeCodeHash']) assert.ok(sdk.includes(token));
  for(const token of ['parseStrictJsonBytes','bindJson(packageValue,packageBytes',
    'bindJson(stage.raw,stage.rawBytes','bindJson(stage.receipt,stage.receiptBytes',
    'bindJson(stage.completion,stage.completionBytes','bindJson(stage.anchor,stage.anchorBytes',
    'stage.raw.rawSha256!==sha(stage.rawTransactionBytes)']) assert.ok(sdk.includes(token),token);
});

test('completion rejects detached JSON values and noncanonical authority bytes',()=>{
  const value={schema:'example',nested:{value:'bound'}};
  assert.doesNotThrow(()=>_mainnetDeploymentCompletionInternals.bindJson(value,
    Buffer.from(`${JSON.stringify(value)}\n`),'fixture'));
  assert.throws(()=>_mainnetDeploymentCompletionInternals.bindJson(value,
    Buffer.from('{"schema":"example","nested":{"value":"changed"}}\n'),'fixture'),
  /bytes differ from parsed authority/);
  assert.throws(()=>_mainnetDeploymentCompletionInternals.bindJson(value,
    Buffer.from('{"schema":"example","schema":"example","nested":{"value":"bound"}}\n'),'fixture'),
  /duplicate object key/);
});

test('completion rejects block chronology impossible for consecutive deployer nonces',()=>{
  const make=(receipt,receiptHash,transactionIndex,finalized,finalizedHash)=>({
    receiptBlockNumber:receipt,receiptBlockHash:receiptHash,
    receiptTransactionIndex:transactionIndex,
    finalizedBlockNumber:finalized,finalizedBlockHash:finalizedHash,
  });
  const h=value=>`0x${value.repeat(64)}`;
  const valid=[make('0x10',h('1'),'0x1','0x12',h('a')),
    make('0x10',h('1'),'0x2','0x13',h('b')),
    make('0x11',h('2'),'0x0','0x13',h('b')),
    make('0x12',h('3'),'0x0','0x14',h('c'))];
  assert.doesNotThrow(()=>_mainnetDeploymentCompletionInternals.validateDeploymentChronology(valid));
  for(const mutate of [
    value=>{value[2].receiptBlockNumber='0xf';},
    value=>{value[2].finalizedBlockNumber='0x11';},
    value=>{value[1].receiptBlockHash=h('9');},
    value=>{value[1].receiptTransactionIndex='0x1';},
    value=>{value[2].finalizedBlockHash=h('9');},
  ]) {
    const changed=structuredClone(valid); mutate(changed);
    assert.throws(()=>_mainnetDeploymentCompletionInternals.validateDeploymentChronology(changed),
      /chronology/);
  }
});

test('completion builder rejects reordered receipts and duplicate same-block transaction indexes',async()=>{
  const authority=await completionAuthority();
  const completion=buildMainnetDeploymentCompletion(authority);
  assert.deepEqual(completion.deployments.map(value=>value.receiptTransactionIndex),
    ['0x1','0x2','0x3','0x4']);
  for(const mutate of [
    stages=>{
      stages[2].receipt.blockNumber='0xf'; stages[2].receipt.blockHash=h('9');
      stages[2].completion.receiptBlockNumber='0xf'; stages[2].completion.receiptBlockHash=h('9');
    },
    stages=>{stages[1].receipt.transactionIndex=stages[0].receipt.transactionIndex;},
  ]) {
    const changed={...authority,stages:structuredClone(authority.stages)}; mutate(changed.stages);
    for(const stage of changed.stages) {
      stage.rawTransactionBytes=Buffer.from(stage.rawTransactionBytes);
      stage.rawBytes=jsonBytes(stage.raw); stage.receiptBytes=jsonBytes(stage.receipt);
      stage.completionBytes=jsonBytes(stage.completion); stage.anchorBytes=jsonBytes(stage.anchor);
    }
    assert.throws(()=>buildMainnetDeploymentCompletion(changed),/chronology/);
  }
});

test('open-claims DAG places deployment before proof and pilot operations',()=>{
  const writer=fileURLToPath(new URL('../../scripts/write-open-claims-execution-plan.mjs',import.meta.url));
  const result=spawnSync(process.execPath,[writer],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  const plan=JSON.parse(result.stdout),deployment=plan.phaseOrder.indexOf('execute-mainnet-deployment-secret');
  assert.ok(deployment>plan.phaseOrder.indexOf('prepare-deployment'));
  for(const phase of ['produce-checkpoint-evidence-secret','execute-pilot-deposit-secret',
    'execute-pilot-redemption-secret']) assert.ok(deployment<plan.phaseOrder.indexOf(phase));
  assert.match(plan.phaseArtifacts[deployment].generatedScriptSha256,/^[0-9a-f]{64}$/);
});
