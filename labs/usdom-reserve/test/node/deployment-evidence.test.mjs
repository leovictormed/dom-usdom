import test from 'node:test';
import assert from 'node:assert/strict';
import {getAddress} from 'ethers';
import {projectDeploymentReceipt,validateDeploymentEvidence,validateDeploymentRawEvidence,
  validateDeploymentFeeAnchor,validateDeploymentReceiptEvidence,validateDeploymentStageLink}
  from '../../sdk/deployment-evidence.mjs';
import {MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS,MAINNET_DEPLOYMENT_MAX_GAS_LIMIT}
  from '../../sdk/mainnet-deployment-execution.mjs';

const h=n=>'0x'+n.toString(16).padStart(64,'0');
const fixture=()=>({schema:'usdom-mainnet-deployment-evidence-v1',index:'0',
  name:'finalizedBurnVerifier',chainId:'1',releaseConfigSha256:'11'.repeat(32),
  packageSha256:'22'.repeat(32),rpcCatalogSha256:'33'.repeat(32),
  observationDocumentSha256:'44'.repeat(32),observationHash:h(5),transactionHash:h(6),
  from:getAddress('0x00000000000000000000000000000000000000aa'),nonce:'8',rawSha256:'55'.repeat(32),
  initcodeHash:h(9),expectedContract:getAddress('0x00000000000000000000000000000000000000bb'),
  runtimeCodeHash:h(11),receiptBlockNumber:'0xc',receiptBlockHash:h(13),
  finalizedBlockNumber:'0xe',finalizedBlockHash:h(15)});

test('deployment evidence accepts the exact flat writer schema',()=>{
  const value=fixture(); assert.equal(validateDeploymentEvidence(value),value);
});

test('deployment fee anchor is closed, context-bound and recomputes fee projection',()=>{
  let projected=10000000000n; for(let i=0;i<12;i++) projected=(projected*9n+7n)/8n;
  projected+=2000000000n;
  const fixture=()=>({schema:'usdom-mainnet-deployment-fee-anchor-v1',index:'0',
    name:'finalizedBurnVerifier',chainId:'1',packageSha256:'22'.repeat(32),
    observationDocumentSha256:'44'.repeat(32),observationHash:h(5),finalizedBlockNumber:'0xc',
    finalizedBlockHash:h(13),maximumBaseFeePerGas:'10000000000',gasLimit:'100000',
    maxFeePerGas:projected.toString()});
  assert.equal(validateDeploymentFeeAnchor(fixture()).schema,'usdom-mainnet-deployment-fee-anchor-v1');
  for(const mutate of [v=>{v.extra=true;},v=>{delete v.packageSha256;},v=>{v.schema='v2';},
    v=>{v.chainId=1;},v=>{v.index='1';},v=>{v.finalizedBlockNumber='0x0c';},
    v=>{v.maximumBaseFeePerGas='010000000000';},v=>{v.maxFeePerGas='1';},
    v=>{v.observationHash={hash:v.observationHash};}]) {
    const value=fixture(); mutate(value); assert.throws(()=>validateDeploymentFeeAnchor(value));
  }
});

test('RPC receipt projects to one closed canonical evidence schema',()=>{
  const rpc={transactionHash:h(6).toUpperCase().replace('0X','0x'),blockNumber:'0xc',blockHash:h(13),
    transactionIndex:'0x2',
    status:'0x01',from:'0x00000000000000000000000000000000000000aa',to:null,
    contractAddress:'0x00000000000000000000000000000000000000bb',gasUsed:'0x5208',effectiveGasPrice:'0x1',logs:[]};
  const value=projectDeploymentReceipt(rpc);
  assert.deepEqual(Object.keys(value),['schema','transactionHash','blockNumber','blockHash','transactionIndex','status','from','to','contractAddress','gasUsed','effectiveGasPrice','actualCost']);
  assert.equal(validateDeploymentReceiptEvidence(value),value);
  for(const mutate of [v=>{v.extra=true;},v=>{delete v.blockHash;},v=>{v.schema='v2';},
    v=>{v.status='0x0';},v=>{v.to=v.contractAddress;},v=>{v.blockNumber='0x0c';},
    v=>{v.transactionIndex='0x02';},
    v=>{v.transactionHash={hash:v.transactionHash};},v=>{v.actualCost='1';},v=>{v.gasUsed='0x0';}]) {
    const changed=structuredClone(value); mutate(changed); assert.throws(()=>validateDeploymentReceiptEvidence(changed));
  }
});

test('RPC receipt projection bounds gas quantities before arithmetic conversion',()=>{
  const rpc={transactionHash:h(6),blockNumber:'0xc',blockHash:h(13),transactionIndex:'0x2',status:'0x1',
    from:'0x00000000000000000000000000000000000000aa',to:null,
    contractAddress:'0x00000000000000000000000000000000000000bb',
    gasUsed:'0x5208',effectiveGasPrice:'0x1'};
  for(const mutate of [
    value=>{value.gasUsed=`0x${'f'.repeat(100_000)}`;},
    value=>{value.effectiveGasPrice=`0x${'f'.repeat(100_000)}`;},
    value=>{value.gasUsed=`0x${(MAINNET_DEPLOYMENT_MAX_GAS_LIMIT+1n).toString(16)}`;},
    value=>{value.effectiveGasPrice=`0x${(MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS+1n).toString(16)}`;},
  ]) {
    const changed=structuredClone(rpc); mutate(changed);
    assert.throws(()=>projectDeploymentReceipt(changed),/(canonical lowercase hex|supported bound)/);
  }
});

const rawFixture=()=>({schema:'usdom-mainnet-deployment-raw-validation-v1',index:'0',
  name:'finalizedBurnVerifier',from:getAddress('0x00000000000000000000000000000000000000aa'),
  nonce:'8',expectedContract:getAddress('0x00000000000000000000000000000000000000bb'),
  transactionHash:h(6),gasLimit:'100000',maxFeePerGas:'10000000000',
  maxPriorityFeePerGas:'2000000000',maximumCost:'1000000000000000',chainId:'1',
  releaseConfigSha256:'11'.repeat(32),packageSha256:'22'.repeat(32),
  rpcCatalogSha256:'33'.repeat(32),observationDocumentSha256:'44'.repeat(32),
  observationHash:h(5),rawSha256:'55'.repeat(32)});

test('deployment raw evidence exact schema and arithmetic match the writer',()=>{
  const value=rawFixture(); assert.equal(validateDeploymentRawEvidence(value),value);
  for(const mutate of [
    v=>{v.extra=true;},v=>{delete v.rawSha256;},v=>{v.schema='unknown';},v=>{v.chainId=1;},
    v=>{v.index='1';},v=>{v.gasLimit='0100000';},v=>{v.maximumCost='1';},
    v=>{v.maxPriorityFeePerGas='1';},v=>{v.transactionHash={value:v.transactionHash};},
  ]) { const changed=rawFixture(); mutate(changed); assert.throws(()=>validateDeploymentRawEvidence(changed)); }
});

test('deployment stages are causally linked before completion is accepted',()=>{
  let maxFee=10000000000n; for(let i=0;i<12;i++) maxFee=(maxFee*9n+7n)/8n;
  maxFee+=2000000000n;
  const raw=rawFixture(); raw.maxFeePerGas=maxFee.toString();
  raw.maximumCost=(BigInt(raw.gasLimit)*maxFee).toString();
  const receipt={schema:'usdom-mainnet-deployment-receipt-v1',transactionHash:raw.transactionHash,
    blockNumber:'0xc',blockHash:h(13),transactionIndex:'0x2',status:'0x1',from:raw.from,to:null,
    contractAddress:raw.expectedContract,gasUsed:'0x5208',effectiveGasPrice:'0x1',actualCost:'21000'};
  const completion=fixture();
  const anchor={schema:'usdom-mainnet-deployment-fee-anchor-v1',index:raw.index,name:raw.name,
    chainId:raw.chainId,packageSha256:raw.packageSha256,
    observationDocumentSha256:raw.observationDocumentSha256,observationHash:raw.observationHash,
    finalizedBlockNumber:'0xc',finalizedBlockHash:h(13),maximumBaseFeePerGas:'10000000000',
    gasLimit:raw.gasLimit,maxFeePerGas:raw.maxFeePerGas};
  assert.equal(validateDeploymentStageLink({raw,receipt,completion,anchor}),true);
  for(const mutate of [v=>{v.receipt.transactionHash=h(99);},v=>{v.completion.rawSha256='66'.repeat(32);},
    v=>{v.anchor.gasLimit='99999';},
    v=>{v.receipt.gasUsed=`0x${(BigInt(v.raw.gasLimit)+1n).toString(16)}`;
      v.receipt.actualCost=BigInt(v.receipt.gasUsed).toString();},
    v=>{v.receipt.effectiveGasPrice=`0x${(BigInt(v.raw.maxFeePerGas)+1n).toString(16)}`;
      v.receipt.actualCost=(BigInt(v.receipt.gasUsed)*BigInt(v.receipt.effectiveGasPrice)).toString();},
    v=>{v.anchor.finalizedBlockNumber='0xf';v.anchor.finalizedBlockHash=h(15);},
    v=>{v.completion.finalizedBlockNumber=v.receipt.blockNumber;
      v.completion.finalizedBlockHash=h(99);},
    v=>{v.completion.finalizedBlockNumber=v.anchor.finalizedBlockNumber;
      v.completion.finalizedBlockHash=h(99);},
    v=>{v.anchor.finalizedBlockNumber=v.receipt.blockNumber;
      v.anchor.finalizedBlockHash=h(99);},
    v=>{v.receipt.actualCost=v.raw.maximumCost;v.raw.maximumCost='1';}]) {
    const value=structuredClone({raw,receipt,completion,anchor}); mutate(value);
    assert.throws(()=>validateDeploymentStageLink(value));
  }
});

test('deployment evidence rejects null document commitments',()=>{
  for(const build of [fixture,rawFixture]) {
    for(const field of ['releaseConfigSha256','packageSha256','rpcCatalogSha256',
      'observationDocumentSha256','rawSha256']) {
      const value=build();
      if(!(field in value)) continue;
      value[field]='00'.repeat(32);
      assert.throws(()=>build===fixture?validateDeploymentEvidence(value):validateDeploymentRawEvidence(value));
    }
  }
});

test('deployment evidence rejects extras, missing keys, nesting, versions and type drift',()=>{
  const mutations=[
    v=>{v.extra=true;},v=>{delete v.rawSha256;},v=>{v.schema='usdom-mainnet-deployment-evidence-v2';},
    v=>{v.index='1';},v=>{v.chainId=1;},v=>{v.nonce='08';},v=>{v.receiptBlockNumber='0x0c';},
    v=>{v.receiptBlockNumber='0xf';},v=>{v.transactionHash={value:v.transactionHash,extra:true};},
    v=>{v.context={packageSha256:v.packageSha256};},v=>{v.from=v.from.toLowerCase();},
  ];
  for(const mutate of mutations) { const value=fixture(); mutate(value); assert.throws(()=>validateDeploymentEvidence(value)); }
});
