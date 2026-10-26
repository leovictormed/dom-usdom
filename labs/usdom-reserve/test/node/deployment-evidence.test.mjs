import test from 'node:test';
import assert from 'node:assert/strict';
import {getAddress} from 'ethers';
import {projectDeploymentReceipt,validateDeploymentEvidence,validateDeploymentRawEvidence,
  validateDeploymentFeeAnchor,validateDeploymentReceiptEvidence} from '../../sdk/deployment-evidence.mjs';

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
    status:'0x01',from:'0x00000000000000000000000000000000000000aa',to:null,
    contractAddress:'0x00000000000000000000000000000000000000bb',gasUsed:'0x5208',effectiveGasPrice:'0x1',logs:[]};
  const value=projectDeploymentReceipt(rpc);
  assert.deepEqual(Object.keys(value),['schema','transactionHash','blockNumber','blockHash','status','from','to','contractAddress','gasUsed','effectiveGasPrice','actualCost']);
  assert.equal(validateDeploymentReceiptEvidence(value),value);
  for(const mutate of [v=>{v.extra=true;},v=>{delete v.blockHash;},v=>{v.schema='v2';},
    v=>{v.status='0x0';},v=>{v.to=v.contractAddress;},v=>{v.blockNumber='0x0c';},
    v=>{v.transactionHash={hash:v.transactionHash};},v=>{v.actualCost='1';},v=>{v.gasUsed='0x0';}]) {
    const changed=structuredClone(value); mutate(changed); assert.throws(()=>validateDeploymentReceiptEvidence(changed));
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

test('deployment evidence rejects extras, missing keys, nesting, versions and type drift',()=>{
  const mutations=[
    v=>{v.extra=true;},v=>{delete v.rawSha256;},v=>{v.schema='usdom-mainnet-deployment-evidence-v2';},
    v=>{v.index='1';},v=>{v.chainId=1;},v=>{v.nonce='08';},v=>{v.receiptBlockNumber='0x0c';},
    v=>{v.receiptBlockNumber='0xf';},v=>{v.transactionHash={value:v.transactionHash,extra:true};},
    v=>{v.context={packageSha256:v.packageSha256};},v=>{v.from=v.from.toLowerCase();},
  ];
  for(const mutate of mutations) { const value=fixture(); mutate(value); assert.throws(()=>validateDeploymentEvidence(value)); }
});
