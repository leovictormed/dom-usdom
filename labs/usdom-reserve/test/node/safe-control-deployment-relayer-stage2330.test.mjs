import test from 'node:test';import assert from 'node:assert/strict';
import {Wallet,keccak256} from 'ethers';import {readFile} from 'node:fs/promises';import {createHash} from 'node:crypto';
import {buildSafeDeploymentRelayerEnvelope,validateSafeDeploymentRelayerRaw} from '../../sdk/safe-control-deployment-relayer.mjs';

const relayer=new Wallet('0x'+'91'.repeat(32)),owner=new Wallet('0x'+'92'.repeat(32));
const bytes=value=>Buffer.from(`${JSON.stringify(value)}\n`),input={to:'0x1111111111111111111111111111111111111111',value:'0',data:'0x12345678'};
const pkg={factory:'0x1111111111111111111111111111111111111111',singleton:'0x2222222222222222222222222222222222222222',
 fallbackHandler:'0x3333333333333333333333333333333333333333',controls:[{role:'governance',safe:'0x4444444444444444444444444444444444444444',
 owners:[owner.address,'0x5555555555555555555555555555555555555555','0x6666666666666666666666666666666666666666'],to:input.to,data:input.data,dataHash:keccak256(input.data)}]};
const keystore={version:3,id:'00000000-0000-4000-8000-000000000000',address:relayer.address.slice(2).toLowerCase(),crypto:{ciphertext:'aa',cipherparams:{iv:'11'.repeat(16)},cipher:'aes-128-ctr',kdf:'scrypt',kdfparams:{dklen:32,n:262144,p:1,r:8,salt:'22'.repeat(32)},mac:'33'.repeat(32)}};
const keystoreBytes=bytes(keystore),policy={schema:'usdom-safe-deployment-relayer-policy/v1',chainId:'1',relayer:relayer.address,
 maxGasLimit:'1000000',maxFeePerGas:'100000000000',maxPriorityFeePerGas:'2000000000',maxTotalGasCost:'300000000000000000',
 encryptedKeystoreSha256:createHash('sha256').update(keystoreBytes).digest('hex'),gasOnlyAcknowledged:true};
const policyBytes=bytes(policy),packageBytes=bytes(pkg);

test('gas-only relayer envelope binds package, encrypted keystore, nonce and fee caps and accepts exact raw',async()=>{
 const envelope=buildSafeDeploymentRelayerEnvelope({role:'governance',input,pkg,packageBytes,policy,policyBytes,keystore,keystoreBytes,
  nonce:'7',gasLimit:'250000',maxFeePerGas:'40000000000',maxPriorityFeePerGas:'2000000000'});
 const raw=await relayer.signTransaction({type:2,chainId:1,nonce:7,to:input.to,value:0,data:input.data,gasLimit:250000,
  maxFeePerGas:40000000000n,maxPriorityFeePerGas:2000000000n,accessList:[]});
 const result=validateSafeDeploymentRelayerRaw({role:'governance',rawBytes:Buffer.from(`${raw}\n`),envelope,input,pkg,
  packageBytes,policy,policyBytes,keystore,keystoreBytes});
 assert.equal(result.from,relayer.address);assert.equal(result.nonce,'7');assert.equal(result.dataHash,keccak256(input.data));
 await assert.rejects(async()=>validateSafeDeploymentRelayerRaw({role:'governance',rawBytes:Buffer.from(`${raw.toUpperCase()}\n`),envelope,input,pkg,packageBytes,policy,policyBytes,keystore,keystoreBytes}),/framing/u);
});

test('authority overlap, cap excess and changed keystore fail closed',()=>{
 assert.throws(()=>buildSafeDeploymentRelayerEnvelope({role:'governance',input,pkg,packageBytes,policy:{...policy,relayer:owner.address},policyBytes,keystore:{...keystore,address:owner.address.slice(2).toLowerCase()},keystoreBytes,nonce:'0',gasLimit:'1',maxFeePerGas:'1',maxPriorityFeePerGas:'1'}),/policy|overlaps/u);
 assert.throws(()=>buildSafeDeploymentRelayerEnvelope({role:'governance',input,pkg,packageBytes,policy,policyBytes,keystore,keystoreBytes,nonce:'0',gasLimit:'1000001',maxFeePerGas:'1',maxPriorityFeePerGas:'1'}));
});

test('executor has no hardware signing path and stops for separately installed raw',async()=>{
 const source=await readFile(new URL('../../scripts/execute-safe-control-deployment.sh',import.meta.url),'utf8');
 for(const marker of ['safe-control-deployment-relayer-policy.json','safe-control-deployment-relayer-keystore.json',
  'prepare-safe-control-deployment-relayer-envelope.mjs','check-safe-control-deployment-relayer-raw.mjs','exit 78',
  'safe_broadcast_state=signed-unresolved','status=80','--block pending','--block finalized'])assert.ok(source.includes(marker),marker);
 assert.doesNotMatch(source,/--ledger|wallet sign|wallet address|sign-onekey|prepare-ledger|assemble-ledger/iu);
 assert.ok(source.indexOf('check-safe-control-deployment-relayer-raw.mjs')<source.indexOf('safe_broadcast_state=signed-unresolved'));
 assert.ok(source.lastIndexOf('safe_broadcast_state=clean')>source.lastIndexOf('install_private_create_once "$receipt_consensus"'));
});
