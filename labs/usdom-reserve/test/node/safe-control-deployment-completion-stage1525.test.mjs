import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {_safeControlDeploymentCompletionInternals} from '../../sdk/safe-control-deployment-completion.mjs';
import {buildSafeControlDeploymentCompletion} from '../../sdk/safe-control-deployment-completion.mjs';
import {Wallet,keccak256} from 'ethers';
import {buildRecoverableSafeControlDeploymentPackage,SAFE_MAINNET_IDENTITY}
  from '../../sdk/safe-control-deployment.mjs';
import {safeControlConfigurationHash,_safeControlObservationInternals}
  from '../../sdk/safe-control-observation.mjs';
import {rpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';

const root=new URL('../../',import.meta.url);
const read=file=>readFile(new URL(file,root),'utf8');
const hash=value=>`0x${value.repeat(64)}`;
const json=value=>Buffer.from(JSON.stringify(value));

async function safeCompletionAuthority() {
  const fixture=JSON.parse(await read('test/fixtures/safe-1.4.1-mainnet.json'));
  const ownersByRole={governance:['11','12','13'],reserveGuardian:['11','12','13'],
    checkpointGuardian:['11','12','13'],usdtCustody:['11','12','13']};
  for(const [role,values] of Object.entries(ownersByRole)) {
    ownersByRole[role]=values.map(value=>`0x${`100${value}`.padStart(40,'0')}`);
  }
  const packageDocument=buildRecoverableSafeControlDeploymentPackage({ownersByRole,
    proxyCreationCode:fixture.proxyCreationCode});
  const packageBytes=json(packageDocument);
  const packageHash=_safeControlObservationInternals.documentHash(packageDocument);
  const proxyRuntimeCodeHash=hash('9');
  const roles=packageDocument.controls.map(control=>{
    const role={role:control.role,address:control.safe,runtimeCodeHash:proxyRuntimeCodeHash,
      singleton:SAFE_MAINNET_IDENTITY.singleton,fallbackHandler:SAFE_MAINNET_IDENTITY.fallbackHandler,
      guard:'0x'+'0'.repeat(40),owners:packageDocument.ownersByRole[control.role],threshold:'2',
      nonce:'0',modules:[]};
    return {...role,configurationHash:safeControlConfigurationHash({...role,safe:role.address,packageHash})};
  });
  const baseline={schema:'usdom-safe-controls-finalized-snapshot/v2',ethereumChainId:'1',packageHash,
    finalizedBlockNumber:'18',finalizedBlockHash:hash('a'),proxyRuntimeCodeHash,roles,
    rpcConsensus:rpcConsensusEvidence([{sourceId:'a',originKeccak256:hash('7')},
      {sourceId:'b',originKeccak256:hash('8')}])};
  baseline.snapshotHash=_safeControlObservationInternals.documentHash(baseline);
  const baselineBytes=json(baseline),wallet=new Wallet(
    '0x0123456789012345678901234567890123456789012345678901234567890123');
  const entries=[];
  for(let index=0;index<4;index++) {
    const control=packageDocument.controls[index];
    const raw=await wallet.signTransaction({type:2,chainId:1,nonce:7+index,to:control.to,value:0,
      data:control.data,gasLimit:500000,maxFeePerGas:3000000000n,maxPriorityFeePerGas:2000000000n});
    const validation={schema:'usdom-safe-deployment-raw/v1',role:control.role,safe:control.safe,
      from:wallet.address,nonce:String(7+index),to:control.to,dataHash:keccak256(control.data),
      transactionHash:keccak256(raw),gasLimit:'500000',maxFeePerGas:'3000000000',rawHash:keccak256(raw)};
    const journal={schema:'usdom-safe-deployment-journal/v1',role:control.role,raw,validation};
    const receipt={schema:'usdom-safe-deployment-receipt/v1',role:control.role,
      transactionHash:validation.transactionHash,blockNumber:'0x10',blockHash:hash('b'),
      transactionIndex:`0x${index.toString(16)}`,status:'0x1',from:wallet.address,to:control.to};
    entries.push({role:control.role,journal,journalBytes:json(journal),rawBytes:Buffer.from(`${raw}\n`),
      validation,validationBytes:json(validation),receipt,receiptBytes:json(receipt)});
  }
  return {packageDocument,packageBytes,baseline,baselineBytes,roles:entries};
}

test('deployment executor publishes finalized baseline before output-last completion',async()=>{
  const source=await read('scripts/execute-safe-control-deployment.sh');
  const baseline=source.lastIndexOf('scripts/collect-recoverable-safe-controls.mjs');
  const completion=source.lastIndexOf('scripts/materialize-safe-control-deployment-completion.mjs');
  const success=source.lastIndexOf('All four recoverable Safes are finalized');
  assert.ok(baseline>0&&completion>baseline&&success>completion);
  assert.match(source,/safe-deployment-finalized-completion\.json/);
  assert.match(source,/run_cmp -s "\$completion_candidate" "\$temporary\/safe-deployment-completion\.rechecked\.json"/);
});

test('completion binds journals, raw transactions, receipts and exact 2-of-3 baseline',async()=>{
  const sdk=await read('sdk/safe-control-deployment-completion.mjs');
  for(const token of ['validateRecoverableSafeControlBaseline','Transaction.from(raw)',
    'validateRecoverableSafeControlPackage',
    "journal.schema!=='usdom-safe-deployment-journal/v1'","receipt.status!=='0x1'",
    "observed.threshold!=='2'","observed.owners.length!==3",
    'BigInt(receipt.blockHash)===0n',
    'BigInt(receipt.blockNumber)>BigInt(baseline.finalizedBlockNumber)']) assert.ok(sdk.includes(token));
});

test('Safe completion rejects an object detached from its hashed bytes',()=>{
  const value={role:'governance'};
  assert.doesNotThrow(()=>_safeControlDeploymentCompletionInternals.bindJson(value,
    Buffer.from('{"role":"governance"}\n'),'fixture'));
  assert.throws(()=>_safeControlDeploymentCompletionInternals.bindJson(value,
    Buffer.from('{"role":"reserveGuardian"}\n'),'fixture'),/bytes differ/);
});

test('Safe completion rejects nonce drift and same-height block identity conflicts',()=>{
  const address=value=>`0x${value.repeat(40)}`;
  const hash=value=>`0x${value.repeat(64)}`;
  const baseline={finalizedBlockNumber:'0x12',finalizedBlockHash:hash('a')};
  const valid=[0,1,2,3].map((offset,index)=>({from:address('1'),nonce:String(7+offset),
    receiptBlockNumber:index===3?'0x12':`0x${(15+index).toString(16)}`,
    receiptBlockHash:index===3?hash('a'):hash(String(index+1)),
    receiptTransactionIndex:`0x${index.toString(16)}`}));
  assert.doesNotThrow(()=>_safeControlDeploymentCompletionInternals
    .validateSafeDeploymentSequence(valid,baseline));
  for(const mutate of [
    value=>{value[1].from=address('2');},
    value=>{value[1].nonce='9';},
    value=>{value[3].receiptBlockHash=hash('b');},
    value=>{value[1].receiptBlockNumber='0xf';},
    value=>{value[1].receiptBlockNumber=value[0].receiptBlockNumber;
      value[1].receiptBlockHash=hash('b');},
    value=>{value[1].receiptBlockNumber=value[0].receiptBlockNumber;
      value[1].receiptBlockHash=value[0].receiptBlockHash;
      value[1].receiptTransactionIndex=value[0].receiptTransactionIndex;},
  ]) {
    const changed=structuredClone(valid); mutate(changed);
    assert.throws(()=>_safeControlDeploymentCompletionInternals
      .validateSafeDeploymentSequence(changed,baseline),/deployer|baseline|chronology/);
  }
});

test('Safe completion builder rejects duplicate and reversed same-block transaction indexes',async()=>{
  const authority=await safeCompletionAuthority();
  assert.deepEqual(buildSafeControlDeploymentCompletion(authority).deployments
    .map(value=>value.receiptTransactionIndex),['0x0','0x1','0x2','0x3']);
  for(const index of ['0x0','0x2']) {
    const changed={...authority,roles:structuredClone(authority.roles)};
    changed.roles[1].receipt.transactionIndex=index;
    for(const role of changed.roles) {
      role.rawBytes=Buffer.from(role.rawBytes); role.journalBytes=json(role.journal);
      role.validationBytes=json(role.validation); role.receiptBytes=json(role.receipt);
    }
    assert.throws(()=>buildSafeControlDeploymentCompletion(changed),/chronology/);
  }
});

test('generated execute and materialize phases reject missing or divergent completion',async()=>{
  const generator=await read('scripts/generate-closed-mainnet-phase-command.sh');
  const execute=generator.slice(generator.indexOf('  execute-safe-controls-deployment-secret)'),
    generator.indexOf('  prepare-safe-recovery-secret)'));
  const materialize=generator.slice(generator.indexOf('  materialize-safe-control-config)'),
    generator.indexOf('  validate-local)'));
  for(const phase of [execute,materialize]) {
    assert.match(phase,/safe-deployment-finalized-completion\.json/);
    assert.match(phase,/materialize-safe-control-deployment-completion\.mjs/);
    assert.match(phase,/cmp -s/);
  }
});
