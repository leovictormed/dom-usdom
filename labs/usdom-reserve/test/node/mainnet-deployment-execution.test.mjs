import test from 'node:test';
import assert from 'node:assert/strict';
import {Wallet,getCreateAddress,keccak256} from 'ethers';
import {readFile} from 'node:fs/promises';
import {
  auditedDeploymentGasLimit,
  MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS,MAINNET_DEPLOYMENT_MAX_GAS_LIMIT,
  MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST,
  MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS,planMainnetDeploymentGas,
  validateMainnetDeploymentRawTransaction,
} from '../../sdk/mainnet-deployment-execution.mjs';
import {buildMainnetDeploymentPackage} from '../../sdk/deployment-package.mjs';

const wallet=new Wallet('0x0123456789012345678901234567890123456789012345678901234567890123');
const expected={
  name:'finalizedBurnVerifier',from:wallet.address,nonce:'7',data:'0x60006000f3',
  expectedContract:getCreateAddress({from:wallet.address,nonce:7}),
};
expected.initcodeHash=keccak256(expected.data);
const auditedGasLimit=auditedDeploymentGasLimit(expected.name,expected.data);
const valid={type:2,chainId:1,nonce:7,to:null,value:0,data:expected.data,gasLimit:auditedGasLimit,
  maxFeePerGas:10_000_000_000n,maxPriorityFeePerGas:MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS,
  accessList:[]};

test('mainnet deployment raw validator independently recovers the exact bounded CREATE',async()=>{
  const raw=await wallet.signTransaction(valid);
  const result=validateMainnetDeploymentRawTransaction({raw,expected,index:'0'});
  assert.equal(result.from,wallet.address);
  assert.equal(result.nonce,'7');
  assert.equal(result.gasLimit,auditedGasLimit.toString());
  assert.equal(result.maxPriorityFeePerGas,MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS.toString());
  assert.match(result.transactionHash,/^0x[0-9a-f]{64}$/);
});

test('mainnet deployment raw validator rejects every security-relevant field change',async()=>{
  const cases=[
    {...valid,chainId:31337},
    {...valid,nonce:8},
    {...valid,to:wallet.address},
    {...valid,value:1},
    {...valid,data:'0x6001'},
    {...valid,gasLimit:auditedGasLimit-1n},
    {...valid,gasLimit:auditedGasLimit+1n},
    {...valid,gasLimit:MAINNET_DEPLOYMENT_MAX_GAS_LIMIT+1n},
    {...valid,maxFeePerGas:MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS+1n},
    {...valid,gasLimit:auditedGasLimit,
      maxFeePerGas:MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST/auditedGasLimit+1n},
    {...valid,maxPriorityFeePerGas:MAINNET_DEPLOYMENT_PRIORITY_FEE_PER_GAS+1n},
    {...valid,accessList:[{address:wallet.address,storageKeys:[]}]},
  ];
  for(const transaction of cases) {
    const raw=await wallet.signTransaction(transaction);
    assert.throws(()=>validateMainnetDeploymentRawTransaction({raw,expected,index:'0'}),
      /differs from the bounded mainnet deployment plan/);
  }
  const other=new Wallet('0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd');
  const otherRaw=await other.signTransaction(valid);
  assert.throws(()=>validateMainnetDeploymentRawTransaction({
    raw:otherRaw,expected,index:'0',
  }),/differs from the bounded mainnet deployment plan/);
  const raw=await wallet.signTransaction(valid);
  assert.throws(()=>validateMainnetDeploymentRawTransaction({
    raw,expected:{...expected,data:'0x6001'},index:'0',
  }),/deployment plan is malformed/);
});

test('deployment gas planner binds audited trace, calldata, EIP-3860 and 25 percent margin',()=>{
  const maximumEstimate=(auditedGasLimit*100n)/125n;
  assert.equal(planMainnetDeploymentGas({name:expected.name,data:expected.data,maximumEstimate}),
    auditedGasLimit);
  assert.throws(()=>planMainnetDeploymentGas({
    name:expected.name,data:expected.data,maximumEstimate:maximumEstimate+1n,
  }),/exceeds the audited constructor policy/);
  assert.ok(auditedDeploymentGasLimit('reserve',`0x${'ff'.repeat(25_073)}`)<
    MAINNET_DEPLOYMENT_MAX_GAS_LIMIT);
  assert.throws(()=>auditedDeploymentGasLimit('reserve',`0x${'ff'.repeat(40_961)}`),
    /EIP-3860 safety margin/);
});

test('mainnet deployment raw validator independently binds CREATE and approved initcode',async()=>{
  const raw=await wallet.signTransaction(valid);
  for(const changed of [
    {...expected,expectedContract:wallet.address},
    {...expected,initcodeHash:`0x${'11'.repeat(32)}`},
    {...expected,initcodeHash:expected.initcodeHash.toUpperCase()},
    {...expected,nonce:'07'},
    {...expected,nonce:(2n**64n).toString()},
    {...expected,name:'reserve'},
  ]) {
    assert.throws(()=>validateMainnetDeploymentRawTransaction({raw,expected:changed,index:'0'}),
      /deployment plan is malformed/);
  }
});

test('raw validator accepts the exact canonical package transaction schema',async()=>{
  const names=['finalizedBurnVerifier','checkpointVerifier','checkpointRegistry','reserve'];
  const plans=Object.fromEntries(names.map((name,index)=>[name,{
    from:wallet.address,nonce:String(7+index),
    expectedContract:getCreateAddress({from:wallet.address,nonce:7+index}),
    expectedInitcodeHash:keccak256(expected.data),
    expectedRuntimeCodeHash:`0x${'22'.repeat(32)}`,data:expected.data,
  }]));
  const packageValue=buildMainnetDeploymentPackage({
    releaseConfigSha256:'33'.repeat(32),observationDocumentSha256:'44'.repeat(32),
    observationHash:`0x${'55'.repeat(32)}`,plans,
    approvedArtifacts:Object.fromEntries(Object.entries(plans).map(([name,plan])=>[name,{
      expectedContract:plan.expectedContract,expectedInitcodeHash:plan.expectedInitcodeHash,
      expectedRuntimeCodeHash:plan.expectedRuntimeCodeHash,
    }])),
  });
  const raw=await wallet.signTransaction(valid);
  assert.equal(validateMainnetDeploymentRawTransaction({
    raw,expected:packageValue.transactions[0],index:'0',
  }).expectedContract,plans.finalizedBurnVerifier.expectedContract);
});

test('deployment fee ceremony bounds arithmetic and rechecks worst-case balance',async()=>{
  const script=await readFile(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8');
  for(const marker of [
    'BigInt(process.argv[1])>16000000n','value===0n||value>120000000000n',
    'plan-mainnet-deployment-gas.mjs "$deployment_name" "$data" "$maximum_estimate"',
    'for(let i=0;i<12;i++)fee=(fee*9n+7n)/8n',
    'rpc balance "$from" --block finalized','BigInt(process.argv[2])*BigInt(process.argv[3])',
    'maximum_cost=$(canonical_decimal','transmit_balance=$(canonical_decimal "$(rpc balance',
    'transmit_estimate=$(canonical_decimal "$(rpc estimate',
    'transmit_base=$(canonical_quantity "$("$jq_bin" -er',
    'usdom-mainnet-deployment-fee-anchor-v1','finalized_anchor_hash',
    "'.hash|ascii_downcase' \"$transmit_anchor_before\"",
  ]) assert.ok(script.includes(marker),marker);
  assert.match(script,/transmission_authorization[\s\S]*transmit_balance=/);
  assert.match(script,/assert_prior_deployments_finalized/);
  assert.match(script,/while \(\( prior < index \)\)/);
  assert.match(script,/\.transactions\[\$prior\]\.expectedRuntimeCodeHash/);
  assert.match(script,/contract-deployment-\$prior-receipt\.json/);
  assert.match(script,/eth_getTransactionByHash "\$prior_hash"/);
  assert.match(script,/eth_getTransactionReceipt "\$prior_hash"/);
  assert.match(script,/\.input\|ascii_downcase/);
  assert.match(script,/\.contractAddress\|ascii_downcase/);
  assert.match(script,/canonical_quantity "\$prior_receipt_block" "\$prior_finalized_number"/);
  for(const marker of ['rpcCatalogSha256','releaseConfigSha256','packageSha256',
    'observationDocumentSha256','prior_raw_snapshot','check-private-strict-json-file.mjs',
    'prior-validation.recheck.json','usdom-mainnet-deployment-evidence-v1',
    'contract-deployment-$index-evidence.json','prior_evidence_snapshot',
    'receiptBlockHash:$blockHash']) assert.ok(script.includes(marker),marker);
  assert.ok((script.match(/assert_prior_deployments_finalized "\$endpoint"/g)??[]).length>=3);
  assert.equal((script.match(/rpc nonce "\$expected" --block finalized/g)??[]).length,3);
  assert.equal((script.match(/rpc nonce "\$expected" --block pending/g)??[]).length,3);
  assert.doesNotMatch(script,/rpc balance "\$expected"/);
  const publish=script.indexOf('rpc publish "$raw"');
  assert.ok(script.lastIndexOf('rpc nonce "$expected" --block pending')<publish);
});

test('deployment derivation children are bounded process groups with canonical output',async()=>{
  const [script,preparer]=await Promise.all([
    readFile(new URL('../../scripts/check-mainnet-deployment-raw-transaction.mjs',import.meta.url),'utf8'),
    readFile(new URL('../../scripts/prepare-mainnet-deployment-transaction.mjs',import.meta.url),'utf8'),
  ]);
  assert.match(script,/parseStrictJsonBytes\(expectedResult\.stdout,/);
  assert.match(script,/expectedResult\.stdout\.equals\(Buffer\.from\(`\$\{JSON\.stringify\(expected\)\}\\n`\)\)/);
  assert.match(script,/expectedResult\.stderr\.length!==0/);
  assert.doesNotMatch(script,/expectedResult\.stdout\.toString|parseStrictJson\(/);
  for(const source of [script,preparer]) {
    assert.match(source,/snapshotExecutablePath\(process\.execPath\)/);
    assert.match(source,/runPinnedExecutable\(node,/);
    assert.match(source,/maxBuffer:8\*1024\*1024,timeout:10\*60\*1000/);
    assert.doesNotMatch(source,/execFile\(|node:child_process|promisify/);
  }
});

test('final evidence barrier revalidates every RPC at one finalized snapshot before persistence',async()=>{
  const script=await readFile(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8');
  const barrier=script.slice(script.indexOf('final_barrier_number='),
    script.indexOf('if [[ ! -e $receipt_file ]]'));
  assert.match(barrier,/for source_index in "\$\{!rpc_urls\[@\]\}"/);
  assert.match(barrier,/rpc receipt "\$transaction_hash"/);
  assert.match(barrier,/assert_cmp_unchanged; "\$cmp_bin" -s "\$temporary\/receipt-0\.projected\.json"/);
  assert.match(barrier,/rpc block "\$barrier_number"/);
  assert.match(barrier,/test "\$barrier_finalized_number" = "\$final_barrier_number"/);
  assert.match(barrier,/test "\$barrier_finalized_hash" = "\$final_barrier_hash"/);
  assert.match(barrier,/canonical_quantity "\$barrier_number" "\$barrier_finalized_number"/);
  assert.match(barrier,/rpc code "\$expected" --block "\$barrier_finalized_number"/);
  assert.match(barrier,/if \[\[ \$index == 3 \]\]/);
  assert.match(barrier,/rpc call "\$expected" 'paused\(\)\(bool\)' --block "\$barrier_finalized_number"/);
  assert.match(barrier,/barrier-anchor-before-\$source_index\.json/);
  assert.match(barrier,/barrier-anchor-after-\$source_index\.json/);
  assert.match(barrier,/assert_cmp_unchanged; "\$cmp_bin" -s "\$barrier_anchor_before" "\$barrier_anchor_after"/);
  assert.match(barrier,/barrier-finalized-recheck-\$source_index\.json/);
  assert.match(barrier,/test "\$\("\$jq_bin" -er '\.number' "\$barrier_finalized_recheck"\)" = "\$final_barrier_number"/);
  assert.match(barrier,/barrier-anchor-recheck-\$source_index\.json/);
  assert.match(barrier,/assert_cmp_unchanged; "\$cmp_bin" -s "\$temporary\/barrier-anchor-after-\$source_index\.json" "\$barrier_anchor_recheck"/);
  assert.doesNotMatch(barrier,/(?:^|\n)\s*cmp -s/m);
  assert.match(barrier,/validation\.barrier\.json/);
  assert.doesNotMatch(barrier,/--block latest|rpc block latest/);
  const persistence=script.indexOf('if [[ ! -e $receipt_file ]]');
  assert.ok(script.indexOf('final_barrier_number=')<persistence);
  assert.ok(script.lastIndexOf('usdom-mainnet-deployment-evidence-v1')>persistence);
});

test('partial recovery authenticates the persisted finalized anchor on every RPC',async()=>{
  const script=await readFile(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8');
  const recovery=script.slice(script.indexOf('assert_prior_deployments_finalized()'),
    script.indexOf('if [[ ! -e $raw_file ]]'));
  assert.match(recovery,/prior_anchor_number=.*finalizedBlockNumber/);
  assert.match(recovery,/prior_anchor_hash=.*finalizedBlockHash\|ascii_downcase/);
  assert.match(recovery,/canonical_quantity "\$prior_anchor_number" "\$prior_finalized_number"/);
  assert.match(recovery,/rpc block "\$prior_anchor_number"/);
  assert.match(recovery,/\.number' "\$prior_anchor".*= "\$prior_anchor_number"/s);
  assert.match(recovery,/\.hash\|ascii_downcase' "\$prior_anchor".*= "\$prior_anchor_hash"/s);
  assert.match(recovery,/rpc code "\$prior_address" --block "\$prior_anchor_number"/);
  assert.match(recovery,/prior-finalized-anchor\.recheck\.json/);
  assert.match(recovery,/assert_cmp_unchanged; "\$cmp_bin" -s "\$prior_anchor" "\$prior_anchor_recheck"/);
  assert.doesNotMatch(recovery,/(?:^|\n)\s*cmp -s/m);
  assert.doesNotMatch(recovery,/rpc code "\$prior_address" --block finalized/);
  assert.doesNotMatch(recovery,/rpc block latest/);
});

test('signed CREATE restart accepts finalized-head advancement but authenticates its fixed anchor',async()=>{
  const script=await readFile(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8');
  const transmit=script.slice(script.indexOf('if [[ $seen_any == false ]]'),
    script.indexOf('receipt_1='));
  assert.match(transmit,/rpc block "\$finalized_anchor_number".*transmit_anchor_before/s);
  assert.match(transmit,/\.hash\|ascii_downcase' "\$transmit_anchor_before"\)" = "\$finalized_anchor_hash"/);
  assert.match(transmit,/canonical_quantity "\$finalized_anchor_number" "\$transmit_finalized_number"/);
  assert.match(transmit,/assert_cmp_unchanged; "\$cmp_bin" -s "\$transmit_anchor_before" "\$transmit_anchor_after"/);
  assert.doesNotMatch(transmit,/transmit_finalized_number.*= "\$finalized_anchor_number"/);
  const authorization=transmit.indexOf('AUTORIZO TRANSMITIR DEPLOY MAINNET');
  const finalPendingNonce=transmit.lastIndexOf('rpc nonce "$expected" --block pending');
  const finalAbsence=transmit.lastIndexOf('eth_getTransactionByHash "$transaction_hash"');
  const publish=transmit.indexOf('rpc publish "$raw"');
  assert.ok(authorization>=0&&authorization<finalPendingNonce&&finalPendingNonce<finalAbsence
    &&finalAbsence<publish);
});

test('receipt and finalized comparisons use the bounded BigInt quantity helper',async()=>{
  const script=await readFile(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8');
  assert.match(script,/canonical_quantity\(\)/);
  for(const comparison of [
    'canonical_quantity "$prior_receipt_block" "$prior_finalized_number"',
    'canonical_quantity "$prior_anchor_number" "$prior_finalized_number"',
    'canonical_quantity "$receipt_number" "$finalized_number"',
    'canonical_quantity "$stable_number" "$stable_finalized_number"',
    'canonical_quantity "$barrier_number" "$barrier_finalized_number"',
  ]) assert.ok(script.includes(comparison),comparison);
  assert.doesNotMatch(script,/\(\(\s*(?:prior_receipt_block|prior_anchor_number|receipt_number|stable_number|barrier_number)\s*<=/);
});

test('RPC nonce, gas, fee and balance authorities are canonicalized before use',async()=>{
  const script=await readFile(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8');
  for(const marker of [
    `canonical_quantity "$("$jq_bin" -er '.nonce' "$prior_tx")"`,
    'estimate=$(canonical_decimal "$(rpc estimate',
    'balance=$(canonical_decimal "$(rpc balance',
    `canonical_quantity "$("$jq_bin" -er '.baseFeePerGas'`,
    `canonical_quantity "$("$jq_bin" -er '.gasLimit'`,
    'maximum_cost=$(canonical_decimal',
  ]) assert.ok(script.includes(marker),marker);
  assert.doesNotMatch(script,/BigInt\(s\.trim\(\)\)|=\$\(\([^\n]*(?:base|gas_limit|blockNumber)/);
});
