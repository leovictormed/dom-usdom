import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {keccak256} from 'ethers';
import {validateNativeFinalizedDepositVector} from '../../sdk/native-deposit-vector.mjs';
import {FINALIZED_DEPOSIT_SOURCE_CATALOG_SCHEMA,finalizedDepositSourceSetCommitment}
  from '../../sdk/finalized-deposit-source-catalog.mjs';

const h=n=>n.repeat(64), manifestBytes=Buffer.from('{}\n'), manifestPin=createHash('sha256').update(manifestBytes).digest('hex');
const witness=Buffer.from('UDOMDPW1-real-format-fixture'), witnessSha256=createHash('sha256').update(witness).digest('hex');
const reserve='0xdAC17F958D2ee523a2206206994597C13D831ec7';
const releaseConfigBytes=Buffer.from(`${JSON.stringify({ethereumChainId:'1',reserve})}\n`);
const releaseConfigSha256=createHash('sha256').update(releaseConfigBytes).digest('hex');
const runtimeBytecode='0x6001600055';
const sourceCatalog={schema:FINALIZED_DEPOSIT_SOURCE_CATALOG_SCHEMA,sources:[
  {operatorId:'alpha',executionOriginKeccak256:`0x${h('1')}`,beaconOriginKeccak256:`0x${h('2')}`},
  {operatorId:'bravo',executionOriginKeccak256:`0x${h('3')}`,beaconOriginKeccak256:`0x${h('4')}`},
]};
const rawTransaction='0x01',transactionHash=keccak256(rawTransaction);
const source={schema:'usdom-finalized-deposit-source-v2',releaseConfigSha256,
  nativeManifestSha256:manifestPin,transactionHash,chainId:'1',
  reserve,depositId:`0x${h('2')}`,
  funder:'0x1212121212121212121212121212121212121212',amountBaseUnits:'1000000',
  receivingCommitment:`0x${'03'.repeat(32)}`,transactionIndex:0,receiptLogIndex:0,
  depositBlockNumber:'5',depositBlockHash:`0x${h('f')}`,
  bootstrap:{header:{beacon:{slot:'7'}}},updates:[],
  finality:{finalized_header:{beacon:{slot:'8'},execution:{block_number:'7',block_hash:`0x${h('3')}`}}},
  headers:[
    {number:'0x5',hash:`0x${h('f')}`,parentHash:`0x${h('5')}`,receiptsRoot:`0x${h('6')}`,stateRoot:`0x${h('7')}`},
    {number:'0x6',hash:`0x${h('8')}`,parentHash:`0x${h('f')}`,receiptsRoot:`0x${h('9')}`,stateRoot:`0x${h('a')}`},
    {number:'0x7',hash:`0x${h('3')}`,parentHash:`0x${h('8')}`,receiptsRoot:`0x${h('b')}`,stateRoot:`0x${h('c')}`},
  ],rawTransactions:[rawTransaction],receipts:['0x01'],reserveAccount:{address:'0xdac17f958d2ee523a2206206994597c13d831ec7',
    balance:'0x1',codeHash:keccak256(runtimeBytecode),nonce:'0x1',storageHash:`0x${h('d')}`,
    accountProof:['0x01']},runtimeBytecode,sourceCatalog,sourceCount:'2',
  sourceSetCommitment:finalizedDepositSourceSetCommitment(sourceCatalog)};
const sourceBytes=Buffer.from(`${JSON.stringify(source)}\n`);
const index={schema:'usdom-finalized-deposit-witness-v1',native_manifest_sha256:manifestPin,
  source_file:'finalized-deposit-source.json',source_sha256:createHash('sha256').update(sourceBytes).digest('hex'),release_config_sha256:releaseConfigSha256,
  source_transaction_hash:transactionHash,funder:`0x${'12'.repeat(20)}`,
  deposit_block_number:'5',deposit_block_hash:`0x${h('f')}`,finalized_beacon_slot:'8',
  finalized_beacon_root:`0x${h('1')}`,finalized_execution_block_number:'7',
  finalized_execution_block_hash:`0x${h('3')}`,replay_slot:'8',deposit_policy_hash:`0x${h('4')}`,
  witness_sha256:witnessSha256,witness_file:'finalized-deposit-witness.bin',witness_bytes:witness.length,
  witness_verified:true,relation_executed:true,broadcasts:false,mines:false,amount_base_units:'1000000',
  deposit_id:`0x${h('2')}`,receiving_commitment:`0x${'03'.repeat(32)}`,
  transaction_index:0,receipt_log_index:0};
const registration={schema:'usdom-expected-deposit-registration-v1',native_manifest_sha256:manifestPin,
  witness_sha256:witnessSha256,deposit_id:h('2'),amount_base_units:'1000000',receiving_commitment:'03'.repeat(32),
  note_commitment:'04'.repeat(32),wallet_address:Buffer.from('USDADR01').toString('hex')+h('5')+'03'.repeat(32)+h('6'),
  registered_tip_height:'0',registered_tip_hash:h('7'),snapshot_generation:'1',snapshot_seal:'8'.repeat(96),submits:false,mines:false};
const submission={schema:'usdom-finalized-deposit-issuance-submission-v1',amountBaseUnits:'1000000',
  broadcastsEthereum:false,candidateId:`0x${h('9')}`,depositId:`0x${h('2')}`,domChainId:`0x${h('a')}`,
  domGenesisHash:`0x${h('7')}`,mined:false,noteCommitment:`0x${'04'.repeat(32)}`,observedTipHash:`0x${h('7')}`,
  observedTipHeight:'0',state:'queued',submittedAt:'2026-10-27T12:00:00.000Z',witnessSha256};
const block={schema:'usdom-closed-mainnet-issuance-block-v1',candidateId:submission.candidateId,
  depositId:submission.depositId,parentHeight:'0',parentHash:`0x${h('7')}`,blockHeight:'1',blockHash:`0x${h('b')}`,
  domChainId:submission.domChainId,domGenesisHash:submission.domGenesisHash,exactlyOneBlock:true,
  continuousMining:false,issuanceObserved:false,producedAt:'2026-10-27T12:01:00.000Z'};
const observation={schema:'usdom-canonical-deposit-observation-v1',native_manifest_sha256:manifestPin,
  deposit_id:h('2'),note_commitment:'04'.repeat(32),amount_base_units:'1000000',available_balance_base_units:'1000000',
  canonical:true,dom_chain_id:h('a'),block_height:'1',block_hash:h('b'),snapshot_generation:'2',
  snapshot_seal:'c'.repeat(96),history_authenticated:true,broadcasts:false,mines:false};
const fixture={manifestBytes,manifestPin,sourceBytes,releaseConfigBytes,witness,index,registration,submission,block,observation};

test('validates the exact authenticated one-block finalized-deposit vector',()=>{
  const result=validateNativeFinalizedDepositVector(fixture);
  assert.equal(result.historyAuthenticated,true); assert.equal(result.exactlyOneBlock,true);
});
test('rejects substitutions across every semantic boundary',()=>{
  for(const changed of [
    {...fixture,observation:{...observation,history_authenticated:false}},
    {...fixture,observation:{...observation,block_hash:h('d')}},
    {...fixture,block:{...block,continuousMining:true}},
    {...fixture,submission:{...submission,witnessSha256:h('e')}},
    {...fixture,witness:Buffer.from('foreign')},
    {...fixture,sourceBytes:Buffer.from('foreign source')},
    {...fixture,releaseConfigBytes:Buffer.from('foreign release')},
    {...fixture,sourceBytes:Buffer.from(`${JSON.stringify({...source,transactionHash:`0x${h('d')}`})}\n`),
      index:{...index,source_sha256:createHash('sha256').update(Buffer.from(`${JSON.stringify({...source,transactionHash:`0x${h('d')}`})}\n`)).digest('hex')}},
  ]) assert.throws(()=>validateNativeFinalizedDepositVector(changed));
});
test('reopens the source preimage and rejects a rewritten source/index pair',()=>{
  const mutations=[
    value=>{value.transactionHash=`0x${h('d')}`;},
    value=>{value.depositId=`0x${h('d')}`;},
    value=>{value.funder='0x3434343434343434343434343434343434343434';},
    value=>{value.receivingCommitment=`0x${'05'.repeat(32)}`;},
    value=>{value.depositBlockNumber='6'; value.headers[0].number='0x6';
      value.headers[1].number='0x7'; value.headers[2].number='0x8';
      value.finality.finalized_header.execution.block_number='8';},
    value=>{value.finality.finalized_header.beacon.slot='9';},
    value=>{value.transactionIndex=1; value.rawTransactions.push('0x02'); value.receipts.push('0x02');},
    value=>{value.receiptLogIndex=1;},
  ];
  for(const mutate of mutations) {
    const changed=structuredClone(source); mutate(changed);
    const changedBytes=Buffer.from(`${JSON.stringify(changed)}\n`);
    assert.throws(()=>validateNativeFinalizedDepositVector({...fixture,sourceBytes:changedBytes,
      index:{...index,source_sha256:createHash('sha256').update(changedBytes).digest('hex')}}),
    /(witness index does not match|deposit transaction hash is not bound)/);
  }
});
test('binds the authenticated source reserve to the exact release configuration preimage',()=>{
  const changedRelease=Buffer.from(`${JSON.stringify({ethereumChainId:'1',
    reserve:'0x3434343434343434343434343434343434343434'})}\n`);
  const changedReleaseSha=createHash('sha256').update(changedRelease).digest('hex');
  const changedSource={...source,releaseConfigSha256:changedReleaseSha};
  const changedSourceBytes=Buffer.from(`${JSON.stringify(changedSource)}\n`);
  assert.throws(()=>validateNativeFinalizedDepositVector({...fixture,
    releaseConfigBytes:changedRelease,sourceBytes:changedSourceBytes,index:{...index,
      release_config_sha256:changedReleaseSha,
      source_sha256:createHash('sha256').update(changedSourceBytes).digest('hex')}}),
  /witness index does not match/);
});
test('vector checker snapshots and rechecks source, release, witness, block and private state',async()=>{
  const source=await readFile(new URL('../../scripts/check-native-finalized-deposit-vector.mjs',
    import.meta.url),'utf8');
  for(const token of ['finalized-deposit-source/finalized-deposit-source.json',
    'config/proof-reserve.unconfigured.json','readDirectProjectFile','readDirectFile',
    'projectAfter','walletAfter','native finalized-deposit vector inputs changed during validation']) {
    assert.match(source,new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  }
  assert.match(source,/^if\(!\/\^\[0-9a-f\]\{64\}\\n\$\//m);
  assert.doesNotMatch(source,/\breadFile\(/);
});
