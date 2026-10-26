import test from 'node:test';
import assert from 'node:assert/strict';
import {Interface,Wallet,getAddress} from 'ethers';
import {
  CLOSED_MAINNET_DEPOSIT_AMOUNT,buildClosedMainnetDepositPackage,
  validateClosedMainnetDepositPackage,validateNativeReceivingWalletPublic,
} from '../../sdk/closed-mainnet-deposit.mjs';
import {proofReserveDeploymentConfigHash} from '../../sdk/configuration.mjs';
import {readFileSync} from 'node:fs';
import {CLOSED_DEPOSIT_MAX_FEE_PER_GAS,CLOSED_DEPOSIT_PRIORITY_FEE_PER_GAS,
  validateClosedMainnetDepositRawTransaction} from '../../sdk/closed-mainnet-deposit-execution.mjs';

const hash=byte=>'0x'+byte.toString(16).padStart(2,'0').repeat(32);
const raw=byte=>byte.toString(16).padStart(2,'0').repeat(32);
const tokenInterface=new Interface(['function approve(address spender,uint256 amount) returns (bool)']);
const reserveInterface=new Interface([
  'function deposit(uint64 amount,bytes32 salt,bytes32 receivingCommitment) returns (bytes32)',
]);

function fixture() {
  const configuration={
    ethereumChainId:'1',reserve:'0x0000000000000000000000000000000000000020',
    token:'0xdAC17F958D2ee523a2206206994597C13D831ec7',tokenCodeHash:hash(21),
    verifier:'0x0000000000000000000000000000000000000021',verifierCodeHash:hash(22),
    verifierConfigHash:hash(23),
    checkpointRegistry:'0x0000000000000000000000000000000000000024',
    checkpointRegistryRuntimeCodeHash:hash(28),checkpointRegistryConfigHash:hash(29),
    domDomain:hash(24),activationScheduleCommitment:hash(25),
    governance:'0x0000000000000000000000000000000000000022',governanceCodeHash:hash(26),
    governanceImplementation:'0x0000000000000000000000000000000000000022',
    governanceImplementationCodeHash:hash(26),
    governanceOwnersCommitment:hash(36),
    guardian:'0x0000000000000000000000000000000000000023',guardianCodeHash:hash(27),
    guardianImplementation:'0x0000000000000000000000000000000000000023',
    guardianImplementationCodeHash:hash(27),
    guardianOwnersCommitment:hash(37),
    withdrawalDelaySeconds:'86400',governanceDelaySeconds:'172800',
    maxOutstandingBaseUnits:'1000000',outflowCapacityBaseUnitsPerDay:'1000000',
  };
  const release={...configuration,
    reserveConfigHash:proofReserveDeploymentConfigHash(configuration).reserveConfigHash,
    productionReady:true,realFundsAuthorized:true,
  };
  const chain=raw(2),owner=raw(3),scan=raw(4);
  const wallet={
    schema:'usdom-native-receiving-wallet-public-v1',domDomain:configuration.domDomain,
    privacyPolicyHash:hash(5),chainScalar:'0x'+chain,receivingCommitment:'0x'+owner,
    recipientAddress:Buffer.concat([
      Buffer.from('USDADR01','ascii'),Buffer.from(chain,'hex'),Buffer.from(owner,'hex'),
      Buffer.from(scan,'hex'),
    ]).toString('hex'),
    backupPath:'/home/operator/.local/share/dom-usdom/mainnet-wallet/recovery.usdom',
  };
  return {release,wallet,funder:'0x0000000000000000000000000000000000000040',salt:hash(41),
    releaseConfigSha256:raw(42),walletIdentitySha256:raw(43)};
}

test('closed mainnet deposit package fixes one USDT and exact three-step calldata',()=>{
  const f=fixture();
  const value=buildClosedMainnetDepositPackage(f);
  assert.equal(validateClosedMainnetDepositPackage(value),value);
  assert.equal(value.amountBaseUnits,CLOSED_MAINNET_DEPOSIT_AMOUNT.toString());
  assert.equal(value.broadcastAuthorized,false);
  assert.equal(value.transactions.length,3);
  assert.deepEqual([...tokenInterface.decodeFunctionData('approve',value.transactions[0].data)],
    [getAddress(value.reserve),0n]);
  assert.deepEqual([...tokenInterface.decodeFunctionData('approve',value.transactions[1].data)],
    [getAddress(value.reserve),CLOSED_MAINNET_DEPOSIT_AMOUNT]);
  assert.deepEqual([...reserveInterface.decodeFunctionData('deposit',value.transactions[2].data)],
    [CLOSED_MAINNET_DEPOSIT_AMOUNT,f.salt,f.wallet.receivingCommitment]);
});

test('wallet identity rejects substitutions in every encoded public component',()=>{
  for(const mutate of [
    wallet=>{wallet.recipientAddress='00'+wallet.recipientAddress.slice(2);},
    wallet=>{wallet.recipientAddress=wallet.recipientAddress.slice(0,80)+raw(6)
      +wallet.recipientAddress.slice(144);},
    wallet=>{wallet.recipientAddress=wallet.recipientAddress.slice(0,144)+'00'.repeat(32);},
    wallet=>{wallet.receivingCommitment=hash(7);},
    wallet=>{wallet.extra=true;},
  ]) {
    const {wallet}=fixture(); mutate(wallet);
    assert.throws(()=>validateNativeReceivingWalletPublic(wallet));
  }
});

test('closed mainnet package rejects metadata, authorization and calldata substitutions',()=>{
  const original=buildClosedMainnetDepositPackage(fixture());
  for(const mutate of [
    value=>{value.amountBaseUnits='2000000';},
    value=>{value.broadcastAuthorized=true;},
    value=>{value.releaseConfigSha256='AA'.repeat(32);},
    value=>{value.reserveConfigHash=hash(0);},
    value=>{value.salt=hash(44);},
    value=>{value.depositId=hash(45);},
    value=>{value.receivingCommitment=hash(46);},
    value=>{value.recipientAddress='00'+value.recipientAddress.slice(2);},
    value=>{value.transactions.reverse();},
    value=>{value.transactions[0].data+='00';},
    value=>{value.transactions[1].data=tokenInterface.encodeFunctionData('approve',[
      value.reserve,2_000_000n,
    ]);},
    value=>{value.transactions[2].data=reserveInterface.encodeFunctionData('deposit',[
      CLOSED_MAINNET_DEPOSIT_AMOUNT,value.salt,hash(47),
    ]);},
    value=>{value.transactions[0].extra=true;},
    value=>{value.extra=true;},
    value=>{value.transactions={length:3};},
  ]) {
    const value=structuredClone(original); mutate(value);
    assert.throws(()=>validateClosedMainnetDepositPackage(value));
  }
});

test('construction is gated by exact production release and wallet domain',()=>{
  for(const mutate of [
    f=>{f.release.productionReady=false;},
    f=>{f.release.realFundsAuthorized=false;},
    f=>{f.release.ethereumChainId='31337';},
    f=>{f.wallet.domDomain=hash(48);},
    f=>{f.release.maxOutstandingBaseUnits='2000000';},
    f=>{f.release.outflowCapacityBaseUnitsPerDay='2000000';},
    f=>{f.releaseConfigSha256='0x'+raw(49);},
  ]) {
    const f=fixture(); mutate(f);
    assert.throws(()=>buildClosedMainnetDepositPackage(f));
  }
});

test('closed deposit raw validator binds each zero-value hardware transaction',async()=>{
  const wallet=new Wallet('0x0123456789012345678901234567890123456789012345678901234567890123');
  const input=fixture(); input.funder=wallet.address;
  const packageValue=buildClosedMainnetDepositPackage(input),expected=packageValue.transactions[1];
  const tx={type:2,chainId:1,nonce:9,to:expected.to,value:0,data:expected.data,gasLimit:100000n,
    maxFeePerGas:10_000_000_000n,maxPriorityFeePerGas:CLOSED_DEPOSIT_PRIORITY_FEE_PER_GAS,accessList:[]};
  const raw=await wallet.signTransaction(tx);
  assert.equal(validateClosedMainnetDepositRawTransaction({raw,packageValue,index:1,nonce:'9'}).value,'0');
  for(const changed of [{...tx,value:1},{...tx,chainId:31337},{...tx,nonce:10},{...tx,to:wallet.address},
    {...tx,data:'0x'}, {...tx,maxFeePerGas:CLOSED_DEPOSIT_MAX_FEE_PER_GAS+1n}]) {
    const changedRaw=await wallet.signTransaction(changed);
    assert.throws(()=>validateClosedMainnetDepositRawTransaction({raw:changedRaw,packageValue,index:1,nonce:'9'}));
  }
});

test('closed deposit executor separates sign, validate, publish and output-last evidence',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  assert.match(source,/check-mainnet-readiness\.mjs real-funds/);
  assert.match(source,/AUTORIZO ASSINAR DEPOSITO MAINNET ETAPA \$index/);
  assert.match(source,/check-closed-mainnet-deposit-raw\.mjs/);
  assert.match(source,/AUTORIZO TRANSMITIR DEPOSITO MAINNET ETAPA \$index/);
  assert.ok(source.indexOf('check-closed-mainnet-deposit-raw.mjs')<source.indexOf('publish-private-raw-transaction.mjs'));
  assert.match(source,/allowance\(address,address\)\(uint256\)/);
  assert.match(source,/isBlackListed\(address\)\(bool\)/);
  assert.match(source,/refresh_consensus_block/);
  assert.match(source,/hash1=.*cast block "\$consensus_block"/);
  assert.match(source,/test "\$hash1" = "\$hash2"/);
  assert.match(source,/expected_next_nonce=\$\(node -e/);
  assert.match(source,/cast nonce "\$funder" --block pending --rpc-url "\$rpc"\)" = "\$expected_next_nonce"/);
  assert.match(source,/cast block finalized --field number/);
  assert.match(source,/closed-mainnet-deposit-execution\.json/);
  assert.match(source,/Earlier receipts authenticate history/);
  assert.match(source,/test ! -L "\$receipt_record"/);
  assert.doesNotMatch(source,/cast send|cast publish|--private-key|--mnemonic|USDOM_CLOSED_MAINNET_DEPOSIT_RAW=/);
});
