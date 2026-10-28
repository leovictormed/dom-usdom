import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Interface,getAddress,keccak256} from 'ethers';
import {buildPilotFundsConsumption,pilotFundsConsumptionSha256,
  validatePilotFundsConsumption} from '../../sdk/pilot-funds-consumption.mjs';
import {reserveDepositId} from '../../sdk/proof-reserve.mjs';

const hash=value=>'0x'+value.repeat(64);
const encode=value=>Buffer.from(`${JSON.stringify(value)}\n`);
function fixture() {
  const funder=getAddress('0x'+'1'.repeat(40)),reserve=getAddress('0x'+'2'.repeat(40));
  const token=getAddress('0xdAC17F958D2ee523a2206206994597C13D831ec7'),salt=hash('3');
  const receivingCommitment=hash('1'),chainScalar='5'.repeat(64),scan='6'.repeat(64);
  const recipientAddress=Buffer.concat([Buffer.from('USDADR01'),Buffer.from(chainScalar,'hex'),
    Buffer.from(receivingCommitment.slice(2),'hex'),Buffer.from(scan,'hex')]).toString('hex');
  const tokenInterface=new Interface(['function approve(address spender,uint256 amount) returns(bool)']);
  const reserveInterface=new Interface(['function deposit(uint64 amount,bytes32 salt,bytes32 receivingCommitment) returns(bytes32)']);
  const transaction=(name,to,method,data)=>({name,to,value:'0',method,data,dataKeccak256:keccak256(data)});
  const reset=tokenInterface.encodeFunctionData('approve',[reserve,0n]);
  const approve=tokenInterface.encodeFunctionData('approve',[reserve,1_000_000n]);
  const deposit=reserveInterface.encodeFunctionData('deposit',[1_000_000n,salt,receivingCommitment]);
  const packageValue={schema:'usdom-closed-mainnet-deposit-v1',releaseConfigSha256:'7'.repeat(64),
    reserveConfigHash:hash('8'),walletIdentitySha256:'9'.repeat(64),
    pilotFundsAuthorizationDigest:hash('2'),ethereumChainId:'1',funder,token,reserve,
    amountBaseUnits:'1000000',salt,depositId:reserveDepositId({chainId:1n,reserve,funder,salt}),
    receivingCommitment,recipientAddress,transactions:[
      transaction('reset-usdt-allowance',token,'approve(address,uint256)',reset),
      transaction('approve-exact-usdt',token,'approve(address,uint256)',approve),
      transaction('deposit-usdt',reserve,'deposit(uint64,bytes32,bytes32)',deposit),
    ],broadcastAuthorized:false};
  const packageBytes=encode(packageValue);
  const gateBytes=encode({schema:'usdom-pilot-deposit-gate-finalized/v2',
    transactionHash:hash('a'),safeTxHash:hash('b'),blockNumber:'9',blockHash:hash('c'),
    transactionIndex:'1',finalizedBlockNumber:'9',finalizedBlockHash:hash('c'),
    snapshotCommitment:hash('d'),expectedAuthorization:hash('e'),generation:'0'});
  const finalityBytes=[0,1,2].map(index=>encode({schema:'usdom-closed-mainnet-deposit-finality-v2',
    transactionHash:hash(String(index+4)),blockNumber:`0x${index+10}`,blockHash:hash(String(index+7)),
    transactionIndex:'0x0',
    finalizedRpcCount:2,gasUsed:'1',effectiveGasPrice:'2',actualCost:'2',maximumCost:'3'}));
  const executionBytes=encode({schema:'usdom-closed-mainnet-deposit-execution-v3',chainId:'1',
    packageSha256:pilotFundsConsumptionSha256(packageBytes),amountBaseUnits:'1000000',
    financialBaselineSha256:'3'.repeat(64),depositFinalitySha256:pilotFundsConsumptionSha256(finalityBytes[2]),
    snapshotBlockNumber:'18',snapshotBlockHash:hash('9'),funderBalanceBefore:'2000000',
    funderBalanceAfter:'1000000',reserveBalanceBefore:'0',reserveBalanceAfter:'1000000',
    totalDepositedBefore:'0',totalDepositedAfter:'1000000',outstandingBefore:'0',
    outstandingAfter:'1000000',steps:3,allowanceBefore:'0',allowanceAfter:'0',outputLast:true,
    transactionHashes:[hash('4'),hash('5'),hash('6')]});
  return {packageValue,packageBytes,gateBytes,executionBytes,finalityBytes};
}

test('consumption marker binds package, execution and each finalized transaction',()=>{
  const inputs=fixture(),marker=buildPilotFundsConsumption(inputs);
  assert.equal(marker.schema,'usdom-pilot-funds-authorization-consumption/v3');
  assert.equal(marker.finalizedTransactions.length,3);
  assert.equal(validatePilotFundsConsumption(marker,inputs),marker);
  for(const field of ['packageBytes','gateBytes','executionBytes']) {
    const changed={...inputs,[field]:Buffer.concat([inputs[field],Buffer.from(' ')] )};
    assert.throws(()=>validatePilotFundsConsumption(marker,changed));
  }
  for(let index=0;index<3;index++) {
    const changed={...inputs,finalityBytes:[...inputs.finalityBytes]};
    changed.finalityBytes[index]=Buffer.concat([changed.finalityBytes[index],Buffer.from(' ')]);
    assert.throws(()=>validatePilotFundsConsumption(marker,changed));
  }
  assert.throws(()=>validatePilotFundsConsumption({...marker,schema:'usdom-pilot-funds-authorization-consumption/v1'},inputs));
});

test('consumption construction rejects stale execution and repeated finality transactions',()=>{
  const inputs=fixture();
  const detached={...inputs,packageValue:{...inputs.packageValue,
    pilotFundsAuthorizationDigest:hash('a')}};
  assert.throws(()=>buildPilotFundsConsumption(detached),/bytes differ from parsed authority/);
  const execution=JSON.parse(inputs.executionBytes);
  execution.packageSha256='0'.repeat(64);
  assert.throws(()=>buildPilotFundsConsumption({...inputs,executionBytes:encode(execution)}));
  const finalityBytes=[...inputs.finalityBytes]; finalityBytes[1]=finalityBytes[0];
  assert.throws(()=>buildPilotFundsConsumption({...inputs,finalityBytes}));
  const reordered=[...inputs.finalityBytes]; [reordered[0],reordered[1]]=[reordered[1],reordered[0]];
  assert.throws(()=>buildPilotFundsConsumption({...inputs,finalityBytes:reordered}),/order differs/);
  const sameBlock=inputs.finalityBytes.map(bytes=>JSON.parse(bytes));
  sameBlock[1].blockNumber=sameBlock[0].blockNumber;
  sameBlock[1].transactionIndex=sameBlock[0].transactionIndex;
  assert.throws(()=>buildPilotFundsConsumption({...inputs,finalityBytes:sameBlock.map(encode)}),
    /strict canonical transaction order/);
  sameBlock[1].transactionIndex='0x1';
  assert.doesNotThrow(()=>buildPilotFundsConsumption({...inputs,finalityBytes:sameBlock.map(encode)}));
  const sameGateBlock=JSON.parse(inputs.gateBytes);
  sameGateBlock.blockNumber='16';sameGateBlock.finalizedBlockNumber='16';
  sameGateBlock.transactionIndex='0';sameGateBlock.blockHash=hash('7');
  sameGateBlock.finalizedBlockHash=hash('7');
  assert.throws(()=>buildPilotFundsConsumption({...inputs,gateBytes:encode(sameGateBlock)}),
    /before its authorization gate/);
  sameGateBlock.transactionIndex='0';
  const first=JSON.parse(inputs.finalityBytes[0]);first.transactionIndex='0x1';
  assert.doesNotThrow(()=>buildPilotFundsConsumption({...inputs,gateBytes:encode(sameGateBlock),
    finalityBytes:[encode(first),...inputs.finalityBytes.slice(1)]}));
});

test('executor validates a consumed marker against finalized chain state and remains restartable',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  assert.doesNotMatch(source,/test ! -e "\$pilot_authorization_consumed"/);
  const consumed=source.indexOf('if [[ -e $pilot_authorization_consumed');
  const success=source.indexOf("printf '%s\\n' 'Pilot authorization was already consumed",consumed);
  assert.ok(consumed>=0&&success>consumed);
  const branch=source.slice(consumed,success);
  assert.match(branch,/check-pilot-funds-consumption\.mjs/);
  assert.equal((branch.match(/cast receipt/g)??[]).length,1);
  assert.match(branch,/cast block finalized/);
  assert.match(branch,/deposits\(bytes32\)\(address,uint64,bytes32\)/);
  assert.match(branch,/check_rpc_transaction_binding/);
  const signing=source.indexOf('prepare-onekey-eip1559-transaction.mjs');
  assert.ok(source.lastIndexOf('check-pilot-funds-authorization-live.mjs',signing)>source.lastIndexOf('read -r -p',signing));
  const publish=source.indexOf('publish-private-raw-transaction.mjs');
  assert.ok(source.lastIndexOf('check-pilot-funds-authorization-live.mjs',publish)>source.lastIndexOf('read -r -p',publish));
});

test('permissionless front-run cannot consume the authorized funder deposit identity',()=>{
  const reserve=readFileSync(new URL('../../contracts/USDOMProofReserve.sol',import.meta.url),'utf8');
  assert.match(reserve,/id = depositId\(msg\.sender, salt\)/);
  assert.match(reserve,/_callToken\(abi\.encodeCall\(IERC20\.transferFrom, \(msg\.sender, address\(this\), amount\)\)\)/);
  assert.match(reserve,/deposits\[id\] = Deposit\(msg\.sender, amount, receivingCommitment\)/);
  const executor=readFileSync(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  const consumed=executor.slice(executor.indexOf('if [[ -e $pilot_authorization_consumed'),
    executor.indexOf("printf '%s\\n' 'Pilot authorization was already consumed"));
  assert.match(consumed,/test "\$\{record_fields\[0\],,\}" = "\$\{funder,,\}"/);
  assert.match(consumed,/test "\$\{record_fields\[1\]%% \*\}" = 1000000/);
  assert.match(consumed,/test "\$\{record_fields\[2\],,\}" = "\$\{commitment,,\}"/);
});
