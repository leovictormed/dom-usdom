import assert from 'node:assert/strict';
import test from 'node:test';
import {chmod,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {getCreateAddress,Transaction,Wallet} from 'ethers';
import {prepareOneKeyEip1559CreateTransaction,validatePreparedOneKeyEip1559Transaction}
  from '../../sdk/onekey-eip1559-transaction.mjs';
import {runOneKeyMainnetTransaction} from '../../sdk/onekey-mainnet-transaction-cli.mjs';

const wallet=new Wallet('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a841b1f6ea2b34be6d0');
const expected=getCreateAddress({from:wallet.address,nonce:7});
const input={from:wallet.address,data:`0x60${'ab'.repeat(1024)}`,nonce:'7',gasLimit:'2000000',
  maxFeePerGas:'20000000000',maxPriorityFeePerGas:'2000000000',expectedContract:expected};

test('OneKey CREATE envelope binds initcode, nonce, fees and expected deployed address',()=>{
  const prepared=prepareOneKeyEip1559CreateTransaction(input),tx=Transaction.from(prepared.unsignedSerialized);
  assert.equal(tx.to,null);assert.equal(tx.data,input.data);assert.equal(tx.nonce,7);
  assert.equal(tx.gasLimit,2000000n);assert.equal(tx.maxFeePerGas,20000000000n);
  assert.equal(prepared.expectedContract,expected);
  assert.equal(validatePreparedOneKeyEip1559Transaction(prepared).unsignedHash,tx.unsignedHash);
  for(const mutation of [
    value=>value.expectedContract=getCreateAddress({from:wallet.address,nonce:8}),
    value=>value.unsignedHash=`0x${'00'.repeat(32)}`,value=>value.extra=true,
  ]) {const value={...prepared};mutation(value);assert.throws(()=>validatePreparedOneKeyEip1559Transaction(value));}
  assert.throws(()=>prepareOneKeyEip1559CreateTransaction({...input,expectedContract:getCreateAddress({from:wallet.address,nonce:8})}),/address mismatch/);
});

test('transport boundary signs CREATE with official empty destination and persists exact raw bytes',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'usdom-onekey-create-'));await chmod(directory,0o700);
  const identityPath=join(directory,'identity.json'),preparedPath=join(directory,'prepared.json'),outputPath=join(directory,'raw.txt');
  const prepared=prepareOneKeyEip1559CreateTransaction(input),calls=[];
  await writeFile(identityPath,JSON.stringify({schema:'usdom-onekey-classic-1s-identity/v1',deviceId:'classic-1s',
    derivationPath:"m/44'/60'/0'/0/0",expectedAddress:wallet.address}),{mode:0o600});
  await writeFile(preparedPath,JSON.stringify(prepared),{mode:0o600});
  const factory=async()=>({connectId:'ble-session',deviceId:'classic-1s',cancel(){calls.push('cancel');},
    async close(){calls.push('close');},device:{
      async evmGetAddress(_connect,_device,request){calls.push(['address',request]);return{success:true,payload:{address:wallet.address}};},
      async evmSignTransaction(_connect,_device,request){calls.push(['sign',request]);
        assert.equal(request.transaction.to,'');assert.equal(request.transaction.chainId,1);
        assert.equal(request.transaction.nonce,'0x7');assert.equal(request.transaction.gasLimit,'0x1e8480');
        assert.equal(request.transaction.data,input.data);
        const unsigned=Transaction.from({...request.transaction,to:null,type:2,accessList:[]});
        const signature=wallet.signingKey.sign(unsigned.unsignedHash);
        return{success:true,payload:{v:`0x${signature.yParity}`,r:signature.r,s:signature.s}};},
      async evmSignTypedData(){throw new Error('not used');},
    }});
  try {
    await runOneKeyMainnetTransaction({identityPath,preparedPath,outputPath,factory,timeoutMilliseconds:1000});
    const raw=(await readFile(outputPath,'ascii')).trim(),signed=Transaction.from(raw);
    assert.equal(signed.to,null);assert.equal(signed.from,wallet.address);assert.equal(signed.unsignedHash,prepared.unsignedHash);
    assert.deepEqual(calls.map(value=>Array.isArray(value)?value[0]:value),['address','sign','close']);
  } finally {await rm(directory,{recursive:true,force:true});}
});

test('deployment executor accepts only a separately installed gas-relayer raw',async()=>{
  const source=await readFile(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8');
  assert.doesNotMatch(source,/wallet (?:address|sign)[^\n]*--ledger|sign-onekey-mainnet-transaction|onekey-classic-1s-identity/);
  assert.match(source,/contract-deployment-\$index-relayer-envelope\.json/);
  assert.match(source,/contract-deployment-\$index-relayer-external-raw\.txt/);
  assert.ok(source.indexOf('deployment_broadcast_state=signed-unresolved')
    >source.indexOf('check-mainnet-deployment-raw-transaction.mjs'));
  assert.match(source,/prepare-private-mainnet-create\.mjs prepare[\s\S]*"\$nonce" "\$gas_limit" "\$max_fee" "\$priority_fee"/);
});
