import assert from 'node:assert/strict';
import test from 'node:test';
import {mkdtemp,readFile,rm,writeFile,chmod,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Transaction,Wallet} from 'ethers';
import {prepareOneKeyEip1559Transaction} from '../../sdk/onekey-eip1559-transaction.mjs';
import {runOneKeyMainnetTransaction} from '../../sdk/onekey-mainnet-transaction-cli.mjs';
import {openApprovedOneKeyBluetooth} from '../../sdk/onekey-bluetooth-factory.mjs';

const wallet=new Wallet('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a841b1f6ea2b34be6d0');
const connectId='session-1',deviceId='classic-1s-1',derivationPath="m/44'/60'/0'/0/0";

async function files() {
  const directory=await mkdtemp(join(tmpdir(),'usdom-onekey-cli-')); await chmod(directory,0o700);
  const identityPath=join(directory,'identity.json'),preparedPath=join(directory,'prepared.json'),outputPath=join(directory,'raw.txt');
  const identity={schema:'usdom-onekey-classic-1s-identity/v1',deviceId,derivationPath,expectedAddress:wallet.address};
  const prepared=prepareOneKeyEip1559Transaction({chainId:'1',from:wallet.address,
    to:'0x1111111111111111111111111111111111111111',data:'0x1234',nonce:'7',gasLimit:'90000',
    maxFeePerGas:'20000000000',maxPriorityFeePerGas:'2000000000'});
  await writeFile(identityPath,`${JSON.stringify(identity)}\n`,{mode:0o600});
  await writeFile(preparedPath,`${JSON.stringify(prepared)}\n`,{mode:0o600});
  return {directory,identityPath,preparedPath,outputPath,prepared};
}

function factory(calls,{reject=false,hang=false,foreign=false,liveConnectId=connectId}={}) {
  let rejectPending,cancelled=false;
  return async()=>({connectId:liveConnectId,deviceId:foreign?'other-device':deviceId,
    cancel(){calls.push('cancel');cancelled=true;rejectPending?.(new Error('cancelled by host'));},
    close:async()=>calls.push('close'),device:{
    async evmGetAddress(connection,_device,request){if(connection!==liveConnectId)throw new Error('stale connectId');calls.push(['address',request]);return {success:true,payload:{address:wallet.address}};},
    async evmSignTransaction(connection,_device,request){if(connection!==liveConnectId)throw new Error('stale connectId');calls.push(['sign',request]);if(hang)return new Promise((resolve,rejectPromise)=>{rejectPending=rejectPromise;if(cancelled)return rejectPromise(new Error('cancelled by host'));setTimeout(()=>resolve({success:true,payload:{v:'0x0',r:`0x${'01'.repeat(32)}`,s:`0x${'02'.repeat(32)}`}}),100);});if(reject)return {success:false,payload:{error:'cancelled'}};const signature=wallet.signingKey.sign(Transaction.from(request.transaction).unsignedHash);return {success:true,payload:{v:`0x${signature.yParity}`,r:signature.r,s:signature.s}};},
    async evmSignTypedData(){throw new Error('not used');},
  }});
}

test('CLI writes only the exact private raw transaction and confirms address first',async()=>{
  const f=await files(),calls=[];
  try {
    const result=await runOneKeyMainnetTransaction({...f,factory:factory(calls),timeoutMilliseconds:1000});
    const raw=(await readFile(f.outputPath,'ascii')).trim();
    assert.equal(Transaction.from(raw).unsignedHash,f.prepared.unsignedHash);
    assert.equal(result.address,wallet.address);
    assert.deepEqual(calls.map(x=>Array.isArray(x)?x[0]:x),['address','sign','close']);
    assert.equal(calls[0][1].showOnOneKey,true);
    assert.equal((await stat(f.outputPath)).mode&0o777,0o600);
  } finally {await rm(f.directory,{recursive:true,force:true});}
});

test('CLI fails closed on wrong device, cancellation and timeout without output',async()=>{
  for(const options of [{foreign:true},{reject:true},{hang:true}]) {
    const f=await files(),calls=[];
    try {
      await assert.rejects(runOneKeyMainnetTransaction({...f,factory:factory(calls,options),timeoutMilliseconds:20}),
        /identity mismatch|failed|timed out/);
      await assert.rejects(readFile(f.outputPath),error=>error.code==='ENOENT');
      assert.equal(calls.at(-1),'close');
      if(options.hang) assert.deepEqual(calls.slice(-2),['cancel','close']);
    } finally {await rm(f.directory,{recursive:true,force:true});}
  }
});

test('CLI rejects altered prepared bytes and unsafe private inputs before opening the transport',async()=>{
  const f=await files(),calls=[];
  try {
    const prepared=JSON.parse(await readFile(f.preparedPath,'utf8'));prepared.unsignedHash=`0x${'00'.repeat(32)}`;
    await writeFile(f.preparedPath,JSON.stringify(prepared),{mode:0o600});
    await assert.rejects(runOneKeyMainnetTransaction({...f,factory:factory(calls)}),/hash mismatch/);
    assert.deepEqual(calls,[]);
    await chmod(f.identityPath,0o644);
    await assert.rejects(runOneKeyMainnetTransaction({...f,factory:factory(calls)}),/safe direct regular file/);
  } finally {await rm(f.directory,{recursive:true,force:true});}
});

test('CLI accepts an ephemeral reconnect id only when the stable device id matches',async()=>{
  const f=await files(),calls=[];
  try {
    await runOneKeyMainnetTransaction({...f,factory:factory(calls,{liveConnectId:'session-after-reconnect'}),timeoutMilliseconds:1000});
    assert.equal(calls[0][0],'address');
    await rm(f.outputPath);
    await assert.rejects(runOneKeyMainnetTransaction({...f,factory:factory([],{liveConnectId:'session-next',foreign:true}),timeoutMilliseconds:1000}),/identity mismatch/);
  } finally {await rm(f.directory,{recursive:true,force:true});}
});

test('CLI refuses a pre-existing output before opening the transport',async()=>{
  const f=await files(),calls=[];
  try {
    await writeFile(f.outputPath,'do-not-replace\n',{mode:0o600});
    await assert.rejects(runOneKeyMainnetTransaction({...f,factory:factory(calls)}),/already exists/);
    assert.deepEqual(calls,[]);
    assert.equal(await readFile(f.outputPath,'utf8'),'do-not-replace\n');
  } finally {await rm(f.directory,{recursive:true,force:true});}
});

test('production Bluetooth factory remains fail-closed without an approved BLE transport',async()=>{
  await assert.rejects(openApprovedOneKeyBluetooth({expectedDeviceId:deviceId}),/authenticated Electron Bluetooth handoff is not approved/);
  const source=await readFile(new URL('../../scripts/sign-onekey-mainnet-transaction.mjs',import.meta.url),'utf8');
  assert.match(source,/onekey-bluetooth-factory\.mjs/);
  assert.doesNotMatch(source,/onekey-usb-factory|ledger|--ledger/i);
});
