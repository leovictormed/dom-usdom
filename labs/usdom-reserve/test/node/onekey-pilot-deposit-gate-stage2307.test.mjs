import assert from 'node:assert/strict';
import test from 'node:test';
import {chmod,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {TypedDataEncoder,Wallet} from 'ethers';
import {pilotDepositGateSafeTypedData,PILOT_GATE_PLAN_SCHEMA} from '../../sdk/pilot-deposit-gate.mjs';
import {assembleOneKeySafeSignatures} from '../../scripts/assemble-onekey-safe-signatures.mjs';

const wallets=[new Wallet('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a841b1f6ea2b34be6d0'),
 new Wallet('0x8b3a350cf5c34c9194ca3a545d0e38ea0c6c13f9b0c91ad5a25a4e9c86b5e5d1')];
const safe='0x1111111111111111111111111111111111111111',target='0x2222222222222222222222222222222222222222';
const safeTransaction={to:target,value:'0',data:'0x1234',operation:'0',safeTxGas:'0',baseGas:'0',gasPrice:'0',
 gasToken:'0x0000000000000000000000000000000000000000',refundReceiver:'0x0000000000000000000000000000000000000000',nonce:'9'};
const domain={chainId:'1',verifyingContract:safe};
const fields=[{name:'to',type:'address'},{name:'value',type:'uint256'},{name:'data',type:'bytes'},
 {name:'operation',type:'uint8'},{name:'safeTxGas',type:'uint256'},{name:'baseGas',type:'uint256'},
 {name:'gasPrice',type:'uint256'},{name:'gasToken',type:'address'},{name:'refundReceiver',type:'address'},{name:'nonce',type:'uint256'}];
const safeTxHash=TypedDataEncoder.hash(domain,{SafeTx:fields},safeTransaction);
const plan={schema:PILOT_GATE_PLAN_SCHEMA,chainId:'1',governanceSafe:safe,safeTransaction,safeTxHash,
 authorizedOwners:wallets.map(w=>w.address).sort((a,b)=>BigInt(a)<BigInt(b)?-1:1)};

test('pilot Safe OneKey typed data exactly reproduces the reviewed Safe transaction hash',()=>{
 const typed=pilotDepositGateSafeTypedData(plan),types={...typed.types};delete types.EIP712Domain;
 assert.equal(typed.primaryType,'SafeTx');assert.equal(TypedDataEncoder.hash(typed.domain,types,typed.message),safeTxHash);
 for(const mutation of [{...plan,safeTxHash:`0x${'00'.repeat(32)}`},{...plan,chainId:'2'}])
  assert.throws(()=>pilotDepositGateSafeTypedData(mutation));
});

test('generic OneKey Safe assembler preserves owner quorum and canonical order for pilot hash',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'usdom-pilot-onekey-'));await chmod(directory,0o700);
 const typed=pilotDepositGateSafeTypedData(plan),envelope=join(directory,'envelope.json'),output=join(directory,'bundle.hex');
 await writeFile(envelope,JSON.stringify({schema:'usdom-onekey-eip712-signing/v1',digest:safeTxHash,typedData:typed}),{mode:0o600});
 const files=[];for(let i=0;i<2;i++){const p=join(directory,`sig-${i}.hex`);files.push(p);
  await writeFile(p,`${await wallets[i].signTypedData(domain,{SafeTx:fields},safeTransaction)}\n`,{mode:0o600});}
 try {await assembleOneKeySafeSignatures({envelopePath:envelope,owner1:wallets[0].address,signature1Path:files[0],
  owner2:wallets[1].address,signature2Path:files[1],outputPath:output});assert.match(await readFile(output,'ascii'),/^0x[0-9a-f]{260}\n$/);}
 finally {await rm(directory,{recursive:true,force:true});}
});

test('pilot signature materializer binds identity, owner position and create-once output',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'usdom-pilot-materialize-'));await chmod(directory,0o700);
 const planPath=join(directory,'plan.json'),identityPath=join(directory,'identity.json'),signaturePath=join(directory,'signature.hex'),outputPath=join(directory,'record.json');
 const first=wallets.find(wallet=>wallet.address===plan.authorizedOwners[0]);
 await writeFile(planPath,JSON.stringify(plan),{mode:0o600});
 await writeFile(identityPath,JSON.stringify({schema:'usdom-onekey-classic-1s-identity/v1',deviceId:'classic-1s',derivationPath:"m/44'/60'/0'/0/0",expectedAddress:first.address}),{mode:0o600});
 await writeFile(signaturePath,`${await first.signTypedData(domain,{SafeTx:fields},safeTransaction)}\n`,{mode:0o600});
 const script=new URL('../../scripts/materialize-pilot-gate-onekey-signature.mjs',import.meta.url).pathname;
 const run=()=>spawnSync(process.execPath,[script,planPath,identityPath,signaturePath,'1',outputPath],{encoding:'utf8'});
 try {
  assert.equal(run().status,0);const record=JSON.parse(await readFile(outputPath,'utf8'));assert.equal(record.signer,first.address);
  assert.equal(run().status,80);
  await rm(outputPath);const wrong=spawnSync(process.execPath,[script,planPath,identityPath,signaturePath,'2',outputPath],{encoding:'utf8'});
  assert.equal(wrong.status,1);await assert.rejects(readFile(outputPath),error=>error.code==='ENOENT');
  await chmod(signaturePath,0o644);assert.equal(run().status,1);
 } finally {await rm(directory,{recursive:true,force:true});}
});

test('pilot gate executor uses only OneKey signers and marks every completed signing unresolved before persistence',async()=>{
 const source=await readFile(new URL('../../scripts/execute-pilot-deposit-gate.sh',import.meta.url),'utf8');
 assert.doesNotMatch(source,/wallet (?:address|sign)[^\n]*--ledger|prepare-ledger|assemble-ledger|ledger_signature|observed_payer/);
 assert.match(source,/sign-onekey-ios-walletconnect-typed-data\.mjs/);assert.doesNotMatch(source,/sign-onekey-mainnet-(?:transaction|typed-data)\.mjs/);
 assert.match(source,/prepare-pilot-gate-onekey-envelope\.mjs/);assert.match(source,/prepare-pilot-gate-relayer-envelope\.mjs/);
 const typed=source.indexOf('sign-onekey-ios-walletconnect-typed-data.mjs'),materialize=source.indexOf('materialize-pilot-gate-onekey-signature.mjs');
 assert.ok(typed>=0&&source.indexOf('pilot_broadcast_state=signed-unresolved',typed)<materialize);
 assert.match(source,/raw privada do relayer ausente/);assert.match(source,/check-pilot-gate-relayer-raw\.mjs/);
 assert.match(source,/observe "\$rpc1" "\$tmp\/owner-\$index-pre-sign-a\.json"[\s\S]*assert_plan_prestate/);
 assert.match(source,/observe "\$rpc1" "\$tmp\/pre-send-a\.json"[\s\S]*assert_plan_prestate/);
});
