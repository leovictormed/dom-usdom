import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile} from 'node:fs/promises';import {tmpdir} from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {Wallet,Transaction,keccak256} from 'ethers';
const root=path.resolve(import.meta.dirname,'../..'),node=process.execPath;
const run=(script,args=[],input)=>spawnSync(node,[path.join(root,'scripts',script),...args],{cwd:root,input,encoding:'utf8'});
async function privateJson(dir,name,value){const p=path.join(dir,name);await writeFile(p,`${JSON.stringify(value)}\n`,{mode:0o600});return p;}
test('generic gas-only installer binds full transaction and disposable encrypted keystore',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'usdom-relayer-')),wallet=Wallet.createRandom(),to=Wallet.createRandom().address,data='0x12345678';
 const encrypted=JSON.parse(await wallet.encrypt('discardable-test-only'));
 const policy={schema:'test-policy/v1',chainId:'1',relayer:wallet.address,maxGasLimit:'300000',maxFeePerGas:'50000000000',maxPriorityFeePerGas:'3000000000'};
 const envelope={schema:'test-envelope/v1',chainId:'1',relayer:wallet.address,to,value:'0',dataHash:keccak256(data),nonce:'7',gasLimit:'210000',maxFeePerGas:'40000000000',maxPriorityFeePerGas:'2000000000'};
 const [e,i,p,k]=await Promise.all([privateJson(dir,'e.json',envelope),privateJson(dir,'i.json',{to,data}),privateJson(dir,'p.json',policy),privateJson(dir,'k.json',encrypted)]);
 const prepared=run('prepare-gas-only-relayer-signing.mjs',[e,i,p,k]);assert.equal(prepared.status,0,prepared.stderr);const request=JSON.parse(prepared.stdout),requestPath=await privateJson(dir,'request.json',request);
 const signature=wallet.signingKey.sign(request.unsignedHash).serialized,assembled=run('assemble-gas-only-relayer-signing.mjs',[requestPath],`${signature}\n`);assert.equal(assembled.status,0,assembled.stderr);
 const tx=Transaction.from(assembled.stdout.trim());assert.equal(tx.from,wallet.address);assert.equal(tx.to,to);assert.equal(tx.data,data);assert.equal(tx.nonce,7);assert.equal(tx.chainId,1n);assert.equal(tx.value,0n);assert.deepEqual(tx.accessList,[]);
 const bad=await privateJson(dir,'bad.json',{...envelope,dataHash:`0x${'00'.repeat(32)}`});assert.notEqual(run('prepare-gas-only-relayer-signing.mjs',[bad,i,p,k]).status,0);
 const authority=Wallet.createRandom(),wrong=await privateJson(dir,'wrong-policy.json',{...policy,relayer:authority.address});assert.notEqual(run('prepare-gas-only-relayer-signing.mjs',[e,i,wrong,k]).status,0);
 assert.notEqual(run('assemble-gas-only-relayer-signing.mjs',[requestPath],`${signature.toUpperCase()}\n`).status,0);
});
test('all status-78 operational families have one reusable no-broadcast signer',async()=>{
 const dispatcher=await readFile(path.join(root,'scripts/sign-operational-gas-relayer.sh'),'utf8');
 for(const marker of ['safe-deployment:governance','recovery:governance','reserve-resume:schedule','pilot-gate:execute','pilot-gate:cancel','pilot-gate:clear','sign-gas-only-relayer-envelope.sh'])assert.match(dispatcher,new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
 const signer=await readFile(path.join(root,'scripts/sign-gas-only-relayer-envelope.sh'),'utf8');assert.match(signer,/wallet sign --no-hash/);assert.match(signer,/install-private-file-new-stdin\.mjs/);assert.doesNotMatch(signer,/sendRawTransaction|publish-private|eth_send/);
 for(const file of ['sign-operational-gas-relayer.sh','sign-gas-only-relayer-envelope.sh','execute-safe-control-deployment.sh','execute-recoverable-safe-recovery.sh','execute-reserve-resume.sh'])assert.equal(spawnSync('bash',['-n',path.join(root,'scripts',file)]).status,0,file);
});
