import assert from 'node:assert/strict';
import test from 'node:test';
import {mkdtemp,readFile,writeFile,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {Wallet,keccak256} from 'ethers';

const root=new URL('../..',import.meta.url).pathname;
const node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';
const hex=n=>`0x${n.repeat(64)}`;
async function privateJson(dir,name,value){const target=path.join(dir,name);await writeFile(target,`${JSON.stringify(value)}\n`,{mode:0o600});await chmod(target,0o600);return target;}
function run(script,args){return spawnSync(node,[path.join(root,'scripts',script),...args],{cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});}

test('relayer envelope and raw validator bind exact Safe execution and reject authorities',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'usdom-relayer-'));
 const relayer=Wallet.createRandom(),safe=Wallet.createRandom().address,data='0x12345678';
 const pkg={schema:'fixture',to:safe,data,dataHash:keccak256(data),safeTxHash:hex('1')};
 const policy={schema:'usdom-pilot-gate-relayer-policy/v1',chainId:'1',relayer:relayer.address,maxGasLimit:'500000',maxFeePerGas:'50000000000',maxPriorityFeePerGas:'3000000000'};
 const input=await privateJson(dir,'input.json',{to:safe,data}),packagePath=await privateJson(dir,'package.json',pkg),policyPath=await privateJson(dir,'policy.json',policy);
 const prepared=run('prepare-pilot-gate-relayer-envelope.mjs',[input,packagePath,policyPath,'7','100000','3000000000','2000000000']);assert.equal(prepared.status,0,prepared.stderr);
 const envelope=JSON.parse(prepared.stdout),envelopePath=await privateJson(dir,'envelope.json',envelope);
 assert.equal(envelope.packageHash,keccak256(await readFile(packagePath)));assert.equal(envelope.policyHash,keccak256(await readFile(policyPath)));
 const raw=await relayer.signTransaction({type:2,chainId:1,nonce:7,to:safe,value:0,data,gasLimit:100000,maxFeePerGas:3000000000n,maxPriorityFeePerGas:2000000000n});
 const rawPath=path.join(dir,'raw.txt');await writeFile(rawPath,`${raw}\n`,{mode:0o600});await chmod(rawPath,0o600);
 const release={token:Wallet.createRandom().address,reserve:Wallet.createRandom().address,governance:Wallet.createRandom().address,guardian:Wallet.createRandom().address,governanceOwners:[],guardianOwners:[],checkpointGuardianOwners:[]};
 const releasePath=await privateJson(dir,'release.json',release);
 const checked=run('check-pilot-gate-relayer-raw.mjs',[rawPath,packagePath,envelopePath,releasePath,policyPath]);assert.equal(checked.status,0,checked.stderr);assert.equal(JSON.parse(checked.stdout).from,relayer.address);
 await writeFile(rawPath,`${raw.toUpperCase()}\n`,{mode:0o600});assert.notEqual(run('check-pilot-gate-relayer-raw.mjs',[rawPath,packagePath,envelopePath,releasePath,policyPath]).status,0);
 await writeFile(rawPath,`${raw} \n`,{mode:0o600});assert.notEqual(run('check-pilot-gate-relayer-raw.mjs',[rawPath,packagePath,envelopePath,releasePath,policyPath]).status,0);
 const withAccessList=await relayer.signTransaction({type:2,chainId:1,nonce:7,to:safe,value:0,data,gasLimit:100000,maxFeePerGas:3000000000n,maxPriorityFeePerGas:2000000000n,accessList:[{address:safe,storageKeys:[]}]});
 await writeFile(rawPath,`${withAccessList}\n`,{mode:0o600});assert.notEqual(run('check-pilot-gate-relayer-raw.mjs',[rawPath,packagePath,envelopePath,releasePath,policyPath]).status,0);
 await writeFile(rawPath,`${raw}\n`,{mode:0o600});
 await writeFile(packagePath,`${JSON.stringify(pkg,null,2)}\n`,{mode:0o600});assert.notEqual(run('check-pilot-gate-relayer-raw.mjs',[rawPath,packagePath,envelopePath,releasePath,policyPath]).status,0);
 await writeFile(packagePath,`${JSON.stringify(pkg)}\n`,{mode:0o600});
 const relaxedPolicyPath=await privateJson(dir,'relaxed-policy.json',{...policy,maxGasLimit:'600000'});assert.notEqual(run('check-pilot-gate-relayer-raw.mjs',[rawPath,packagePath,envelopePath,releasePath,relaxedPolicyPath]).status,0);
 const authorityPath=await privateJson(dir,'authority.json',{...release,governanceOwners:[relayer.address]});
 const rejected=run('check-pilot-gate-relayer-raw.mjs',[rawPath,packagePath,envelopePath,authorityPath,policyPath]);assert.notEqual(rejected.status,0);assert.match(rejected.stderr,/RELEASE_OPERATION_REJECTED/);
 const altered=await relayer.signTransaction({type:2,chainId:1,nonce:7,to:safe,value:0,data:'0x12345679',gasLimit:100000,maxFeePerGas:3000000000n,maxPriorityFeePerGas:2000000000n});
 await writeFile(rawPath,`${altered}\n`,{mode:0o600});
 const alteredResult=run('check-pilot-gate-relayer-raw.mjs',[rawPath,packagePath,envelopePath,releasePath,policyPath]);assert.notEqual(alteredResult.status,0);
});

test('pilot executor has no OneKey payer signing and requires a separate bounded relayer raw',async()=>{
 const source=await readFile(new URL('../../scripts/execute-pilot-deposit-gate.sh',import.meta.url),'utf8');
 assert.doesNotMatch(source,/sign-onekey-mainnet-transaction|prepare-onekey-eip1559|payer_identity|onekey-classic-1s-identity/);
 assert.match(source,/pilot-gate-relayer-policy\.json/);assert.match(source,/pilot-deposit-gate-relayer-envelope\.json/);
 assert.match(source,/check-pilot-gate-relayer-raw\.mjs/);assert.match(source,/cast code "\$relayer" --block finalized/);
 assert.match(source,/raw privada do relayer ausente/);assert.match(source,/exit 78/);
 for(const field of ['.token','.reserve','.governance','.guardian','.governanceOwners[]','.guardianOwners[]','.checkpointGuardianOwners[]']) assert.ok(source.includes(field),field);
 const safeSign=source.indexOf('sign-onekey-mainnet-typed-data.mjs'),relayerEnvelope=source.indexOf('prepare-pilot-gate-relayer-envelope.mjs');
 assert.ok(safeSign>=0&&relayerEnvelope>safeSign);
});

test('real-funds design moves approve and deposit custody to Safe while relayer only pays gas',async()=>{
 const design=await readFile(new URL('../../docs/PILOT-SAFE-CUSTODY-RELAYER-DESIGN-ETAPA2315-2026-10-28.md',import.meta.url),'utf8');
 for(const marker of ['USDT.approve(reserve, amount)','reserve.deposit(amount, salt, receivingCommitment)','dedicated\ndeposit Safe','zero USDT','consecutive create-once Safe plans','current EOA-funder deposit path remains\nblocked']) assert.ok(design.includes(marker),marker);
});
