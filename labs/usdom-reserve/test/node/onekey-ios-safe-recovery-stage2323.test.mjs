import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {Wallet,TypedDataEncoder} from 'ethers';
import {prepareOneKeyIosTypedDataRequest,readOneKeyIosTypedDataRequest} from '../../sdk/onekey-ios-walletconnect-typed-data.mjs';

const root=new URL('../..',import.meta.url);
const shell=fileURLToPath(new URL('../../scripts/sign-recoverable-safe-recovery.sh',import.meta.url));
const reader=fileURLToPath(new URL('../../scripts/read-onekey-ios-walletconnect-signature.mjs',import.meta.url));
const projectId='1'.repeat(32);
const typedData=(safe)=>({types:{EIP712Domain:[{name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'}],SafeTx:[{name:'nonce',type:'uint256'}]},primaryType:'SafeTx',domain:{chainId:1,verifyingContract:safe},message:{nonce:'7'}});

async function fixture(){const dir=await mkdtemp(join(tmpdir(),'usdom-recovery-ios-'));const wallet=Wallet.createRandom();
 const typed=typedData(Wallet.createRandom().address),evidence=join(dir,'evidence.json'),request=join(dir,'request.json'),response=join(dir,'response.json'),typedPath=join(dir,'typed.json');
 await writeFile(evidence,`${JSON.stringify({schema:'usdom-onekey-ios-hardware-account-evidence/v1',source:'onekey-ios-app',deviceId:'device',firmware:'1.2.3',address:wallet.address,appReleaseSha256:'a'.repeat(64),hardwareAddressConfirmed:true,hardwareAccountSelected:true,ratified:true,hardwareSigningApproved:false})}\n`,{mode:0o600});
 await writeFile(typedPath,`${JSON.stringify(typed)}\n`,{mode:0o600});await chmod(dir,0o700);
 await prepareOneKeyIosTypedDataRequest({path:request,expectedAddress:wallet.address,typedData:typed,physicalEvidencePath:evidence,walletConnectProjectId:projectId});
 const req=await readOneKeyIosTypedDataRequest(request),types={...typed.types};delete types.EIP712Domain;
 const signature=await wallet.signTypedData(typed.domain,types,typed.message);
 await writeFile(response,`${JSON.stringify({schema:req.schema,requestSha256:req.requestSha256,digest:req.digest,expectedAddress:req.expectedAddress,signature})}\n`,{mode:0o600});
 return{dir,wallet,typed,typedPath,request,response};}

test('recovery signer contains no Ledger or transaction method and persists per-owner handoff',async()=>{const source=await readFile(shell,'utf8');
 assert.equal(spawnSync('bash',['-n',shell],{encoding:'utf8'}).status,0);assert.doesNotMatch(source,/--ledger|wallet address|wallet sign/i);
 assert.doesNotMatch(source,/eth_sendTransaction|eth_signTransaction/);assert.match(source,/artifact_prefix="\$signatures_output\.onekey-\$role-\$signer_index"/);
 assert.match(source,/request="\$artifact_prefix\.request\.json"/);assert.match(source,/response="\$artifact_prefix\.response\.json"/);assert.match(source,/signing_status == 80/);});

test('response reader binds request, current Safe typed data and exact owner',async()=>{const f=await fixture();
 const ok=spawnSync(process.execPath,[reader,f.request,f.response,f.wallet.address,f.typedPath],{cwd:root,encoding:'utf8'});assert.equal(ok.status,0,ok.stderr);assert.match(ok.stdout,/^0x[0-9a-fA-F]{130}\n$/u);
 const changed=join(f.dir,'changed.json');const altered=structuredClone(f.typed);altered.message.nonce='8';await writeFile(changed,`${JSON.stringify(altered)}\n`,{mode:0o600});
 const rejected=spawnSync(process.execPath,[reader,f.request,f.response,f.wallet.address,changed],{cwd:root,encoding:'utf8'});assert.notEqual(rejected.status,0);
 assert.notEqual(TypedDataEncoder.hash(f.typed.domain,{SafeTx:f.typed.types.SafeTx},f.typed.message),TypedDataEncoder.hash(altered.domain,{SafeTx:altered.types.SafeTx},altered.message));});

test('response reader rejects a symlink and wrong owner',async()=>{const f=await fixture();const other=Wallet.createRandom();
 let result=spawnSync(process.execPath,[reader,f.request,f.response,other.address,f.typedPath],{cwd:root,encoding:'utf8'});assert.notEqual(result.status,0);
 const link=join(f.dir,'response-link.json');await (await import('node:fs/promises')).symlink(f.response,link);
 result=spawnSync(process.execPath,[reader,f.request,link,f.wallet.address,f.typedPath],{cwd:root,encoding:'utf8'});assert.notEqual(result.status,0);});
