import assert from 'node:assert/strict';
import test from 'node:test';
import {chmod,mkdtemp,readFile,rm,stat,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Signature,TypedDataEncoder,Wallet} from 'ethers';
import {runOneKeyMainnetTypedData} from '../../sdk/onekey-mainnet-typed-data-cli.mjs';

const wallet=new Wallet('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a841b1f6ea2b34be6d0');
const deviceId='classic-1s-ble',connectId='ephemeral-ble-session',path="m/44'/60'/0'/0/0";
const typedData={types:{EIP712Domain:[{name:'name',type:'string'},{name:'version',type:'string'},
 {name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'}],
 Approval:[{name:'action',type:'bytes32'}]},primaryType:'Approval',domain:{name:'USD0M',version:'1',chainId:'1',
 verifyingContract:'0x1111111111111111111111111111111111111111'},message:{action:`0x${'22'.repeat(32)}`}};
const signingTypes={Approval:typedData.types.Approval};

async function fixture() {
 const directory=await mkdtemp(join(tmpdir(),'onekey-typed-'));await chmod(directory,0o700);
 const identityPath=join(directory,'identity.json'),envelopePath=join(directory,'envelope.json'),outputPath=join(directory,'signature.txt');
 await writeFile(identityPath,JSON.stringify({schema:'usdom-onekey-classic-1s-identity/v1',deviceId,
  derivationPath:path,expectedAddress:wallet.address}),{mode:0o600});
 await writeFile(envelopePath,JSON.stringify({schema:'usdom-onekey-eip712-signing/v1',
  digest:TypedDataEncoder.hash(typedData.domain,signingTypes,typedData.message),typedData}),{mode:0o600});
 return {directory,identityPath,envelopePath,outputPath};
}
function factory(calls,{hang=false,foreign=false}={}) {let rejectPending;
 return async()=>({connectId,deviceId:foreign?'foreign':deviceId,cancel(){calls.push('cancel');rejectPending?.(new Error('cancelled'));},
  async close(){calls.push('close');},device:{async evmGetAddress(_c,_d,request){calls.push(['address',request]);return {success:true,payload:{address:wallet.address}};},
  async evmSignTypedData(_c,_d,request){calls.push(['sign',request]);if(hang)return new Promise((_,reject)=>{rejectPending=reject;});
   const signature=await wallet.signTypedData(request.data.domain,signingTypes,request.data.message);
   return {success:true,payload:{address:wallet.address,signature:signature.slice(2)}};},
  async evmSignTransaction(){throw new Error('not used');}}});}

test('typed CLI binds the complete official payload and creates one private signature',async()=>{const f=await fixture(),calls=[];try{
 const result=await runOneKeyMainnetTypedData({...f,factory:factory(calls),timeoutMilliseconds:1000});
 assert.equal(result.digest,TypedDataEncoder.hash(typedData.domain,signingTypes,typedData.message));
 assert.match(await readFile(f.outputPath,'ascii'),/^0x[0-9a-f]{130}\n$/);
 assert.equal((await stat(f.outputPath)).mode&0o777,0o600);
 assert.deepEqual(calls.map(v=>Array.isArray(v)?v[0]:v),['address','sign','close']);
 assert.equal(JSON.stringify(calls[1][1].data),JSON.stringify(typedData));assert.equal(calls[1][1].metamaskV4Compat,true);
 }finally{await rm(f.directory,{recursive:true,force:true});}});

test('typed CLI rejects any digest/message mutation before transport open',async()=>{const f=await fixture(),calls=[];try{
 const envelope=JSON.parse(await readFile(f.envelopePath));envelope.typedData.message.action=`0x${'33'.repeat(32)}`;
 await writeFile(f.envelopePath,JSON.stringify(envelope),{mode:0o600});
 await assert.rejects(runOneKeyMainnetTypedData({...f,factory:factory(calls)}),/digest binding/);assert.deepEqual(calls,[]);
 }finally{await rm(f.directory,{recursive:true,force:true});}});

test('typed CLI cancels and reaches quiescence on timeout without output',async()=>{const f=await fixture(),calls=[];try{
 await assert.rejects(runOneKeyMainnetTypedData({...f,factory:factory(calls,{hang:true}),timeoutMilliseconds:20}),/timed out/);
 assert.deepEqual(calls.slice(-2),['cancel','close']);await assert.rejects(readFile(f.outputPath),e=>e.code==='ENOENT');
 }finally{await rm(f.directory,{recursive:true,force:true});}});

test('typed CLI rejects device substitution and existing output before signing',async()=>{const f=await fixture(),calls=[];try{
 await assert.rejects(runOneKeyMainnetTypedData({...f,factory:factory(calls,{foreign:true})}),/identity mismatch/);
 await writeFile(f.outputPath,'fixed\n',{mode:0o600});const second=[];
 await assert.rejects(runOneKeyMainnetTypedData({...f,factory:factory(second)}),/already exists/);assert.deepEqual(second,[]);
 }finally{await rm(f.directory,{recursive:true,force:true});}});
