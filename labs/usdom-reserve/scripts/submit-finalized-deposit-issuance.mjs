import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import {request} from 'node:http';
import path from 'node:path';
import process from 'node:process';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {
  validateDomMainnetIdentity,
  validateFinalizedDepositIssuance,
  validateIssuanceSubmissionResponse,validatePersistedIssuanceSubmission
} from '../sdk/finalized-deposit-issuance.mjs';

if(process.env.USDOM_SECRET_NODE_LAUNCHER!=='1') {
  throw new Error('token-bearing operator must use its hardened package launcher');
}
const root=path.resolve(import.meta.dirname,'..');
const witnessRoot=path.join(root,'evidence/finalized-deposit-witness');
const runtimeRoot=path.join(root,'evidence/native-runtime');
const walletRoot=path.join(process.env.HOME??'','.local/share/dom-usdom/mainnet-wallet');
const stateRoot=path.join(walletRoot,'registered-state-v1');
const files={
  witness:path.join(witnessRoot,'finalized-deposit-witness.bin'),
  index:path.join(witnessRoot,'finalized-deposit-witness-index.json'),
  manifest:path.join(runtimeRoot,'native-usdom-v2.json'),
  manifestPin:path.join(runtimeRoot,'native-usdom-v2.manifest.sha256'),
  registration:path.join(stateRoot,'expected-deposit-registration.json'),
  token:path.join(process.env.HOME??'','.local/share/dom-usdom/mainnet-node/rpc.token'),
  intent:path.join(stateRoot,'issuance-submission-intent.json'),
  receipt:path.join(stateRoot,'issuance-submission.json')
};

if(process.argv.length!==2) {
  console.error('Usage: npm run --silent submit:finalized-deposit-issuance');
  process.exit(2);
}
if(!process.env.HOME) throw new Error('HOME is required');
const secretBuffers=[];

async function secureRead(file,maximum,{secret=false}={}) {
  const bytes=await readDirectFile(file,{minimum:1,maximum,privateMode:secret,
    label:secret?'secret input':'issuance input'});
  if(secret) secretBuffers.push(bytes);
  return bytes;
}

const issuanceInputSpecifications=[
  [files.witness,4*1024*1024,false],[files.index,128*1024,false],
  [files.registration,128*1024,true],[files.manifest,1024*1024,false],
  [files.manifestPin,128,false],[files.token,256,true],
];
const readIssuanceInputs=()=>Promise.all(issuanceInputSpecifications.map(([file,maximum,secret])=>
  secureRead(file,maximum,{secret})));
const decodeJson=(bytes,label,maximum)=>parseStrictJsonBytes(
  bytes,{label,maxBytes:maximum,maxDepth:32,maxNodes:10_000,maxStringBytes:maximum,
    maxObjectEntries:4096,maxArrayEntries:4096});
function decodeUtf8(bytes,label) {
  try { return new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { throw new Error(`${label} contains invalid UTF-8`); }
}

function rpc(method,rpcPath,body,token) {
  return new Promise((resolve,reject)=>{
    const req=request({hostname:'127.0.0.1',port:33372,path:rpcPath,method,
      headers:{
        ...(body?{'content-type':'application/octet-stream','content-length':body.length}:{}),
        ...(token?{authorization:`Bearer ${token}`}:{})
      },timeout:125_000},res=>{
      const chunks=[]; let length=0;
      res.on('data',chunk=>{
        length+=chunk.length;
        if(length>65_536) { req.destroy(new Error('DOM RPC response exceeds 64 KiB')); return; }
        chunks.push(chunk);
      });
      res.on('end',()=>{
        if(res.statusCode!==200) return reject(new Error(`DOM RPC ${rpcPath} returned status ${res.statusCode}`));
        try { resolve(decodeJson(Buffer.concat(chunks),`DOM RPC ${rpcPath}`,65_536)); }
        catch { reject(new Error(`DOM RPC ${rpcPath} returned invalid JSON`)); }
      });
    });
    req.on('timeout',()=>req.destroy(new Error(`DOM RPC ${rpcPath} timed out`)));
    req.on('error',reject);
    if(body) req.write(body);
    req.end();
  });
}

async function atomicWrite(file,value) {
  await writePrivateFileDurableNew(file,value,{maximum:1024*1024});
}

async function persistIntent(value) {
  const encoded=Buffer.from(`${JSON.stringify(value,null,2)}\n`);
  const readRecorded=()=>readDirectFile(files.intent,{minimum:encoded.length,maximum:encoded.length,
    privateMode:true,label:'issuance submission intent'});
  try {
    const recorded=await readRecorded();
    if(!recorded.equals(encoded)) throw new Error('existing issuance submission intent differs');
    return;
  } catch(error) {
    if(error?.code!=='ENOENT') throw error;
  }
  try { await writePrivateFileDurableNew(files.intent,encoded,{maximum:1024*1024}); }
  catch(error) {
    if(error?.message!=='durable target already exists') throw error;
    const recorded=await readRecorded();
    if(!recorded.equals(encoded)) throw new Error('existing issuance submission intent differs');
  }
}

let completed=false;
try {
  const issuanceInputs=await readIssuanceInputs();
  const [witness,indexBytes,registrationBytes,manifestBytes,pinBytes,tokenBytes]=issuanceInputs;
  const manifestPin=decodeUtf8(pinBytes,'native manifest pin');
  if(!/^[0-9a-f]{64}\n$/.test(manifestPin)) throw new Error('native manifest pin framing is invalid');
  const manifestSha256=manifestPin.slice(0,-1);
  if(createHash('sha256').update(manifestBytes).digest('hex')!==manifestSha256)
    throw new Error('native manifest does not match its SHA-256 pin');
  const tokenText=decodeUtf8(tokenBytes,'DOM RPC token');
  if(!/^[0-9a-f]{64}\n$/.test(tokenText)) {
    throw new Error('DOM RPC token must be exact newline-terminated 32-byte lowercase hex');
  }
  const token=tokenText.slice(0,-1);
  const index=decodeJson(indexBytes,'finalized deposit witness index',128*1024);
  const registration=decodeJson(registrationBytes,'expected deposit registration',128*1024);
  const binding=validateFinalizedDepositIssuance({index,registration,witness,manifestSha256});
  const before=validateDomMainnetIdentity(await rpc('GET','/chain/identity'));
  const beforeRecheck=validateDomMainnetIdentity(await rpc('GET','/chain/identity'));
  if(JSON.stringify(beforeRecheck)!==JSON.stringify(before)) {
    throw new Error('DOM chain identity changed before issuance submission');
  }
  // A durable completion receipt is the restart boundary.  Revalidate it
  // against immutable inputs and the chain identity, then return it without
  // resubmitting the witness.  Deleting it here would reopen the mutation and
  // create an avoidable duplicate-admission window after a clean restart.
  try {
    const persistedBytes=await readDirectFile(files.receipt,{minimum:1,maximum:1024*1024,
      privateMode:true,label:'issuance submission receipt'});
    const persisted=validatePersistedIssuanceSubmission(
      decodeJson(persistedBytes,'issuance submission receipt',1024*1024),{binding,identity:before});
    process.stdout.write(`${JSON.stringify(persisted,null,2)}\n`);
    completed=true;
  } catch(error) {
    if(error?.code!=='ENOENT') throw error;
  }
  if(!completed) {
  const intent={schema:'usdom-finalized-deposit-issuance-intent-v1',...binding,
    witnessSha256:createHash('sha256').update(witness).digest('hex'),manifestSha256,
    domChainId:`0x${before.chain_id}`,domGenesisHash:`0x${before.genesis_hash}`,
    broadcastsEthereum:false};
  await persistIntent(intent);
  const preSubmissionInputs=await readIssuanceInputs();
  if(preSubmissionInputs.some((bytes,index)=>!bytes.equals(issuanceInputs[index]))) {
    throw new Error('finalized deposit issuance inputs changed before submission');
  }
  const admission=validateIssuanceSubmissionResponse(
    await rpc('POST','/usdom/v4/issuance/submit/v1',witness,token));
  const after=validateDomMainnetIdentity(await rpc('GET','/chain/identity'));
  if(before.chain_id!==after.chain_id || before.genesis_hash!==after.genesis_hash)
    throw new Error('DOM chain identity changed during issuance submission');
  const afterRecheck=validateDomMainnetIdentity(await rpc('GET','/chain/identity'));
  if(JSON.stringify(afterRecheck)!==JSON.stringify(after)) {
    throw new Error('DOM chain identity changed after issuance submission');
  }
  const receipt={schema:'usdom-finalized-deposit-issuance-submission-v1',...binding,
    candidateId:`0x${admission.candidate_id}`,state:admission.state,
    domChainId:`0x${after.chain_id}`,domGenesisHash:`0x${after.genesis_hash}`,
    observedTipHeight:String(after.tip_height),
    observedTipHash:`0x${after.tip_hash}`,submittedAt:new Date().toISOString(),
    mined:false,broadcastsEthereum:false};
  const currentIssuanceInputs=await readIssuanceInputs();
  if(currentIssuanceInputs.some((bytes,index)=>!bytes.equals(issuanceInputs[index]))) {
    throw new Error('finalized deposit issuance inputs changed during submission');
  }
  await atomicWrite(files.receipt,`${JSON.stringify(receipt,null,2)}\n`);
  process.stdout.write(`${JSON.stringify(receipt,null,2)}\n`);
  }
} catch(error) {
  writePilotFailure('closed-mainnet-issuance-submit',error);
  process.exitCode=1;
} finally {
  for(const bytes of secretBuffers) bytes.fill(0);
}
