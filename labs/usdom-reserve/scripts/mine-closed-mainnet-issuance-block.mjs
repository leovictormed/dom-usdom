import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {request} from 'node:http';
import path from 'node:path';
import process from 'node:process';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {closedMainnetMineRequest,validateClosedMainnetMineResponse,validatePersistedIssuanceBlock,
  validateQueuedIssuanceReceipt} from '../sdk/closed-mainnet-block.mjs';
import {validateDomMainnetIdentity} from '../sdk/finalized-deposit-issuance.mjs';

if(process.env.USDOM_SECRET_NODE_LAUNCHER!=='1') {
  throw new Error('token-bearing operator must use its hardened package launcher');
}
if(process.argv.length!==2) {
  console.error('Usage: npm run --silent mine:closed-mainnet-issuance-block');
  process.exit(2);
}
if(!process.env.HOME) throw new Error('HOME is required');
const nodeRoot=path.join(process.env.HOME,'.local/share/dom-usdom/mainnet-node');
const stateRoot=path.join(process.env.HOME,'.local/share/dom-usdom/mainnet-wallet/registered-state-v1');
const tokenFile=path.join(nodeRoot,'rpc.token');
const submissionFile=path.join(stateRoot,'issuance-submission.json');
const receiptFile=path.join(stateRoot,'issuance-block-production.json');
const intentFile=path.join(stateRoot,'issuance-block-production-intent.json');
const secretBuffers=[];

async function directRead(file,maximum,{secret=false}={}) {
  const bytes=await readDirectFile(file,{minimum:1,maximum,privateMode:secret,
    label:secret?'closed-mainnet secret input':'closed-mainnet input'});
  if(secret) secretBuffers.push(bytes);
  return bytes;
}

function rpc(method,rpcPath,body,token) {
  return new Promise((resolve,reject)=>{
    const encoded=body===undefined?undefined:Buffer.from(JSON.stringify(body));
    const req=request({hostname:'127.0.0.1',port:33372,path:rpcPath,method,
      headers:{...(encoded?{'content-type':'application/json','content-length':encoded.length}:{}),
        ...(token?{authorization:`Bearer ${token}`}:{})},timeout:4*60*60*1000},res=>{
      const chunks=[]; let length=0;
      res.on('data',chunk=>{ length+=chunk.length; if(length>65_536) req.destroy(new Error('DOM RPC response exceeds 64 KiB')); else chunks.push(chunk); });
      res.on('end',()=>{
        let payload;
        try { payload=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)); }
        catch { return reject(new Error(`DOM RPC ${rpcPath} returned invalid UTF-8`)); }
        if(res.statusCode!==200) return reject(new Error(`DOM RPC ${rpcPath} returned status ${res.statusCode}`));
        try { resolve(parseStrictJson(payload,{label:`DOM RPC ${rpcPath}`,maxBytes:65_536,maxDepth:32,
          maxNodes:10_000,maxStringBytes:65_536,maxObjectEntries:4096,maxArrayEntries:4096})); }
        catch { reject(new Error(`DOM RPC ${rpcPath} returned invalid JSON`)); }
      });
    });
    req.on('timeout',()=>req.destroy(new Error(`DOM RPC ${rpcPath} timed out`)));
    req.on('error',reject); if(encoded) req.write(encoded); req.end();
  });
}

async function atomicWrite(file,value) {
  await writePrivateFileDurableNew(file,value,{maximum:1024*1024});
}

async function journalIntent(value) {
  const encoded=Buffer.from(`${JSON.stringify(value,null,2)}\n`);
  try {
    const recorded=await readDirectFile(intentFile,{minimum:encoded.length,maximum:encoded.length,
      privateMode:true,label:'issuance block production intent'});
    if(!recorded.equals(encoded)) throw new Error('existing issuance block intent differs');
    return;
  } catch(error) { if(error?.code!=='ENOENT') throw error; }
  await writePrivateFileDurableNew(intentFile,encoded,{maximum:1024*1024});
}

try {
  const [tokenBytes,submissionBytes]=await Promise.all([
    directRead(tokenFile,256,{secret:true}),directRead(submissionFile,128*1024,{secret:true})
  ]);
  const token=tokenBytes.toString('utf8').trim();
  if(!/^[0-9a-f]{64}$/.test(token)) throw new Error('DOM RPC token must be 32-byte lowercase hex');
  const before=validateDomMainnetIdentity(await rpc('GET','/chain/identity'));
  const beforeRecheck=validateDomMainnetIdentity(await rpc('GET','/chain/identity'));
  if(JSON.stringify(beforeRecheck)!==JSON.stringify(before)) {
    throw new Error('canonical identity changed before issuance block production');
  }
  const submissionJson=new TextDecoder('utf-8',{fatal:true}).decode(submissionBytes);
  const submission=parseStrictJson(submissionJson,{
    label:'issuance submission',maxBytes:128*1024,maxDepth:32});
  let completed=false;
  try {
    const persistedBytes=await readDirectFile(receiptFile,{minimum:1,maximum:1024*1024,
      privateMode:true,label:'issuance block receipt'});
    const persisted=parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(persistedBytes),{
      label:'issuance block receipt',maxBytes:1024*1024,maxDepth:32});
    validatePersistedIssuanceBlock(persisted,submission,before);
    process.stdout.write(`${JSON.stringify(persisted,null,2)}\n`);
    completed=true;
  } catch(error) { if(error?.code!=='ENOENT') throw error; }
  if(!completed) {
  if(before.tip_height!==0) throw new Error('first closed issuance block must extend the fixed genesis at height zero');
  validateQueuedIssuanceReceipt(submission,before);
  const expected=closedMainnetMineRequest(before);
  await journalIntent({schema:'usdom-closed-mainnet-issuance-block-intent-v1',
    candidateId:submission.candidateId,depositId:submission.depositId,
    parentHeight:String(before.tip_height),parentHash:`0x${before.tip_hash}`,
    domChainId:`0x${before.chain_id}`,request:expected,continuousMining:false});
  const [tokenBeforeAction,submissionBeforeAction]=await Promise.all([
    directRead(tokenFile,tokenBytes.length,{secret:true}),
    directRead(submissionFile,submissionBytes.length,{secret:true}),
  ]);
  if(!tokenBeforeAction.equals(tokenBytes)||!submissionBeforeAction.equals(submissionBytes)) {
    throw new Error('closed Mainnet issuance inputs changed before block production');
  }
  const block=validateClosedMainnetMineResponse(
    await rpc('POST','/closed-mainnet/mine-one/v1',expected,token),expected);
  const after=validateDomMainnetIdentity(await rpc('GET','/chain/identity'));
  if(after.chain_id!==before.chain_id || after.genesis_hash!==before.genesis_hash
      || after.tip_height!==block.height || after.tip_hash!==block.block_hash)
    throw new Error('canonical identity does not match the produced issuance block');
  const afterRecheck=validateDomMainnetIdentity(await rpc('GET','/chain/identity'));
  if(JSON.stringify(afterRecheck)!==JSON.stringify(after)) {
    throw new Error('canonical identity changed after issuance block production');
  }
  const receipt={schema:'usdom-closed-mainnet-issuance-block-v1',
    candidateId:submission.candidateId,depositId:submission.depositId,
    parentHeight:String(before.tip_height),parentHash:`0x${before.tip_hash}`,
    blockHeight:String(block.height),blockHash:`0x${block.block_hash}`,
    domChainId:`0x${after.chain_id}`,domGenesisHash:`0x${after.genesis_hash}`,
    exactlyOneBlock:true,continuousMining:false,
    issuanceObserved:false,producedAt:new Date().toISOString()};
  const [currentTokenBytes,currentSubmissionBytes]=await Promise.all([
    directRead(tokenFile,tokenBytes.length,{secret:true}),
    directRead(submissionFile,submissionBytes.length,{secret:true}),
  ]);
  if(!currentTokenBytes.equals(tokenBytes)||!currentSubmissionBytes.equals(submissionBytes)) {
    throw new Error('closed Mainnet issuance inputs changed during block production');
  }
  await atomicWrite(receiptFile,`${JSON.stringify(receipt,null,2)}\n`);
  process.stdout.write(`${JSON.stringify(receipt,null,2)}\n`);
  }
} catch(error) {
  writePilotFailure('closed-mainnet-issuance-mine',error);
  process.exitCode=1;
} finally {
  for(const bytes of secretBuffers) bytes.fill(0);
}
