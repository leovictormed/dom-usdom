import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {request} from 'node:http';
import {lstat} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {closedMainnetMineRequest,validateClosedMainnetMineResponse} from '../sdk/closed-mainnet-block.mjs';
import {validateDomMainnetIdentity} from '../sdk/finalized-deposit-issuance.mjs';

if(process.env.USDOM_SECRET_NODE_LAUNCHER!=='1') {
  throw new Error('token-bearing operator must use its hardened package launcher');
}
if(process.argv.length!==2) {
  console.error('Usage: npm run --silent initialize:closed-mainnet-genesis');
  process.exit(2);
}
if(!process.env.HOME) throw new Error('HOME is required');
const root=path.join(process.env.HOME,'.local/share/dom-usdom/mainnet-node');
const tokenFile=path.join(root,'rpc.token');
const receiptFile=path.join(root,'genesis-initialization.json');
const intentFile=path.join(root,'genesis-initialization-intent.json');
const secretBuffers=[];

async function secureRead(file,maximum) {
  const bytes=await readDirectFile(file,{minimum:1,maximum,privateMode:true,label:'DOM RPC token'});
  secretBuffers.push(bytes);
  return bytes;
}

function rpc(method,rpcPath,body,token,{acceptError=false}={}) {
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
        if(res.statusCode!==200) return acceptError?resolve({status:res.statusCode}):reject(new Error(`DOM RPC ${rpcPath} returned status ${res.statusCode}`));
        try { resolve({status:200,value:parseStrictJson(payload,{label:`DOM RPC ${rpcPath}`,
          maxBytes:65_536,maxDepth:32,maxNodes:10_000,maxStringBytes:65_536,
          maxObjectEntries:4096,maxArrayEntries:4096})}); }
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
      privateMode:true,label:'genesis initialization intent'});
    if(!recorded.equals(encoded)) throw new Error('existing genesis initialization intent differs');
    return;
  } catch(error) { if(error?.code!=='ENOENT') throw error; }
  await writePrivateFileDurableNew(intentFile,encoded,{maximum:1024*1024});
}

try {
  try { await lstat(receiptFile); throw new Error('genesis initialization receipt already exists'); }
  catch(error) { if(error?.code!=='ENOENT') throw error; }
  const tokenBytes=await secureRead(tokenFile,256);
  const token=tokenBytes.toString('utf8').trim();
  if(!/^[0-9a-f]{64}$/.test(token)) throw new Error('DOM RPC token must be 32-byte lowercase hex');
  const beforeResult=await rpc('GET','/chain/identity',undefined,undefined,{acceptError:true});
  const beforeRecheck=await rpc('GET','/chain/identity',undefined,undefined,{acceptError:true});
  if(beforeResult.status!==beforeRecheck.status
      ||(beforeResult.status===200&&JSON.stringify(beforeResult.value)!==JSON.stringify(beforeRecheck.value))) {
    throw new Error('canonical identity changed before genesis initialization');
  }
  let block;
  if(beforeResult.status===200) {
    const existing=validateDomMainnetIdentity(beforeResult.value);
    if(existing.tip_height!==0) throw new Error('closed Mainnet genesis initialization requires height zero');
    block={height:0,block_hash:existing.tip_hash,initialized_genesis:false,count:0};
  } else {
    const expected=closedMainnetMineRequest(null);
    await journalIntent({schema:'usdom-closed-mainnet-genesis-intent-v1',network:'mainnet',
      request:expected,continuousMining:false,peering:false});
    const tokenBeforeAction=await secureRead(tokenFile,tokenBytes.length);
    if(!tokenBeforeAction.equals(tokenBytes)) {
      throw new Error('DOM RPC token changed before genesis initialization');
    }
    block=validateClosedMainnetMineResponse(
      (await rpc('POST','/closed-mainnet/mine-one/v1',expected,token)).value,expected);
  }
  const identity=validateDomMainnetIdentity((await rpc('GET','/chain/identity')).value);
  if(identity.tip_height!==0 || identity.tip_hash!==block.block_hash)
    throw new Error('canonical identity does not match initialized Mainnet genesis');
  const identityRecheck=validateDomMainnetIdentity((await rpc('GET','/chain/identity')).value);
  if(JSON.stringify(identityRecheck)!==JSON.stringify(identity)) {
    throw new Error('canonical identity changed after genesis initialization');
  }
  const receipt={schema:'usdom-closed-mainnet-genesis-v1',network:'mainnet',
    networkMagic:identity.network_magic,chainId:`0x${identity.chain_id}`,
    genesisHash:`0x${identity.genesis_hash}`,tipHeight:'0',tipHash:`0x${identity.tip_hash}`,
    createdNow:block.initialized_genesis===true,continuousMining:false,peering:false,
    recordedAt:new Date().toISOString()};
  const currentTokenBytes=await secureRead(tokenFile,tokenBytes.length);
  if(!currentTokenBytes.equals(tokenBytes)) {
    throw new Error('DOM RPC token changed during genesis initialization');
  }
  await atomicWrite(receiptFile,`${JSON.stringify(receipt,null,2)}\n`);
  process.stdout.write(`${JSON.stringify(receipt,null,2)}\n`);
} catch(error) {
  writePilotFailure('closed-mainnet-genesis-initialize',error);
  process.exitCode=1;
} finally {
  for(const bytes of secretBuffers) bytes.fill(0);
}
