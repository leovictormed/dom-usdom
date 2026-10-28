import {request} from 'node:http';
import {createInterface} from 'node:readline/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {closedMainnetMineRequest,validateClosedMainnetMineResponse} from '../sdk/closed-mainnet-block.mjs';
import {closedMainnetBurnScanRequest,validateClosedMainnetBurnBlockReceipt,validateClosedMainnetBurnScan} from '../sdk/closed-mainnet-burn-block.mjs';
import {validateDomMainnetIdentity} from '../sdk/finalized-deposit-issuance.mjs';
import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';

if(process.env.USDOM_SECRET_NODE_LAUNCHER!=='1') throw new Error('token-bearing operator must use its hardened package launcher');
if(process.argv.length!==2||!process.env.HOME) throw new Error('fixed burn-block miner takes no arguments and requires HOME');
const wallet=path.join(process.env.HOME,'.local/share/dom-usdom/mainnet-wallet');
const nodeRoot=path.join(process.env.HOME,'.local/share/dom-usdom/mainnet-node');
const submissionFile=path.join(wallet,'private-burn-submission-v1.json');
const preparedIndex=path.join(wallet,'prepared-burn-state-v1/private-burn-index.json');
const tokenFile=path.join(nodeRoot,'rpc.token');
const receiptFile=path.join(wallet,'private-burn-block-production-v1.json');
const secrets=[];
async function read(file,max,{secret=false}={}) { const b=await readDirectFile(file,{minimum:1,maximum:max,privateMode:true,label:'burn block input'}); if(secret) secrets.push(b); return b; }
function rpc(method,rpcPath,body,token) { return new Promise((resolve,reject)=>{
  const encoded=body===undefined?undefined:Buffer.from(JSON.stringify(body));
  const req=request({hostname:'127.0.0.1',port:33372,path:rpcPath,method,headers:{...(encoded?{'content-type':'application/json','content-length':encoded.length}:{}),authorization:`Bearer ${token}`},timeout:4*60*60*1000},res=>{
    const chunks=[]; let size=0; res.on('data',c=>{size+=c.length;if(size>65536) req.destroy(new Error('DOM RPC response too large'));else chunks.push(c);});
    res.on('end',()=>{if(res.statusCode!==200)return reject(new Error(`DOM RPC status ${res.statusCode}`));try{resolve(parseStrictJson(Buffer.concat(chunks).toString('utf8'),{label:'DOM RPC response',maxBytes:65536,maxDepth:32}));}catch(e){reject(e);}});
  }); req.on('timeout',()=>req.destroy(new Error('DOM RPC timed out')));req.on('error',reject);if(encoded)req.write(encoded);req.end();
}); }
async function scanInclusion(receipt,token){
  const scan=await rpc('POST','/usdom/v4/burn/scan/v1',closedMainnetBurnScanRequest(receipt),token);
  validateClosedMainnetBurnScan(scan,receipt);
}
try {
  const [tokenBytes,submissionBytes,indexBytes]=await Promise.all([read(tokenFile,256,{secret:true}),read(submissionFile,128*1024),read(preparedIndex,128*1024)]);
  const token=tokenBytes.toString('utf8').trim(); if(!/^[0-9a-f]{64}$/.test(token)) throw new Error('invalid DOM RPC token');
  const submission=parseStrictJson(submissionBytes.toString('utf8'),{label:'private burn submission',maxBytes:128*1024,maxDepth:32});
  const index=parseStrictJson(indexBytes.toString('utf8'),{label:'private burn index',maxBytes:128*1024,maxDepth:32});
  if(submission.schema!=='usdom-closed-mainnet-private-burn-submission-v1'||submission.accepted!==true||submission.state!=='queued'||submission.mines!==false
    ||!/^([0-9a-f]{64})$/.test(submission.transition_id)||!/^([0-9a-f]{64})$/.test(submission.candidate_id)
    ||submission.transition_id!==String(index.transition_id??'').replace(/^0x/,'')) throw new Error('queued burn receipt does not bind prepared burn');
  try {
    const existing=parseStrictJson((await read(receiptFile,128*1024)).toString('utf8'),{label:'existing burn block receipt',maxBytes:128*1024,maxDepth:32});
    validateClosedMainnetBurnBlockReceipt(existing,submission,index);await scanInclusion(existing,token);
    await new Promise(resolve=>process.stdout.write(`${JSON.stringify({schema:existing.schema,status:'already-canonical',blockHeight:existing.blockHeight,blockHash:existing.blockHash})}\n`,resolve));
    for(const secret of secrets) secret.fill(0);
    process.exit(0);
  } catch(error) { if(error?.code!=='ENOENT') throw error; }
  const before=validateDomMainnetIdentity(await rpc('GET','/chain/identity',undefined,token));
  if(before.tip_height<1) throw new Error('burn block must extend the finalized issuance chain');
  if(!process.stdin.isTTY||!process.stderr.isTTY) throw new Error('one-block mining requires an interactive authorization terminal');
  const prompt=createInterface({input:process.stdin,output:process.stderr,terminal:true});
  const approval=await prompt.question(`Digite AUTORIZO MINERAR UM BLOCO USDOM parentHeight=${before.tip_height}: `);prompt.close();
  if(approval!=='AUTORIZO MINERAR UM BLOCO USDOM') throw new Error('one-block mining was not authorized');
  const requestBody=closedMainnetMineRequest(before);
  const block=validateClosedMainnetMineResponse(await rpc('POST','/closed-mainnet/mine-one/v1',requestBody,token),requestBody);
  const after=validateDomMainnetIdentity(await rpc('GET','/chain/identity',undefined,token));
  if(after.tip_height!==block.height||after.tip_hash!==block.block_hash||after.chain_id!==before.chain_id||after.genesis_hash!==before.genesis_hash) throw new Error('canonical tip differs from produced burn block');
  const receipt={schema:'usdom-closed-mainnet-private-burn-block-v1',transitionId:submission.transition_id,candidateId:submission.candidate_id,
    authorityBinding:submission.authority_binding,tpmNvIndex:submission.tpm_nv_index,authorizedSnapshotGeneration:submission.authorized_snapshot_generation,
    authorizedSnapshotSealSha256:createHash('sha256').update(Buffer.from(submission.authorized_snapshot_seal,'hex')).digest('hex'),
    parentHeight:String(before.tip_height),parentHash:`0x${before.tip_hash}`,blockHeight:String(after.tip_height),blockHash:`0x${after.tip_hash}`,
    domNetworkMagic:after.network_magic,domChainId:`0x${after.chain_id}`,domGenesisHash:`0x${after.genesis_hash}`,exactlyOneBlock:true,continuousMining:false,producedAt:new Date().toISOString()};
  validateClosedMainnetBurnBlockReceipt(receipt,submission,index);await scanInclusion(receipt,token);
  await writePrivateFileDurableNew(receiptFile,`${JSON.stringify(receipt,null,2)}\n`,{maximum:1024*1024});
  process.stdout.write(`${JSON.stringify({schema:receipt.schema,status:'mined-and-canonical',blockHeight:receipt.blockHeight,blockHash:receipt.blockHash})}\n`);
} catch(error) { writePilotFailure('closed-mainnet-burn-block',error); process.exitCode=1; }
finally { for(const secret of secrets) secret.fill(0); }
