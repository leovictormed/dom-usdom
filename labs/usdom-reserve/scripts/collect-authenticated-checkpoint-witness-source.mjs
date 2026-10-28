import {createHash} from 'node:crypto';
import {lstat,mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {getAddress,keccak256,toUtf8Bytes} from 'ethers';
import {encodeRpcReceipt,boundedTransactionHashes} from '../sdk/finalized-deposit-source.mjs';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {removePrivateFileDurableIfExists,writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {parseStrictJsonBytes,parseStrictJson} from '../sdk/strict-json.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {requireSecureHttpsTransportEnvironment} from '../sdk/mainnet-preflight-rpc.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {safeJsonUint} from '../sdk/safe-json-integer.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const manifestPath=path.join(root,'evidence/native-runtime/native-usdom-v2.json');
const reportPath='evidence/checkpoint-finalized-event/checkpoint-finalized-event-report.json';
const statementPath='evidence/checkpoint-outer-proof-job/checkpoint-statement-v6.bin';
const beaconCatalogPath='config/ethereum-checkpoint-source-catalog.json';
const output=path.join(root,'evidence/checkpoint-witness-source/checkpoint-witness-source.json');
const completion=path.join(root,'evidence/checkpoint-witness-source/checkpoint-witness-source.complete.json');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const hex=(value,bytes,label)=>{
  const text=String(value).toLowerCase();
  if(!new RegExp(`^(?:0x)?[0-9a-f]{${bytes*2}}$`).test(text)) throw new Error(`${label} invalid`);
  return text.replace(/^0x/,'');
};
function endpoint(value) {
  const url=new URL(value);
  if(url.protocol!=='https:'||url.username||url.password||url.hash) throw new Error('RPC endpoint is unsafe');
  return url;
}
async function responseJson(response,label,limit) {
  if(!response.ok) throw new Error(`${label} HTTP ${response.status}`);
  const chunks=[]; let size=0;
  for await(const chunk of response.body) { size+=chunk.length; if(size>limit) throw new Error(`${label} exceeds byte limit`); chunks.push(chunk); }
  let text; try { text=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,size)); }
  catch { throw new Error(`${label} response is not valid UTF-8`); }
  return parseStrictJson(text,{label,maxBytes:limit,maxDepth:64,maxNodes:200000,maxArrayEntries:8192,maxObjectEntries:8192,maxStringBytes:limit});
}
let rpcId=0;
async function rpc(url,method,params,limit=32*1024*1024) {
  requireSecureHttpsTransportEnvironment(); const id=++rpcId;
  const response=await fetch(url,{method:'POST',redirect:'error',signal:AbortSignal.timeout(60000),headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id,method,params})});
  const value=await responseJson(response,method,limit);
  if(value?.jsonrpc!=='2.0'||value.id!==id||value.error||value.result==null||Object.keys(value).some(key=>!['jsonrpc','id','result'].includes(key))) throw new Error(`${method} malformed result`);
  return value.result;
}
async function beacon(base,pathname,limit=32*1024*1024) {
  requireSecureHttpsTransportEnvironment(); const url=new URL(base); const requested=new URL(pathname,'https://invalid');
  url.pathname=url.pathname.replace(/\/$/,'')+requested.pathname; url.search=requested.search;
  const value=await responseJson(await fetch(url,{redirect:'error',signal:AbortSignal.timeout(60000),headers:{accept:'application/json'}}),pathname,limit);
  if(value?.data==null) throw new Error(`${pathname} malformed response`); return value.data;
}
function header(block) {
  const result={};
  for(const key of ['baseFeePerGas','blobGasUsed','difficulty','excessBlobGas','extraData','gasLimit','gasUsed','hash','logsBloom','miner','mixHash','nonce','number','parentBeaconBlockRoot','parentHash','receiptsRoot','requestsHash','sha3Uncles','stateRoot','timestamp','transactionsRoot','withdrawalsRoot']) {
    if(!(key in block)) throw new Error(`execution header missing ${key}`); result[key]=typeof block[key]==='string'?block[key].toLowerCase():block[key];
  }
  return result;
}
function policyHex(manifest) {
  const e=manifest.ethereum,c=manifest.checkpoint,parts=['5544435053503031','0001',hex(e.trusted_checkpoint,32,'trusted checkpoint'),hex(e.genesis_validators_root,32,'genesis root'),BigInt(c.ethereum_chain_id).toString(16).padStart(16,'0'),hex(e.genesis_validators_root,32,'checkpoint genesis'),hex(c.registry,20,'registry'),hex(c.runtime_code_hash,32,'runtime hash'),hex(c.config_storage_slot,32,'config slot'),hex(c.checkpoint_config_hash,32,'config hash'),hex(c.bridge_domain,32,'bridge domain'),BigInt(manifest.network_magic).toString(16).padStart(8,'0')];
  for(const name of ['genesis','altair','bellatrix','capella','deneb','electra','fulu','gloas']) { const fork=e.forks[name]; parts.push(BigInt(fork.epoch).toString(16).padStart(16,'0'),hex(fork.version,4,`${name} version`)); }
  const value='0x'+parts.join(''); if(value.length!==2+362*2) throw new Error('static policy length mismatch'); return value;
}
async function collect(source,manifest,report) {
  const execution=endpoint(source.executionUrl),consensus=endpoint(source.beaconUrl);
  if(await rpc(execution,'eth_chainId',[])!=='0x1') throw new Error('execution source is not mainnet');
  const finality=await beacon(consensus,'/eth/v1/beacon/light_client/finality_update');
  const trusted='0x'+hex(manifest.ethereum.trusted_checkpoint,32,'trusted checkpoint');
  const bootstrap=await beacon(consensus,`/eth/v1/beacon/light_client/bootstrap/${trusted}`);
  const start=BigInt(bootstrap.header.beacon.slot)/(32n*256n),end=BigInt(finality.finalized_header.beacon.slot)/(32n*256n),count=end-start+1n;
  if(count<1n||count>128n) throw new Error('light-client update span limit');
  const updatesRaw=await beacon(consensus,`/eth/v1/beacon/light_client/updates?start_period=${start}&count=${count}`);
  if(!Array.isArray(updatesRaw)||updatesRaw.length>128) throw new Error('light-client updates invalid');
  const eventNumber=BigInt(report.blockNumber),finalizedNumber=BigInt(finality.finalized_header.execution.block_number);
  if(finalizedNumber<eventNumber||finalizedNumber-eventNumber>=256n) throw new Error('checkpoint event outside finalized ancestry bound');
  const headers=[]; let eventBlock;
  for(let number=eventNumber;number<=finalizedNumber;number++) { const block=await rpc(execution,'eth_getBlockByNumber',['0x'+number.toString(16),false]); headers.push(header(block)); if(number===eventNumber) eventBlock=block; }
  if(headers.at(-1).hash!==finality.finalized_header.execution.block_hash.toLowerCase()||eventBlock.hash.toLowerCase()!==report.blockHash) throw new Error('Beacon/execution/report block mismatch');
  const hashes=boundedTransactionHashes(eventBlock,'checkpoint event block'); let receipts;
  try { receipts=await rpc(execution,'eth_getBlockReceipts',[report.blockHash],64*1024*1024); }
  catch { receipts=[]; for(const hashValue of hashes) receipts.push(await rpc(execution,'eth_getTransactionReceipt',[hashValue],2*1024*1024)); }
  receipts.sort((a,b)=>Number(BigInt(a.transactionIndex)-BigInt(b.transactionIndex)));
  if(receipts.length!==hashes.length||receipts.some((item,index)=>BigInt(item.transactionIndex)!==BigInt(index)||item.transactionHash.toLowerCase()!==hashes[index])) throw new Error('receipt set incomplete or unordered');
  const target=receipts.find(item=>item.transactionHash.toLowerCase()===report.transactionHash);
  if(!target) throw new Error('checkpoint receipt absent from block receipt set');
  const slot='0x'+hex(manifest.checkpoint.config_storage_slot,32,'config slot');
  const [proof,code]=await Promise.all([
    rpc(execution,'eth_getProof',[manifest.checkpoint.registry,[slot],target.blockNumber]),
    rpc(execution,'eth_getCode',[manifest.checkpoint.registry,target.blockNumber]),
  ]);
  if(proof.storageProof?.length!==1||proof.storageProof[0].key.toLowerCase()!==slot) throw new Error('config storage proof missing');
  const logIndex=target.logs.findIndex(log=>log.address.toLowerCase()===manifest.checkpoint.registry.toLowerCase()&&log.topics?.[0]===report.observations[0].log.topics[0]);
  if(logIndex<0) throw new Error('checkpoint log absent from authenticated receipt');
  return {static_policy_hex:policyHex(manifest),max_current_slot:safeJsonUint(finality.signature_slot,'Beacon signature slot'),bootstrap,updates:updatesRaw.map(value=>value.data??value),finality,execution_headers:eventNumber===finalizedNumber?[]:headers,receipts:receipts.map(encodeRpcReceipt),transaction_index:safeJsonUint(target.transactionIndex,'transaction index',{bits:32}),receipt_log_index:logIndex,registry_account:{block_hash:report.blockHash,block_number:safeJsonUint(eventNumber,'checkpoint block number'),address:getAddress(proof.address),nonce:safeJsonUint(proof.nonce,'registry account nonce'),balance:proof.balance,storage_root:proof.storageHash,code_hash:proof.codeHash,proof:proof.accountProof},config_storage:{slot,value:proof.storageProof[0].value,proof:proof.storageProof[0].proof},runtime_bytecode:code};
}

try {
  if(process.argv.length!==2) throw new Error('fixed checkpoint witness collector accepts no arguments');
  const runtime=readRuntimeSecretJsonFile('USDOM_CHECKPOINT_WITNESS_RPC_SOURCES',{label:'USDOM_CHECKPOINT_WITNESS_RPC_SOURCES',maxBytes:64*1024,maxDepth:8});
  if(!Array.isArray(runtime)||runtime.length<2||runtime.length>5) throw new Error('two to five paired RPC sources required');
  const [manifestBytes,reportBytes,statementBytes,beaconCatalogBytes]=await Promise.all([readDirectFile(manifestPath,{minimum:2,maximum:128*1024,label:'native manifest'}),readDirectProjectFile(root,reportPath,{minimum:2,maximum:4*1024*1024,label:reportPath}),readDirectProjectFile(root,statementPath,{minimum:1,maximum:64*1024,label:statementPath}),readDirectProjectFile(root,beaconCatalogPath,{minimum:2,maximum:64*1024,label:beaconCatalogPath})]);
  const manifest=parseStrictJsonBytes(manifestBytes,{label:'native manifest',maxBytes:128*1024}),report=parseStrictJsonBytes(reportBytes,{label:reportPath,maxBytes:4*1024*1024}),beaconCatalog=parseStrictJsonBytes(beaconCatalogBytes,{label:beaconCatalogPath,maxBytes:64*1024});
  const directory=path.dirname(output),evidenceRoot=path.join(root,'evidence');
  const evidenceMetadata=await lstat(evidenceRoot);
  if(!evidenceMetadata.isDirectory()||evidenceMetadata.isSymbolicLink()||evidenceMetadata.uid!==process.getuid()||(evidenceMetadata.mode&0o077)!==0) throw new Error('evidence root is unsafe');
  try { await mkdir(directory,{mode:0o700}); } catch(error) { if(error?.code!=='EEXIST') throw error; }
  const directoryMetadata=await lstat(directory);
  if(!directoryMetadata.isDirectory()||directoryMetadata.isSymbolicLink()||directoryMetadata.uid!==process.getuid()||(directoryMetadata.mode&0o077)!==0) throw new Error('checkpoint witness source directory is unsafe');
  // A source without its completion marker is an unauthoritative crash orphan.
  // Remove both names durably before starting a new authenticated generation.
  await removePrivateFileDurableIfExists(completion);
  await removePrivateFileDurableIfExists(output);
  const ids=new Set(runtime.map(item=>item.operatorId)),beaconIds=new Set(runtime.map(item=>item.beaconOperatorId));
  if(ids.size!==runtime.length||beaconIds.size!==runtime.length||runtime.some(item=>{
    const executionRow=report.observations.find(observation=>observation.operatorId===item.operatorId);
    const beaconRow=beaconCatalog.sources?.find(row=>row.operatorId===item.beaconOperatorId);
    let executionOrigin,beaconOrigin; try { executionOrigin=endpoint(item.executionUrl).origin.toLowerCase(); beaconOrigin=endpoint(item.beaconUrl).origin.toLowerCase(); } catch { return true; }
    return !executionRow||!beaconRow||executionRow.originKeccak256!==keccak256(toUtf8Bytes(executionOrigin))||beaconRow.originKeccak256!==keccak256(toUtf8Bytes(beaconOrigin));
  })) throw new Error('RPC sources must be distinct and match both authenticated catalogs');
  const sourceCatalog=runtime.map(item=>{ const executionRow=report.observations.find(row=>row.operatorId===item.operatorId),beaconRow=beaconCatalog.sources.find(row=>row.operatorId===item.beaconOperatorId); return {execution_operator_id:item.operatorId,execution_origin_keccak256:executionRow.originKeccak256,beacon_operator_id:item.beaconOperatorId,beacon_origin_keccak256:beaconRow.originKeccak256}; }).sort((left,right)=>left.execution_operator_id.localeCompare(right.execution_operator_id));
  const observations=[]; for(const item of runtime) observations.push({...await collect(item,manifest,report),source_catalog:sourceCatalog});
  const canonical=JSON.stringify(observations[0]); if(observations.some(item=>JSON.stringify(item)!==canonical)) throw new Error('independent checkpoint witness sources disagree');
  const reread=await Promise.all([readDirectFile(manifestPath,{minimum:2,maximum:128*1024,label:'native manifest'}),readDirectProjectFile(root,reportPath),readDirectProjectFile(root,statementPath),readDirectProjectFile(root,beaconCatalogPath)]);
  if(!reread[0].equals(manifestBytes)||!reread[1].equals(reportBytes)||!reread[2].equals(statementBytes)||!reread[3].equals(beaconCatalogBytes)) throw new Error('checkpoint witness inputs changed during collection');
  const bytes=Buffer.from(canonical); await writePrivateFileDurableNew(output,bytes,{maximum:64*1024*1024});
  await writePrivateFileDurableNew(completion,Buffer.from(JSON.stringify({schema:'usdom-checkpoint-witness-source-completion/v1',sourceSha256:sha(bytes),status:'complete'})+'\n'),{maximum:4096});
  console.log(JSON.stringify({status:'complete',sourceCount:runtime.length,sourceSha256:sha(bytes),broadcasts:false,mines:false},null,2));
} catch(error) { writeReleaseFailure('collect-authenticated-checkpoint-witness-source',error); process.exitCode=1; }
