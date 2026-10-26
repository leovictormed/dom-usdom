import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import {lstat,mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {getAddress} from 'ethers';
import {
  boundedTransactionHashes,DEPOSITED_TOPIC,FINALIZED_DEPOSIT_SOURCE_SCHEMA,encodeRpcReceipt,
  validateFinalizedDepositSource,
} from '../sdk/finalized-deposit-source.mjs';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {
  removePrivateFileDurableIfExists,writePrivateFileDurableNew,
} from '../sdk/durable-private-file.mjs';
import {parseStrictJson,parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {requireSecureHttpsTransportEnvironment} from '../sdk/mainnet-preflight-rpc.mjs';
import {finalizedDepositSourceSetCommitment,matchFinalizedDepositSourceCatalog,
  reconcileFinalizedDepositObservations}
  from '../sdk/finalized-deposit-source-catalog.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const releasePath='config/proof-reserve.unconfigured.json';
const runtimeDirectory=path.join(root,'evidence','native-runtime');
const manifestPath=path.join(runtimeDirectory,'native-usdom-v2.json');
const manifestPinPath=path.join(runtimeDirectory,'native-usdom-v2.manifest.sha256');
const transactionPath=path.join(root,'evidence','finalized-deposit-source','deposit-transaction-hash.hex');
const outputPath=path.join(root,'evidence','finalized-deposit-source','finalized-deposit-source.json');
const sourceCatalogPath='config/finalized-deposit-source-catalog.json';
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
function decodeUtf8(bytes,label) {
  try { return new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { throw new Error(`${label} contains invalid UTF-8`); }
}

function endpointValue(raw) {
  if(typeof raw!=='string'||raw.length<10||raw.length>4096) throw new Error('endpoint is missing');
  const value=new URL(raw);
  if(value.protocol!=='https:'||value.username||value.password||value.hash) {
    throw new Error('endpoint must be an HTTPS URL without URL userinfo or fragment');
  }
  return value;
}
async function responseJson(response,label,maximum) {
  if(!response.ok) throw new Error(`${label} returned HTTP ${response.status}`);
  const declared=response.headers.get('content-length');
  if(declared!==null&&(!/^[0-9]+$/.test(declared)||Number(declared)>maximum)) {
    throw new Error(`${label} response exceeds byte limit`);
  }
  const reader=response.body?.getReader();
  if(!reader) throw new Error(`${label} response has no body`);
  const chunks=[]; let length=0;
  while(true) {
    const {done,value}=await reader.read(); if(done) break;
    length+=value.length;
    if(length>maximum) { await reader.cancel(); throw new Error(`${label} response exceeds byte limit`); }
    chunks.push(value);
  }
  let text;
  try { text=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,length)); }
  catch { throw new Error(`${label} response is not valid UTF-8`); }
  return parseStrictJson(text,{label,maxBytes:maximum,maxDepth:32,maxNodes:100_000,
    maxStringBytes:maximum,maxObjectEntries:8192,maxArrayEntries:8192});
}
let rpcId=0;
async function rpc(url,method,params,maximum=32*1024*1024) {
  requireSecureHttpsTransportEnvironment();
  const id=++rpcId;
  let response;
  try { response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({jsonrpc:'2.0',id,method,params}),redirect:'error',signal:AbortSignal.timeout(60000)}); }
  catch { throw new Error('execution RPC transport failed'); }
  const value=await responseJson(response,method,maximum);
  if(value?.jsonrpc!=='2.0'||value.id!==id||value.error||value.result===undefined
      ||value.result===null||Object.keys(value).some(key=>!['jsonrpc','id','result'].includes(key))) {
    throw new Error(`${method} returned an invalid JSON-RPC result`);
  }
  return value.result;
}
async function beacon(url,pathname,maximum=32*1024*1024) {
  requireSecureHttpsTransportEnvironment();
  const requested=new URL(pathname,'https://usdom.invalid');
  const target=new URL(url);
  target.pathname=target.pathname.replace(/\/$/,'')+requested.pathname;
  for(const [key,value] of requested.searchParams) target.searchParams.set(key,value);
  target.hash='';
  let response;
  try { response=await fetch(target,{headers:{accept:'application/json'},
    redirect:'error',signal:AbortSignal.timeout(60000)}); }
  catch { throw new Error('Beacon API transport failed'); }
  const value=await responseJson(response,pathname,maximum);
  if(!value||typeof value!=='object'||value.data===undefined) {
    throw new Error(`${pathname} returned an invalid Beacon response`);
  }
  return value.data;
}
function hex32(value,label) {
  if(typeof value!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${label} invalid`);
  return value.toLowerCase();
}
function bigintQuantity(value,label) {
  if(typeof value!=='string'||!/^0x[0-9a-fA-F]+$/.test(value)) throw new Error(`${label} invalid`);
  return BigInt(value);
}
function normalizeHeader(block) {
  const keys=[
    'baseFeePerGas','blobGasUsed','difficulty','excessBlobGas','extraData','gasLimit','gasUsed',
    'hash','logsBloom','miner','mixHash','nonce','number','parentBeaconBlockRoot','parentHash',
    'receiptsRoot','requestsHash','sha3Uncles','stateRoot','timestamp','transactionsRoot',
    'withdrawalsRoot',
  ];
  const header=Object.create(null);
  for(const key of keys) {
    if(!(key in block)) throw new Error(`execution block is missing ${key}`);
    header[key]=typeof block[key]==='string'?block[key].toLowerCase():block[key];
  }
  return header;
}
async function directFile(file,maximum,label) {
  return readDirectFile(file,{minimum:1,maximum,label});
}
async function boundedStdin(maximum) {
  const chunks=[]; let length=0;
  for await(const chunk of process.stdin) {
    length+=chunk.length;
    if(length>maximum) throw new Error('finalized-deposit RPC sources exceed byte limit');
    chunks.push(chunk);
  }
  if(length===0) throw new Error('finalized-deposit RPC sources are empty');
  return Buffer.concat(chunks,length);
}
async function prepareOutput() {
  const directory=path.dirname(outputPath);
  try { await mkdir(directory,{mode:0o700}); }
  catch(error) { if(error?.code!=='EEXIST') throw error; }
  const metadata=await lstat(directory);
  if(!metadata.isDirectory()||metadata.isSymbolicLink()||(metadata.mode&0o077)!==0) {
    throw new Error('finalized-deposit evidence directory is unsafe');
  }
  await removePrivateFileDurableIfExists(outputPath);
}
async function atomicWrite(bytes) {
  await writePrivateFileDurableNew(outputPath,bytes,{maximum:32*1024*1024});
}

async function observeSource(execution,consensus,source,trusted) {
  const [chainId,receipt,finality,bootstrap,updates]=await Promise.all([
    rpc(execution,'eth_chainId',[]),rpc(execution,'eth_getTransactionReceipt',[source.transactionHash]),
    beacon(consensus,'/eth/v1/beacon/light_client/finality_update'),
    beacon(consensus,`/eth/v1/beacon/light_client/bootstrap/${trusted}`),
    (async()=>{
      const start=BigInt(source.bootstrap.header.beacon.slot)/(32n*256n);
      const end=BigInt(source.finality.finalized_header.beacon.slot)/(32n*256n);
      return beacon(consensus,`/eth/v1/beacon/light_client/updates?start_period=${start}&count=${end-start+1n}`);
    })(),
  ]);
  if(chainId!=='0x1') throw new Error('cataloged execution RPC is not mainnet');
  const headers=[]; let depositBlock;
  for(let number=BigInt(source.depositBlockNumber),end=BigInt(source.finality.finalized_header.execution.block_number);
    number<=end;number++) {
    const block=await rpc(execution,'eth_getBlockByNumber',['0x'+number.toString(16),false]);
    if(number===BigInt(source.depositBlockNumber)) depositBlock=block;
    headers.push(normalizeHeader(block));
  }
  const transactionHashes=boundedTransactionHashes(depositBlock,'deposit block');
  let receipts;
  try { receipts=await rpc(execution,'eth_getBlockReceipts',[source.depositBlockHash],64*1024*1024); }
  catch { receipts=[]; for(const hash of transactionHashes) {
    receipts.push(await rpc(execution,'eth_getTransactionReceipt',[hash],2*1024*1024));
  }}
  receipts.sort((a,b)=>Number(bigintQuantity(a.transactionIndex,'transaction index')
    -bigintQuantity(b.transactionIndex,'transaction index')));
  const [proof,runtimeBytecode]=await Promise.all([
    rpc(execution,'eth_getProof',[source.reserve,[],receipt.blockNumber]),
    rpc(execution,'eth_getCode',[source.reserve,receipt.blockNumber]),
  ]);
  if(!Array.isArray(updates)) throw new Error('Beacon light-client updates are invalid');
  return {receiptIdentity:{transactionHash:receipt.transactionHash.toLowerCase(),
      blockHash:receipt.blockHash.toLowerCase(),blockNumber:bigintQuantity(receipt.blockNumber,'receipt block').toString(),
      transactionIndex:bigintQuantity(receipt.transactionIndex,'receipt transaction index').toString()},
    receipt:encodeRpcReceipt(receipt),finality,bootstrap,
    updates:updates.map(value=>value.data??value),headers,receipts:receipts.map(encodeRpcReceipt),
    reserveAccount:{address:proof.address.toLowerCase(),balance:proof.balance.toLowerCase(),
      codeHash:proof.codeHash.toLowerCase(),nonce:proof.nonce.toLowerCase(),
      storageHash:proof.storageHash.toLowerCase(),accountProof:proof.accountProof.map(value=>value.toLowerCase())},
    runtimeBytecode:runtimeBytecode.toLowerCase()};
}

if(process.argv.length!==2) {
  console.error('Usage: npm run --silent collect:finalized-deposit-source'); process.exitCode=2;
} else {
  let runtimeSourcesForRedaction=[];
  try {
    // The collected source is the completion artifact for one authenticated
    // generation. Remove an older generation durably before inputs or RPC.
    await prepareOutput();
    // The wrapper sends provider URLs through an anonymous pipe so reusable
    // API credentials never enter argv, the environment or a filesystem.
    const runtimeSourceBytes=await boundedStdin(64*1024);
    let runtimeSources;
    try {
      runtimeSources=parseStrictJsonBytes(runtimeSourceBytes,
        {label:'finalized-deposit RPC sources',maxBytes:64*1024,maxDepth:8});
    } finally { runtimeSourceBytes.fill(0); }
    runtimeSourcesForRedaction=runtimeSources;
    const catalogBytes=await readDirectProjectFile(root,sourceCatalogPath);
    const catalog=parseStrictJsonBytes(catalogBytes,
      {label:sourceCatalogPath,maxBytes:64*1024,maxDepth:8});
    const sources=matchFinalizedDepositSourceCatalog(catalog,runtimeSources);
    const execution=endpointValue(sources[0].executionUrl);
    const consensus=endpointValue(sources[0].beaconUrl);
    const [releaseBytes,manifestBytes,pinBytes,transactionBytes]=await Promise.all([
      readDirectProjectFile(root,releasePath),directFile(manifestPath,64*1024,'native manifest'),
      directFile(manifestPinPath,128,'native manifest pin'),
      directFile(transactionPath,128,'deposit transaction hash'),
    ]);
    const release=parseStrictJsonBytes(releaseBytes,{label:releasePath,maxBytes:256*1024});
    const manifest=parseStrictJsonBytes(manifestBytes,{label:'native manifest',maxBytes:64*1024});
    const manifestSha=sha256(manifestBytes);
    if(decodeUtf8(pinBytes,'native manifest pin')!==manifestSha+'\n'||release.productionReady!==true
        ||release.realFundsAuthorized!==true||release.ethereumChainId!=='1') {
      throw new Error('exact release or native manifest is not authorized');
    }
    const transactionText=decodeUtf8(transactionBytes,'deposit transaction hash');
    const txHash=hex32(transactionText.trim(),'deposit transaction hash');
    if(transactionText!==`${txHash}\n`) throw new Error('deposit transaction hash framing invalid');
    if(await rpc(execution,'eth_chainId',[])!=='0x1') throw new Error('execution RPC is not mainnet');
    const receipt=await rpc(execution,'eth_getTransactionReceipt',[txHash]);
    const reserve=getAddress(release.reserve);
    if(receipt.transactionHash.toLowerCase()!==txHash||getAddress(receipt.to)!==reserve
        ||bigintQuantity(receipt.status,'receipt status')!==1n) {
      throw new Error('deposit transaction did not succeed at the exact reserve');
    }
    const finality=await beacon(consensus,'/eth/v1/beacon/light_client/finality_update');
    const finalizedNumber=BigInt(finality.finalized_header.execution.block_number);
    const depositNumber=bigintQuantity(receipt.blockNumber,'deposit block number');
    const distance=finalizedNumber-depositNumber;
    if(distance<0n||distance>=256n) throw new Error('deposit is not within the finalized ancestry window');
    const trusted=hex32('0x'+manifest.ethereum.trusted_checkpoint.replace(/^0x/,''),
      'trusted checkpoint');
    const bootstrap=await beacon(consensus,`/eth/v1/beacon/light_client/bootstrap/${trusted}`);
    const bootstrapSlot=BigInt(bootstrap.header.beacon.slot);
    const finalizedSlot=BigInt(finality.finalized_header.beacon.slot);
    const startPeriod=bootstrapSlot/(32n*256n),endPeriod=finalizedSlot/(32n*256n);
    const periodCount=endPeriod-startPeriod+1n;
    if(periodCount<=0n||periodCount>128n) throw new Error('weak-subjectivity update span exceeds policy');
    const updates=await beacon(consensus,
      `/eth/v1/beacon/light_client/updates?start_period=${startPeriod}&count=${periodCount}`);
    if(!Array.isArray(updates)||updates.length>Number(periodCount)) {
      throw new Error('Beacon light-client update response is invalid');
    }
    const headers=[];
    let depositBlock;
    for(let number=depositNumber;number<=finalizedNumber;number++) {
      const block=await rpc(execution,'eth_getBlockByNumber',['0x'+number.toString(16),false]);
      if(bigintQuantity(block.number,'execution block number')!==number) throw new Error('wrong execution block');
      if(number===depositNumber) depositBlock=block;
      headers.push(normalizeHeader(block));
    }
    if(headers.at(-1).hash!==finality.finalized_header.execution.block_hash.toLowerCase()) {
      throw new Error('execution RPC and Beacon finality disagree');
    }
    const transactionHashes=boundedTransactionHashes(depositBlock,'deposit block');
    let rpcReceipts;
    try { rpcReceipts=await rpc(execution,'eth_getBlockReceipts',[receipt.blockHash],64*1024*1024); }
    catch { rpcReceipts=[]; for(const hash of transactionHashes) {
      rpcReceipts.push(await rpc(execution,'eth_getTransactionReceipt',[hash],2*1024*1024));
    }}
    if(!Array.isArray(rpcReceipts)||rpcReceipts.length!==transactionHashes.length
        ||rpcReceipts.length===0||rpcReceipts.length>4096) throw new Error('block receipt set is incomplete');
    rpcReceipts.sort((a,b)=>Number(bigintQuantity(a.transactionIndex,'transaction index')
      -bigintQuantity(b.transactionIndex,'transaction index')));
    for(const [index,item] of rpcReceipts.entries()) {
      if(bigintQuantity(item.transactionIndex,'transaction index')!==BigInt(index)
          ||item.blockHash.toLowerCase()!==receipt.blockHash.toLowerCase()
          ||item.transactionHash.toLowerCase()!==transactionHashes[index]) {
        throw new Error('block receipt ordering or identity is inconsistent');
      }
    }
    const transactionIndex=Number(bigintQuantity(receipt.transactionIndex,'deposit transaction index'));
    const matchingLogs=receipt.logs.map((log,index)=>({log,index})).filter(({log})=>
      getAddress(log.address)===reserve&&log.topics[0]?.toLowerCase()===DEPOSITED_TOPIC);
    if(matchingLogs.length!==1) throw new Error('deposit receipt must contain exactly one Deposited event');
    const log=matchingLogs[0].log;
    if(log.topics.length!==3||!/^0x[0-9a-fA-F]{128}$/.test(log.data)) {
      throw new Error('Deposited event encoding is invalid');
    }
    if(log.topics[2].slice(2,26)!=='0'.repeat(24)) throw new Error('indexed funder is noncanonical');
    const depositId=hex32(log.topics[1].toLowerCase(),'deposit ID');
    const funder=getAddress('0x'+log.topics[2].slice(-40));
    const amount=BigInt('0x'+log.data.slice(2,66));
    const receivingCommitment=hex32('0x'+log.data.slice(66),'receiving commitment');
    const scalarField=BigInt('0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001');
    if(amount!==1_000_000n||BigInt(receivingCommitment)>=scalarField) {
      throw new Error('closed deposit amount or receiving commitment is outside policy');
    }
    const proof=await rpc(execution,'eth_getProof',[reserve,[],receipt.blockNumber]);
    const runtimeBytecode=(await rpc(execution,'eth_getCode',[reserve,receipt.blockNumber])).toLowerCase();
    const source={
      schema:FINALIZED_DEPOSIT_SOURCE_SCHEMA,releaseConfigSha256:sha256(releaseBytes),
      nativeManifestSha256:manifestSha,transactionHash:txHash,chainId:'1',reserve,
      depositId,funder,amountBaseUnits:amount.toString(),receivingCommitment,
      transactionIndex,receiptLogIndex:matchingLogs[0].index,
      depositBlockNumber:depositNumber.toString(),depositBlockHash:receipt.blockHash.toLowerCase(),bootstrap,
      updates:updates.map(value=>value.data??value),finality,headers,
      receipts:rpcReceipts.map(encodeRpcReceipt),
      sourceCatalog:catalog,sourceCount:String(catalog.sources.length),
      sourceSetCommitment:finalizedDepositSourceSetCommitment(catalog),
      reserveAccount:{address:proof.address.toLowerCase(),balance:proof.balance.toLowerCase(),
        codeHash:proof.codeHash.toLowerCase(),nonce:proof.nonce.toLowerCase(),
        storageHash:proof.storageHash.toLowerCase(),
        accountProof:proof.accountProof.map(value=>value.toLowerCase())},
      runtimeBytecode,
    };
    validateFinalizedDepositSource(source);
    const expectedObservation={receiptIdentity:{transactionHash:txHash,blockHash:source.depositBlockHash,
        blockNumber:source.depositBlockNumber,transactionIndex:String(source.transactionIndex)},
      receipt:encodeRpcReceipt(receipt),finality:source.finality,
      bootstrap:source.bootstrap,updates:source.updates,headers:source.headers,receipts:source.receipts,
      reserveAccount:source.reserveAccount,runtimeBytecode:source.runtimeBytecode};
    const observations=[];
    for(const item of sources) {
      const executionUrl=endpointValue(item.executionUrl),beaconUrl=endpointValue(item.beaconUrl);
      const before=await observeSource(executionUrl,beaconUrl,source,trusted);
      const after=await observeSource(executionUrl,beaconUrl,source,trusted);
      if(JSON.stringify(before)!==JSON.stringify(after)||JSON.stringify(before)!==JSON.stringify(expectedObservation)) {
        throw new Error('cataloged finalized-deposit observation is inconsistent or changed during collection');
      }
      observations.push(before);
    }
    reconcileFinalizedDepositObservations(observations);
    const reread=await Promise.all([readDirectProjectFile(root,releasePath),directFile(manifestPath,64*1024,'native manifest'),
      directFile(manifestPinPath,128,'native manifest pin'),directFile(transactionPath,128,'deposit transaction hash')]);
    const catalogReread=await readDirectProjectFile(root,sourceCatalogPath);
    if(!reread[0].equals(releaseBytes)||!reread[1].equals(manifestBytes)||!reread[2].equals(pinBytes)
        ||!reread[3].equals(transactionBytes)||!catalogReread.equals(catalogBytes)) {
      throw new Error('collector inputs changed during collection');
    }
    await atomicWrite(Buffer.from(JSON.stringify(source)+'\n'));
    console.log(JSON.stringify({status:'collected',output:path.relative(root,outputPath),
      transactionHash:txHash,depositId,amountBaseUnits:amount.toString(),
      finalizedBeaconSlot:finality.finalized_header.beacon.slot,
      finalizedExecutionBlock:finality.finalized_header.execution.block_number,
      headerCount:headers.length,receiptCount:rpcReceipts.length,mines:false,
      broadcasts:false},null,2));
  } catch(error) {
    writeReleaseFailure('collect-finalized-deposit-source',error); process.exitCode=1;
  }
}
