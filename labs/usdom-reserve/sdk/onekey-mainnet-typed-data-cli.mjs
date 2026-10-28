import {TypedDataEncoder} from 'ethers';
import {lstat} from 'node:fs/promises';
import {readDirectFile} from './direct-project-file.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {writePrivateFileDurableNew} from './durable-private-file.mjs';
import {createOneKeyEthereumMainnetBoundary} from './onekey-ethereum-mainnet.mjs';

const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const disposed=new WeakSet();

async function bounded(operation,milliseconds,label) {
  let timer; try { return await Promise.race([operation,new Promise((_,reject)=>{
    timer=setTimeout(()=>reject(new Error(`${label} timed out`)),milliseconds);
  })]); } finally { clearTimeout(timer); }
}

async function deviceOperation(operation,milliseconds,session) {
  const timeout=Symbol('timeout'); let timer;
  try { return await Promise.race([operation,new Promise((_,reject)=>{
    timer=setTimeout(()=>reject(timeout),milliseconds);
  })]); } catch(error) {
    if(error!==timeout) throw error;
    if(typeof session.cancel!=='function') throw new Error('OneKey typed-data signing timed out without cancellation');
    session.cancel(); let settled=false,settleTimer;
    try { await Promise.race([operation.then(()=>{settled=true;},()=>{settled=true;}),
      new Promise(resolve=>{settleTimer=setTimeout(resolve,10_000);})]); }
    finally { clearTimeout(settleTimer); }
    if(!settled) { await session.close(); disposed.add(session); }
    throw new Error('OneKey typed-data signing timed out and was cancelled');
  } finally { clearTimeout(timer); }
}

function validateEnvelope(value) {
  if(!exact(value,['schema','digest','typedData'])
      ||value.schema!=='usdom-onekey-eip712-signing/v1'
      ||!/^0x[0-9a-f]{64}$/.test(value.digest??'')
      ||!exact(value.typedData,['types','primaryType','domain','message'])
      ||!value.typedData.types?.EIP712Domain
      ||typeof value.typedData.primaryType!=='string') throw new Error('private EIP-712 envelope is invalid');
  const signingTypes={...value.typedData.types}; delete signingTypes.EIP712Domain;
  if(TypedDataEncoder.from(signingTypes).primaryType!==value.typedData.primaryType
      ||TypedDataEncoder.hash(value.typedData.domain,signingTypes,value.typedData.message)!==value.digest) {
    throw new Error('private EIP-712 envelope digest binding mismatch');
  }
  return value;
}

export async function runOneKeyMainnetTypedData({identityPath,envelopePath,outputPath,
  factory,timeoutMilliseconds=300_000}={}) {
  if(typeof factory!=='function'||!Number.isSafeInteger(timeoutMilliseconds)
      ||timeoutMilliseconds<1||timeoutMilliseconds>300_000) throw new Error('OneKey CLI configuration is invalid');
  const identity=parseStrictJsonBytes(await readDirectFile(identityPath,{minimum:2,maximum:16384,
    privateMode:true,exactMode:0o600,label:'private OneKey identity'}),{label:'private OneKey identity'});
  if(!exact(identity,['schema','deviceId','derivationPath','expectedAddress'])
      ||identity.schema!=='usdom-onekey-classic-1s-identity/v1') throw new Error('private OneKey identity is invalid');
  const envelope=validateEnvelope(parseStrictJsonBytes(await readDirectFile(envelopePath,
    {minimum:2,maximum:2*1024*1024,privateMode:true,exactMode:0o600,label:'private EIP-712 envelope'}),
  {label:'private EIP-712 envelope'}));
  try { await lstat(outputPath); throw new Error('private OneKey output already exists'); }
  catch(error) { if(error?.code!=='ENOENT') throw error; }
  let opened;
  try {
    opened=await bounded(Promise.resolve().then(()=>factory({expectedDeviceId:identity.deviceId})),timeoutMilliseconds,'OneKey transport open');
    if(!opened||opened.deviceId!==identity.deviceId) throw new Error('OneKey live device identity mismatch');
    const boundary=createOneKeyEthereumMainnetBoundary({device:opened.device,connectId:opened.connectId,
      deviceId:opened.deviceId,derivationPath:identity.derivationPath,expectedAddress:identity.expectedAddress});
    const {typedData}=envelope;
    const signing=boundary.signTypedData({domain:typedData.domain,types:typedData.types,
      value:typedData.message,digest:envelope.digest});
    let signed;
    try { signed=await deviceOperation(signing,timeoutMilliseconds,opened); }
    catch(error) { error.exitCode=80; throw error; }
    try { await writePrivateFileDurableNew(outputPath,Buffer.from(`${signed.signature}\n`,'ascii'),
      {maximum:1024}); }
    catch(cause) { const error=new Error('OneKey signature completed but private output was not durably installed',{cause});
      error.exitCode=80; throw error; }
    return Object.freeze({digest:signed.digest,address:signed.address});
  } finally {
    if(opened?.close&&!disposed.has(opened)) await bounded(Promise.resolve().then(()=>opened.close()),10_000,'OneKey transport close');
  }
}

