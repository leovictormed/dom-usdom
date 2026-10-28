import {readDirectFile} from './direct-project-file.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {writePrivateFileDurableNew} from './durable-private-file.mjs';
import {createOneKeyEthereumMainnetBoundary} from './onekey-ethereum-mainnet.mjs';
import {validatePreparedOneKeyEip1559Transaction} from './onekey-eip1559-transaction.mjs';
import {lstat} from 'node:fs/promises';

const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const disposedSessions=new WeakSet();

async function bounded(operation,milliseconds,label) {
  let timer;
  try {
    return await Promise.race([operation,new Promise((_,reject)=>{
      timer=setTimeout(()=>reject(new Error(`${label} timed out`)),milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

async function boundedDeviceOperation(operation,milliseconds,label,session) {
  const timeout=Symbol('timeout');let timer;
  try {
    return await Promise.race([operation,new Promise((_,reject)=>{
      timer=setTimeout(()=>reject(timeout),milliseconds);
    })]);
  } catch(error) {
    if(error!==timeout) throw error;
    if(typeof session.cancel!=='function') throw new Error(`${label} timed out without a cancellation boundary`);
    session.cancel();
    let settled=false,settleTimer;
    try {
      await Promise.race([
        operation.then(()=>{settled=true;},()=>{settled=true;}),
        new Promise(resolve=>{settleTimer=setTimeout(resolve,10_000);}),
      ]);
    } finally {clearTimeout(settleTimer);}
    if(!settled) {
      await session.close();
      disposedSessions.add(session);
    }
    throw new Error(`${label} timed out and was cancelled`);
  } finally { clearTimeout(timer); }
}

export async function runOneKeyMainnetTransaction({identityPath,preparedPath,outputPath,
  factory,timeoutMilliseconds=300_000}={}) {
  if(typeof factory!=='function'||!Number.isSafeInteger(timeoutMilliseconds)
      ||timeoutMilliseconds<1||timeoutMilliseconds>300_000) throw new Error('OneKey CLI configuration is invalid');
  const identity=parseStrictJsonBytes(await readDirectFile(identityPath,{minimum:2,maximum:16384,
    privateMode:true,exactMode:0o600,label:'private OneKey identity'}),{label:'private OneKey identity'});
  if(!exact(identity,['schema','deviceId','derivationPath','expectedAddress'])
      ||identity.schema!=='usdom-onekey-classic-1s-identity/v1') throw new Error('private OneKey identity is invalid');
  const prepared=validatePreparedOneKeyEip1559Transaction(parseStrictJsonBytes(
    await readDirectFile(preparedPath,{minimum:2,maximum:2*1024*1024,privateMode:true,
      exactMode:0o600,label:'private prepared transaction'}),{label:'private prepared transaction'}));
  const preparedKeys=prepared.schema==='usdom-onekey-eip1559-create-signing/v1'
    ?['schema','from','expectedContract','maxGasLimit','unsignedHash','unsignedSerialized']
    :['schema','from','maxGasLimit','unsignedHash','unsignedSerialized'];
  if(!exact(prepared,preparedKeys)
      ||!['usdom-onekey-eip1559-signing/v1','usdom-onekey-eip1559-create-signing/v1'].includes(prepared.schema)
      ||prepared.from!==identity.expectedAddress) throw new Error('private prepared transaction is invalid');
  try {await lstat(outputPath);throw new Error('private OneKey output already exists');}
  catch(error){if(error?.code!=='ENOENT')throw error;}
  let opened;
  try {
    opened=await bounded(Promise.resolve().then(()=>factory({expectedDeviceId:identity.deviceId})),timeoutMilliseconds,'OneKey transport open');
    if(!opened||opened.deviceId!==identity.deviceId) {
      throw new Error('OneKey live device identity mismatch');
    }
    const boundary=createOneKeyEthereumMainnetBoundary({device:opened.device,
      connectId:opened.connectId,deviceId:opened.deviceId,derivationPath:identity.derivationPath,
      expectedAddress:identity.expectedAddress});
    const signing=boundary.signTransaction({unsignedSerialized:prepared.unsignedSerialized,
      unsignedHash:prepared.unsignedHash});
    let signed;
    try {signed=await boundedDeviceOperation(signing,timeoutMilliseconds,'OneKey transaction signing',opened);}
    catch(error){error.exitCode=80;throw error;}
    try {
      await writePrivateFileDurableNew(outputPath,Buffer.from(`${signed.rawTransaction}\n`,'ascii'),{maximum:2*1024*1024});
    } catch(cause) {
      const error=new Error('OneKey signature completed but private output was not durably installed',{cause});
      error.exitCode=80;throw error;
    }
    return Object.freeze({unsignedHash:signed.unsignedHash,address:signed.address});
  } finally {
    if(opened?.close&&!disposedSessions.has(opened)) await bounded(Promise.resolve().then(()=>opened.close()),10_000,'OneKey transport close');
  }
}

