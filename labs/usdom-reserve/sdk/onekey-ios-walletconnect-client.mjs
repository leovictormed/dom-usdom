import {SignClient} from '@walletconnect/sign-client';
import {randomUUID} from 'node:crypto';
import {readDirectFile} from './direct-project-file.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {executeOneKeyIosTypedDataRequest,OneKeyIosSigningFailure,oneKeyIosSigningBoundary,
  combineOneKeyIosSigningFailures} from './onekey-ios-walletconnect-typed-data.mjs';

const CONFIG_SCHEMA='usdom-onekey-ios-walletconnect-client-config/v1';
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');

class EphemeralWalletConnectStorage {
  #values=new Map();
  async getKeys(){return [...this.#values.keys()];}
  async getEntries(){return [...this.#values.entries()];}
  async getItem(key){return this.#values.get(key);}
  async setItem(key,value){this.#values.set(key,value);}
  async removeItem(key){this.#values.delete(key);}
  clear(){this.#values.clear();}
}

export async function readOneKeyIosWalletConnectClientConfig(path) {
  const config=parseStrictJsonBytes(await readDirectFile(path,{minimum:2,maximum:16384,privateMode:true,
    exactMode:0o600,label:'private WalletConnect client configuration'}),
  {label:'private WalletConnect client configuration'});
  if(!exact(config,['schema','projectId','metadata','communityLicenseAccepted','networkExecutionApproved'])
    ||config.schema!==CONFIG_SCHEMA||!/^[0-9a-f]{32}$/u.test(config.projectId??'')
    ||config.communityLicenseAccepted!==true||config.networkExecutionApproved!==true
    ||!exact(config.metadata,['name','description','url','icons'])
    ||typeof config.metadata.name!=='string'||config.metadata.name.length<1||config.metadata.name.length>64
    ||typeof config.metadata.description!=='string'||config.metadata.description.length>128
    ||typeof config.metadata.url!=='string'||!/^https:\/\/[a-z0-9.-]+(?:\/[a-z0-9._~!$&'()*+,;=:@%/-]*)?$/iu.test(config.metadata.url)
    ||!Array.isArray(config.metadata.icons)||config.metadata.icons.length!==1
    ||typeof config.metadata.icons[0]!=='string'||!/^https:\/\//iu.test(config.metadata.icons[0])) {
    throw new Error('WalletConnect client configuration is not approved');
  }
  return config;
}

export async function openOneKeyIosWalletConnectClient({configPath,signClient=SignClient}={}) {
  const config=await oneKeyIosSigningBoundary(()=>readOneKeyIosWalletConnectClientConfig(configPath),
    'CLIENT_CONFIG_INVALID','initializing-client');
  if(typeof signClient?.init!=='function')throw new Error('WalletConnect SignClient implementation unavailable');
  const storage=new EphemeralWalletConnectStorage();
  const client=await signClient.init({projectId:config.projectId,metadata:config.metadata,logger:'silent',
    storage,telemetryEnabled:false,customStoragePrefix:`usdom-${randomUUID()}`});
  if(!client||typeof client.connect!=='function'||client.core?.projectId!==config.projectId) {
    storage.clear();throw new Error('WalletConnect SignClient initialization rejected');
  }
  // The request boundary authenticates this public identifier without exposing other configuration.
  client.projectId=config.projectId;
  return Object.freeze({client,projectId:config.projectId,async close(){
    try {
      try {await client.core?.heartbeat?.stop?.();}
      finally {if(typeof client.core?.relayer?.transportClose==='function')await client.core.relayer.transportClose();}
    }
    finally {storage.clear();}
  }});
}

export async function runOneKeyIosWalletConnectSigning({configPath,requestPath,physicalEvidencePath,outputPath,
  displayDeepLink,timeoutMilliseconds=300_000,clientFactory=openOneKeyIosWalletConnectClient}={}) {
  if(typeof clientFactory!=='function'||typeof displayDeepLink!=='function') {
    throw new OneKeyIosSigningFailure('REQUEST_INVALID','validating-request');
  }
  let opened,signed=false,result,failure;
  try {
    opened=await oneKeyIosSigningBoundary(()=>clientFactory({configPath}),'INITIALIZATION_FAILED','initializing-client');
    result=await oneKeyIosSigningBoundary(()=>executeOneKeyIosTypedDataRequest({requestPath,physicalEvidencePath,outputPath,
      client:opened.client,onDeepLink:displayDeepLink,timeoutMilliseconds}),'REQUEST_INVALID','validating-request');
    signed=true;
  } catch(error) {
    failure=error;
  } finally {
    if(opened?.close)try {await opened.close();} catch(cause) {
      failure=combineOneKeyIosSigningFailures(failure,
        new OneKeyIosSigningFailure('CLIENT_SHUTDOWN_FAILED','client-shutdown',{cause}),{signed});
    }
  }
  if(failure)throw failure;
  return result;
}

export const ONEKEY_IOS_WC_CLIENT_CONFIG_SCHEMA=CONFIG_SCHEMA;
export {EphemeralWalletConnectStorage};
