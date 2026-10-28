import {getAddress} from 'ethers';

const CHAIN='eip155:1';
const METHOD='eth_signTypedData_v4';
// OneKey advertises its full supported EVM capability set even for a narrower proposal.
// Source: OneKeyHQ/app-monorepo @ 6c60d4d2744ad41d4f458551e5c534a71401bf42,
// packages/shared/src/walletConnect/constant.ts and ServiceWalletConnect.buildWalletConnectNamespace.
// Accepting these advertised capabilities does not authorize invoking them: the signing
// adapter constructs only eth_signTypedData_v4, while discovery never calls request().
const advertisedMethods=new Set(['personal_sign','eth_sign','eth_signTransaction','eth_signTypedData',
  'eth_signTypedData_v3',METHOD,'eth_sendRawTransaction','eth_sendTransaction']);
const advertisedEvents=new Set(['accountsChanged','chainChanged']);
const accountPattern=/^eip155:1:0x[0-9a-fA-F]{40}$/u;
const codes=new Set(['SESSION_TOPIC_INVALID','SESSION_NAMESPACE_INVALID','SESSION_ACCOUNT_INVALID',
  'SESSION_CHAIN_INVALID','SESSION_METHODS_INVALID','SESSION_EVENTS_INVALID','SESSION_ACCOUNT_MISMATCH']);
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const exact=(value,keys)=>object(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());

export class OneKeyIosSessionError extends Error {
  constructor(code){
    if(!codes.has(code))throw new TypeError('unknown OneKey session error code');
    super(`WalletConnect session rejected or overprivileged: ${code}`);
    this.name='OneKeyIosSessionError';
    this.code=code;
  }
}

const reject=code=>{throw new OneKeyIosSessionError(code);};
function addressFromAccount(account,code){
  if(typeof account!=='string'||!accountPattern.test(account))reject(code);
  try{return getAddress(account.slice(CHAIN.length+1));}
  catch{reject(code);}
}

export function validateOneKeyIosCapabilities({methods,events}={}){
  if(!Array.isArray(methods)||methods.length<1||methods.length>advertisedMethods.size
    ||methods.some(method=>!advertisedMethods.has(method))||new Set(methods).size!==methods.length
    ||!methods.includes(METHOD))reject('SESSION_METHODS_INVALID');
  if(!Array.isArray(events)||events.length>advertisedEvents.size
    ||events.some(event=>!advertisedEvents.has(event))||new Set(events).size!==events.length) {
    reject('SESSION_EVENTS_INVALID');
  }
  return Object.freeze({methods:Object.freeze([...methods]),events:Object.freeze([...events])});
}

export function validateOneKeyIosSession(session,{expectedAccount}={}){
  if(!object(session)||typeof session.topic!=='string'||session.topic.length<16) {
    reject('SESSION_TOPIC_INVALID');
  }
  if(!object(session.namespaces))reject('SESSION_NAMESPACE_INVALID');
  const keys=Object.keys(session.namespaces);
  if(keys.length!==1||!['eip155',CHAIN].includes(keys[0]))reject('SESSION_NAMESPACE_INVALID');
  const namespace=session.namespaces[keys[0]];
  if(!exact(namespace,['accounts','methods','events'])
    &&!exact(namespace,['accounts','chains','methods','events']))reject('SESSION_NAMESPACE_INVALID');
  if(!Array.isArray(namespace.accounts)||namespace.accounts.length!==1)reject('SESSION_ACCOUNT_INVALID');
  const address=addressFromAccount(namespace.accounts[0],'SESSION_ACCOUNT_INVALID');
  if(Object.hasOwn(namespace,'chains')
    &&(!Array.isArray(namespace.chains)||namespace.chains.length!==1||namespace.chains[0]!==CHAIN)) {
    reject('SESSION_CHAIN_INVALID');
  }
  const capabilities=validateOneKeyIosCapabilities(namespace);
  if(expectedAccount!==undefined
    &&addressFromAccount(expectedAccount,'SESSION_ACCOUNT_MISMATCH')!==address) {
    reject('SESSION_ACCOUNT_MISMATCH');
  }
  return Object.freeze({address,account:`${CHAIN}:${address}`,...capabilities,chains:Object.freeze([CHAIN])});
}
