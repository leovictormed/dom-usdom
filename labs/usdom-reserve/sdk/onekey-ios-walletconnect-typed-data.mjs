import {createHash,randomBytes} from 'node:crypto';
import {getAddress,TypedDataEncoder,verifyTypedData} from 'ethers';
import {readDirectFile} from './direct-project-file.mjs';
import {writePrivateFileDurableNew} from './durable-private-file.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {OneKeyIosSessionError,validateOneKeyIosSession} from './onekey-ios-walletconnect-session.mjs';

const signingMessages=Object.freeze({
 INITIALIZATION_FAILED:'Não foi possível inicializar o cliente WalletConnect.',
 CLIENT_CONFIG_INVALID:'A configuração local WalletConnect não foi aceita.',
 REQUEST_INVALID:'O pedido local de assinatura não passou pela validação.',
 PHYSICAL_EVIDENCE_INVALID:'A evidência da conta física não corresponde ao pedido atual.',
 PROJECT_MISMATCH:'O projeto WalletConnect não corresponde ao pedido atual.',
 PAIRING_FAILED:'Não foi possível criar a conexão com a carteira.',
 PAIRING_INVALID:'A conexão retornada pelo relay é inválida.',
 PAIRING_TIMEOUT:'A criação da conexão excedeu o tempo limite.',
 DEEPLINK_FAILED:'Não foi possível mostrar o link no terminal.',
 DEEPLINK_TIMEOUT:'A apresentação do link excedeu o tempo limite.',
 APPROVAL_FAILED:'O relay não concluiu a aprovação da conexão.',
 APPROVAL_TIMEOUT:'A aprovação da conexão não chegou dentro do tempo limite.',
 SESSION_TOPIC_INVALID:'A carteira retornou uma sessão inválida.',
 SESSION_NAMESPACE_INVALID:'A sessão retornou redes ou formato inesperados.',
 SESSION_ACCOUNT_INVALID:'A conexão deve conter somente uma conta Ethereum.',
 SESSION_CHAIN_INVALID:'A conta retornada precisa pertencer à Ethereum mainnet.',
 SESSION_METHODS_INVALID:'A carteira anunciou métodos incompatíveis com este fluxo.',
 SESSION_EVENTS_INVALID:'A carteira anunciou eventos incompatíveis com este fluxo.',
 SESSION_ACCOUNT_MISMATCH:'A conta conectada difere da conta esperada para esta assinatura.',
 SESSION_INVALID:'A sessão WalletConnect não passou pela validação.',
 SIGNATURE_REQUEST_FAILED:'O aplicativo ou relay não concluiu o pedido de assinatura.',
 WALLET_REJECTED:'A carteira devolveu uma rejeição do pedido; isso também pode indicar erro no aplicativo.',
 WALLET_UNSUPPORTED_REQUEST:'A carteira informou que não suporta o pedido solicitado.',
 SIGNATURE_TIMEOUT:'A resposta de assinatura não chegou dentro do tempo limite.',
 SIGNATURE_FORMAT_INVALID:'A carteira retornou uma assinatura com formato inválido.',
 SIGNATURE_INVALID:'A assinatura retornada não passou pela verificação criptográfica.',
 SIGNATURE_SIGNER_MISMATCH:'A assinatura retornada pertence a uma conta diferente da esperada.',
 REQUEST_QUIESCENCE_FAILED:'Não foi possível confirmar o encerramento do pedido após o tempo limite.',
 SESSION_CLEANUP_FAILED:'Não foi possível confirmar a remoção da sessão WalletConnect.',
 PAIRING_CLEANUP_FAILED:'Não foi possível confirmar a remoção do pareamento WalletConnect.',
 RESPONSE_WRITE_FAILED:'A assinatura foi recebida, mas não foi possível salvar sua resposta com segurança.',
 CLIENT_SHUTDOWN_FAILED:'Não foi possível confirmar o encerramento do cliente WalletConnect.',
 TERMINAL_RESTORE_FAILED:'Não foi possível confirmar a restauração do terminal.',
 OPERATION_INCOMPLETE:'A operação terminou sem uma resposta de assinatura completa.',
 UNEXPECTED_FAILURE:'A assinatura não foi concluída; o diagnóstico não contém dados privados.',
});
const signingPhases=new Set(['initializing-client','validating-request','pairing','awaiting-approval',
 'validating-session','awaiting-signature','validating-signature','deleting-session','deleting-pairing',
 'saving-response','client-shutdown']);
const signingFailures=new WeakMap();
export class OneKeyIosSigningFailure extends Error {
 constructor(code,phase,{cause,exitCode=1,cleanupFailures=[]}={}) {
  if(!Object.hasOwn(signingMessages,code)||(!signingPhases.has(phase)&&phase!=='unknown')
    ||![1,80].includes(exitCode)||!Array.isArray(cleanupFailures)
    ||cleanupFailures.some(value=>!signingPhases.has(value.phase)||!Object.hasOwn(signingMessages,value.code))) {
   throw new TypeError('invalid local signing diagnostic');
  }
  super(signingMessages[code],{cause});this.name='OneKeyIosSigningFailure';this.exitCode=exitCode;
  signingFailures.set(this,Object.freeze({code,phase,exitCode,cleanupFailures:Object.freeze(
   cleanupFailures.map(({code,phase})=>Object.freeze({code,phase})))}));
 }
}
export function describeOneKeyIosSigningFailure(error,fallbackPhase='unknown') {
 const details=signingFailures.get(error),phase=details?.phase??(signingPhases.has(fallbackPhase)?fallbackPhase:'unknown');
 const code=details?.code??(phase==='initializing-client'?'INITIALIZATION_FAILED':
  phase==='client-shutdown'?'CLIENT_SHUTDOWN_FAILED':'UNEXPECTED_FAILURE');
 return Object.freeze({phase,code,message:signingMessages[code],
  ...(details?.cleanupFailures.length?{cleanupFailures:details.cleanupFailures}:{})});
}
export function oneKeyIosSigningExitCode(error) {return signingFailures.get(error)?.exitCode??1;}
export function combineOneKeyIosSigningFailures(primary,cleanup,{signed=false}={}) {
 const next=signingFailures.get(cleanup);
 if(!next)throw new TypeError('cleanup diagnostic must be local');
 if(!primary)return new OneKeyIosSigningFailure(next.code,next.phase,{cause:cleanup,
  exitCode:signed?80:next.exitCode,cleanupFailures:next.cleanupFailures});
 const first=signingFailures.get(primary);
 if(!first)throw new TypeError('primary diagnostic must be local');
 return new OneKeyIosSigningFailure(first.code,first.phase,{cause:primary,
  exitCode:signed||first.exitCode===80||next.exitCode===80?80:1,
  cleanupFailures:[...first.cleanupFailures,{code:next.code,phase:next.phase},...next.cleanupFailures]});
}
export async function oneKeyIosSigningBoundary(operation,code,phase,{remote=false}={}) {
 try {return await operation();}
 catch(cause) {
  if(signingFailures.has(cause))throw cause;
  if(phase==='validating-session'&&cause instanceof OneKeyIosSessionError
    &&Object.hasOwn(signingMessages,cause.code))code=cause.code;
  if(remote) {
   let remoteCode;try {remoteCode=cause?.code;}catch{}
   if([4001,5000,5001,5002,5003].includes(remoteCode))code='WALLET_REJECTED';
   else if([5100,5101,5102,5103,5104].includes(remoteCode))code='WALLET_UNSUPPORTED_REQUEST';
  }
  throw new OneKeyIosSigningFailure(code,phase,{cause});
 }
}

export const ONEKEY_IOS_WC_SCHEMA='usdom-onekey-ios-walletconnect-typed-data/v1';
export const ONEKEY_IOS_WC_METHOD='eth_signTypedData_v4';
const CHAIN='eip155:1';
const forbiddenMethods=Object.freeze(['eth_sendTransaction','eth_signTransaction','personal_sign',
 'wallet_switchEthereumChain','wallet_addEthereumChain','eth_sendRawTransaction']);
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
 &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const canonical=value=>{if(value===null||typeof value==='boolean'||typeof value==='string')return JSON.stringify(value);
 if(typeof value==='number'&&Number.isSafeInteger(value))return JSON.stringify(value);
 if(Array.isArray(value))return`[${value.map(canonical).join(',')}]`;
 if(value&&typeof value==='object')return`{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
 throw new Error('non-canonical WalletConnect request');};
const sha=value=>createHash('sha256').update(canonical(value)).digest('hex');

export function buildOneKeyIosWalletConnectProposal(expectedAddress) {
 const account=getAddress(expectedAddress);
 return Object.freeze({requiredNamespaces:Object.freeze({eip155:Object.freeze({chains:[CHAIN],
  methods:[ONEKEY_IOS_WC_METHOD],events:[]})}),expectedAccount:`${CHAIN}:${account}`});
}

async function readPhysicalAccountEvidence(path,expectedAddress,walletConnectProjectId) {
 const bytes=await readDirectFile(path,{minimum:2,maximum:65536,privateMode:true,exactMode:0o600,label:'OneKey iOS onboarding evidence'});
 const evidence=parseStrictJsonBytes(bytes,{label:'OneKey iOS onboarding evidence'});
 if(!exact(evidence,['schema','status','projectIdSha256','address','roles','walletConnectExposesDeviceIdentity','physicalConfirmationSource','model','addressShownOnDevice','operatorConfirmed','singleOperatorResidualRisk','hardwareSigningApproved','realFundsApproved'])
  ||evidence.schema!=='usdom-onekey-ios-onboarding-evidence-v1'||evidence.status!=='observed-awaiting-role-ratification'
  ||evidence.projectIdSha256!==createHash('sha256').update(walletConnectProjectId).digest('hex')
  ||getAddress(evidence.address)!==getAddress(expectedAddress)||evidence.walletConnectExposesDeviceIdentity!==false
  ||evidence.physicalConfirmationSource!=='human-observed-device-screen'||evidence.model!=='classic1s'
  ||evidence.addressShownOnDevice!==true||evidence.operatorConfirmed!==true||evidence.hardwareSigningApproved!==false||evidence.realFundsApproved!==false)
  throw new Error('OneKey iOS onboarding evidence rejected');
 return {evidence,sha256:createHash('sha256').update(bytes).digest('hex')};
}
export async function prepareOneKeyIosTypedDataRequest({path,expectedAddress,typedData,
 physicalEvidencePath,walletConnectProjectId}={}) {
 const account=getAddress(expectedAddress);
 if(!/^[0-9a-f]{32}$/u.test(walletConnectProjectId??''))throw new Error('WalletConnect project id is not configured');
 const physical=await readPhysicalAccountEvidence(physicalEvidencePath,account,walletConnectProjectId);
 if(!exact(typedData,['types','primaryType','domain','message'])||!typedData.types?.EIP712Domain) {
  throw new Error('invalid EIP-712 typed data');
 }
 const types={...typedData.types};delete types.EIP712Domain;
 if(TypedDataEncoder.from(types).primaryType!==typedData.primaryType)throw new Error('EIP-712 primary type mismatch');
 const digest=TypedDataEncoder.hash(typedData.domain,types,typedData.message);
 const body={schema:ONEKEY_IOS_WC_SCHEMA,requestId:randomBytes(32).toString('hex'),chainId:CHAIN,
  method:ONEKEY_IOS_WC_METHOD,expectedAddress:account,digest,typedData,walletConnectProjectId,
  physicalEvidenceSha256:physical.sha256,onboardingProjectIdSha256:physical.evidence.projectIdSha256,confirmationSource:physical.evidence.physicalConfirmationSource,model:physical.evidence.model,limitations:['walletconnect-does-not-expose-device-id','walletconnect-does-not-expose-firmware']};
 const document={...body,requestSha256:sha(body)};
 await writePrivateFileDurableNew(path,Buffer.from(`${canonical(document)}\n`),{maximum:2*1024*1024});
 return Object.freeze({requestSha256:document.requestSha256,digest,expectedAddress:account});
}

export async function readOneKeyIosTypedDataRequest(path) {
 const request=parseStrictJsonBytes(await readDirectFile(path,{minimum:2,maximum:2*1024*1024,privateMode:true,
  exactMode:0o600,label:'OneKey iOS WalletConnect request'}),{label:'OneKey iOS WalletConnect request'});
 if(!exact(request,['schema','requestId','chainId','method','expectedAddress','digest','typedData','walletConnectProjectId',
   'physicalEvidenceSha256','onboardingProjectIdSha256','confirmationSource','model','limitations','requestSha256'])
   ||request.schema!==ONEKEY_IOS_WC_SCHEMA||!/^[0-9a-f]{64}$/u.test(request.requestId)
   ||request.chainId!==CHAIN||request.method!==ONEKEY_IOS_WC_METHOD||!/^[0-9a-f]{32}$/u.test(request.walletConnectProjectId)
   ||!/^[0-9a-f]{64}$/u.test(request.physicalEvidenceSha256)||!/^[0-9a-f]{64}$/u.test(request.onboardingProjectIdSha256)
   ||request.confirmationSource!=='human-observed-device-screen'||request.model!=='classic1s'||JSON.stringify(request.limitations)!==JSON.stringify(['walletconnect-does-not-expose-device-id','walletconnect-does-not-expose-firmware'])
   ||getAddress(request.expectedAddress)!==request.expectedAddress)throw new Error('invalid OneKey iOS WalletConnect request');
 const body={...request};delete body.requestSha256;if(sha(body)!==request.requestSha256)throw new Error('WalletConnect request hash mismatch');
 const types={...request.typedData.types};delete types.EIP712Domain;
 if(TypedDataEncoder.hash(request.typedData.domain,types,request.typedData.message)!==request.digest)throw new Error('WalletConnect typed-data digest mismatch');
 return request;
}

export async function readOneKeyIosTypedDataResponse(path,requestPath) {
 const request=await readOneKeyIosTypedDataRequest(requestPath);
 const response=parseStrictJsonBytes(await readDirectFile(path,{minimum:2,maximum:4096,privateMode:true,
  exactMode:0o600,label:'OneKey iOS WalletConnect response'}),{label:'OneKey iOS WalletConnect response'});
 if(!exact(response,['schema','requestSha256','digest','expectedAddress','signature'])
   ||response.schema!==ONEKEY_IOS_WC_SCHEMA||response.requestSha256!==request.requestSha256
   ||response.digest!==request.digest||getAddress(response.expectedAddress)!==request.expectedAddress
   ||typeof response.signature!=='string'||!/^0x[0-9a-fA-F]{130}$/u.test(response.signature)) {
  throw new Error('WalletConnect response binding rejected');
 }
 const types={...request.typedData.types};delete types.EIP712Domain;
 if(getAddress(verifyTypedData(request.typedData.domain,types,request.typedData.message,response.signature))!==request.expectedAddress) {
  throw new Error('WalletConnect response signer rejected');
 }
 return Object.freeze(response);
}

const bounded=(promise,milliseconds,code,phase)=>{let timer;return Promise.race([promise,new Promise((_,reject)=>{
 timer=setTimeout(()=>reject(new OneKeyIosSigningFailure(code,phase)),milliseconds);})]).finally(()=>clearTimeout(timer));};

const pairingTopicFromUri=uri=>{const match=/^wc:([a-zA-Z0-9_-]{1,256})@2(?:\?|$)/u.exec(uri);return match?.[1];};
async function deletePairing(client,topic) {
 if(!topic||typeof client?.core?.pairing?.disconnect!=='function'||typeof client.core.pairing.getPairings!=='function')throw new Error('WalletConnect pairing deletion unavailable');
 const before=client.core.pairing.getPairings?.()??[];if(!before.some(item=>item.topic===topic))return;
 await client.core.pairing.disconnect({topic});
 const remaining=client.core.pairing.getPairings?.()??[];
 if(remaining.some(item=>item.topic===topic))throw new Error('WalletConnect pairing deletion not proven');
}
async function deleteSession(client,topic) {
 if(typeof client?.session?.getAll!=='function')throw new Error('WalletConnect session deletion proof unavailable');
 const before=client.session?.getAll?.()??[];if(!before.some(item=>item.topic===topic))return;
 await client.disconnect({topic,reason:{code:6000,message:'USDOM signing session complete'}});
 const remaining=client.session?.getAll?.()??[];
 if(remaining.some(item=>item.topic===topic))throw new Error('WalletConnect session deletion not proven');
}
async function boundedCancelable(promise,milliseconds,code,phase,cancel) {
 let timer,timedOut=false;
 const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>{timedOut=true;reject(new OneKeyIosSigningFailure(code,phase));},milliseconds);});
 try{return await Promise.race([promise,timeout]);}
 catch(error){if(!timedOut)throw error;
  try {await cancel();await bounded(promise.then(()=>{},()=>{}),
   Math.min(10_000,Math.max(10,milliseconds)),'REQUEST_QUIESCENCE_FAILED',phase);}
  catch(cause){const cleanup=signingFailures.has(cause)?cause:
   new OneKeyIosSigningFailure('REQUEST_QUIESCENCE_FAILED',phase,{cause});
   throw combineOneKeyIosSigningFailures(error,cleanup);}
  throw error;
 }
 finally{clearTimeout(timer);}
}

export async function executeOneKeyIosTypedDataRequest({requestPath,physicalEvidencePath,outputPath,client,onDeepLink,
 timeoutMilliseconds=300_000}={}) {
 let request,proposal;
 await oneKeyIosSigningBoundary(async()=>{
 if(!client||typeof client.connect!=='function'||typeof client.request!=='function'||typeof client.disconnect!=='function'
   ||typeof client?.core?.pairing?.disconnect!=='function'||typeof client?.core?.pairing?.getPairings!=='function'
   ||typeof client?.session?.getAll!=='function'
   ||typeof onDeepLink!=='function'||!Number.isSafeInteger(timeoutMilliseconds)||timeoutMilliseconds<1
   ||timeoutMilliseconds>300_000)throw new Error('invalid WalletConnect boundary');
 request=await readOneKeyIosTypedDataRequest(requestPath);proposal=buildOneKeyIosWalletConnectProposal(request.expectedAddress);
 const physical=await oneKeyIosSigningBoundary(()=>readPhysicalAccountEvidence(physicalEvidencePath,
  request.expectedAddress,request.walletConnectProjectId),'PHYSICAL_EVIDENCE_INVALID','validating-request');
 if(physical.sha256!==request.physicalEvidenceSha256
   ||physical.evidence.projectIdSha256!==request.onboardingProjectIdSha256
   ||physical.evidence.physicalConfirmationSource!==request.confirmationSource
   ||physical.evidence.model!==request.model) {
  throw new OneKeyIosSigningFailure('PHYSICAL_EVIDENCE_INVALID','validating-request');
 }
 if(client.projectId!==request.walletConnectProjectId)throw new OneKeyIosSigningFailure('PROJECT_MISMATCH','validating-request');
 if(typeof outputPath!=='string')throw new Error('private WalletConnect response path required');
 },'REQUEST_INVALID','validating-request');
 let topic,pairingTopic,approval,signed=false,cleanupComplete=false,result,failure;
 try {
  const connectPromise=Promise.resolve().then(()=>client.connect({requiredNamespaces:proposal.requiredNamespaces}));
  const pairing=await oneKeyIosSigningBoundary(()=>boundedCancelable(connectPromise,timeoutMilliseconds,
   'PAIRING_TIMEOUT','pairing',async()=>{
    connectPromise.then(late=>{const lateTopic=pairingTopicFromUri(late?.uri);
     if(lateTopic)void deletePairing(client,lateTopic).catch(()=>{});},()=>{});
   }),'PAIRING_FAILED','pairing');
  if(!pairing||typeof pairing.uri!=='string'||pairing.uri.length>4096||!/^[a-z0-9%:@?&=._-]+$/iu.test(pairing.uri)
    ||!pairing.uri.startsWith('wc:')||typeof pairing.approval!=='function')throw new OneKeyIosSigningFailure('PAIRING_INVALID','pairing');
  approval=pairing.approval;pairingTopic=pairingTopicFromUri(pairing.uri);
  if(!pairingTopic)throw new OneKeyIosSigningFailure('PAIRING_INVALID','pairing');
  await oneKeyIosSigningBoundary(()=>bounded(Promise.resolve().then(()=>onDeepLink(
   `onekey-wallet://wc?uri=${encodeURIComponent(pairing.uri)}`)),timeoutMilliseconds,'DEEPLINK_TIMEOUT','pairing'),
  'DEEPLINK_FAILED','pairing');
  const approvalPromise=Promise.resolve().then(approval);
  const session=await oneKeyIosSigningBoundary(()=>boundedCancelable(approvalPromise,timeoutMilliseconds,
   'APPROVAL_TIMEOUT','awaiting-approval',()=>oneKeyIosSigningBoundary(()=>deletePairing(client,pairingTopic),
    'PAIRING_CLEANUP_FAILED','deleting-pairing')),'APPROVAL_FAILED','awaiting-approval',{remote:true});
  if(typeof session?.topic==='string')topic=session.topic;
  await oneKeyIosSigningBoundary(()=>validateOneKeyIosSession(session,{expectedAccount:proposal.expectedAccount}),
   'SESSION_INVALID','validating-session');
  const signaturePromise=Promise.resolve().then(()=>client.request({topic,chainId:CHAIN,request:{method:ONEKEY_IOS_WC_METHOD,
   params:[request.expectedAddress,JSON.stringify(request.typedData)]}}));
  const signature=await oneKeyIosSigningBoundary(()=>boundedCancelable(signaturePromise,timeoutMilliseconds,
   'SIGNATURE_TIMEOUT','awaiting-signature',()=>oneKeyIosSigningBoundary(()=>deleteSession(client,topic),
    'SESSION_CLEANUP_FAILED','deleting-session')),'SIGNATURE_REQUEST_FAILED','awaiting-signature',{remote:true});
  await oneKeyIosSigningBoundary(()=>{
   if(typeof signature!=='string'||!/^0x[0-9a-fA-F]{130}$/u.test(signature)) {
    throw new OneKeyIosSigningFailure('SIGNATURE_FORMAT_INVALID','validating-signature');
   }
   if(getAddress(verifyTypedData(request.typedData.domain,(()=>{const t={...request.typedData.types};delete t.EIP712Domain;return t;})(),
    request.typedData.message,signature))!==request.expectedAddress) {
    throw new OneKeyIosSigningFailure('SIGNATURE_SIGNER_MISMATCH','validating-signature');
   }
  },'SIGNATURE_INVALID','validating-signature');
  signed=true;result={schema:ONEKEY_IOS_WC_SCHEMA,requestSha256:request.requestSha256,digest:request.digest,
   expectedAddress:request.expectedAddress,signature};
 } catch(error) {
  failure=signingFailures.has(error)?error:new OneKeyIosSigningFailure('UNEXPECTED_FAILURE','unknown',{cause:error});
 } finally {
  try {if(topic)await oneKeyIosSigningBoundary(()=>bounded(deleteSession(client,topic),10_000,
    'SESSION_CLEANUP_FAILED','deleting-session'),'SESSION_CLEANUP_FAILED','deleting-session');
   if(pairingTopic)await oneKeyIosSigningBoundary(()=>bounded(deletePairing(client,pairingTopic),10_000,
    'PAIRING_CLEANUP_FAILED','deleting-pairing'),'PAIRING_CLEANUP_FAILED','deleting-pairing');cleanupComplete=true;}
  catch(cleanup){failure=combineOneKeyIosSigningFailures(failure,cleanup,{signed});}
 }
 if(failure)throw failure;
 if(!cleanupComplete||!result)throw new OneKeyIosSigningFailure('OPERATION_INCOMPLETE','validating-signature');
 try {await writePrivateFileDurableNew(outputPath,Buffer.from(`${canonical(result)}\n`),{maximum:4096});}
 catch(cause){throw new OneKeyIosSigningFailure('RESPONSE_WRITE_FAILED','saving-response',{cause,exitCode:80});}
 return Object.freeze({requestSha256:result.requestSha256,digest:result.digest,expectedAddress:result.expectedAddress});
}

export const ONEKEY_IOS_WC_FORBIDDEN_METHODS=forbiddenMethods;
