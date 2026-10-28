import {createHash} from 'node:crypto';
import {getAddress} from 'ethers';
import {writePrivateFileDurableNew} from './durable-private-file.mjs';
import {OneKeyIosSessionError,validateOneKeyIosCapabilities,validateOneKeyIosSession}
  from './onekey-ios-walletconnect-session.mjs';

const failureMessages=Object.freeze({
  INITIALIZATION_FAILED:'Não foi possível inicializar a conexão WalletConnect.',
  BOUNDARY_INVALID:'A configuração local do onboarding é inválida.',
  PAIRING_FAILED:'Não foi possível criar a conexão com a carteira.',
  PAIRING_TIMEOUT:'O relay não criou a conexão dentro de cinco minutos.',
  PAIRING_INVALID:'O relay retornou uma conexão inválida.',
  DEEPLINK_FAILED:'Não foi possível apresentar o link no terminal.',
  DEEPLINK_TIMEOUT:'A apresentação do link excedeu o tempo limite.',
  APPROVAL_FAILED:'O relay não concluiu a aprovação da conexão.',
  APPROVAL_TIMEOUT:'A aprovação não chegou pelo relay dentro de cinco minutos.',
  WALLET_REJECTED:'A carteira devolveu uma rejeição da conexão; isso também pode indicar erro no aplicativo.',
  WALLET_UNSUPPORTED_REQUEST:'A carteira informou que não suporta a configuração solicitada.',
  STAGE_UPDATE_FAILED:'Não foi possível atualizar o estado no terminal.',
  PAIRING_MISMATCH:'A resposta da carteira não corresponde à conexão aberta.',
  PHYSICAL_CONFIRMATION_FAILED:'A confirmação física não foi registrada. Após conferir o visor da OneKey, responda no terminal com CONFIRMO seguido do endereço completo solicitado.',
  CLEANUP_FAILED:'Não foi possível confirmar o encerramento da sessão WalletConnect.',
  EVIDENCE_WRITE_FAILED:'Não foi possível salvar a confirmação da carteira.',
  CLIENT_SHUTDOWN_FAILED:'Não foi possível encerrar o cliente WalletConnect.',
  SESSION_TOPIC_INVALID:'A carteira retornou uma sessão inválida.',
  SESSION_NAMESPACE_INVALID:'A sessão retornou redes ou formato inesperados.',
  SESSION_ACCOUNT_INVALID:'Selecione somente uma conta Ethereum na conexão OneKey.',
  SESSION_CHAIN_INVALID:'A conta retornada precisa pertencer à Ethereum mainnet.',
  SESSION_METHODS_INVALID:'A carteira anunciou métodos incompatíveis com este fluxo.',
  SESSION_EVENTS_INVALID:'A carteira anunciou eventos incompatíveis com este fluxo.',
  SESSION_ACCOUNT_MISMATCH:'A conta retornada difere da conta esperada.',
  UNEXPECTED_FAILURE:'O onboarding não foi concluído; o diagnóstico não contém dados privados.',
});
const phases=new Set(['initializing','connecting','deeplink-ready','awaiting-approval','approval-received',
  'validating-session','physical-confirmation-required','cleanup-complete','saving-evidence','client-shutdown']);
class OnboardingFailure extends Error {
  constructor(code,cause){super(failureMessages[code],{cause});this.code=code;}
}
export function describeIosOnboardingFailure(error,phase){
  const safePhase=phases.has(phase)?phase:'unknown';
  const local=error instanceof OnboardingFailure||error instanceof OneKeyIosSessionError;
  const code=local&&Object.hasOwn(failureMessages,error.code)?error.code:
    safePhase==='initializing'?'INITIALIZATION_FAILED':
      safePhase==='client-shutdown'?'CLIENT_SHUTDOWN_FAILED':'UNEXPECTED_FAILURE';
  return Object.freeze({phase:safePhase,code,message:failureMessages[code]});
}
async function boundary(promise,code){
  try{return await promise;}
  catch(cause){
    if(cause instanceof OnboardingFailure||cause instanceof OneKeyIosSessionError)throw cause;
    if(code==='APPROVAL_FAILED') {
      if([4001,5000,5001,5002,5003].includes(cause?.code))code='WALLET_REJECTED';
      else if([5100,5101,5102,5103,5104].includes(cause?.code))code='WALLET_UNSUPPORTED_REQUEST';
    }
    throw new OnboardingFailure(code,cause);
  }
}

const exact=(value,keys,label)=>{
  if(value===null||typeof value!=='object'||Array.isArray(value)
    ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    throw new Error(`${label} schema invalid`);
  }
};
const id=/^[0-9a-f]{32}$/u;

export function buildReownProjectRequest(){
  return {
    schema:'usdom-reown-project-request-v1',
    dashboard:'https://cloud.reown.com',
    requestedFields:['projectId'],
    forbiddenFields:['secret','privateKey','seed','mnemonic','walletConnectUri'],
    instruction:'Crie um projeto público para WalletConnect v2 e devolva somente o projectId público de 32 caracteres hexadecimais.',
  };
}

export function validateReownProjectResponse(value){
  exact(value,['schema','projectId'],'Reown response');
  if(value.schema!=='usdom-reown-project-response-v1'||!id.test(value.projectId)) {
    throw new Error('public Reown projectId rejected');
  }
  return value.projectId;
}

export function buildIosOnboardingEvidence({projectId,session,physical,roles}){
  if(!id.test(projectId))throw new Error('projectId invalid');
  exact(session,['schema','chain','account','methods','events','sessionDeleted'],'WC session');
  exact(physical,['schema','source','model','addressShownOnDevice','address','operatorConfirmed','mock'],
    'physical confirmation');
  if(session.schema!=='usdom-onekey-ios-wc-onboarding-session-v1'||session.chain!=='eip155:1'
    ||session.sessionDeleted!==true||physical.schema!=='usdom-onekey-classic1s-human-confirmation-v1'
    ||physical.source!=='human-observed-device-screen'||physical.model!=='classic1s'
    ||physical.addressShownOnDevice!==true||physical.operatorConfirmed!==true||physical.mock!==false) {
    throw new Error('onboarding evidence incomplete');
  }
  validateOneKeyIosCapabilities(session);
  if(!/^eip155:1:0x[0-9a-fA-F]{40}$/u.test(session.account))throw new Error('WC account invalid');
  const account=getAddress(session.account.split(':').at(-1));
  const shown=getAddress(physical.address);
  if(account!==shown)throw new Error('WalletConnect account differs from hardware screen');
  if(!Array.isArray(roles)||roles.length!==1||!/^(?:owner|replacement-owner)-[1-9][0-9]*$/u.test(roles[0])) {
    throw new Error('roles invalid');
  }
  return {
    schema:'usdom-onekey-ios-onboarding-evidence-v1',status:'observed-awaiting-role-ratification',
    projectIdSha256:createHash('sha256').update(projectId).digest('hex'),address:account,
    roles:roles.map(role=>({role,address:account,derivationPolicy:'same-confirmed-hardware-account-single-operator-pilot'})),
    walletConnectExposesDeviceIdentity:false,physicalConfirmationSource:'human-observed-device-screen',
    model:'classic1s',addressShownOnDevice:true,operatorConfirmed:true,singleOperatorResidualRisk:true,
    hardwareSigningApproved:false,realFundsApproved:false,
  };
}

export async function writeIosOnboardingEvidence(path,input){
  const result=buildIosOnboardingEvidence(input);
  await writePrivateFileDurableNew(path,`${JSON.stringify(result,null,2)}\n`,{maximum:65536});
  return result;
}

const bounded=(promise,milliseconds,code)=>{
  let timer;
  return Promise.race([promise,new Promise((_,reject)=>{
    timer=setTimeout(()=>reject(new OnboardingFailure(code)),milliseconds);
  })]).finally(()=>clearTimeout(timer));
};

const pairingTopicFromUri=uri=>{
  const match=/^wc:([a-zA-Z0-9_-]{1,256})@2(?:\?|$)/u.exec(uri);
  return match?.[1];
};

async function deletePairing(client,topic){
  if(!topic||typeof client?.core?.pairing?.disconnect!=='function'
    ||typeof client.core.pairing.getPairings!=='function') {
    throw new Error('WalletConnect pairing deletion unavailable');
  }
  if(!client.core.pairing.getPairings().some(item=>item.topic===topic))return;
  await client.core.pairing.disconnect({topic});
  if(client.core.pairing.getPairings().some(item=>item.topic===topic)) {
    throw new Error('WalletConnect pairing deletion not proven');
  }
}

async function deleteSession(client,topic){
  if(!topic||typeof client?.disconnect!=='function'||typeof client?.session?.getAll!=='function') {
    throw new Error('WalletConnect session deletion unavailable');
  }
  if(!client.session.getAll().some(item=>item.topic===topic))return;
  await client.disconnect({topic,reason:{code:6000,message:'USDOM onboarding complete'}});
  if(client.session.getAll().some(item=>item.topic===topic)) {
    throw new Error('WalletConnect session deletion not proven');
  }
}

async function reportStage(onStage,name,details={}){
  await boundary(bounded(Promise.resolve().then(()=>onStage(name,details)),10_000,'STAGE_UPDATE_FAILED'),
    'STAGE_UPDATE_FAILED');
}

export async function executeIosOnboarding({client,projectId,ownerRole,onDeepLink,confirmOnDevice,outputPath,
  onStage=async()=>{},timeoutMilliseconds=300_000}={}){
  validateReownProjectResponse({schema:'usdom-reown-project-response-v1',projectId});
  if(!/^(?:owner|replacement-owner)-[1-9][0-9]*$/u.test(ownerRole)
    ||typeof onDeepLink!=='function'||typeof confirmOnDevice!=='function'||typeof onStage!=='function'
    ||typeof outputPath!=='string'||!Number.isSafeInteger(timeoutMilliseconds)||timeoutMilliseconds<1
    ||timeoutMilliseconds>300_000||typeof client?.connect!=='function'||typeof client?.disconnect!=='function'
    ||typeof client?.session?.getAll!=='function'||typeof client?.core?.pairing?.disconnect!=='function'
    ||typeof client?.core?.pairing?.getPairings!=='function') {
    throw new OnboardingFailure('BOUNDARY_INVALID');
  }

  const requiredNamespaces={eip155:{chains:['eip155:1'],methods:['eth_signTypedData_v4'],events:[]}};
  let topic,pairingTopic,result,cleanupComplete=false;
  try {
    await reportStage(onStage,'connecting');
    const connection=await boundary(bounded(Promise.resolve().then(()=>client.connect({requiredNamespaces})),
      timeoutMilliseconds,'PAIRING_TIMEOUT'),'PAIRING_FAILED');
    if(typeof connection?.uri!=='string'||connection.uri.length>4096||!connection.uri.startsWith('wc:')
      ||typeof connection.approval!=='function')throw new OnboardingFailure('PAIRING_INVALID');
    pairingTopic=pairingTopicFromUri(connection.uri);
    if(!pairingTopic)throw new OnboardingFailure('PAIRING_INVALID');

    await reportStage(onStage,'deeplink-ready');
    await boundary(bounded(Promise.resolve().then(()=>onDeepLink(
      `onekey-wallet://wc?uri=${encodeURIComponent(connection.uri)}`)),timeoutMilliseconds,'DEEPLINK_TIMEOUT'),
    'DEEPLINK_FAILED');
    connection.uri=null;

    await reportStage(onStage,'awaiting-approval');
    const session=await boundary(bounded(Promise.resolve().then(()=>connection.approval()),timeoutMilliseconds,
      'APPROVAL_TIMEOUT'),'APPROVAL_FAILED');
    topic=session?.topic;
    await reportStage(onStage,'approval-received');
    await reportStage(onStage,'validating-session');
    if(session?.pairingTopic&&session.pairingTopic!==pairingTopic) {
      throw new OnboardingFailure('PAIRING_MISMATCH');
    }
    const namespace=validateOneKeyIosSession(session);
    const {address,account}=namespace;
    await reportStage(onStage,'physical-confirmation-required',{address});
    const physical=await boundary(Promise.resolve().then(()=>confirmOnDevice({ownerRole,address,
      prompt:`Confirme no visor da OneKey Classic 1S o endereço ${address}`})),'PHYSICAL_CONFIRMATION_FAILED');
    result={projectId,session:{schema:'usdom-onekey-ios-wc-onboarding-session-v1',chain:'eip155:1',
      account,methods:namespace.methods,events:namespace.events,sessionDeleted:true},physical,
      roles:[ownerRole]};
    await boundary(Promise.resolve().then(()=>buildIosOnboardingEvidence(result)),'PHYSICAL_CONFIRMATION_FAILED');
  } finally {
    try {
      if(topic)await bounded(deleteSession(client,topic),10_000,'CLEANUP_FAILED');
      if(pairingTopic)await bounded(deletePairing(client,pairingTopic),10_000,'CLEANUP_FAILED');
      cleanupComplete=true;
    } catch(cause) {
      const error=new OnboardingFailure('CLEANUP_FAILED',cause);
      if(result)error.exitCode=80;
      throw error;
    }
  }
  if(!cleanupComplete||!result)throw new Error('WalletConnect onboarding incomplete');
  await reportStage(onStage,'cleanup-complete');
  await reportStage(onStage,'saving-evidence');
  return await boundary(writeIosOnboardingEvidence(outputPath,result),'EVIDENCE_WRITE_FAILED');
}
