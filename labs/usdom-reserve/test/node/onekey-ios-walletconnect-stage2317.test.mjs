import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {Wallet} from 'ethers';
import {buildOneKeyIosWalletConnectProposal,executeOneKeyIosTypedDataRequest,
 prepareOneKeyIosTypedDataRequest,readOneKeyIosTypedDataRequest,describeOneKeyIosSigningFailure,
 oneKeyIosSigningExitCode} from '../../sdk/onekey-ios-walletconnect-typed-data.mjs';
import {OneKeyIosSessionError,validateOneKeyIosSession} from '../../sdk/onekey-ios-walletconnect-session.mjs';

const wallet=new Wallet('0x'+'11'.repeat(32));
const typedData={types:{EIP712Domain:[{name:'chainId',type:'uint256'}],Pilot:[{name:'nonce',type:'uint256'}]},
 primaryType:'Pilot',domain:{chainId:1},message:{nonce:7}};
const fresh=async()=>mkdtemp('/dev/shm/usdom-onekey-ios-');
const projectId='33'.repeat(16);
// Actual OneKey advertised capabilities at app-monorepo 6c60d4d2744ad41d4f458551e5c534a71401bf42.
const oneKeyMethods=['personal_sign','eth_sign','eth_signTransaction','eth_signTypedData',
 'eth_signTypedData_v3','eth_signTypedData_v4','eth_sendRawTransaction','eth_sendTransaction'];
const evidence={schema:'usdom-onekey-ios-onboarding-evidence-v1',status:'observed-awaiting-role-ratification',projectIdSha256:createHash('sha256').update(projectId).digest('hex'),address:wallet.address,roles:[{role:'owner-1',address:wallet.address,derivationPolicy:'same-confirmed-hardware-account-single-operator-pilot'}],walletConnectExposesDeviceIdentity:false,physicalConfirmationSource:'human-observed-device-screen',model:'classic1s',addressShownOnDevice:true,operatorConfirmed:true,singleOperatorResidualRisk:true,hardwareSigningApproved:false,realFundsApproved:false};
async function setup(){const dir=await fresh(),path=join(dir,'request.json'),physicalEvidencePath=join(dir,'physical.json');
 const outputPath=join(dir,'response.json');await writeFile(physicalEvidencePath,`${JSON.stringify(evidence)}\n`,{mode:0o600,flag:'wx'});
 return{dir,path,physicalEvidencePath,outputPath};}
function lifecycle(client){let pairings=[],sessions=[];const connect=client.connect.bind(client),disconnect=client.disconnect.bind(client);
 client.connect=async value=>{const result=await connect(value);const topic=/^wc:([^@]+)@2/u.exec(result.uri)?.[1];if(topic)pairings=[{topic}];
  const approval=result.approval;result.approval=async()=>{const session=await approval();sessions=[session];return session;};return result;};
 client.disconnect=async value=>{await disconnect(value);sessions=sessions.filter(item=>item.topic!==value.topic);};
 client.core={pairing:{getPairings:()=>pairings,disconnect:async({topic})=>{pairings=pairings.filter(item=>item.topic!==topic);}}};
 client.session={getAll:()=>sessions};return client;}

test('private request is create-once, hash-bound and proposes only typed-data on mainnet',async()=>{
 const {dir,path,physicalEvidencePath}=await setup();try{
  await prepareOneKeyIosTypedDataRequest({path,expectedAddress:wallet.address,typedData,physicalEvidencePath,walletConnectProjectId:projectId});
  await assert.rejects(prepareOneKeyIosTypedDataRequest({path,expectedAddress:wallet.address,typedData,physicalEvidencePath,walletConnectProjectId:projectId}),/exists|EEXIST/u);
  const request=await readOneKeyIosTypedDataRequest(path);assert.equal(request.method,'eth_signTypedData_v4');
  assert.deepEqual(buildOneKeyIosWalletConnectProposal(wallet.address),{requiredNamespaces:{eip155:{chains:['eip155:1'],
   methods:['eth_signTypedData_v4'],events:[]}},expectedAccount:`eip155:1:${wallet.address}`});
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('session is exact, deeplink is official, signature is recovered and session deleted',async()=>{
 const {dir,path,physicalEvidencePath,outputPath}=await setup();try{
  await prepareOneKeyIosTypedDataRequest({path,expectedAddress:wallet.address,typedData,physicalEvidencePath,walletConnectProjectId:projectId});let proposal,request,disconnected,link;
  const client=lifecycle({projectId,async connect(value){proposal=value;return{uri:'wc:abc123@2?relay-protocol=irn&symKey='+'22'.repeat(32),approval:async()=>({
   topic:'a'.repeat(64),namespaces:{eip155:{accounts:[`eip155:1:${wallet.address.toLowerCase()}`],chains:['eip155:1'],
    methods:['eth_signTypedData_v4'],events:[]}}})};},async request(value){request=value;
    const types={...typedData.types};delete types.EIP712Domain;return wallet.signTypedData(typedData.domain,types,typedData.message);},
   async disconnect(value){disconnected=value;}});
  const result=await executeOneKeyIosTypedDataRequest({requestPath:path,physicalEvidencePath,outputPath,client,onDeepLink:async value=>{link=value;},timeoutMilliseconds:1000});
  assert.deepEqual(proposal.requiredNamespaces.eip155.methods,['eth_signTypedData_v4']);
  assert.match(link,/^onekey-wallet:\/\/wc\?uri=wc%3A/u);assert.equal(request.request.method,'eth_signTypedData_v4');
  assert.equal(request.chainId,'eip155:1');assert.equal(result.expectedAddress,wallet.address);assert.equal(disconnected.topic,'a'.repeat(64));
  const installed=JSON.parse(await readFile(outputPath));assert.match(installed.signature,/^0x[0-9a-f]{130}$/iu);
  assert.equal(client.session.getAll().length,0);
  assert.equal(client.core.pairing.getPairings().length,0);
 }finally{await rm(dir,{recursive:true,force:true});}
});

for(const namespaceKey of ['eip155','eip155:1']) {
 test(`signing accepts CAIP-10 mainnet account without optional chains under ${namespaceKey}`,async()=>{
  const {dir,path,physicalEvidencePath,outputPath}=await setup();
  try {
   await prepareOneKeyIosTypedDataRequest({path,expectedAddress:wallet.address,typedData,
    physicalEvidencePath,walletConnectProjectId:projectId});
   let requested;
   const client=lifecycle({projectId,connect:async()=>({uri:'wc:approved@2?relay-protocol=irn',
    approval:async()=>({topic:'d'.repeat(64),namespaces:{[namespaceKey]:{
     accounts:[`eip155:1:${wallet.address.toLowerCase()}`],methods:['eth_signTypedData_v4'],events:[]}}})}),
    request:async request=>{
     requested=request;
     const types={...typedData.types};delete types.EIP712Domain;
     return wallet.signTypedData(typedData.domain,types,typedData.message);
    },disconnect:async()=>{}});
   const result=await executeOneKeyIosTypedDataRequest({requestPath:path,physicalEvidencePath,outputPath,
    client,onDeepLink:async()=>{},timeoutMilliseconds:1000});
   assert.equal(result.expectedAddress,wallet.address);
   assert.equal(requested.chainId,'eip155:1');
   assert.equal(requested.request.method,'eth_signTypedData_v4');
   assert.equal(client.session.getAll().length,0);
   assert.equal(client.core.pairing.getPairings().length,0);
  }finally{await rm(dir,{recursive:true,force:true});}
 });
}

test('session compatibility retains chain, identity and capability boundaries with safe errors',()=>{
 const base=()=>({topic:'v'.repeat(64),namespaces:{eip155:{
  accounts:[`eip155:1:${wallet.address}`],methods:['eth_signTypedData_v4'],events:[]}}});
 const mutations=[
  ['SESSION_NAMESPACE_INVALID',session=>session.namespaces.solana={accounts:[],methods:[],events:[]}],
  ['SESSION_ACCOUNT_INVALID',session=>session.namespaces.eip155.accounts.push(`eip155:1:${wallet.address}`)],
  ['SESSION_ACCOUNT_INVALID',session=>session.namespaces.eip155.accounts[0]=`eip155:137:${wallet.address}`],
  ['SESSION_ACCOUNT_INVALID',session=>session.namespaces.eip155.accounts[0]=`${wallet.address}`],
  ['SESSION_CHAIN_INVALID',session=>session.namespaces.eip155.chains=['eip155:137']],
  ['SESSION_CHAIN_INVALID',session=>session.namespaces.eip155.chains=undefined],
  ['SESSION_METHODS_INVALID',session=>session.namespaces.eip155.methods.push('wallet_sendCalls')],
  ['SESSION_METHODS_INVALID',session=>session.namespaces.eip155.methods=['eth_sendTransaction']],
  ['SESSION_METHODS_INVALID',session=>session.namespaces.eip155.methods.push('eth_signTypedData_v4')],
  ['SESSION_EVENTS_INVALID',session=>session.namespaces.eip155.events.push('unknownEvent')],
  ['SESSION_EVENTS_INVALID',session=>session.namespaces.eip155.events=['accountsChanged','accountsChanged']],
 ];
 for(const [code,mutate] of mutations){
  const session=base();mutate(session);
  assert.throws(()=>validateOneKeyIosSession(session),error=>{
   assert.ok(error instanceof OneKeyIosSessionError);
   assert.equal(error.code,code);
   assert.ok(!error.message.includes(wallet.address));
   return true;
  });
 }
 assert.throws(()=>validateOneKeyIosSession(base(),{expectedAccount:`eip155:1:${new Wallet('0x'+'22'.repeat(32)).address}`}),
  error=>error.code==='SESSION_ACCOUNT_MISMATCH');
});

test('official OneKey capabilities permit only the requested typed-data operation in the adapter',async()=>{
 const {dir,path,physicalEvidencePath,outputPath}=await setup();
 try {
  await prepareOneKeyIosTypedDataRequest({path,expectedAddress:wallet.address,typedData,
   physicalEvidencePath,walletConnectProjectId:projectId});
  const requests=[];
  const session={topic:'o'.repeat(64),namespaces:{eip155:{accounts:[`eip155:1:${wallet.address}`],
   chains:['eip155:1'],methods:oneKeyMethods,events:['accountsChanged','chainChanged']}}};
  const canonical=validateOneKeyIosSession(session);
  assert.deepEqual(canonical.methods,oneKeyMethods);
  assert.deepEqual(canonical.events,['accountsChanged','chainChanged']);
  const client=lifecycle({projectId,connect:async()=>({uri:'wc:onekey@2?relay-protocol=irn',approval:async()=>session}),
   request:async request=>{
    requests.push(request);
    const types={...typedData.types};delete types.EIP712Domain;
    return wallet.signTypedData(typedData.domain,types,typedData.message);
   },disconnect:async()=>{}});
  await executeOneKeyIosTypedDataRequest({requestPath:path,physicalEvidencePath,outputPath,client,
   onDeepLink:async()=>{},timeoutMilliseconds:1000});
  assert.equal(requests.length,1);
  assert.deepEqual({...requests[0],request:{...requests[0].request,
   params:[requests[0].request.params[0],JSON.parse(requests[0].request.params[1])]}},
   {topic:session.topic,chainId:'eip155:1',request:{method:'eth_signTypedData_v4',params:[wallet.address,typedData]}});
  assert.equal(client.session.getAll().length,0);
  assert.equal(client.core.pairing.getPairings().length,0);
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('post-sign delete failure is unresolved status 80 and late signature cannot install output',async()=>{
 const {dir,path,physicalEvidencePath,outputPath}=await setup();try{
  await prepareOneKeyIosTypedDataRequest({path,expectedAddress:wallet.address,typedData,physicalEvidencePath,walletConnectProjectId:projectId});
  const types={...typedData.types};delete types.EIP712Domain;const signature=await wallet.signTypedData(typedData.domain,types,typedData.message);
  const session={topic:'c'.repeat(64),namespaces:{eip155:{accounts:[`eip155:1:${wallet.address}`],chains:['eip155:1'],methods:['eth_signTypedData_v4'],events:[]}}};
  const failing=lifecycle({projectId,connect:async()=>({uri:'wc:z@2?relay-protocol=irn',approval:async()=>session}),
   request:async()=>signature,disconnect:async()=>{throw new Error('delete failed');}});
  const deletion=await executeOneKeyIosTypedDataRequest({requestPath:path,physicalEvidencePath,outputPath,client:failing,onDeepLink:async()=>{}})
   .then(()=>null,error=>error);assert.equal(deletion.exitCode,80);await assert.rejects(readFile(outputPath),/ENOENT/u);
  const late=lifecycle({projectId,connect:async()=>({uri:'wc:q@2?relay-protocol=irn',approval:async()=>session}),
   request:()=>new Promise(resolve=>setTimeout(()=>resolve(signature),8)),disconnect:async()=>{}});
  await assert.rejects(executeOneKeyIosTypedDataRequest({requestPath:path,physicalEvidencePath,outputPath,client:late,
   onDeepLink:async()=>{},timeoutMilliseconds:5}),error=>describeOneKeyIosSigningFailure(error).code==='SIGNATURE_TIMEOUT');await assert.rejects(readFile(outputPath),/ENOENT/u);
  assert.equal(late.session.getAll().length,0);
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('overprivileged account/session, wrong signer and timeout fail closed with cleanup',async()=>{
 const {dir,path,physicalEvidencePath,outputPath}=await setup();try{
  await prepareOneKeyIosTypedDataRequest({path,expectedAddress:wallet.address,typedData,physicalEvidencePath,walletConnectProjectId:projectId});
  const base=methods=>({topic:'b'.repeat(64),namespaces:{eip155:{accounts:[`eip155:1:${wallet.address}`],chains:['eip155:1'],methods,events:[]}}});
  const over=lifecycle({projectId,connect:async()=>({uri:'wc:x@2?relay-protocol=irn',approval:async()=>base(['eth_signTypedData_v4','wallet_sendCalls'])}),
   request:async()=>assert.fail('invalid session must not request a signature'),disconnect:async()=>{}});
  await assert.rejects(executeOneKeyIosTypedDataRequest({requestPath:path,physicalEvidencePath,outputPath,client:over,onDeepLink:async()=>{}}),error=>describeOneKeyIosSigningFailure(error).code==='SESSION_METHODS_INVALID');
  assert.equal(over.session.getAll().length,0);
  assert.equal(over.core.pairing.getPairings().length,0);
  await assert.rejects(readFile(outputPath),/ENOENT/u);
  const timeout=lifecycle({projectId,connect:async()=>({uri:'wc:x@2?relay-protocol=irn',approval:()=>new Promise(()=>{})}),
   request:async()=>'',disconnect:async()=>{}});
  await assert.rejects(executeOneKeyIosTypedDataRequest({requestPath:path,physicalEvidencePath,outputPath,client:timeout,onDeepLink:async()=>{},timeoutMilliseconds:5}),error=>describeOneKeyIosSigningFailure(error).code==='APPROVAL_TIMEOUT');
  assert.equal(timeout.core.pairing.getPairings().length,0);
  const wrong=new Wallet('0x'+'22'.repeat(32));const wrongClient=lifecycle({projectId,connect:async()=>({uri:'wc:x@2?relay-protocol=irn',approval:async()=>base(['eth_signTypedData_v4'])}),
   request:async()=>{const types={...typedData.types};delete types.EIP712Domain;return wrong.signTypedData(typedData.domain,types,typedData.message);},disconnect:async()=>{}});
  await assert.rejects(executeOneKeyIosTypedDataRequest({requestPath:path,physicalEvidencePath,outputPath,client:wrongClient,onDeepLink:async()=>{}}),error=>describeOneKeyIosSigningFailure(error).code==='SIGNATURE_SIGNER_MISMATCH');
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('authority explicitly rejects raw/send methods and cannot self-attest hardware custody',async()=>{
 const authority=JSON.parse(await readFile(new URL('../../config/onekey-ios-walletconnect-authority.json',import.meta.url)));
 assert.deepEqual(authority.allowedMethods,['eth_signTypedData_v4']);assert.equal(authority.rawTransactionSigningDocumented,false);
 assert.equal(authority.sessionRuntimeApproved,false);assert.equal(authority.hardwareAccountApproved,false);
 assert.equal(authority.hardwareSigningApproved,false);assert.ok(authority.forbiddenMethods.includes('eth_sendTransaction'));
});

test('signing diagnostics distinguish receipt, format, signer and remote failures without exposing response data',async()=>{
 const types={...typedData.types};delete types.EIP712Domain;
 const valid=await wallet.signTypedData(typedData.domain,types,typedData.message);
 const wrong=await new Wallet('0x'+'22'.repeat(32)).signTypedData(typedData.domain,types,typedData.message);
 const canary='PRIVATE_REMOTE_DIAGNOSTIC_CANARY';
 const cases=[
  {code:'SIGNATURE_FORMAT_INVALID',phase:'validating-signature',response:async()=>({signature:valid,secret:canary})},
  {code:'SIGNATURE_INVALID',phase:'validating-signature',response:async()=>'0x'+'00'.repeat(65)},
  {code:'SIGNATURE_SIGNER_MISMATCH',phase:'validating-signature',response:async()=>wrong},
  {code:'WALLET_REJECTED',phase:'awaiting-signature',response:async()=>{throw {code:4001,message:canary,phase:'saving-response'};}},
  {code:'WALLET_UNSUPPORTED_REQUEST',phase:'awaiting-signature',response:async()=>{throw {code:5100,message:canary};}},
  {code:'SIGNATURE_REQUEST_FAILED',phase:'awaiting-signature',response:async()=>{throw {code:'SIGNATURE_FORMAT_INVALID',message:canary,exitCode:80};}},
  {code:'SIGNATURE_TIMEOUT',phase:'awaiting-signature',response:()=>new Promise(resolve=>setTimeout(()=>resolve(valid),8)),timeout:5},
  {code:'WALLET_REJECTED',phase:'awaiting-approval',approvalError:{code:5000,message:canary}},
  {code:'SESSION_ACCOUNT_MISMATCH',phase:'validating-session',wrongAccount:true},
 ];
 for(const spec of cases) {
  const h=await setup();
  try {
   await prepareOneKeyIosTypedDataRequest({path:h.path,expectedAddress:wallet.address,typedData,
    physicalEvidencePath:h.physicalEvidencePath,walletConnectProjectId:projectId});
   const client=lifecycle({projectId,connect:async()=>({uri:'wc:diagnostic@2?relay-protocol=irn',approval:async()=>{
    if(spec.approvalError)throw spec.approvalError;
    return {topic:'e'.repeat(64),namespaces:{eip155:{accounts:[`eip155:1:${spec.wrongAccount?new Wallet('0x'+'22'.repeat(32)).address:wallet.address}`],
     methods:['eth_signTypedData_v4'],events:[]}}};
   }}),request:spec.response??(async()=>assert.fail('invalid session must not sign')),disconnect:async()=>{}});
   const error=await executeOneKeyIosTypedDataRequest({requestPath:h.path,physicalEvidencePath:h.physicalEvidencePath,
    outputPath:h.outputPath,client,onDeepLink:async()=>{},timeoutMilliseconds:spec.timeout??1000})
    .then(()=>assert.fail('invalid signing must fail'),error=>error);
   const diagnostic=describeOneKeyIosSigningFailure(error);
   assert.equal(diagnostic.phase,spec.phase);assert.equal(diagnostic.code,spec.code);
   assert.equal(oneKeyIosSigningExitCode(error),1);
   assert.doesNotMatch(JSON.stringify(diagnostic),new RegExp(`${canary}|${valid}|${wrong}|wc:|symKey|${wallet.address}`));
   assert.equal(client.session.getAll().length,0);assert.equal(client.core.pairing.getPairings().length,0);
   await assert.rejects(readFile(h.outputPath),/ENOENT/);
  } finally {await rm(h.dir,{recursive:true,force:true});}
 }
 assert.deepEqual(describeOneKeyIosSigningFailure({code:'WALLET_REJECTED',phase:'awaiting-signature',message:canary,exitCode:80}),{
  phase:'unknown',code:'UNEXPECTED_FAILURE',message:'A assinatura não foi concluída; o diagnóstico não contém dados privados.',
 });
});

test('cleanup diagnostics preserve the first failure phase and saving failures retain status 80',async()=>{
 const types={...typedData.types};delete types.EIP712Domain;
 const valid=await wallet.signTypedData(typedData.domain,types,typedData.message);
 for(const mode of ['rejection-and-cleanup','signed-cleanup','saving-response']) {
  const h=await setup();
  try {
   await prepareOneKeyIosTypedDataRequest({path:h.path,expectedAddress:wallet.address,typedData,
    physicalEvidencePath:h.physicalEvidencePath,walletConnectProjectId:projectId});
   if(mode==='saving-response')await writeFile(h.outputPath,'preserved-output',{mode:0o600,flag:'wx'});
   const client=lifecycle({projectId,connect:async()=>({uri:'wc:cleanup@2?relay-protocol=irn',
    approval:async()=>({topic:'f'.repeat(64),namespaces:{eip155:{accounts:[`eip155:1:${wallet.address}`],
     methods:['eth_signTypedData_v4'],events:[]}}})}),request:async()=>{
     if(mode==='rejection-and-cleanup')throw {code:4001,message:'PRIVATE_REJECTION'};return valid;
    },disconnect:async()=>{if(mode!=='saving-response')throw new Error('PRIVATE_DELETE_FAILURE');}});
   const error=await executeOneKeyIosTypedDataRequest({requestPath:h.path,physicalEvidencePath:h.physicalEvidencePath,
    outputPath:h.outputPath,client,onDeepLink:async()=>{}}).then(()=>assert.fail('must fail'),error=>error);
   const diagnostic=describeOneKeyIosSigningFailure(error);
   assert.doesNotMatch(JSON.stringify(diagnostic),/PRIVATE_/);
   if(mode==='rejection-and-cleanup') {
    assert.equal(diagnostic.phase,'awaiting-signature');assert.equal(diagnostic.code,'WALLET_REJECTED');
    assert.deepEqual(diagnostic.cleanupFailures,[{code:'SESSION_CLEANUP_FAILED',phase:'deleting-session'}]);
    assert.equal(oneKeyIosSigningExitCode(error),1);
   } else {
    assert.equal(oneKeyIosSigningExitCode(error),80);
    assert.equal(diagnostic.phase,mode==='signed-cleanup'?'deleting-session':'saving-response');
    assert.equal(diagnostic.code,mode==='signed-cleanup'?'SESSION_CLEANUP_FAILED':'RESPONSE_WRITE_FAILED');
   }
   if(mode==='saving-response')assert.equal(await readFile(h.outputPath,'utf8'),'preserved-output');
   else await assert.rejects(readFile(h.outputPath),/ENOENT/);
  } finally {await rm(h.dir,{recursive:true,force:true});}
 }
});
