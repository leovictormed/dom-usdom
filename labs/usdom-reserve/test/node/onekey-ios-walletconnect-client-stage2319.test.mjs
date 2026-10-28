import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,readFile,rm,stat,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {Wallet} from 'ethers';
import {SignClient} from '@walletconnect/sign-client';
import {openOneKeyIosWalletConnectClient,runOneKeyIosWalletConnectSigning} from '../../sdk/onekey-ios-walletconnect-client.mjs';
import {buildIosOnboardingEvidence} from '../../sdk/onekey-ios-onboarding.mjs';
import {prepareOneKeyIosTypedDataRequest,describeOneKeyIosSigningFailure} from '../../sdk/onekey-ios-walletconnect-typed-data.mjs';

const run=promisify(execFile),wallet=new Wallet('0x'+'71'.repeat(32)),projectId='72'.repeat(16);
const typedData={types:{EIP712Domain:[{name:'chainId',type:'uint256'}],Pilot:[{name:'nonce',type:'uint256'}]},
 primaryType:'Pilot',domain:{chainId:1},message:{nonce:19}};
const evidence=buildIosOnboardingEvidence({projectId,session:{schema:'usdom-onekey-ios-wc-onboarding-session-v1',
 chain:'eip155:1',account:`eip155:1:${wallet.address}`,methods:['eth_signTypedData_v4'],events:[],sessionDeleted:true},
 physical:{schema:'usdom-onekey-classic1s-human-confirmation-v1',source:'human-observed-device-screen',model:'classic1s',
  addressShownOnDevice:true,address:wallet.address,operatorConfirmed:true,mock:false},roles:['owner-1']});

test('pinned WalletConnect package exposes the production SignClient initializer',()=>{
 assert.equal(typeof SignClient?.init,'function');
});
function client(){let pairings=[],sessions=[];return{projectId,core:{projectId,pairing:{getPairings:()=>pairings,
  disconnect:async({topic})=>{pairings=pairings.filter(item=>item.topic!==topic);}}},session:{getAll:()=>sessions},
 async connect(){pairings=[{topic:'pair'}];return{uri:'wc:pair@2?relay-protocol=irn&symKey='+'00'.repeat(32),approval:async()=>{
  const value={topic:'7'.repeat(64),namespaces:{eip155:{accounts:[`eip155:1:${wallet.address.toLowerCase()}`],chains:['eip155:1'],methods:['eth_signTypedData_v4'],events:[]}}};sessions=[value];return value;}};},
 async request(){const types={...typedData.types};delete types.EIP712Domain;return wallet.signTypedData(typedData.domain,types,typedData.message);},
 async disconnect({topic}){sessions=sessions.filter(item=>item.topic!==topic);}};}

test('runner uses an injected SignClient, displays the symKey only to the display boundary, deletes session and installs 0600 output',async()=>{
 const dir=await mkdtemp('/dev/shm/usdom-wc2319-');try{
  const physical=join(dir,'physical.json'),request=join(dir,'request.json'),output=join(dir,'response.json');
  await writeFile(physical,JSON.stringify(evidence)+'\n',{mode:0o600,flag:'wx'});
  await prepareOneKeyIosTypedDataRequest({path:request,expectedAddress:wallet.address,typedData,
    physicalEvidencePath:physical,walletConnectProjectId:projectId});
  let shown='',closed=0;
  await runOneKeyIosWalletConnectSigning({configPath:join(dir,'unused'),requestPath:request,
    physicalEvidencePath:physical,outputPath:output,displayDeepLink:async value=>{shown=value;},
    clientFactory:async()=>({client:client(),close:async()=>{closed++;}})});
  assert.match(shown,/symKey%3D/u);assert.equal(closed,1);
  const installed=JSON.parse(await readFile(output));assert.match(installed.signature,/^0x[0-9a-f]{130}$/iu);
  assert.equal((await stat(output)).mode&0o777,0o600);
  const persisted=Buffer.concat([await readFile(physical),await readFile(request),await readFile(output)]).toString();
  assert.doesNotMatch(persisted,/symKey|onekey-wallet:\/\/wc/u);
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('production client rejects missing operator license/network approval before initialization',async()=>{
 const dir=await mkdtemp('/dev/shm/usdom-wc2319-config-');try{const path=join(dir,'config.json');
  await writeFile(path,JSON.stringify({schema:'usdom-onekey-ios-walletconnect-client-config/v1',projectId,
   metadata:{name:'USDOM',description:'offline signing',url:'https://example.invalid',icons:['https://example.invalid/icon.png']},
   communityLicenseAccepted:false,networkExecutionApproved:false})+'\n',{mode:0o600,flag:'wx'});
  await assert.rejects(openOneKeyIosWalletConnectClient({configPath:path,signClient:{init:async()=>{throw new Error('must not initialize');}}}),error=>describeOneKeyIosSigningFailure(error).code==='CLIENT_CONFIG_INVALID');
 }finally{await rm(dir,{recursive:true,force:true});}
});

test('dependency authority pins exact package/license and remains runtime blocked',async()=>{
 const {stdout}=await run(process.execPath,['scripts/check-walletconnect-sign-client-dependency.mjs'],{cwd:fileURLToPath(new URL('../..',import.meta.url))});
 assert.match(stdout,/dependency pin: valid/u);
});

for(const scenario of ['success','rejected','shutdown-failed','rejected-and-shutdown-failed']) {
test(`real signing CLI ${scenario} finishes durable cleanup and exits despite SDK timers`,async()=>{
 const dir=await mkdtemp('/dev/shm/usdom-sign-cli-');
 try {
  const physical=join(dir,'physical.json'),request=join(dir,'request.json'),output=join(dir,'response.json'),
   config=join(dir,'config.json');
  await writeFile(physical,JSON.stringify(evidence)+'\n',{mode:0o600,flag:'wx'});
  await writeFile(config,JSON.stringify({schema:'usdom-onekey-ios-walletconnect-client-config/v1',projectId,
   metadata:{name:'USDOM test',description:'offline test',url:'https://example.invalid',
    icons:['https://example.invalid/icon.png']},communityLicenseAccepted:true,networkExecutionApproved:true})+'\n',
  {mode:0o600,flag:'wx'});
  await prepareOneKeyIosTypedDataRequest({path:request,expectedAddress:wallet.address,typedData,
   physicalEvidencePath:physical,walletConnectProjectId:projectId});
  const originalRequest=await readFile(request);
  const cli=new URL('../../scripts/sign-onekey-ios-walletconnect-typed-data.mjs',import.meta.url).href;
  const mockSdk=`import {Wallet} from ${JSON.stringify(import.meta.resolve('ethers'))};
   import assert from 'node:assert/strict';
   const wallet=new Wallet('0x'+'71'.repeat(32));
   export const SignClient={init:async({projectId,storage})=>{
    const heartbeat=setInterval(()=>{},60000);
    setInterval(()=>{},60000); // Residual SDK timer that transportClose does not own.
    await storage.setItem('synthetic-private-session',true);
    let pairings=[],sessions=[];
    return {core:{projectId,heartbeat:{stop(){clearInterval(heartbeat);
      process.stdout.write('HEARTBEAT_STOP\\n');
      ${scenario.includes('shutdown-failed')?'throw new Error("PRIVATE_SHUTDOWN_CANARY");':''}
     }},relayer:{transportClose:async()=>{process.stdout.write('TRANSPORT_CLOSED\\n');}},
     pairing:{getPairings:()=>pairings,disconnect:async()=>{pairings=[];process.stdout.write('PAIRING_DELETED\\n');}}},
     session:{getAll:()=>sessions},
     connect:async()=>{pairings=[{topic:'synthetic-pair'}];return {
      uri:'wc:synthetic-pair@2?relay-protocol=irn&symKey='+'00'.repeat(32),approval:async()=>{
       const session={topic:'synthetic-session',namespaces:{eip155:{accounts:['eip155:1:'+wallet.address],
        methods:['eth_signTypedData_v4'],events:[]}}};sessions=[session];return session;
      }};},
     request:async({chainId,request})=>{
      assert.equal(chainId,'eip155:1');assert.equal(request.method,'eth_signTypedData_v4');
      assert.equal(request.params[0],wallet.address);
      assert.deepEqual(JSON.parse(request.params[1]),${JSON.stringify(typedData)});
      process.stdout.write('REQUEST_TYPED_DATA\\n');
      ${scenario.startsWith('rejected')?'throw new Error("PRIVATE_REMOTE_CANARY");':''}
      const typed=JSON.parse(request.params[1]),types={...typed.types};delete types.EIP712Domain;
      return wallet.signTypedData(typed.domain,types,typed.message);
     },disconnect:async()=>{sessions=[];process.stdout.write('SESSION_DELETED\\n');}};
   }};`;
  const mockFs=`export async function open(){return {write:async text=>{
    if(text.includes('\\u001b[?1049h'))process.stdout.write('SCREEN_ENTER\\n');
    if(text.includes('\\u001b[?1049l'))process.stdout.write('SCREEN_RESTORE\\n');
   },close:async()=>{process.stdout.write('TTY_CLOSED\\n');}};}`;
  const bootstrap=`import {registerHooks} from 'node:module';
   const cli=${JSON.stringify(cli)};
   registerHooks({resolve(specifier,context,next){
    if(specifier==='@walletconnect/sign-client')return {url:'data:text/javascript,'+
     encodeURIComponent(${JSON.stringify(mockSdk)}),shortCircuit:true};
    if(context.parentURL===cli&&specifier==='node:fs/promises')return {url:'data:text/javascript,'+
     encodeURIComponent(${JSON.stringify(mockFs)}),shortCircuit:true};
    return next(specifier,context);
   }});
   process.stderr.write=(...args)=>process.stdout.write(...args);
   process.argv=[process.execPath,cli,${[config,request,physical,output].map(x=>JSON.stringify(x)).join(',')}];
   await import(cli);`;
  const child=spawn(process.execPath,['--input-type=module','-e',bootstrap],{stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='',timedOut=false;
  child.stdout.on('data',bytes=>{stdout+=bytes;});child.stderr.on('data',bytes=>{stderr+=bytes;});
  const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},5000);
  const [code,signal]=await new Promise((resolve,reject)=>{
   child.once('error',reject);child.once('close',(exitCode,exitSignal)=>resolve([exitCode,exitSignal]));
  }).finally(()=>clearTimeout(timer));
  assert.equal(timedOut,false,`CLI held its preparation lock after ${scenario}: ${stdout}${stderr}`);
  assert.equal(signal,null);assert.equal(code,scenario==='success'?0:scenario==='shutdown-failed'?80:1,stderr);
  for(const marker of ['SESSION_DELETED','PAIRING_DELETED','HEARTBEAT_STOP','TRANSPORT_CLOSED','SCREEN_RESTORE','TTY_CLOSED']) {
   assert.ok(stdout.includes(marker),`missing ${marker}: ${stdout}`);
  }
  assert.ok(stdout.indexOf('HEARTBEAT_STOP')<stdout.indexOf('TRANSPORT_CLOSED'));
  assert.equal(stdout.split('REQUEST_TYPED_DATA').length-1,1);
  assert.deepEqual(await readFile(request),originalRequest);
  assert.doesNotMatch(stdout+stderr,/PRIVATE_REMOTE_CANARY|PRIVATE_SHUTDOWN_CANARY|wc:synthetic-pair|symKey/);
  if(scenario==='success') {
   assert.doesNotMatch(stdout,/ONEKEY_SIGNING_FAILED/);
   assert.ok(stdout.indexOf('TTY_CLOSED')<stdout.indexOf('Assinatura salva.'));
  }
  else {
   assert.match(stdout,/ONEKEY_SIGNING_FAILED/);
   assert.ok(stdout.indexOf('TTY_CLOSED')<stdout.indexOf('ONEKEY_SIGNING_FAILED'));
   assert.match(stdout,scenario.startsWith('rejected')
    ?/phase=awaiting-signature code=SIGNATURE_REQUEST_FAILED/
    :/phase=client-shutdown code=CLIENT_SHUTDOWN_FAILED/);
   if(scenario==='rejected-and-shutdown-failed')assert.match(stdout,
    /ONEKEY_SIGNING_CLEANUP_FAILED: phase=client-shutdown code=CLIENT_SHUTDOWN_FAILED/);
  }
  if(scenario.startsWith('rejected'))await assert.rejects(stat(output),error=>error.code==='ENOENT');
  else {
   const saved=JSON.parse(await readFile(output));
   assert.match(saved.signature,/^0x[0-9a-f]{130}$/iu);
   assert.equal((await stat(output)).mode&0o777,0o600);
  }
 } finally {await rm(dir,{recursive:true,force:true});}
});
}
