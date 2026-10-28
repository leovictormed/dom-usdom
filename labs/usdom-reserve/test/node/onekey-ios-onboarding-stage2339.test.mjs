import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,chmod,stat,writeFile,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {Wallet} from 'ethers';
import {spawn} from 'node:child_process';
import {
  buildReownProjectRequest,
  validateReownProjectResponse,
  buildIosOnboardingEvidence,
  executeIosOnboarding,
  describeIosOnboardingFailure,
} from '../../sdk/onekey-ios-onboarding.mjs';

test('request asks only for public projectId and rejects secrets or malformed ids',()=>{
  const request=buildReownProjectRequest();
  assert.deepEqual(request.requestedFields,['projectId']);
  assert.ok(request.forbiddenFields.includes('seed'));
  assert.equal(validateReownProjectResponse({schema:'usdom-reown-project-response-v1',
    projectId:'ab'.repeat(16)}),'ab'.repeat(16));
  assert.throws(()=>validateReownProjectResponse({schema:'usdom-reown-project-response-v1',projectId:'secret'}));
});

test('fake WC discovery cannot replace explicit matching hardware-screen confirmation',()=>{
  const address=Wallet.createRandom().address;
  const session={schema:'usdom-onekey-ios-wc-onboarding-session-v1',chain:'eip155:1',
    account:`eip155:1:${address}`,methods:['eth_signTypedData_v4'],events:[],sessionDeleted:true};
  const physical={schema:'usdom-onekey-classic1s-human-confirmation-v1',
    source:'human-observed-device-screen',model:'classic1s',addressShownOnDevice:true,address,
    operatorConfirmed:true,mock:false};
  const evidence=buildIosOnboardingEvidence({projectId:'ab'.repeat(16),session,physical,roles:['owner-1']});
  assert.equal(evidence.walletConnectExposesDeviceIdentity,false);
  assert.equal(evidence.hardwareSigningApproved,false);
  for(const mutate of [input=>input.physical.mock=true,input=>input.physical.address=Wallet.createRandom().address,
    input=>input.session.methods.push('wallet_grantPermissions'),input=>input.session.account=`eip155:137:${address}`]) {
    const input={projectId:'ab'.repeat(16),session:structuredClone(session),physical:structuredClone(physical),
      roles:['owner-1']};
    mutate(input);
    assert.throws(()=>buildIosOnboardingEvidence(input));
  }
});

const oneKeyCapabilities={
  methods:['personal_sign','eth_sign','eth_signTransaction','eth_signTypedData','eth_signTypedData_v3',
    'eth_signTypedData_v4','eth_sendRawTransaction','eth_sendTransaction'],
  events:['accountsChanged','chainChanged'],
};
for(const variant of ['minimal','onekey','onekey-implicit-chain','onekey-chain-namespace']) {
test(`SignClient onboarding ${variant} reports stages, deletes session/pairing and materializes evidence`,async()=>{
  const address=Wallet.createRandom().address;
  const sessions=[];
  const pairings=[];
  const pairingTopic='p'.repeat(64);
  const sessionTopic='s'.repeat(64);
  const client={
    connect:async()=>{
      pairings.push({topic:pairingTopic});
      return {uri:`wc:${pairingTopic}@2?symKey=${'0'.repeat(64)}`,approval:async()=>{
        const namespace={accounts:[`eip155:1:${address}`],chains:['eip155:1'],
          ...(variant==='minimal'?{methods:['eth_signTypedData_v4'],events:[]}:structuredClone(oneKeyCapabilities))};
        if(variant==='onekey-implicit-chain'||variant==='onekey-chain-namespace')delete namespace.chains;
        const key=variant==='onekey-chain-namespace'?'eip155:1':'eip155';
        const session={topic:sessionTopic,pairingTopic,namespaces:{[key]:namespace}};
        sessions.push(session);
        return session;
      }};
    },
    request:async()=>assert.fail('discovery must never request a signature or transaction'),
    disconnect:async({topic})=>{
      const index=sessions.findIndex(item=>item.topic===topic);
      if(index>=0)sessions.splice(index,1);
    },
    session:{getAll:()=>sessions},
    core:{pairing:{getPairings:()=>pairings,disconnect:async({topic})=>{
      const index=pairings.findIndex(item=>item.topic===topic);
      if(index>=0)pairings.splice(index,1);
    }}},
  };
  const links=[];
  const stages=[];
  const root=await mkdtemp(path.join(os.tmpdir(),'onboard-'));
  await chmod(root,0o700);
  const output=path.join(root,'evidence.json');
  const result=await executeIosOnboarding({client,projectId:'ab'.repeat(16),ownerRole:'owner-1',
    onDeepLink:async link=>links.push(link),onStage:async stageName=>stages.push(stageName),
    confirmOnDevice:async({address:shown})=>({schema:'usdom-onekey-classic1s-human-confirmation-v1',
      source:'human-observed-device-screen',model:'classic1s',addressShownOnDevice:true,address:shown,
      operatorConfirmed:true,mock:false}),outputPath:output});
  assert.equal(links.length,1);
  assert.deepEqual(stages,['connecting','deeplink-ready','awaiting-approval','approval-received',
    'validating-session','physical-confirmation-required','cleanup-complete','saving-evidence']);
  assert.equal(result.address,address);
  assert.equal((await stat(output)).mode&0o777,0o600);
  assert.equal(sessions.length,0);
  assert.equal(pairings.length,0);
  await assert.rejects(()=>writeFile(output,'x',{flag:'wx'}));
  await rm(root,{recursive:true});
});
}

test('approval timeout deletes the pairing and never writes evidence',async()=>{
  const pairingTopic='q'.repeat(64);
  const pairings=[];
  const client={
    connect:async()=>{
      pairings.push({topic:pairingTopic});
      return {uri:`wc:${pairingTopic}@2?symKey=${'1'.repeat(64)}`,approval:async()=>new Promise(()=>{})};
    },
    disconnect:async()=>{},session:{getAll:()=>[]},core:{pairing:{getPairings:()=>pairings,
      disconnect:async({topic})=>{
        const index=pairings.findIndex(item=>item.topic===topic);
        if(index>=0)pairings.splice(index,1);
      }}},
  };
  const root=await mkdtemp(path.join(os.tmpdir(),'onboard-timeout-'));
  await chmod(root,0o700);
  const output=path.join(root,'evidence.json');
  await assert.rejects(()=>executeIosOnboarding({client,projectId:'ab'.repeat(16),ownerRole:'owner-1',
    onDeepLink:async()=>{},confirmOnDevice:async()=>assert.fail('physical confirmation must not run'),
    outputPath:output,timeoutMilliseconds:5}),error=>
    describeIosOnboardingFailure(error,'awaiting-approval').code==='APPROVAL_TIMEOUT');
  assert.equal(pairings.length,0);
  await assert.rejects(()=>stat(output),error=>error.code==='ENOENT');
  await rm(root,{recursive:true});
});

async function failedOnboarding(t,{mutate=()=>{},approvalError,cleanupFails=false}={}){
  const root=await mkdtemp(path.join(os.tmpdir(),'onboard-rejection-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  await chmod(root,0o700);
  const output=path.join(root,'evidence.json');
  const address=Wallet.createRandom().address;
  const pairingTopic='c'.repeat(64);
  let pairings=[],sessions=[],phase='initializing';
  const session={topic:'d'.repeat(64),pairingTopic,namespaces:{eip155:{
    accounts:[`eip155:1:${address}`],chains:['eip155:1'],...structuredClone(oneKeyCapabilities)}}};
  mutate(session);
  const client={
    connect:async()=>{
      pairings=[{topic:pairingTopic}];
      return {uri:`wc:${pairingTopic}@2?relay-protocol=irn`,approval:async()=>{
        if(approvalError)throw approvalError;
        sessions=[session];return session;
      }};
    },
    request:async()=>assert.fail('onboarding must not call request'),
    session:{getAll:()=>sessions},
    disconnect:async()=>{if(!cleanupFails)sessions=[];},
    core:{pairing:{getPairings:()=>pairings,disconnect:async()=>{pairings=[];}}},
  };
  const error=await executeIosOnboarding({client,projectId:'ab'.repeat(16),ownerRole:'owner-1',
    onDeepLink:async()=>{},onStage:async name=>{phase=name;},
    confirmOnDevice:async({address:shown})=>{
      assert.ok(cleanupFails,'invalid session must never reach hardware confirmation');
      return {schema:'usdom-onekey-classic1s-human-confirmation-v1',source:'human-observed-device-screen',
        model:'classic1s',addressShownOnDevice:true,address:shown,operatorConfirmed:true,mock:false};
    },outputPath:output}).then(()=>assert.fail('must fail'),failure=>failure);
  await assert.rejects(()=>stat(output),failure=>failure.code==='ENOENT');
  if(!cleanupFails){assert.equal(sessions.length,0);assert.equal(pairings.length,0);}
  return describeIosOnboardingFailure(error,phase);
}

test('invalid session diagnostics distinguish accounts, chains, methods and events before physical confirmation',async t=>{
  const cases=[
    ['SESSION_ACCOUNT_INVALID',s=>s.namespaces.eip155.accounts.push(s.namespaces.eip155.accounts[0])],
    ['SESSION_CHAIN_INVALID',s=>s.namespaces.eip155.chains=['eip155:137']],
    ['SESSION_METHODS_INVALID',s=>s.namespaces.eip155.methods.push('wallet_grantPermissions')],
    ['SESSION_EVENTS_INVALID',s=>s.namespaces.eip155.events.push('unknownEvent')],
    ['SESSION_NAMESPACE_INVALID',s=>s.namespaces.cosmos=structuredClone(s.namespaces.eip155)],
  ];
  for(const [code,mutate] of cases){
    const diagnostic=await failedOnboarding(t,{mutate});
    assert.equal(diagnostic.phase,'validating-session');assert.equal(diagnostic.code,code);
  }
});

test('approval rejection diagnostic never echoes remote messages or forged local codes',async t=>{
  const sentinel='PRIVATE_REMOTE_TEXT_DO_NOT_ECHO';
  const remote=Object.assign(new Error(sentinel),{code:5000,stack:sentinel});
  const rejected=await failedOnboarding(t,{approvalError:remote});
  assert.equal(rejected.code,'WALLET_REJECTED');assert.equal(rejected.phase,'awaiting-approval');
  assert.ok(!JSON.stringify(rejected).includes(sentinel));
  const unknown=await failedOnboarding(t,{approvalError:{code:'SESSION_ACCOUNT_INVALID',message:sentinel}});
  assert.equal(unknown.code,'APPROVAL_FAILED');assert.ok(!JSON.stringify(unknown).includes(sentinel));
  assert.deepEqual(describeIosOnboardingFailure(remote,sentinel),{
    phase:'unknown',code:'UNEXPECTED_FAILURE',
    message:'O onboarding não foi concluído; o diagnóstico não contém dados privados.',
  });
});

test('cleanup failure reports a distinct safe code and prevents evidence installation',async t=>{
  const diagnostic=await failedOnboarding(t,{cleanupFails:true});
  assert.equal(diagnostic.code,'CLEANUP_FAILED');
});

test('terminal onboarding no longer consumes ENTER while approval is pending',async()=>{
  const source=await readFile(new URL('../../scripts/onboard-onekey-ios-owner.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(source,/await ask\(''\)/u);
  assert.doesNotMatch(source,/Pressione ENTER após aprovar/u);
  assert.match(source,/Não pressione ENTER no Termius/u);
  assert.match(source,/timeoutMilliseconds:300_000/u);
  assert.match(source,/approval-received/u);
});

test('real CLI restores the screen, reports rejection safely and exits despite SDK timers',async()=>{
  const cli=new URL('../../scripts/onboard-onekey-ios-owner.mjs',import.meta.url).href;
  const mockSdk=`export const SignClient={init:async()=>{
    setInterval(()=>{},60000);
    let pairings=[];
    return {connect:async()=>{pairings=[{topic:'pairing'}];return {
      uri:'wc:pairing@2?relay-protocol=irn',approval:async()=>{throw {code:5000,message:'PRIVATE_REMOTE_CANARY'};}
    };},disconnect:async()=>{},session:{getAll:()=>[]},core:{heartbeat:{stop(){}},
      pairing:{getPairings:()=>pairings,disconnect:async()=>{pairings=[];}},relayer:{transportClose:async()=>{}}}};
  }};`;
  const mockFs=`export async function readFile(){return Buffer.from(JSON.stringify({
    schema:'usdom-reown-project-response-v1',projectId:'ab'.repeat(16)}));}
    export async function open(){return {write:async text=>{
      if(text.includes('\\u001b[?1049h'))process.stdout.write('SCREEN_ENTER\\n');
      if(text.includes('\\u001b[?1049l'))process.stdout.write('SCREEN_RESTORE\\n');
    },close:async()=>{}};}`;
  const bootstrap=`import {registerHooks} from 'node:module';
    const cli=${JSON.stringify(cli)};
    registerHooks({resolve(specifier,context,next){
      if(specifier==='@walletconnect/sign-client')return {url:'data:text/javascript,'+
        encodeURIComponent(${JSON.stringify(mockSdk)}),shortCircuit:true};
      if(context.parentURL===cli&&specifier==='node:fs/promises')return {url:'data:text/javascript,'+
        encodeURIComponent(${JSON.stringify(mockFs)}),shortCircuit:true};
      return next(specifier,context);
    }});
    process.argv=[process.execPath,cli,'unused-response','owner-1','unused-output'];
    await import(cli);`;
  const child=spawn(process.execPath,['--input-type=module','-e',bootstrap],{stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='',timedOut=false;
  child.stdout.on('data',bytes=>{stdout+=bytes;});child.stderr.on('data',bytes=>{stderr+=bytes;});
  const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},5000);
  const [code,signal]=await new Promise((resolve,reject)=>{
    child.once('error',reject);child.once('close',(exitCode,exitSignal)=>resolve([exitCode,exitSignal]));
  }).finally(()=>clearTimeout(timer));
  assert.equal(timedOut,false,'CLI must not keep the preparation lock through SDK timers');
  assert.equal(signal,null);assert.equal(code,1,stderr);
  assert.equal(stdout,'SCREEN_ENTER\nSCREEN_RESTORE\n');
  assert.match(stderr,/phase=awaiting-approval code=WALLET_REJECTED/u);
  assert.doesNotMatch(stderr,/PRIVATE_REMOTE_CANARY|wc:pairing|symKey/u);
});

test('CLI retries incomplete confirmation in the same session without accepting missing or wrong addresses',async t=>{
  const address='0x1111111111111111111111111111111111111111';
  const cli=new URL('../../scripts/onboard-onekey-ios-owner.mjs',import.meta.url).href;
  for(const [name,answers,success,retries] of [
    ['incomplete then complete',['CONFIRMO',`CONFIRMO ${address}`],true,1],
    ['incomplete three times',['CONFIRMO','CONFIRMO','CONFIRMO'],false,2],
    ['different address',['CONFIRMO 0x2222222222222222222222222222222222222222'],false,0],
    ['end of input',[],false,0],
  ])await t.test(name,async t=>{
    const root=await mkdtemp(path.join(os.tmpdir(),'onboard-confirmation-'));
    t.after(()=>rm(root,{recursive:true,force:true}));
    await chmod(root,0o700);
    const output=path.join(root,'evidence.json');
    const mockSdk=`export const SignClient={init:async()=>{
      let pairings=[],sessions=[];
      return {connect:async()=>{
        process.stdout.write('CONNECT\\n');pairings=[{topic:'pairing'}];
        return {uri:'wc:pairing@2?relay-protocol=irn',approval:async()=>{
          const session={topic:'d'.repeat(64),pairingTopic:'pairing',namespaces:{eip155:{
            accounts:['eip155:1:${address}'],chains:['eip155:1'],methods:['eth_signTypedData_v4'],events:[]}}};
          sessions=[session];return session;
        }};
      },request:async()=>{throw new Error('discovery must never request signatures');},
      disconnect:async()=>{sessions=[];process.stdout.write('SESSION_CLOSED\\n');},
      session:{getAll:()=>sessions},core:{pairing:{getPairings:()=>pairings,disconnect:async()=>{
        pairings=[];process.stdout.write('PAIRING_CLOSED\\n');
      }},heartbeat:{stop(){}},relayer:{transportClose:async()=>{}}}};
    }};`;
    const mockFs=`import {existsSync} from 'node:fs';
      const answers=${JSON.stringify(answers)};
      export async function readFile(){return Buffer.from(JSON.stringify({
        schema:'usdom-reown-project-response-v1',projectId:'ab'.repeat(16)}));}
      export async function open(){return {write:async text=>{
        if(text.includes('Faltou o endereço'))process.stdout.write('RETRY\\n');
      },read:async buffer=>{
        if(existsSync(${JSON.stringify(output)}))throw new Error('evidence saved before full confirmation');
        const answer=answers.shift();
        const bytes=Buffer.from(answer===undefined?'':answer+'\\n');
        bytes.copy(buffer);return {bytesRead:bytes.length};
      },close:async()=>{}};}`;
    const bootstrap=`import {registerHooks} from 'node:module';
      const cli=${JSON.stringify(cli)};
      registerHooks({resolve(specifier,context,next){
        if(specifier==='@walletconnect/sign-client')return {url:'data:text/javascript,'+
          encodeURIComponent(${JSON.stringify(mockSdk)}),shortCircuit:true};
        if(context.parentURL===cli&&specifier==='node:fs/promises')return {url:'data:text/javascript,'+
          encodeURIComponent(${JSON.stringify(mockFs)}),shortCircuit:true};
        return next(specifier,context);
      }});
      process.argv=[process.execPath,cli,'unused-response','owner-1',${JSON.stringify(output)}];
      await import(cli);`;
    const child=spawn(process.execPath,['--input-type=module','-e',bootstrap],{stdio:['ignore','pipe','pipe']});
    let stdout='',stderr='',timedOut=false;
    child.stdout.on('data',bytes=>{stdout+=bytes;});child.stderr.on('data',bytes=>{stderr+=bytes;});
    const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},5000);
    const [code,signal]=await new Promise((resolve,reject)=>{
      child.once('error',reject);child.once('close',(code,signal)=>resolve([code,signal]));
    }).finally(()=>clearTimeout(timer));
    assert.equal(timedOut,false);assert.equal(signal,null);assert.equal(code,success?0:1,stderr);
    assert.equal(stdout,'CONNECT\n'+'RETRY\n'.repeat(retries)+'SESSION_CLOSED\nPAIRING_CLOSED\n');
    if(success){
      assert.equal(stderr,'');
      const evidence=JSON.parse(await readFile(output,'utf8'));
      assert.equal(evidence.address,address);assert.equal(evidence.operatorConfirmed,true);
      assert.equal(evidence.hardwareSigningApproved,false);assert.equal(evidence.realFundsApproved,false);
    }else{
      assert.match(stderr,/phase=physical-confirmation-required code=PHYSICAL_CONFIRMATION_FAILED/u);
      await assert.rejects(()=>stat(output),error=>error.code==='ENOENT');
    }
  });
});
