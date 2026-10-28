import assert from 'node:assert/strict';
import {chmod,mkdir,mkdtemp,readFile,readdir,rm,stat,symlink,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import {Wallet} from 'ethers';
import {buildIosOnboardingEvidence} from '../../sdk/onekey-ios-onboarding.mjs';
import {buildRecoverableSafeControlDeploymentPackage} from '../../sdk/safe-control-deployment.mjs';
const repo=path.resolve(import.meta.dirname,'../..'),node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node',scriptSource=await readFile(path.join(repo,'scripts/prepare-onekey-ios-safe-mainnet-pilot.sh'),'utf8');
async function file(p,value={ok:true}){await mkdir(path.dirname(p),{recursive:true,mode:0o700});await chmod(path.dirname(p),0o700);await writeFile(p,JSON.stringify(value)+'\n',{mode:0o600,flag:'wx'});}
async function harness(){const base=await mkdtemp('/dev/shm/usdom-command2366-'),state=path.join(base,'state'),relayers=path.join(base,'relayers'),safe=path.join(base,'safe.json'),wc=path.join(state,'onekey-ios-walletconnect-client.json'),script=path.join(base,'prepare.sh');await mkdir(state,{mode:0o700});await file(safe);await writeFile(script,scriptSource.replace(/system_dependencies_ready\(\)\{[^\n]+\}/,'system_dependencies_ready(){ true; }').replace(/toolchain_ready\(\)\{[^\n]+\}/,'toolchain_ready(){ true; }'),{mode:0o700});return{base,state,relayers,safe,wc,script,env:{PATH:'/usr/bin:/bin',HOME:'/tmp',USER:process.env.USER,LOGNAME:process.env.LOGNAME,USDOM_PILOT_STATE_DIR:state,USDOM_RELAYER_STATE_DIR:relayers,USDOM_SAFE_PACKAGE:safe,USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG:wc}};}
test('status audit reaches every exact transition and detects invalid symlink state',async()=>{const h=await harness();try{const run=()=>spawnSync('bash',[h.script,'--status'],{cwd:'/',env:h.env,encoding:'utf8'}).stdout.trim();assert.equal(run(),'rpc-sources-pending');const dangling=path.join(h.state,'mainnet-preflight-rpc-sources.json');await symlink(path.join(h.base,'absent'),dangling);assert.equal(run(),'rpc-sources-invalid');await rm(dangling);const target=path.join(h.base,'rpc-target');await file(target);await symlink(target,path.join(h.state,'mainnet-preflight-rpc-sources.json'));assert.equal(run(),'rpc-sources-invalid');await rm(path.join(h.state,'mainnet-preflight-rpc-sources.json'));await file(path.join(h.state,'mainnet-preflight-rpc-sources.json'));assert.equal(run(),'reown-project-request-pending');await file(path.join(h.state,'reown-project-request.json'));assert.equal(run(),'reown-project-id-pending');await file(path.join(h.state,'reown-project-response.json'));for(let i=1;i<=3;i++){assert.equal(run(),`owner-${i}-pending`);await file(path.join(h.state,`owner-${i}-evidence.json`),{i});}for(const role of ['deployment','safe-deployment','recovery','reserve-resume','pilot-gate']){assert.equal(run(),`relayer-${role}-pending`);await file(path.join(h.relayers,role,'relayer-public-identity.json'),{role});}assert.equal(run(),'owner-identities-pending');await file(path.join(h.state,'safe-owner-identities-v2.json'));assert.equal(run(),'walletconnect-config-pending');await file(h.wc);for(let i=0;i<12;i++){assert.equal(run(),`custody-signature-${i}-pending`);await file(path.join(h.state,`custody-signature-${i}.json`),{i});}assert.equal(run(),'custody-proof-bundle-pending');await file(path.join(h.state,'safe-owner-hardware-custody-proofs-v1.json'));assert.equal(run(),'offline-plan-pending');}finally{await rm(h.base,{recursive:true,force:true});}});
test('--next-command is absolute, shell-complete and contains no secret or placeholder',async()=>{const h=await harness();try{const secret=['synthetic','-environment-','canary-',String(process.pid)].join('');const run=spawnSync('bash',[h.script,'--next-command'],{cwd:'/tmp',env:{...h.env,FORBIDDEN_SECRET:secret},encoding:'utf8'});assert.equal(run.status,0,run.stderr);assert.match(run.stdout,/^\/usr\/bin\/env /);assert.match(run.stdout,/\/home\/leonardov\/usdom-security-audit-20261015\/implementation-dom-protocol\/labs\/usdom-reserve\/scripts\/prepare-onekey-ios-safe-mainnet-pilot\.sh --advance/);assert.doesNotMatch(run.stdout,/TODO|CHANGEME|<[^>]+>|synthetic-environment-canary|FORBIDDEN_SECRET/);assert.equal(run.stderr,'');}finally{await rm(h.base,{recursive:true,force:true});}});
test('WalletConnect config persists only validated public projectId and fixed minimal metadata',async()=>{const base=await mkdtemp('/dev/shm/usdom-wc2366-'),response=path.join(base,'response.json'),output=path.join(base,'config.json'),projectId='ab'.repeat(16),approval=`AUTORIZO WALLETCONNECT EIP712 MAINNET PROJECT ${projectId}\n`;try{await file(response,{schema:'usdom-reown-project-response-v1',projectId});let run=spawnSync(node,['scripts/materialize-onekey-ios-walletconnect-client-config.mjs',response,output],{cwd:repo,input:approval,encoding:'utf8'});assert.equal(run.status,0,run.stderr);const text=await readFile(output,'utf8'),config=JSON.parse(text);assert.equal(config.projectId,projectId);assert.equal(config.networkExecutionApproved,true);assert.doesNotMatch(text,/wc:|symKey|uri|topic|pairing|session/iu);run=spawnSync(node,['scripts/materialize-onekey-ios-walletconnect-client-config.mjs',response,output],{cwd:repo,input:approval,encoding:'utf8'});assert.notEqual(run.status,0);const wrong=path.join(base,'wrong.json');run=spawnSync(node,['scripts/materialize-onekey-ios-walletconnect-client-config.mjs',response,wrong],{cwd:repo,input:'yes\n',encoding:'utf8'});assert.notEqual(run.status,0);assert.equal(await readFile(output,'utf8'),text);}finally{await rm(base,{recursive:true,force:true});}});
test('source has no placeholder/manual-edit path and bounds every human action per advance',()=>{assert.doesNotMatch(scriptSource,/TODO|CHANGEME|INSERT[_ -]|EDIT (?:THIS|THE)|https:\/\/[^\s"']*(?:password|secret)/iu);for(const marker of ['onboard-onekey-ios-owner.mjs','create-mainnet-gas-relayer.sh','sign-onekey-ios-walletconnect-typed-data.mjs'])assert.ok(scriptSource.includes(marker));assert.match(scriptSource,/onboard-onekey-ios-owner\.mjs[\s\S]{0,500}\n exit 0/);assert.match(scriptSource,/create-mainnet-gas-relayer\.sh[\s\S]{0,100}\n exit 0/);assert.match(scriptSource,/install-private-file-new-stdin\.mjs --json "\$signature"\n exit 0/);assert.doesNotMatch(scriptSource,/rpc_[ab].*(?:export|env)/);});

async function custodyHarness({legacyTemporary=false,tamperDuringSignature=false}={}) {
 const base=await mkdtemp('/dev/shm/usdom-custody-loop-'),state=path.join(base,'state');
 await mkdir(state,{mode:0o700});
 const safe=path.join(state,'safe-package.json'),wc=path.join(state,'walletconnect.json'),
  signer=path.join(base,'offline-signer.mjs'),signerLog=path.join(base,'signer-called'),
  tampered=path.join(base,'changed-package.json'),script=path.join(base,'custody-loop.sh');
 const wallets=['21','22','23'].map(value=>new Wallet('0x'+value.repeat(32)));
 const roles=['governance','reserveGuardian','checkpointGuardian','usdtCustody'];
 const ownersByRole=Object.fromEntries(roles.map(role=>[role,wallets.map(wallet=>wallet.address)]));
 const {proxyCreationCode}=JSON.parse(await readFile(path.join(repo,'test/fixtures/safe-1.4.1-mainnet.json'),'utf8'));
 const pkg=buildRecoverableSafeControlDeploymentPackage({ownersByRole,proxyCreationCode}),projectId='24'.repeat(16);
 await file(safe,pkg);
 const changedOwners=[...wallets.slice(0,2).map(wallet=>wallet.address),new Wallet('0x'+'25'.repeat(32)).address];
 await file(tampered,buildRecoverableSafeControlDeploymentPackage({
  ownersByRole:Object.fromEntries(roles.map(role=>[role,changedOwners])),proxyCreationCode}));
 await file(wc,{schema:'usdom-onekey-ios-walletconnect-client-config/v1',projectId,
  metadata:{name:'USDOM offline test',description:'custody loop regression',url:'https://example.invalid',
   icons:['https://example.invalid/icon.png']},communityLicenseAccepted:true,networkExecutionApproved:true});
 for(let index=0;index<wallets.length;index++) {
  const address=wallets[index].address;
  await file(path.join(state,`owner-${index+1}-evidence.json`),buildIosOnboardingEvidence({projectId,
   session:{schema:'usdom-onekey-ios-wc-onboarding-session-v1',chain:'eip155:1',
    account:`eip155:1:${address}`,methods:['eth_signTypedData_v4'],events:[],sessionDeleted:true},
   physical:{schema:'usdom-onekey-classic1s-human-confirmation-v1',source:'human-observed-device-screen',
    model:'classic1s',addressShownOnDevice:true,address,operatorConfirmed:true,mock:false},roles:[`owner-${index+1}`]}));
 }
 const keys=Object.fromEntries(wallets.map(wallet=>[wallet.address,wallet.privateKey]));
 await writeFile(signer,`import {readFile,writeFile} from 'node:fs/promises';
  import assert from 'node:assert/strict';
  import {Wallet} from ${JSON.stringify(import.meta.resolve('ethers'))};
  import {writePrivateFileDurableNew} from ${JSON.stringify(new URL('../../sdk/durable-private-file.mjs',import.meta.url).href)};
  const request=JSON.parse(await readFile(process.argv[3],'utf8'));
  assert.equal(request.chainId,'eip155:1');assert.equal(request.method,'eth_signTypedData_v4');
  assert.equal(request.typedData.primaryType,'SafeOwnerCustodyProof');
  assert.equal(request.typedData.message.role,'governance');assert.equal(request.typedData.message.slot,'primary');
  await writeFile(process.env.USDOM_TEST_SIGNER_LOG,'called\\n',{mode:0o600,flag:'wx'});
  const wallet=new Wallet(${JSON.stringify(keys)}[request.expectedAddress]);
  const types={...request.typedData.types};delete types.EIP712Domain;
  const signature=await wallet.signTypedData(request.typedData.domain,types,request.typedData.message);
  await writePrivateFileDurableNew(process.argv[5],JSON.stringify({schema:request.schema,
   requestSha256:request.requestSha256,digest:request.digest,expectedAddress:request.expectedAddress,signature})+'\\n');
  if(process.env.USDOM_TEST_TAMPER==='1')await writeFile(process.env.USDOM_SAFE_PACKAGE,
   await readFile(process.env.USDOM_TEST_CHANGED_PACKAGE));
 `,{mode:0o600,flag:'wx'});
 const start=scriptSource.indexOf('for index in $(seq 0 11);do\n signature='),
  end=scriptSource.indexOf('\nbundle="$root/safe-owner-hardware-custody-proofs-v1.json"',start);
 assert.ok(start>0&&end>start,'actual custody loop must be extracted');
 let loop=scriptSource.slice(start,end);
 assert.equal(loop.split('"$node_bin" scripts/sign-onekey-ios-walletconnect-typed-data.mjs').length-1,1);
 loop=loop.replace('"$node_bin" scripts/sign-onekey-ios-walletconnect-typed-data.mjs',
  '"$node_bin" "$USDOM_TEST_SIGNER"');
 if(legacyTemporary) {
  assert.ok(loop.includes('"$root/.custody-envelope-recheck.$$.$index.json"'));
  loop=loop.replaceAll('"$root/.custody-envelope-recheck.$$.$index.json"',
   '"/dev/shm/usdom-custody-envelope.$$.$index.json"');
 }
 const privateCheck=scriptSource.split('\n').find(line=>line.startsWith('private_file(){'));
 await writeFile(script,`#!/usr/bin/env bash
set -euo pipefail
root="$USDOM_PILOT_STATE_DIR"
node_bin="$USDOM_TEST_NODE"
${privateCheck}
${loop}
echo UNEXPECTED_SLOT_FALLTHROUGH >&2
exit 99
`,{mode:0o700,flag:'wx'});
 return {base,state,pkg,signerLog,run:()=>spawnSync('/usr/bin/bash',[script],{cwd:repo,encoding:'utf8',timeout:15000,
  env:{PATH:'/usr/bin:/bin',USDOM_PILOT_STATE_DIR:state,USDOM_SAFE_PACKAGE:safe,
   USDOM_ONEKEY_IOS_WALLETCONNECT_CONFIG:wc,USDOM_TEST_SIGNER:signer,USDOM_TEST_SIGNER_LOG:signerLog,
   USDOM_TEST_NODE:node,USDOM_TEST_CHANGED_PACKAGE:tampered,USDOM_TEST_TAMPER:tamperDuringSignature?'1':'0'}})};
}

test('custody loop reproduces unsafe shared temporary failure before requesting a signature',async()=>{
 const h=await custodyHarness({legacyTemporary:true});
 try {
  const result=h.run();assert.equal(result.status,1,result.stderr);
  assert.match(result.stderr,/durable target directory is unsafe/);
  await assert.rejects(stat(h.signerLog),error=>error.code==='ENOENT');
  await assert.rejects(stat(path.join(h.state,'custody-signature-0.json')),error=>error.code==='ENOENT');
 } finally {await rm(h.base,{recursive:true,force:true});}
});

test('real custody loop rechecks in the private directory and advances exactly one slot',async()=>{
 const h=await custodyHarness();
 try {
  const result=h.run();assert.equal(result.status,0,result.stderr);assert.equal(result.signal,null);
  assert.equal(await readFile(h.signerLog,'utf8'),'called\n');
  const signature=JSON.parse(await readFile(path.join(h.state,'custody-signature-0.json'),'utf8'));
  assert.equal(signature.signer,h.pkg.ownersByRole.governance[0]);
  assert.match(signature.signature,/^0x[0-9a-f]{130}$/iu);
  assert.equal((await stat(path.join(h.state,'custody-signature-0.json'))).mode&0o777,0o600);
  for(const name of ['custody-signature-1.json','custody-envelope-1.json','custody-request-1.json']) {
   await assert.rejects(stat(path.join(h.state,name)),error=>error.code==='ENOENT');
  }
  assert.deepEqual((await readdir(h.state)).filter(name=>name.includes('recheck')),[]);
 } finally {await rm(h.base,{recursive:true,force:true});}
});

test('custody loop refuses promotion when a valid Safe package changes during offline signing',async()=>{
 const h=await custodyHarness({tamperDuringSignature:true});
 try {
  const result=h.run();assert.equal(result.status,1,result.stderr);assert.equal(result.signal,null);
  assert.equal(await readFile(h.signerLog,'utf8'),'called\n');
  assert.ok((await stat(path.join(h.state,'custody-response-0.json'))).isFile());
  await assert.rejects(stat(path.join(h.state,'custody-signature-0.json')),error=>error.code==='ENOENT');
  await assert.rejects(stat(path.join(h.state,'custody-envelope-1.json')),error=>error.code==='ENOENT');
  assert.deepEqual((await readdir(h.state)).filter(name=>name.includes('recheck')),[]);
 } finally {await rm(h.base,{recursive:true,force:true});}
});
