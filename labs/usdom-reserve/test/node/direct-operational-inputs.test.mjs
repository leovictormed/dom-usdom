import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,symlink,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {readFile as readSource} from 'node:fs/promises';

const component=path.resolve(import.meta.dirname,'../..');
const scripts=[
  ['prepare-recoverable-safe-recovery.mjs','USDOM_SAFE_PACKAGE'],
  ['prepare-recoverable-safe-recovery-envelope.mjs','USDOM_SAFE_RECOVERY_PLAN'],
  ['check-recoverable-safe-recovery-envelope.mjs','USDOM_SAFE_RECOVERY_PLAN'],
  ['assemble-recoverable-safe-recovery.mjs','USDOM_SAFE_RECOVERY_PLAN'],
  ['check-recoverable-safe-recovery-transactions.mjs','USDOM_SAFE_RECOVERY_PLAN'],
  ['collect-recoverable-safe-recovery.mjs','USDOM_SAFE_PACKAGE'],
  ['observe-recoverable-safe-recovery-execution.mjs','USDOM_SAFE_RECOVERY_PLAN'],
  ['prepare-recoverable-safe-release-evidence.mjs','USDOM_SAFE_PACKAGE'],
  ['check-recoverable-safe-recovery-raw-transaction.mjs','USDOM_SAFE_RECOVERY_PLAN'],
  ['check-recoverable-safe-recovery-plan.mjs','USDOM_SAFE_RECOVERY_PLAN'],
  ['check-recoverable-safe-recovery-target.mjs','USDOM_SAFE_PACKAGE'],
  ['collect-recoverable-safe-controls.mjs','USDOM_SAFE_PACKAGE'],
  ['check-recoverable-safe-release-evidence.mjs','USDOM_SAFE_RELEASE_EVIDENCE_BUNDLE'],
];

test('production Safe workflows reject symbolic-link input before parsing or RPC',async t=>{
  const directory=await mkdtemp(path.join(tmpdir(),'usdom-direct-operational-'));
  t.after(()=>rm(directory,{recursive:true,force:true}));
  const target=path.join(directory,'input.json');
  const linked=path.join(directory,'linked.json');
  await writeFile(target,'{}\n');
  await symlink(target,linked);
  for(const [script,firstInput] of scripts) {
    const env={...process.env,
      USDOM_SAFE_PACKAGE:linked,
      USDOM_SAFE_BASELINE:linked,
      USDOM_SAFE_RECOVERY_PLAN:linked,
      USDOM_SAFE_RECOVERY_TRANSACTIONS:linked,
      USDOM_SAFE_RECOVERY_SIGNATURES:linked,
      USDOM_SAFE_RECOVERY_ENVELOPE:linked,
      USDOM_SAFE_RECOVERY_REPORT:linked,
      USDOM_SAFE_RECOVERY_RAW_TRANSACTION:linked,
      USDOM_SAFE_RELEASE_EVIDENCE_BUNDLE:linked,
      ETHEREUM_RPC_URL:'http://127.0.0.1:1',
      [firstInput]:linked,
    };
    const result=spawnSync(process.execPath,[path.join(component,'scripts',script)],{
      cwd:component,env,encoding:'utf8',timeout:10_000,
    });
    assert.equal(result.status,1,`${script}: ${result.stderr}`);
    assert.equal(JSON.parse(result.stderr).code,'RELEASE_OPERATION_REJECTED',script);
  }
});

test('release authorization and native attestation inputs use the direct private-file boundary',async()=>{
  const expectations={
    'prepare-release-authorization-request.mjs':[
      "['config/operator-intent.json',{exactMode:0o600}]",
      "['config/mainnet-preflight-rpc-catalog.json',{exactMode:0o644,maximum:1024*1024}]",
      'const currentFixedBytes=await readFixedInputs()',
      "label:'residual-risk report'",
      'release inputs changed during request preparation',
    ],
    'prepare-release-authorization-materialization.mjs':[
      "['evidence/authorization/release-authorization-signature.hex'",
      '{exactMode:0o600,maximum:4096}',
      "['config/mainnet-preflight-rpc-catalog.json',{exactMode:0o644,maximum:1024*1024}]",
      'const currentFixedBytes=await readFixedInputs()',
      'release inputs changed during authorization materialization',
    ],
    'prepare-native-release-attestation-materialization.mjs':[
      "...names.map(name=>[path.posix.join('evidence/native-attestations',files[name])",
      '{exactMode:0o600,maximum:4096}',
      "['config/mainnet-preflight-rpc-catalog.json',{exactMode:0o644,maximum:1024*1024}]",
      'const currentFixedBytes=await readFixedInputs()',
      'native release inputs changed during attestation materialization',
    ],
    'prepare-native-release-attestation-requests.mjs':[
      "['config/mainnet-preflight-rpc-catalog.json',{exactMode:0o644,maximum:1024*1024}]",
      'readPrivateWalletEvidence(publicIdentityPath',
      'readPrivateWalletEvidence(tpmEvidencePath',
      'readPrivateWalletEvidence(recoveryEvidencePath',
      'const [currentFixedBytes,currentManifestBytes,currentIdentityBytes,currentTpmBytes,',
      'native release inputs changed during attestation request preparation',
    ],
  };
  for(const [script,markers] of Object.entries(expectations)) {
    const source=await readSource(path.join(component,'scripts',script),'utf8');
    assert.doesNotMatch(source,/from 'node:fs\/promises';/,
      `${script} must not bypass the direct-file boundary`);
    for(const marker of markers) assert.match(source,new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  }
});

test('mainnet gates and RISC Zero health commands use direct project reads',async()=>{
  const expectations={
    'collect-risc0-health-sources.mjs':['readDirectProjectFile(root,catalogPath',
      'readDirectProjectFile(root,referencePath',
      'RISC Zero health inputs changed during observation'],
    'check-risc0-health.mjs':[
      "readDirectProjectFile(root,'config/risc0-ethereum-mainnet-v3.json'",
      'RISC Zero health inputs changed during observation',
    ],
    'check-mainnet-preflight.mjs':[
      'const preflightInputBytes=await readPreflightInputs()',
      'mainnet preflight inputs changed during observation',
      'USDOM_MAINNET_DEPLOYMENT_EVIDENCE_DIRECTORY',
      'assertDeploymentEvidenceUnchanged(deploymentEvidence)',
      'contract-deployment-${index}-raw-validation.json',
    ],
    'check-mainnet-readiness.mjs':[
      'const readRawDirectFile=(relative,options)=>readDirectProjectFile(root,relative,options)',
      "readDirectFile('contracts/USDOMProofReserve.sol')",
      "readDirectFile('contracts/DOMCheckpointRegistry.sol')",
      "readDirectFile(source,{label:'reserve compiled source'})",
    ],
  };
  for(const [script,markers] of Object.entries(expectations)) {
    const source=await readSource(path.join(component,'scripts',script),'utf8');
    assert.doesNotMatch(source,/from 'node:fs\/promises'/,
      `${script} must not bypass the direct project-file boundary`);
    for(const marker of markers) assert.ok(source.includes(marker),`${script}: missing ${marker}`);
  }
});

test('deployment, deposit and configuration preparation reject pathname reopens',async()=>{
  const expectations={
    'prepare-mainnet-deployment.mjs':[
      'sourceContents[source]=await readStable(source,{',
      'const bytes=await readDirectProjectFile(root,relative,options);',
    ],
    'prepare-closed-mainnet-deposit.mjs':[
      'return readDirectFile(walletPath,{',
      "privateMode:true,label:'public wallet identity'",
      'closed mainnet deposit inputs changed during preparation',
    ],
    'check-configuration.mjs':['await readDirectFile(process.argv[2],{'],
  };
  for(const [script,markers] of Object.entries(expectations)) {
    const source=await readSource(path.join(component,'scripts',script),'utf8');
    assert.doesNotMatch(source,/from 'node:fs\/promises'/,
      `${script} must not reopen a validated pathname`);
    for(const marker of markers) assert.ok(source.includes(marker),`${script}: missing ${marker}`);
  }
});

test('finalized deposit issuance preserves every public and private input through submission',async()=>{
  const source=await readSource(path.join(component,'scripts','submit-finalized-deposit-issuance.mjs'),'utf8');
  for(const marker of [
    'const issuanceInputs=await readIssuanceInputs()',
    "readDirectFile(files.receipt,{minimum:1,maximum:1024*1024",
    'const currentIssuanceInputs=await readIssuanceInputs()',
    'finalized deposit issuance inputs changed during submission',
    '[files.registration,128*1024,true]',
    '[files.token,256,true]',
    'writePrivateFileDurableNew(files.intent',
    'existing issuance submission intent differs',
    'finalized deposit issuance inputs changed before submission',
    'writePrivateFileDurableNew(file,value',
    'parseStrictJsonBytes(',
    "new TextDecoder('utf-8',{fatal:true})",
    "decodeUtf8(pinBytes,'native manifest pin')",
    "decodeUtf8(tokenBytes,'DOM RPC token')",
    '/^[0-9a-f]{64}\\n$/.test(tokenText)',
    "decodeJson(indexBytes,'finalized deposit witness index',128*1024)",
    "decodeJson(registrationBytes,'expected deposit registration',128*1024)",
  ]) assert.ok(source.includes(marker),`missing issuance hardening: ${marker}`);
  assert.doesNotMatch(source,/JSON\.parse\(indexBytes|JSON\.parse\(registrationBytes/);
  assert.ok(source.indexOf('const issuanceInputs=await readIssuanceInputs()')
    <source.indexOf('readDirectFile(files.receipt,{minimum:1,maximum:1024*1024')
    &&source.indexOf('readDirectFile(files.receipt,{minimum:1,maximum:1024*1024')
      <source.indexOf("await rpc('POST','/usdom/v4/issuance/submit/v1'"),
  'existing crash-recovery receipt must be reconciled before resubmission');
  assert.ok(source.indexOf('await persistIntent(intent)')
    <source.indexOf("await rpc('POST','/usdom/v4/issuance/submit/v1'"),
  'intent must be journaled before submission');
  assert.ok(source.indexOf('const currentIssuanceInputs=await readIssuanceInputs()')
    <source.indexOf('await atomicWrite(files.receipt'), 'input recheck must precede receipt write');
});

test('wallet identity boundary rejects invalid UTF-8 and duplicate authority keys',async t=>{
  const directory=await mkdtemp(path.join(tmpdir(),'usdom-dom-identity-'));
  t.after(()=>rm(directory,{recursive:true,force:true}));
  const identity=path.join(directory,'identity.json');
  const checker=path.join(component,'scripts','check-dom-mainnet-identity-file.mjs');
  for(const [bytes,pattern] of [
    [Buffer.from('{"network":"mainnet","\\u006eetwork":"regtest"}\n'),
      /duplicate object key "network"/],
    [Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),/invalid UTF-8/],
  ]) {
    await writeFile(identity,bytes,{mode:0o600});
    const result=spawnSync(process.execPath,[checker,identity],{encoding:'utf8'});
    assert.notEqual(result.status,0);
    assert.equal(JSON.parse(result.stderr).code,'RELEASE_OPERATION_REJECTED');
  }
});

test('recoverable Safe target preflight reaches catalog consensus and rechecks inputs',async()=>{
  const source=await readSource(path.join(component,'scripts',
    'check-recoverable-safe-recovery-target.mjs'),'utf8');
  assert.ok(source.includes('validateRecoverableSafeRecoveryEnvelope(plan,transactions,envelope)'));
  assert.ok(source.includes('role:envelope.role'));
  assert.doesNotMatch(source,/process\.env\.USDOM_SAFE_RECOVERY_ROLE\b/);
  assert.ok(source.includes('const [currentPackageBytes,currentPlanBytes,currentTransactionsBytes,currentEnvelopeBytes,'));
  assert.ok(source.includes('matchMainnetPreflightRpcSources'));
  assert.ok(source.includes('independent Safe target RPC observations disagree'));
  assert.ok(source.includes('recoverable Safe target inputs changed during preflight'));
  assert.doesNotMatch(source,/process\.env\.ETHEREUM_RPC_URL\b/);
  assert.ok(source.indexOf('const [currentPackageBytes,currentPlanBytes,currentTransactionsBytes,currentEnvelopeBytes,')
    <source.indexOf('process.stdout.write'), 'input recheck must precede output');
});

test('recoverable Safe recovery observers recheck every file after RPC observation',async()=>{
  const expectations={
    'collect-recoverable-safe-recovery.mjs':'changed during recovery collection',
    'observe-recoverable-safe-recovery-execution.mjs':'changed during execution observation',
  };
  for(const [script,marker] of Object.entries(expectations)) {
    const source=await readSource(path.join(component,'scripts',script),'utf8');
    assert.ok(source.includes('if(!current.equals(input.bytes))'),script);
    assert.ok(source.includes(marker),script);
    assert.ok(source.indexOf('if(!current.equals(input.bytes))')
      <source.indexOf('process.stdout.write'),`${script}: recheck must precede output`);
  }
});

test('closed Mainnet block writers recheck inputs after node RPC actions',async()=>{
  const expectations={
    'initialize-closed-mainnet-genesis.mjs':'DOM RPC token changed during genesis initialization',
    'mine-closed-mainnet-issuance-block.mjs':'closed Mainnet issuance inputs changed during block production',
  };
  for(const [script,marker] of Object.entries(expectations)) {
    const source=await readSource(path.join(component,'scripts',script),'utf8');
    assert.ok(source.includes(marker),script);
    assert.ok(source.indexOf(marker)<source.indexOf('await atomicWrite(receiptFile'),
      `${script}: recheck must precede receipt write`);
  }
});

test('closed Mainnet genesis journals its exact request before block production',async()=>{
  const source=await readSource(path.join(component,'scripts','initialize-closed-mainnet-genesis.mjs'),'utf8');
  for(const marker of ['writePrivateFileDurableNew(intentFile','usdom-closed-mainnet-genesis-intent-v1',
    'existing genesis initialization intent differs','DOM RPC token changed before genesis initialization',
    'parseStrictJson(payload']) assert.ok(source.includes(marker),marker);
  assert.ok(source.indexOf('await journalIntent')
    <source.indexOf("await rpc('POST','/closed-mainnet/mine-one/v1'"));
  assert.doesNotMatch(source,/payload\.slice/);
});

test('closed Mainnet issuance block journals exact parent and request before mining',async()=>{
  const source=await readSource(path.join(component,'scripts','mine-closed-mainnet-issuance-block.mjs'),'utf8');
  for(const marker of ['writePrivateFileDurableNew(intentFile','usdom-closed-mainnet-issuance-block-intent-v1',
    'existing issuance block intent differs','closed Mainnet issuance inputs changed before block production',
    "new TextDecoder('utf-8',{fatal:true}).decode(submissionBytes)"]) {
    assert.ok(source.includes(marker),marker);
  }
  assert.ok(source.indexOf('await journalIntent')
    <source.indexOf("await rpc('POST','/closed-mainnet/mine-one/v1'"));
  assert.doesNotMatch(source,/payload\.slice/);
});

test('recoverable Safe planners recheck every input after RPC planning',async()=>{
  const expectations={
    'prepare-recoverable-safe-recovery.mjs':'changed during recovery planning',
    'prepare-recoverable-safe-recovery-envelope.mjs':'changed during envelope planning',
  };
  for(const [script,marker] of Object.entries(expectations)) {
    const source=await readSource(path.join(component,'scripts',script),'utf8');
    assert.ok(source.includes('if(!current.equals(input.bytes))'),script);
    assert.ok(source.includes(marker),script);
    assert.ok(source.indexOf('if(!current.equals(input.bytes))')
      <source.indexOf('process.stdout.write'),`${script}: recheck must precede output`);
  }
});

test('recoverable Safe control preparation requires cataloged independent RPC agreement',async()=>{
  const source=await readSource(path.join(component,'scripts','prepare-recoverable-safe-controls.mjs'),'utf8');
  for(const marker of ['matchMainnetPreflightRpcSources','for(const source of sources)',
    'independent Safe deployment RPC observations disagree',
    'Safe deployment inputs changed during preparation','USDOM_SAFE_OWNER_IDENTITIES',
    'readDirectFile(ownerIdentityPath',"writeReleaseFailure('prepare-recoverable-safe-controls'"]) {
    assert.ok(source.includes(marker),`missing Safe preparation hardening: ${marker}`);
  }
  assert.equal(source.match(/await prepareRecoverableSafeControlDeployments\(options\)/g)?.length,2,
    'each cataloged source must be observed twice');
  assert.doesNotMatch(source,/process\.env\.ETHEREUM_RPC_URL\b/);
});

test('recoverable Safe envelope uses the bounded catalog source set',async()=>{
  const source=await readSource(path.join(component,'scripts',
    'prepare-recoverable-safe-recovery-envelope.mjs'),'utf8');
  for(const marker of ['matchMainnetPreflightRpcSources','sources,',
    'Safe recovery RPC catalog changed during envelope planning',"writeReleaseFailure('prepare-recoverable-safe-recovery-envelope'"]) {
    assert.ok(source.includes(marker),`missing envelope RPC hardening: ${marker}`);
  }
  assert.doesNotMatch(source,/process\.env\.ETHEREUM_RPC_URL/);
});
