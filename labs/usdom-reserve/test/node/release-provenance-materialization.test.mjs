import test from 'node:test';
import assert from 'node:assert/strict';
import {cpSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import os from 'node:os';
import path from 'node:path';
import {
  deriveReleaseProvenanceIdentity,
  materializeReleaseProvenance,
} from '../../sdk/release-provenance-materialization.mjs';

const evidencePath=fileURLToPath(new URL(
  '../../config/mainnet-release-evidence.unconfigured.json',import.meta.url,
));
const intentPath=fileURLToPath(new URL('../../config/operator-intent.json',import.meta.url));
const sourceCommit='a'.repeat(40);
const signingFingerprint=`SHA256:${'A'.repeat(43)}`;
const projectRoot=fileURLToPath(new URL('../..',import.meta.url));

async function fixture() {
  const [releaseEvidence,operatorIntent]=await Promise.all([
    readFile(evidencePath,'utf8').then(JSON.parse),readFile(intentPath,'utf8').then(JSON.parse),
  ]);
  return {releaseEvidence,operatorIntent,packageVersion:'0.3.0',sourceCommit,signingFingerprint};
}

test('derives one canonical release identity from source commit and package version',()=>{
  assert.deepEqual(deriveReleaseProvenanceIdentity({packageVersion:'0.3.0',sourceCommit,
    signingFingerprint}),{
    releaseId:'usdom-v0.3.0',sourceCommit,sourceTag:'usdom-v0.3.0',signingFingerprint,
  });
});

test('materializes only provenance fields and remains idempotent',async()=>{
  const input=await fixture();
  const beforeEvidence=structuredClone(input.releaseEvidence);
  const beforeIntent=structuredClone(input.operatorIntent);
  const first=materializeReleaseProvenance(input);
  assert.equal(first.releaseEvidence.releaseId,'usdom-v0.3.0');
  assert.equal(first.releaseEvidence.sourceCommit,sourceCommit);
  assert.equal(first.releaseEvidence.sourceTag,'usdom-v0.3.0');
  assert.equal(first.operatorIntent.release_signing_key_fingerprint,signingFingerprint);
  assert.equal(first.operatorIntent.residual_risk_acceptance.releaseId,'usdom-v0.3.0');
  assert.equal(first.operatorIntent.residual_risk_acceptance.sourceCommit,sourceCommit);
  assert.equal(first.operatorIntent.production_approved,false);
  assert.equal(first.operatorIntent.deploy_authorized,false);
  assert.equal(first.operatorIntent.real_funds_authorized,false);
  assert.equal(input.releaseEvidence.releaseId,beforeEvidence.releaseId);
  assert.deepEqual(input.operatorIntent,beforeIntent);
  const second=materializeReleaseProvenance({...input,
    releaseEvidence:first.releaseEvidence,operatorIntent:first.operatorIntent});
  assert.deepEqual(second,first);
});

test('rejects identity substitution and malformed release inputs',async()=>{
  const input=await fixture();
  for(const patch of [
    {packageVersion:'01.0.0'},
    {packageVersion:'1.0'},
    {sourceCommit:'A'.repeat(40)},
    {sourceCommit:'a'.repeat(39)},
    {signingFingerprint:'SHA256:short'},
  ]) assert.throws(()=>deriveReleaseProvenanceIdentity({...input,...patch}));
  for(const mutate of [
    value=>{value.releaseEvidence.releaseId='other';},
    value=>{value.releaseEvidence.sourceCommit='b'.repeat(40);},
    value=>{value.releaseEvidence.sourceTag='usdom-v9.9.9';},
    value=>{value.operatorIntent.release_signing_key_fingerprint=`SHA256:${'B'.repeat(43)}`;},
    value=>{value.operatorIntent.residual_risk_acceptance.releaseId='other';},
    value=>{delete value.operatorIntent.residual_risk_acceptance.sourceCommit;},
  ]) {
    const value=await fixture(); mutate(value);
    assert.throws(()=>materializeReleaseProvenance(value));
  }
});

test('CLI authenticates an actual signed source commit and external fingerprint',()=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-release-provenance-'));
  try {
    const repository=path.join(temporary,'repo');
    const component=path.join(repository,'labs','usdom-reserve');
    for(const directory of ['scripts','sdk','config']) mkdirSync(path.join(component,directory),{
      recursive:true,
    });
    for(const relative of [
      'scripts/prepare-release-provenance-materialization.mjs',
      'sdk/direct-project-file.mjs','sdk/git-signature.mjs',
      'sdk/release-provenance-materialization.mjs','sdk/strict-json.mjs',
      'sdk/stable-executable.mjs','sdk/pinned-executable-child.mjs',
      'config/mainnet-release-evidence.unconfigured.json','config/operator-intent.json',
      'package.json',
    ]) cpSync(path.join(projectRoot,relative),path.join(component,relative));
    const key=path.join(temporary,'release-key');
    const allowed=path.join(temporary,'allowed-signers');
    let result=spawnSync('ssh-keygen',['-q','-t','ed25519','-N','','-f',key],{encoding:'utf8'});
    assert.equal(result.status,0,result.stderr);
    const publicKey=readFileSync(`${key}.pub`,'utf8');
    writeFileSync(allowed,`sorenplanck@tutamail.com ${publicKey}`);
    const git=args=>{
      const value=spawnSync('git',['-C',repository,...args],{encoding:'utf8'});
      assert.equal(value.status,0,value.stderr);
      return value.stdout.trim();
    };
    git(['init','-q']);
    git(['config','user.name','Soren Planck']);
    git(['config','user.email','sorenplanck@tutamail.com']);
    git(['config','gpg.format','ssh']);
    git(['config','user.signingkey',key]);
    git(['config','gpg.ssh.allowedSignersFile',allowed]);
    git(['add','--all']);
    git(['commit','-q','-S','-m','USD0M source fixture']);
    const fingerprint=spawnSync('ssh-keygen',['-lf',`${key}.pub`,'-E','sha256'],{
      encoding:'utf8',
    }).stdout.trim().split(/\s+/)[1];
    result=spawnSync(process.execPath,['scripts/prepare-release-provenance-materialization.mjs'],{
      cwd:component,encoding:'utf8',env:{...process.env,
        USDOM_RELEASE_SIGNING_KEY_FINGERPRINT:fingerprint},
    });
    assert.equal(result.status,0,result.stderr);
    const output=JSON.parse(result.stdout);
    assert.equal(output.identity.sourceCommit,git(['rev-parse','HEAD']));
    assert.equal(output.identity.signingFingerprint,fingerprint);
    assert.equal(output.releaseEvidence.sourceTag,'usdom-v0.3.0');
    const rejected=spawnSync(process.execPath,
      ['scripts/prepare-release-provenance-materialization.mjs'],{
        cwd:component,encoding:'utf8',env:{...process.env,
          USDOM_RELEASE_SIGNING_KEY_FINGERPRINT:signingFingerprint},
      });
    assert.notEqual(rejected.status,0);
    assert.match(rejected.stderr,/signer differs from the external release trust anchor/);
  } finally { rmSync(temporary,{recursive:true,force:true}); }
});

test('provenance CLI pins Git and rejects ambiguous ordinary command output',async()=>{
  const source=await readFile(new URL(
    '../../scripts/prepare-release-provenance-materialization.mjs',import.meta.url),'utf8');
  assert.match(source,/snapshotExecutable\('git'\)/);
  assert.match(source,/runPinnedExecutable\(tool,/);
  assert.match(source,/maxBuffer:4\*1024\*1024,timeout:30\*1000/);
  assert.doesNotMatch(source,/execFile\(|node:child_process|promisify/);
  assert.match(source,/new TextDecoder\('utf-8',\{fatal:true\}\)/);
  assert.match(source,/result\.stderr\.length!==0/);
  assert.match(source,/sourceCommitAfter!==sourceCommit/);
  assert.match(source,/currentInputBytes\.some\(\(bytes,index\)=>!bytes\.equals\(inputBytes\[index\]\)\)/);
  assert.match(source,/parseStrictJsonBytes\(inputBytes/);
  assert.doesNotMatch(source,/execFile\('git'|encoding:'utf8'|\.toString\(['"]utf8['"]\)/);
});
