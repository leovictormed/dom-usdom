import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';
const run=(command,args,options={})=>spawnSync(command,args,{encoding:'utf8',...options});

test('native privacy claims use a dedicated assembly, validation and installation phase',()=>{
  const planResult=run(node,['scripts/write-open-claims-execution-plan.mjs']);
  assert.equal(planResult.status,0,planResult.stderr);
  const plan=JSON.parse(planResult.stdout);
  const phase='finalize-native-privacy-ceremony-secret';
  const generated=run('/usr/bin/bash',['scripts/generate-closed-mainnet-phase-command.sh',phase]);
  assert.equal(generated.status,0,generated.stderr);
  assert.equal(run('/usr/bin/bash',['-n'],{input:generated.stdout}).status,0);
  const byClaim=new Map(plan.entries.map(row=>[row.claim,row]));
  for(const claim of ['native_privacy_trusted_setup_ceremony_completed',
    'native_privacy_production_verifying_key_installed']) {
    assert.equal(byClaim.get(claim).phase,phase);
    assert.equal(byClaim.get(claim).implementationStatus,'external-operation');
  }
  for(const marker of ['for ordinal in 001 002 003',
    'assemble-native-privacy-ceremony.mjs draft','assemble-native-privacy-ceremony.mjs finalize',
    'check:native-privacy-ceremony','install:native-privacy-verifying-key',
    'del(.schema,.nativeRuntimeManifestSha256,.ceremonyTranscriptSha256)',
    'cmp -s "$vk" "$installation/spend-verifying-key.bin"']) assert.match(generated.stdout,
    new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.ok(generated.stdout.lastIndexOf('check:native-privacy-ceremony')
    >generated.stdout.indexOf('install:native-privacy-verifying-key'));
  assert.doesNotMatch(generated.stdout,/YOUR_|CHANGE_ME|PLACEHOLDER|REPLACE_ME|TODO|TBD/);
  const installer=readFileSync('scripts/install-native-privacy-verifying-key.mjs','utf8');
  const attestation=readFileSync('scripts/prepare-native-release-attestation-requests.mjs','utf8');
  assert.match(installer,/readDirectFile/);
  assert.doesNotMatch(installer,/\breadFile\(/);
  assert.match(installer,/buildNativePrivacyInstallationReceipt\(validated,manifestBytes,tb\)/);
  assert.match(attestation,/validateNativePrivacyInstallationReceipt\(privacyInstallation/);
  for(const installed of ['privacyTranscriptBytes','privacyVerifyingKeyBytes','privacyManifestBytes'])
    assert.match(attestation,new RegExp(installed));
});
