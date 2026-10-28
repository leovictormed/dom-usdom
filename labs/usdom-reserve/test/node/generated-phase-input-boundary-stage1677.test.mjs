import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {existsSync,readFileSync} from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const root=new URL('../..',import.meta.url);
const node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';
const generated=spawnSync(node,['scripts/write-open-claims-execution-plan.mjs'],{
  cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024,
});
assert.equal(generated.status,0,generated.stderr);
const plan=JSON.parse(generated.stdout);
const projectRoot=path.resolve(root.pathname);
const phases=new Map(plan.phaseOrder.map(phase=>{
  const result=spawnSync('/usr/bin/bash',['scripts/generate-closed-mainnet-phase-command.sh',phase],{
    cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024,
  });
  assert.equal(result.status,0,result.stderr);
  return [phase,result.stdout];
}));

test('all 23 generated phases are complete scripts without manual placeholders',()=>{
  assert.equal(phases.size,23);
  for(const [phase,source] of phases) {
    assert.doesNotMatch(source,/\b(?:TODO|TBD|FIXME|REPLACE_ME|CHANGEME|CHANGE_ME|YOUR_[A-Z0-9_]+)\b/i,phase);
    assert.doesNotMatch(source,/<(?:address|amount|chain|file|hash|key|password|path|rpc|secret|value)>/i,phase);
    assert.doesNotMatch(source,/(?:nano|vim|vi)\s+(?:config|evidence|\/home)\//,phase);
    const syntax=spawnSync('/usr/bin/bash',['--noprofile','--norc','-n'],{input:source,encoding:'utf8'});
    assert.equal(syntax.status,0,`${phase}: ${syntax.stderr}`);
  }
});

test('generated phases do not expose secrets through argv or environment',()=>{
  for(const [phase,source] of phases) {
    assert.doesNotMatch(source,/--(?:private-key|mnemonic|seed(?:-phrase)?|passphrase)(?:=|\s)/i,phase);
    assert.doesNotMatch(source,/\b(?:export\s+)?[A-Z0-9_]*(?:PRIVATE_KEY|MNEMONIC|SEED_PHRASE|PASSPHRASE)=/i,phase);
    for(const line of source.split('\n').filter(value=>/\b--password\b/.test(value))) {
      assert.match(line,/wallet new .* --password >\/dev\/null$/,`${phase}: password must come from cast hidden prompt`);
    }
  }
});

test('unavoidable external custody input has complete generation or device collection commands',()=>{
  const enrollment=phases.get('enroll-safe-owners-secret');
  assert.match(enrollment,/wallet new "\$USDOM_SAFE_KEYSTORE_DIRECTORY" "\$name" --password >\/dev\/null/);
  assert.match(enrollment,/install-private-file-immutable-stdin\.mjs "\$backup"/);
  const migration=phases.get('migrate-safe-owners-hardware-secret');
  assert.match(migration,/wallet address --ledger/);
  assert.match(migration,/wallet sign --data --from-file "\$typed" --ledger/);
  const recovery=phases.get('prepare-safe-recovery-secret');
  assert.match(recovery,/wallet address --ledger/);
  assert.match(recovery,/wallet sign --data --from-file "\$typed" --ledger/);
  assert.match(recovery,/install-private-file-new-stdin\.mjs --json "\$USDOM_SAFE_RECOVERY_SESSION"/);
});

test('command substitutions that feed later arguments cannot hide collection failures',()=>{
  for(const [phase,source] of phases) {
    assert.doesNotMatch(source,/^\s*export\s+[A-Za-z_][A-Za-z0-9_]*=\$\(/m,
      `${phase}: assignment must succeed before export`);
  }
  const deployment=phases.get('prepare-deployment');
  assert.match(deployment,/USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION_SHA256=\$\([^\n]+\)\nexport USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION_SHA256/);
  for(const phase of ['execute-reserve-resume-secret','execute-pilot-deposit-secret']) {
    assert.match(phases.get(phase),/USDOM_GOVERNANCE_DELAY_SECONDS=\$\([^\n]+\)\nexport USDOM_GOVERNANCE_DELAY_SECONDS/);
  }
});

test('one human coordinator retains nine distinct identities, separated roles and recovery',()=>{
  const generator=readFileSync(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
  const runbook=readFileSync(new URL('../../docs/CLOSED-MAINNET-LINUX-RUNBOOK.md',import.meta.url),'utf8');
  assert.match(generator,/for role in governance reserveGuardian checkpointGuardian; do[\s\S]+for slot in primary secondary recovery; do/);
  assert.match(generator,/unique\|length\)==9/);
  assert.match(generator,/one human coordinator, nine distinct signer identities, three separate 2-of-3 control roles/);
  assert.doesNotMatch(generator,/independent (?:people|persons|humans|operators|custodians|signers)/i);
  assert.match(runbook,/uma única pessoa pode operar nove keystores criptografados distintos/i);
  assert.match(runbook,/Cada ação de um papel exige duas\s+assinaturas produzidas por duas chaves diferentes/);
  assert.match(runbook,/nenhuma chave pode ocupar dois papéis/);
  assert.match(runbook,/As três chaves `recovery` ficam em mídia\s+offline separada/);
  assert.match(runbook,/duas derivações da mesma seed[\s\S]+?não\s+formam quórum/i);
});

test('every literal npm and project-script command in all phases has an executable target',()=>{
  const packageScripts=JSON.parse(readFileSync(new URL('../../package.json',import.meta.url),'utf8')).scripts;
  for(const [phase,source] of phases) {
    for(const match of source.matchAll(/^\s*(?:[A-Z0-9_]+=\S+\s+)*npm run --silent ([a-zA-Z0-9:_-]+)/gm)) {
      assert.equal(typeof packageScripts[match[1]],'string',`${phase}: absent npm command ${match[1]}`);
    }
    for(const match of source.matchAll(/^\s*(?:[A-Z0-9_]+=\S+\s+)*(?:node|python3?|bash) (scripts\/[a-zA-Z0-9._/-]+)/gm)) {
      assert.equal(existsSync(path.join(projectRoot,match[1])),true,`${phase}: absent script ${match[1]}`);
    }
  }
});
