import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';

const root=new URL('../..',import.meta.url);
const generator=readFileSync(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
const runbook=readFileSync(new URL('../../docs/CLOSED-MAINNET-LINUX-RUNBOOK.md',import.meta.url),'utf8');
const signers=['sign-release-authorizations.sh','sign-checkpoint-bootstrap-ratification.sh','sign-recoverable-safe-recovery.sh']
  .map(name=>readFileSync(new URL(`../../scripts/${name}`,import.meta.url),'utf8'));

test('one human is only a coordinator for nine disjoint signer identities',()=>{
  assert.match(runbook,/operador\/coordenador.*, não uma identidade signer/);
  assert.match(runbook,/seed, senha, dispositivo e backup/);
  assert.match(runbook,/Somente um dispositivo deve permanecer conectado por vez/);
  assert.match(generator,/unique\|length\)==9/);
  assert.match(generator,/one human coordinator, nine distinct signer identities, three separate 2-of-3 control roles/);
  assert.doesNotMatch(generator,/one operator, nine distinct keys/);
});

test('each signing and recovery flow requires two distinct signer addresses',()=>{
  assert.match(signers[0],/for index in 0 1/);
  assert.match(signers[1],/for INDEX in 0 1/);
  assert.match(signers[2],/requiredSigners\|length\] == \[2,2,2\]/);
  assert.match(signers[2],/for signer_index in 0 1/);
  for(const source of signers) assert.match(source,/Desconecte o dispositivo do signer/);
});

test('custody phases generate complete commands without editable placeholders',()=>{
  for(const phase of ['enroll-safe-owners-secret','migrate-safe-owners-hardware-secret','prepare-safe-recovery-secret']) {
    const out=spawnSync('bash',['scripts/generate-closed-mainnet-phase-command.sh',phase],{cwd:root,encoding:'utf8'});
    assert.equal(out.status,0,out.stderr);
    assert.doesNotMatch(out.stdout,/\b(?:TODO|PLACEHOLDER|REPLACE_ME)\b/);
    assert.match(out.stdout,/all nine .*owners must be globally distinct|unique\|length\)==9|requiredSigners/);
  }
});

test('custody and replacement proofs require authorization for their complete typed context',()=>{
  assert.match(generator,/usdom-safe-owner-custody-proof-sign-v1\|action=signSafeOwnerCustodyProof\|phase=offline-proof-only\|chainId=1\|role=\$role\|slot=\$slot\|owner=\$\{owner,,\}\|safe=\$\{safe,,\}\|packageHash=\$\{package_hash,,\}/);
  assert.match(generator,/AUTORIZO PROVA CUSTODIA SAFE AUTH \$authorization_hash/);
  assert.match(generator,/usdom-safe-recovery-replacement-proof-sign-v1\|action=signSafeRecoveryReplacementProof\|phase=offline-proof-only\|chainId=1\|role=\$role\|replacementOwner=\$\{replacement,,\}\|safe=\$\{safe,,\}\|planHash=\$\{plan_hash,,\}/);
  assert.match(generator,/AUTORIZO PROVA REPLACEMENT SAFE AUTH \$authorization_hash/);
});
