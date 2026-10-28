import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {
  assertClassifiedOpenReadinessClaims,classifyOpenReadinessClaims,
} from '../../sdk/readiness-open-claims.mjs';
import {assertNoStaleReserveBindings} from '../../sdk/open-claim-route-equivalence.mjs';

test('every false blocking claim is operational or release configuration, not missing code',async()=>{
  const requirements=JSON.parse(await readFile(new URL(
    '../../config/production-requirements.json',import.meta.url),'utf8'));
  const claims=classifyOpenReadinessClaims(requirements);
  assert.equal(claims.length,57);
  assert.deepEqual([...new Set(claims.map(({category})=>category))].sort(),
    ['configuration','operational-evidence']);
  assert.equal(claims.some(({category})=>category==='unclassified'),false);
  assert.equal(claims.some(({key})=>/audited|independently_reviewed|zero_risk/i.test(key)),false);
  assert(Object.isFrozen(claims));
  assert(claims.every(Object.isFrozen));
});

test('provenance checker rejects a newly false unclassified readiness claim',async()=>{
  const requirements=JSON.parse(await readFile(new URL(
    '../../config/production-requirements.json',import.meta.url),'utf8'));
  assert.equal(assertClassifiedOpenReadinessClaims(requirements).length,57);
  requirements.native_consensus_implemented=false;
  assert.throws(()=>assertClassifiedOpenReadinessClaims(requirements),
    /unclassified false readiness claims: native_consensus_implemented/);
});

test('standard provenance command runs the open-claims checker automatically',async()=>{
  const packageJson=JSON.parse(await readFile(new URL('../../package.json',import.meta.url),'utf8'));
  const command=packageJson.scripts['check:provenance'];
  assert.match(command,/mainnet-tool-dispatcher npm run --silent check:implementation-claims && .*mainnet-tool-dispatcher npm run --silent check:tool-dispatch-policy && .*mainnet-tool-dispatcher node scripts\/check-readiness-open-claims\.mjs &&/);
  assert.match(command,/check-readiness-open-claims\.mjs && .*mainnet-tool-dispatcher node scripts\/check-open-claims-execution-plan\.mjs &&/);
});

test('generated execution plan covers all 57 open claims without placeholders',async()=>{
  const script=fileURLToPath(new URL('../../scripts/write-open-claims-execution-plan.mjs',import.meta.url));
  const result=spawnSync(process.execPath,[script],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  const plan=JSON.parse(result.stdout);
  assert.equal(plan.schema,'usdom-open-claims-execution-plan/v1');
  assert.equal(plan.claimCount,57);
  assert.equal(plan.entries.length,57);
  assert.equal(new Set(plan.entries.map(entry=>entry.claim)).size,57);
  assert.equal(plan.phaseArtifacts.length,plan.phaseOrder.length);
  for(const [index,artifact] of plan.phaseArtifacts.entries()) {
    assert.equal(artifact.phase,plan.phaseOrder[index]);
    assert.equal(artifact.ordinal,index+1);
    assert.deepEqual(artifact.prerequisitePhases,plan.phaseOrder.slice(0,index));
    assert.match(artifact.generatedScriptSha256,/^[0-9a-f]{64}$/);
    assert(artifact.generatedScriptBytes>0);
  }
  for(const entry of plan.entries) {
    const clean='env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc';
    const phasePath=`/home/leonardov/usdom-mainnet-private/operator-phases/${entry.phase}.sh`;
    assert.equal(entry.generateCommand,`${clean} scripts/materialize-closed-mainnet-phase-script.sh ${entry.phase}`);
    assert.equal(entry.validateCommand,`${clean} -n ${phasePath}`);
    assert.equal(entry.executeCommand,`${clean} ${phasePath}`);
    const artifact=plan.phaseArtifacts[plan.phaseOrder.indexOf(entry.phase)];
    assert.equal(entry.phaseOrdinal,artifact.ordinal);
    assert.equal(entry.phaseScriptSha256,artifact.generatedScriptSha256);
    assert.equal(entry.phaseScriptBytes,artifact.generatedScriptBytes);
    assert.equal(entry.closingClaim,`operational-claims-ledger.json#/${entry.claim}`);
    assert.doesNotMatch(JSON.stringify(entry),/<[^>]+>|YOUR_|CHANGE_ME|PLACEHOLDER|REPLACE_ME|TODO|TBD/);
  }
});

test('plan integrity checker validates commands, targets and dependency order',()=>{
  const checker=fileURLToPath(new URL('../../scripts/check-open-claims-execution-plan.mjs',import.meta.url));
  const result=spawnSync(process.execPath,[checker],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  assert.match(result.stdout,/PASS: open-claims execution plan integrity 57\/57/);
});

test('route generation rejects removed reserve selectors and prior artifact bindings',()=>{
  assert.equal(assertNoStaleReserveBindings(['current route']),true);
  for(const stale of ['pendingBurnPage','burnIntentHash','initialPauseRequired',
    '27be31d80767bba9ed0369e89e4c0a408a694b16f82d7747f95b8d4179776a3d',
    '2044939ee66c2afafa3e165e700a2884687b0723b956b46b503b74752130f921',
    '86808fa0de635cbc3bc34710a633fae6a16c36e9bf947b68c616399ad9ddfd98']) {
    assert.throws(()=>assertNoStaleReserveBindings([`invoke ${stale}`]),/stale reserve ABI\/runtime binding/);
  }
});

test('generated phases never request public values or manual file edits',()=>{
  const generator=fileURLToPath(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url));
  for(const phase of ['enroll-safe-owners-secret','migrate-safe-owners-hardware-secret',
    'prepare-safe-recovery-secret','execute-safe-recovery-secret','execute-pilot-deposit-secret',
    'execute-pilot-redemption-secret','produce-checkpoint-evidence-secret',
    'execute-mainnet-deployment-secret','execute-reserve-resume-secret']) {
    const result=spawnSync('bash',[generator,phase],{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
    assert.equal(result.status,0,result.stderr);
    for(const line of result.stdout.split('\n').filter(value=>/^\s*(?:IFS=\s*)?read\s.*(?:-p|--prompt)/.test(value))) {
      assert.match(line,/(?:^\s*(?:IFS=\s*)?read\s.*(?:-s\b|--silent\b)|Digite (?:AUTORIZO|ASSINO|CONFIRMO))/);
    }
    assert.doesNotMatch(result.stdout,/(?:nano|vim|vi)\s+config\//);
  }
});

test('irreversible executors display mainnet limits before explicit authorization',async()=>{
  for(const file of ['execute-safe-control-deployment.sh','execute-recoverable-safe-recovery.sh',
    'execute-closed-mainnet-deposit.sh','execute-closed-mainnet-redemption.sh',
    'execute-mainnet-deployment.sh']) {
    const source=await readFile(new URL(`../../scripts/${file}`,import.meta.url),'utf8');
    if(file==='execute-safe-control-deployment.sh') {
      assert.match(source,/prepare-safe-control-deployment-relayer-envelope\.mjs/);
      assert.match(source,/exit 78/);
      assert.match(source,/Digite AUTORIZO TRANSMITIR SAFE \$role NONCE \$nonce TX \$tx_hash/);
      assert.match(source,/eth_getTransactionByHash/);
      continue;
    }
    if(file==='execute-closed-mainnet-deposit.sh') {
      assert.match(source,/usdom-onekey-eip712-signing\/v1/);
      assert.match(source,/materialize-safe-deposit-relayer\.mjs envelope/);
      assert.match(source,/safe-deposit-\$kind-safe-envelope\.json/);
      assert.match(source,/RELAYER_SIGNATURE_REQUIRED/);
      assert.match(source,/BROADCAST_REVALIDATION_REQUIRED/);
      assert.match(source,/exit 80/);
      continue;
    }
    assert.ok(source.indexOf('AUTHORIZE REVIEW')<source.indexOf('Digite AUTORIZO'));
    assert.match(source,/chainId=1/);
    assert.match(source,/gasLimit=/);
    assert.match(source,/maxFeePerGas=/);
    assert.match(source,/maximumGasCostWei=/);
  }
});

test('generated recursive cleanup authenticates temporary inode and handles signals',()=>{
  const generator=fileURLToPath(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url));
  for(const phase of ['migrate-safe-owners-hardware-secret']) {
    const result=spawnSync('bash',[generator,phase],{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
    assert.equal(result.status,0,result.stderr);
    assert.doesNotMatch(result.stdout,/trap ['"]rm -rf/);
    assert.match(result.stdout,/stat -c '%u:%d:%i:%a'/);
    assert.match(result.stdout,/_identity/);
    assert.match(result.stdout,/trap 'cleanup(?:_[a-z_]+)?; exit 143' TERM/);
  }
});

test('all plan commands clear ambient shell and Node injection before bash starts',async()=>{
  const script=fileURLToPath(new URL('../../scripts/write-open-claims-execution-plan.mjs',import.meta.url));
  const result=spawnSync(process.execPath,[script],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  const plan=JSON.parse(result.stdout);
  for(const row of plan.entries) for(const command of [row.generateCommand,row.validateCommand,row.executeCommand]) {
    assert.match(command,/^env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH \/usr\/bin\/bash --noprofile --norc /);
  }
  const generator=await readFile(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
  assert.match(generator,/export LC_ALL=C LANG=C TZ=UTC/);
  assert.match(generator,/unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH/);
  assert.match(generator,/test "\\\$\(command -v node\)" = \/usr\/lib\/chatgpt\/resources\/cua_node\/bin\/node/);
});

test('Ubuntu bootstrap pins packages and executable hashes without implicit sudo',async()=>{
  const source=await readFile(new URL('../../scripts/bootstrap-ubuntu-24.04-dependencies.sh',import.meta.url),'utf8');
  const lock=JSON.parse(await readFile(new URL('../../config/ubuntu-24.04-bootstrap-lock.json',import.meta.url),'utf8'));
  assert.equal(lock.os.id,'ubuntu'); assert.equal(lock.os.versionId,'24.04');
  assert(Object.keys(lock.packages).length>=13); assert(Object.keys(lock.executables).length>=14);
  assert.match(source,/--verify-only/); assert.match(source,/--install/);
  assert.match(source,/apt-get install --no-install-recommends --yes "\$\{specs\[@\]\}"/);
  assert.doesNotMatch(source,/\bsudo\b|\bcurl\b|\bwget\b/);
  assert.match(source,/sha256sum "\$executable"/);
});

test('single pilot entrypoint has safe verify mode and complete next commands',async()=>{
  const entry=fileURLToPath(new URL('../../scripts/prepare-closed-mainnet-pilot.sh',import.meta.url));
  const help=spawnSync('bash',[entry,'--help'],{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  assert.equal(help.status,0,help.stderr);
  assert.match(help.stdout,/--verify-only/); assert.match(help.stdout,/--generate-plan/);
  const source=await readFile(entry,'utf8');
  assert.match(source,/bootstrap-ubuntu-24\.04-dependencies\.sh --verify-only/);
  assert.match(source,/check-mainnet-toolchain\.mjs/);
  assert.match(source,/check-open-claims-execution-plan\.mjs/);
  assert.match(source,/ensure-private-directory-path\.py "\$plan_directory" 0755/);
  assert.match(source,/install-content-addressed-public-plan\.py/);
  assert.match(source,/flock -n 9/);
  assert.match(source,/set \+x/);
  assert.match(source,/ulimit -c 0/);
  assert.doesNotMatch(source,/cp --no-clobber/);
  assert.doesNotMatch(source,/YOUR_|CHANGE_ME|PLACEHOLDER|REPLACE_ME|<[A-Za-z][A-Za-z0-9 _.-]*>/);
  assert.match(source,/NEXT: \/usr\/bin\/bash --noprofile --norc/);
});

test('fixed writable boundaries reject symlinks and enforce owner modes',async()=>{
  const generator=await readFile(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
  assert.match(generator,/test ! -L "\\\$USDOM_CONTROL_EVIDENCE_DIRECTORY"/);
  assert.match(generator,/realpath -e "\\\$USDOM_CONTROL_EVIDENCE_DIRECTORY"/);
  assert.match(generator,/stat -c '%u:%a' "\\\$USDOM_CONTROL_EVIDENCE_DIRECTORY"/);
  assert.match(generator,/test ! -L "\\\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE"/);
  const entry=await readFile(new URL('../../scripts/prepare-closed-mainnet-pilot.sh',import.meta.url),'utf8');
  assert.match(entry,/test ! -L "\$plan_directory"/);
  assert.match(entry,/plan=\$\(\/usr\/bin\/python3 scripts\/install-content-addressed-public-plan\.py/);
  assert.match(entry,/NEXT: jq[^\n]+%s\\n' "\$plan"/);
});
