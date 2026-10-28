import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {chmodSync,mkdtempSync,readFileSync,readdirSync,rmSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const generator=path.join(root,'scripts/generate-closed-mainnet-phase-command.sh');
const publicPhases=['prerequisites','prepare-safe-controls','materialize-safe-control-config',
  'validate-local','prepare-deployment','measure-release-capacity','open-claims-plan','checklist','readiness'];

test('all public phases inherit the hardened prefix and one cross-phase lock',()=>{
  for(const phase of publicPhases) {
    const run=spawnSync('/usr/bin/bash',[generator,phase],{cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
    assert.equal(run.status,0,`${phase}: ${run.stderr}`);
    const source=run.stdout;
    assert.equal(spawnSync('/usr/bin/bash',['-n'],{input:source,encoding:'utf8'}).status,0,phase);
    assert.equal(source.indexOf('set +x'),0);
    assert.match(source,/ulimit -c 0/);
    assert.match(source,/exec 8<"\$USDOM_PILOT_PHASE_LOCK_DIRECTORY"/);
    assert.match(source,/flock -n 8/);
    assert.match(source,/phase-execution-lock/);
    assert.doesNotMatch(source,/\bcast send\b|eth_sendRawTransaction|wallet sign|git push/);
  }
});

test('directory locks authenticate a real opened directory without impossible link counts',()=>{
  const run=spawnSync('/usr/bin/bash',[generator,'open-claims-plan'],{
    cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},
  });
  assert.equal(run.status,0,run.stderr);
  assert.match(run.stdout,/realpath -e \/proc\/\$\$\/fd\/8/);
  assert.match(run.stdout,/stat -Lc '%u:%a' \/proc\/\$\$\/fd\/8/);
  assert.match(run.stdout,/stat -c '%d:%i'.*stat -Lc '%d:%i' \/proc\/\$\$\/fd\/8/);
  const directory=mkdtempSync(path.join(os.tmpdir(),'usdom-real-directory-'));
  chmodSync(directory,0o700);
  try {
    const check=spawnSync('/usr/bin/bash',['--noprofile','--norc','-c',String.raw`
set -euo pipefail
directory=$1
test -d "$directory"; test ! -L "$directory"
test "$(realpath -e "$directory")" = "$directory"
exec 8<"$directory"
test "$(realpath -e /proc/$$/fd/8)" = "$directory"
test "$(stat -Lc '%u:%a' /proc/$$/fd/8)" = "$(id -u):700"
test "$(stat -c '%d:%i' "$directory")" = "$(stat -Lc '%d:%i' /proc/$$/fd/8)"
flock -n 8
`,'usdom-directory-check',directory],{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
    assert.equal(check.status,0,check.stderr);
  } finally {rmSync(directory,{recursive:true,force:true});}
  const offenders=[];
  const visit=directory=>{for(const entry of readdirSync(directory,{withFileTypes:true})) {
    const candidate=path.join(directory,entry.name);
    if(entry.isDirectory()) visit(candidate);
    else if(entry.isFile()&&entry.name.endsWith('.sh')) {
      const source=readFileSync(candidate,'utf8');
      if(source.includes(':700:1')&&!candidate.endsWith('bootstrap-solc-0.8.37.sh')) offenders.push(candidate);
    }
  }};
  visit(path.join(root,'scripts'));
  assert.deepEqual(offenders,[],'directory checks must not require st_nlink == 1');
  const solcBootstrap=readFileSync(path.join(root,'scripts/bootstrap-solc-0.8.37.sh'),'utf8');
  assert.match(solcBootstrap,/test -f "\$target"[\s\S]*:700:1/);
});

test('plan commands use immutable owner-only phase scripts instead of redirecting into tmp',()=>{
  const writer=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{
    cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},
  });
  assert.equal(writer.status,0,writer.stderr);
  const plan=JSON.parse(writer.stdout);
  for(const row of plan.entries) {
    assert.match(row.generateCommand,/materialize-closed-mainnet-phase-script\.sh [a-z0-9-]+$/);
    assert.match(row.validateCommand,/ -n \/home\/leonardov\/usdom-mainnet-private\/operator-phases\/[a-z0-9-]+\.sh$/);
    assert.match(row.executeCommand,/\/home\/leonardov\/usdom-mainnet-private\/operator-phases\/[a-z0-9-]+\.sh$/);
    assert.doesNotMatch(row.generateCommand+row.validateCommand+row.executeCommand,/\/tmp\/|>|>>/);
  }
});

test('phase materializer and pilot entrypoint are fail-closed and crash-safe',()=>{
  const materializer=readFileSync(path.join(root,'scripts/materialize-closed-mainnet-phase-script.sh'),'utf8');
  const entry=readFileSync(path.join(root,'scripts/prepare-closed-mainnet-pilot.sh'),'utf8');
  assert.match(materializer,/ensure-private-directory-path\.py "\$directory"/);
  assert.match(materializer,/flock -n 9/);
  assert.match(materializer,/compgen -A function/);
  assert.match(materializer,/\/proc\/"\$\$"\/fd\/\*/);
  assert.match(materializer,/install-private-file-immutable-stdin\.mjs "\$target"/);
  assert.doesNotMatch(materializer,/cmp -s -- "\$candidate" "\$target"/);
  assert.match(materializer,/temporary_identity=.*'%u:%d:%i:%a'/);
  assert.match(entry,/set \+x/); assert.match(entry,/ulimit -c 0/);
  assert.match(entry,/compgen -A function/);
  assert.match(entry,/\/proc\/"\$\$"\/fd\/\*/);
  assert.match(entry,/flock -n 9/);
  assert.match(entry,/install-content-addressed-public-plan\.py/);
});
