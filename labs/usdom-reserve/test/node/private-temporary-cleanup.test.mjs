import assert from 'node:assert/strict';
import {access,mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');
const scripts=[
  'execute-mainnet-deployment.sh','execute-recoverable-safe-recovery.sh',
  'sign-release-authorizations.sh','sign-checkpoint-bootstrap-ratification.sh',
  'sign-recoverable-safe-recovery.sh',
];

test('operational private temporaries have status-preserving signal cleanup',async()=>{
  const boundedCleanup=new Set([
    'execute-mainnet-deployment.sh','execute-recoverable-safe-recovery.sh',
    'sign-recoverable-safe-recovery.sh','sign-release-authorizations.sh',
    'sign-checkpoint-bootstrap-ratification.sh',
  ]);
  for(const name of scripts) {
    const source=await readFile(path.join(component,'scripts',name),'utf8');
    assert.match(source,/cleanup\(\) \{[\s\S]*local status=\$\{1:-\$\?\}[\s\S]*trap - EXIT HUP INT TERM/);
    if(boundedCleanup.has(name)) {
      const cleanup=source.slice(source.indexOf('cleanup() {'),source.indexOf("trap 'cleanup $?' EXIT"));
      assert.match(cleanup,/assert_node_unchanged && assert_timeout_unchanged/);
      assert.match(cleanup,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s/);
      assert.match(cleanup,/"\$node_bin" -e 'require\("fs"\)\.rmSync\(process\.argv\[1\],\{recursive:true,force:true\}\)'/);
      assert.match(cleanup,/"\$(?:temporary|TEMPORARY)" > \/dev\/null 2> \/dev\/null &&\n\s+assert_node_unchanged && assert_timeout_unchanged && test ! -e "\$(?:temporary|TEMPORARY)"/);
      assert.match(cleanup,/else\n(?:    #.*\n)*(?:    #.*\n)*    (?:status=1|\(\( status != 0 \)\) \|\| status=1)/);
    } else {
      assert.match(source,/"\$node_bin" -e 'require\("fs"\)\.rmSync\(process\.argv\[1\],\{recursive:true,force:true\}\)' "\$(?:temporary|TEMPORARY)" \|\| status=1/);
    }
    for(const [signal,status] of [['HUP',129],['INT',130],['TERM',143]])
      assert.match(source,new RegExp(`trap 'cleanup ${status}' ${signal}`));
    assert.match(source,/trap 'cleanup \$\?' EXIT/);
    assert.doesNotMatch(source,/trap cleanup EXIT HUP INT TERM|trap 'rm -rf|rm -rf -- "\$(?:temporary|TEMPORARY)"/);
  }
});

test('executor cleanup terminates and waits for proxy before erasing secrets',async()=>{
  for(const name of scripts.slice(0,2)) {
    const source=await readFile(path.join(component,'scripts',name),'utf8');
    const cleanup=source.slice(source.indexOf('cleanup() {'),source.indexOf("trap 'cleanup $?' EXIT"));
    assert.ok(cleanup.indexOf('stop_rpc_proxy')<cleanup.indexOf('rmSync'));
  }
});

test('mainnet deployment cleanup authenticates the private directory identity',async()=>{
  const source=await readFile(path.join(component,'scripts/execute-mainnet-deployment.sh'),'utf8');
  assert.match(source,/temporary_identity=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary"\)/);
  assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary" 2>\/dev\/null\) == "\$temporary_identity"/);
  assert.ok(source.indexOf('== "$temporary_identity"')<source.indexOf('rmSync(process.argv[1]'));
});

test('Safe recovery cleanup authenticates the private directory identity',async()=>{
  const source=await readFile(path.join(component,'scripts/execute-recoverable-safe-recovery.sh'),'utf8');
  assert.match(source,/temporary_identity=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary"\)/);
  assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary" 2>\/dev\/null\) == "\$temporary_identity"/);
  assert.ok(source.indexOf('== "$temporary_identity"')<source.indexOf('rmSync(process.argv[1]'));
});

test('Safe deployment cleanup authenticates the private directory identity',async()=>{
  const source=await readFile(path.join(component,'scripts/execute-safe-control-deployment.sh'),'utf8');
  assert.match(source,/temporary_identity=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary"\)/);
  assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary" 2>\/dev\/null\) == "\$temporary_identity"/);
  assert.ok(source.indexOf('== "$temporary_identity"')<source.indexOf('rmSync(process.argv[1]'));
});

test('TERM cleanup removes a private fixture and retains signal status',async t=>{
  const directory=await mkdtemp(path.join(tmpdir(),'usdom-cleanup-signal-'));
  t.after(()=>rm(directory,{recursive:true,force:true}));
  const result=spawnSync('bash',['-c',`
temporary=$1; node_bin=$2
cleanup() { local status=\${1:-$?}; trap - EXIT HUP INT TERM; "$node_bin" -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' "$temporary" || status=1; exit "$status"; }
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
kill -TERM $$
exit 99
`,'bash',directory,process.execPath]);
  assert.equal(result.status,143);
  await assert.rejects(access(directory));
});
