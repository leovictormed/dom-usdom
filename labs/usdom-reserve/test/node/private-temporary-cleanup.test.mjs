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
  for(const name of scripts) {
    const source=await readFile(path.join(component,'scripts',name),'utf8');
    assert.match(source,/cleanup\(\) \{[\s\S]*local status=\$\{1:-\$\?\}[\s\S]*trap - EXIT HUP INT TERM/);
    assert.match(source,/"\$node_bin" -e 'require\("fs"\)\.rmSync\(process\.argv\[1\],\{recursive:true,force:true\}\)' "\$(?:temporary|TEMPORARY)" \|\| status=1/);
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
