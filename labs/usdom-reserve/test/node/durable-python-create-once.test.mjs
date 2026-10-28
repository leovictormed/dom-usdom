import test from 'node:test';
import assert from 'node:assert/strict';
import {chmod,link,lstat,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import path from 'node:path';

const scripts=path.resolve(import.meta.dirname,'../../scripts');
const program='from pathlib import Path; from durable_create_once import install_create_once; import sys; install_create_once(Path(sys.argv[1]),b"evidence\\n",mode=int(sys.argv[2],8),maximum=1024,private_parent=True,allow_equal=True)';
const run=(target,mode,env={})=>spawnSync('/usr/bin/python3',['-c',program,target,mode],{
  encoding:'utf8',env:{PATH:'/usr/bin:/bin',PYTHONPATH:scripts,...env},
});

for(const mode of ['0400','0500','0600']) for(const fault of ['after-temporary-fsync','after-create-once-link']) {
  test(`Python durable create-once recovers ${mode} after ${fault}`,async t=>{
    const root=await mkdtemp(path.join(tmpdir(),'usdom-python-durable-')); t.after(()=>rm(root,{recursive:true,force:true}));
    await chmod(root,0o700); const target=path.join(root,'record');
    const killed=run(target,mode,{USDOM_TEST_DURABLE_CREATE_ONCE_FAULT:fault});
    assert.equal(killed.signal,'SIGKILL');
    const recovered=run(target,mode); assert.equal(recovered.status,0,recovered.stderr);
    assert.equal(await readFile(target,'utf8'),'evidence\n');
    assert.equal((await lstat(target)).nlink,1);
    assert.equal((await lstat(target)).mode&0o777,Number.parseInt(mode,8));
  });
}

test('Python durable create-once rejects a forged recoverable hardlink',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-python-durable-')); t.after(()=>rm(root,{recursive:true,force:true}));
  await chmod(root,0o700); const target=path.join(root,'record'),foreign=path.join(root,'foreign');
  await writeFile(foreign,'evidence\n',{mode:0o600}); await chmod(foreign,0o600);
  await link(foreign,path.join(root,'.record.2147483647.0123456789abcdef01234567.tmp'));
  const result=run(target,'0600'); assert.notEqual(result.status,0);
  assert.match(result.stderr,/hardlink has no content-addressed target|hardlink has no target|durable temporary hardlink/);
});

test('Python durable create-once pins the parent inode across pathname substitution',async t=>{
  const base=await mkdtemp(path.join(tmpdir(),'usdom-python-parent-race-')); t.after(()=>rm(base,{recursive:true,force:true}));
  const root=path.join(base,'private'),moved=path.join(base,'moved');
  await import('node:fs/promises').then(({mkdir})=>mkdir(root,{mode:0o700})); await chmod(root,0o700);
  const target=path.join(root,'record');
  const race=`from pathlib import Path\nfrom durable_create_once import install_create_once\nimport os,sys\np=Path(sys.argv[1]); moved=Path(sys.argv[2])\ndef hook(point):\n if point=='after-parent-validation': os.rename(p.parent,moved); os.mkdir(p.parent,0o700)\ninstall_create_once(p,b'evidence\\n',private_parent=True,fault_injection=hook)`;
  const result=spawnSync('/usr/bin/python3',['-c',race,target,moved],{encoding:'utf8',
    env:{PATH:'/usr/bin:/bin',PYTHONPATH:scripts}});
  assert.notEqual(result.status,0); assert.match(result.stderr,/parent changed/);
  await assert.rejects(lstat(target),{code:'ENOENT'});
  assert.equal(await readFile(path.join(moved,'record'),'utf8'),'evidence\n');
});

test('Python durable create-once rejects target substitution after descriptor validation',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-python-target-race-')); t.after(()=>rm(root,{recursive:true,force:true}));
  await chmod(root,0o700); const target=path.join(root,'record'),foreign=path.join(root,'foreign');
  await writeFile(target,'evidence\n',{mode:0o600}); await chmod(target,0o600);
  await writeFile(foreign,'evidence\n',{mode:0o600}); await chmod(foreign,0o600);
  const race=`from pathlib import Path\nfrom durable_create_once import install_create_once\nimport os,sys\np=Path(sys.argv[1]); foreign=sys.argv[2]\ndef hook(point):\n if point=='after-existing-target-validation': os.unlink(p); os.symlink(foreign,p)\ninstall_create_once(p,b'evidence\\n',private_parent=True,allow_equal=True,fault_injection=hook)`;
  const result=spawnSync('/usr/bin/python3',['-c',race,target,foreign],{encoding:'utf8',
    env:{PATH:'/usr/bin:/bin',PYTHONPATH:scripts}});
  assert.notEqual(result.status,0); assert.match(result.stderr,/changed after validation/);
  assert.ok((await lstat(target)).isSymbolicLink());
});
