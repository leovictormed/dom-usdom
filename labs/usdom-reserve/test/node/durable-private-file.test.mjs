import test from 'node:test';
import assert from 'node:assert/strict';
import {chmod,link,lstat,mkdtemp,mkdir,readFile,rm,symlink,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {
  writeFileDurable,writePrivateFileDurable,writePrivateJsonDurable,
  removePrivateFileDurableIfExists,writePrivateFileDurableNew,
} from '../../sdk/durable-private-file.mjs';

const component=path.resolve(import.meta.dirname,'../..');

test('durable writer pins the parent inode for create and rename',async()=>{
  const source=await readFile(path.join(component,'sdk/durable-private-file.mjs'),'utf8');
  assert.match(source,/constants\.O_RDONLY\|constants\.O_DIRECTORY\|constants\.O_NOFOLLOW/);
  assert.match(source,/`\/proc\/self\/fd\/\$\{directoryHandle\.fd\}`/);
  assert.match(source,/rename\(temporary,targetViaDescriptor\)/);
  assert.match(source,/link\(temporary,targetViaDescriptor\)/);
  assert.match(source,/unlink\(temporary\)/);
  assert.match(source,/namedMetadata\.ino!==directoryMetadata\.ino/);
  assert.doesNotMatch(source,/rename\(temporary,absolute\)/);
});

test('durable private writes are exact, owner-only and reject indirect targets',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-durable-private-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const target=path.join(root,'status.json');
  await writePrivateJsonDurable(target,{status:'running'});
  assert.equal(await readFile(target,'utf8'),'{\n  "status": "running"\n}\n');
  assert.equal((await lstat(target)).mode&0o777,0o600);
  await writePrivateFileDurable(target,'completed\n');
  assert.equal(await readFile(target,'utf8'),'completed\n');
  await assert.rejects(writePrivateFileDurable(target,'',{maximum:16}),/size bound/);
  await assert.rejects(writePrivateFileDurable(target,'too large',{maximum:2}),/size bound/);
  const immutableTarget=path.join(root,'immutable.json');
  await writePrivateFileDurableNew(immutableTarget,'first\n');
  await assert.rejects(writePrivateFileDurableNew(immutableTarget,'second\n'),/already exists/);
  assert.equal(await readFile(immutableTarget,'utf8'),'first\n');

  const linkedTarget=path.join(root,'linked-target');
  await symlink(target,linkedTarget);
  await assert.rejects(writePrivateFileDurable(linkedTarget,'blocked\n'),/target is unsafe/);
  const realDirectory=path.join(root,'real');
  const linkedDirectory=path.join(root,'linked-directory');
  await mkdir(realDirectory);
  await symlink(realDirectory,linkedDirectory);
  await assert.rejects(writePrivateFileDurable(path.join(linkedDirectory,'blocked'),'blocked\n'),
    /directory is unsafe/);

  const publicTarget=path.join(root,'release.json');
  await writeFileDurable(publicTarget,'{}\n',{mode:0o644});
  assert.equal((await lstat(publicTarget)).mode&0o777,0o644);
  await assert.rejects(writeFileDurable(publicTarget,'{}\n',{mode:0o666}),/invalid durable file mode/);
  const unsafeDirectory=path.join(root,'unsafe-directory');
  await mkdir(unsafeDirectory);
  await chmod(unsafeDirectory,0o770);
  await assert.rejects(writeFileDurable(path.join(unsafeDirectory,'blocked'),'blocked\n'),
    /directory is unsafe/);

  const listableDirectory=path.join(root,'listable-private-parent');
  await mkdir(listableDirectory,{mode:0o755});
  await chmod(listableDirectory,0o755);
  await assert.rejects(
    writePrivateFileDurable(path.join(listableDirectory,'credential'),'secret\n'),
    /directory is unsafe/,
  );
  await writeFileDurable(path.join(listableDirectory,'public-evidence'),'public\n',{mode:0o644});
});

test('immutable private installer is idempotent and never replaces an inode',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-immutable-private-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const installer=path.join(component,'scripts','install-private-file-immutable-stdin.mjs');
  const target=path.join(root,'artifact.json');
  const run=input=>spawnSync(process.execPath,[installer,target],{input,encoding:'utf8'});
  assert.equal(run('{"release":1}\n').status,0);
  assert.equal(run('{"release":1}\n').status,0);
  const different=run('{"release":2}\n');
  assert.notEqual(different.status,0);
  assert.match(different.stderr,/contains different bytes/);
  assert.equal(await readFile(target,'utf8'),'{"release":1}\n');
  const indirect=path.join(root,'indirect.json');
  await symlink(target,indirect);
  const indirectRun=spawnSync(process.execPath,[installer,indirect],{
    input:'{"release":1}\n',encoding:'utf8',
  });
  assert.notEqual(indirectRun.status,0);
  assert.match(indirectRun.stderr,/safe direct regular file/);
  const hardlink=path.join(root,'hardlink.json');
  await link(target,hardlink);
  const hardlinkRun=run('{"release":1}\n');
  assert.notEqual(hardlinkRun.status,0);
  assert.match(hardlinkRun.stderr,/safe direct regular file/);
});

test('durable private invalidation is idempotent and rejects indirect completion artifacts',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-durable-removal-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const target=path.join(root,'submission.json');
  await writePrivateFileDurableNew(target,'old generation\n');
  await removePrivateFileDurableIfExists(target);
  await assert.rejects(lstat(target),{code:'ENOENT'});
  await removePrivateFileDurableIfExists(target);
  await writePrivateFileDurableNew(target,'new generation\n');
  const linked=path.join(root,'linked.json');
  await symlink(target,linked);
  await assert.rejects(removePrivateFileDurableIfExists(linked),/target is unsafe/);
  assert.equal(await readFile(target,'utf8'),'new generation\n');
});

test('release-config reader requires one direct exact-mode inode',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-release-config-reader-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const reader=path.join(component,'scripts','read-release-config-file-stdout.mjs');
  const target=path.join(root,'release.json');
  await writeFile(target,'{"release":1}\n',{mode:0o644});
  await chmod(target,0o644);
  const run=file=>spawnSync(process.execPath,[reader,file],{encoding:'utf8'});
  const direct=run(target);
  assert.equal(direct.status,0,direct.stderr);
  assert.equal(direct.stdout,'{"release":1}\n');
  await chmod(target,0o600);
  assert.notEqual(run(target).status,0);
  await chmod(target,0o644);
  const indirect=path.join(root,'indirect.json');
  await symlink(target,indirect);
  assert.notEqual(run(indirect).status,0);
  const hardlink=path.join(root,'hardlink.json');
  await link(target,hardlink);
  assert.notEqual(run(target).status,0);
});

test('private reader pins an exact owner-only parent and rejects listable or indirect parents',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-private-reader-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const reader=path.join(component,'scripts','read-private-file-stdout.mjs');
  const target=path.join(root,'credential');
  await writeFile(target,'secret-bytes',{mode:0o600});
  await chmod(target,0o600);
  const run=file=>spawnSync(process.execPath,[reader,file],{encoding:'utf8'});
  const direct=run(target);
  assert.equal(direct.status,0,direct.stderr);
  assert.equal(direct.stdout,'secret-bytes');

  await chmod(root,0o755);
  const listable=run(target);
  assert.notEqual(listable.status,0);
  assert.match(listable.stderr,/parent is not a safe direct directory/);
  await chmod(root,0o700);

  const parent=path.dirname(root),linked=path.join(parent,`${path.basename(root)}-linked`);
  await symlink(root,linked);
  assert.notEqual(run(path.join(linked,'credential')).status,0);
});

test('public authority reader pins a non-writable direct parent without requiring 0700',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-public-reader-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const reader=path.join(component,'scripts','read-release-config-file-stdout.mjs');
  const target=path.join(root,'manifest.json');
  await writeFile(target,'{"version":1}\n',{mode:0o644});
  await chmod(target,0o644);
  await chmod(root,0o755);
  const run=file=>spawnSync(process.execPath,[reader,file],{encoding:'utf8'});
  const published=run(target);
  assert.equal(published.status,0,published.stderr);
  assert.equal(published.stdout,'{"version":1}\n');

  await chmod(root,0o775);
  assert.notEqual(run(target).status,0);
  await chmod(root,0o755);
  const linked=`${root}-linked`;
  await symlink(root,linked);
  assert.notEqual(run(path.join(linked,'manifest.json')).status,0);
});

test('private child-directory setup pins its 0700 root and never follows a symlink',async t=>{
  const parent=await mkdtemp(path.join(tmpdir(),'usdom-private-directory-'));
  t.after(()=>rm(parent,{recursive:true,force:true}));
  const helper=path.join(component,'scripts','ensure-private-child-directory.py');
  const root=path.join(parent,'authority');
  await mkdir(root,{mode:0o700});
  await chmod(root,0o700);
  const run=name=>spawnSync('python3',[helper,root,name],{encoding:'utf8'});
  const created=run('wallet');
  assert.equal(created.status,0,created.stderr);
  assert.equal((await lstat(path.join(root,'wallet'))).mode&0o777,0o700);
  assert.equal(run('wallet').status,0);

  const target=path.join(root,'target');
  await mkdir(target,{mode:0o750});
  await chmod(target,0o750);
  await symlink(target,path.join(root,'linked'));
  const linked=run('linked');
  assert.notEqual(linked.status,0);
  assert.equal((await lstat(target)).mode&0o777,0o750);

  await chmod(root,0o770);
  const unsafe=run('blocked');
  assert.notEqual(unsafe.status,0);
  assert.equal(await lstat(path.join(root,'blocked')).then(()=>true,()=>false),false);
});

test('submission and finalized-deposit writers use the fsynced private boundary',async()=>{
  const scripts=[
    'prepare-authenticated-checkpoint-submission.mjs',
    'prepare-authenticated-finalized-burn-submission.mjs',
    'observe-authenticated-checkpoint.mjs',
    'collect-finalized-deposit-source.mjs',
  ];
  for(const script of scripts) {
    const source=await readFile(path.join(component,'scripts',script),'utf8');
    const writer=/writePrivateFileDurable(?:New)?\(outputPath,/;
    assert.match(source,writer,
      `${script} bypasses the durable writer`);
    assert.doesNotMatch(source,/\brename\s*\(|\bwriteFile\s*\(/,
      `${script} reintroduced a non-durable writer`);
  }
  const depositCollector=await readFile(
    path.join(component,'scripts/collect-finalized-deposit-source.mjs'),'utf8');
  assert.match(depositCollector,/removePrivateFileDurableIfExists\(outputPath\)/);
  const invalidation=depositCollector.indexOf('await prepareOutput();');
  const input=depositCollector.indexOf('const runtimeSourceBytes=await boundedStdin',invalidation);
  const firstRpc=depositCollector.indexOf("await rpc(execution,'eth_chainId'",input);
  assert.ok(invalidation>=0&&input>invalidation&&firstRpc>input);
  assert.match(depositCollector,/return readDirectFile\(file,\{minimum:1,maximum,label\}\)/);
  assert.match(depositCollector,/mkdir\(directory,\{mode:0o700\}\)/);
  assert.match(depositCollector,/parseStrictJsonBytes\(runtimeSourceBytes/);
  assert.match(depositCollector,/parseStrictJsonBytes\(catalogBytes/);
  assert.match(depositCollector,/parseStrictJsonBytes\(releaseBytes/);
  assert.match(depositCollector,/parseStrictJsonBytes\(manifestBytes/);
  assert.match(depositCollector,/decodeUtf8\(transactionBytes,'deposit transaction hash'\)/);
  assert.match(depositCollector,/transactionText!==`\$\{txHash\}\\n`/);
});
