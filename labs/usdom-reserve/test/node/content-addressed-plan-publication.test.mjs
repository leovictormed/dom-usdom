import test from 'node:test';
import assert from 'node:assert/strict';
import {chmod,link,mkdtemp,mkdir,readFile,rm,stat,symlink,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const helper=fileURLToPath(new URL('../../scripts/install-content-addressed-public-plan.py',import.meta.url));
const digest=value=>createHash('sha256').update(value).digest('hex');

test('content-addressed plan publication is idempotent and preserves prior generations',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-plan-publication-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const candidates=path.join(root,'private'),published=path.join(root,'public');
  await mkdir(candidates,{mode:0o700}); await chmod(candidates,0o700);
  await mkdir(published,{mode:0o755}); await chmod(published,0o755);
  const first=Buffer.from('{"schema":"plan","generation":1}\n');
  const second=Buffer.from('{"schema":"plan","generation":2}\n');
  const firstCandidate=path.join(candidates,'first.json');
  const secondCandidate=path.join(candidates,'second.json');
  await writeFile(firstCandidate,first,{mode:0o644}); await chmod(firstCandidate,0o644);
  await writeFile(secondCandidate,second,{mode:0o644}); await chmod(secondCandidate,0o644);
  const publicationIdentity=await stat(published);
  const run=candidate=>spawnSync('/usr/bin/python3',[helper,candidate,published,String(publicationIdentity.dev),String(publicationIdentity.ino)],{encoding:'utf8'});
  const firstRun=run(firstCandidate); assert.equal(firstRun.status,0,firstRun.stderr);
  const firstPath=firstRun.stdout.trim();
  assert.equal(path.basename(firstPath),`open-claims-execution-plan-v1-${digest(first)}.json`);
  const repeated=run(firstCandidate); assert.equal(repeated.status,0,repeated.stderr);
  assert.equal(repeated.stdout.trim(),firstPath);
  const evolved=run(secondCandidate); assert.equal(evolved.status,0,evolved.stderr);
  const secondPath=evolved.stdout.trim(); assert.notEqual(secondPath,firstPath);
  assert.deepEqual(await readFile(firstPath),first);
  assert.deepEqual(await readFile(secondPath),second);
  for(const target of [firstPath,secondPath]) {
    const metadata=await stat(target);
    assert.equal(metadata.mode&0o777,0o644); assert.equal(metadata.nlink,1);
  }
});

test('content-addressed publisher rejects a prepositioned indirect target',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-plan-indirect-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const candidates=path.join(root,'private'),published=path.join(root,'public');
  await mkdir(candidates,{mode:0o700}); await chmod(candidates,0o700);
  await mkdir(published,{mode:0o755}); await chmod(published,0o755);
  const bytes=Buffer.from('{"schema":"plan","generation":3}\n');
  const candidate=path.join(candidates,'candidate.json');
  await writeFile(candidate,bytes,{mode:0o644}); await chmod(candidate,0o644);
  const destination=path.join(published,`open-claims-execution-plan-v1-${digest(bytes)}.json`);
  await symlink(candidate,destination);
  const publicationIdentity=await stat(published);
  const result=spawnSync('/usr/bin/python3',[helper,candidate,published,String(publicationIdentity.dev),String(publicationIdentity.ino)],{encoding:'utf8'});
  assert.notEqual(result.status,0);
  assert.match(result.stderr,/content-addressed plan publication failed/);
});

test('content-addressed publisher rejects a replaced directory inode',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-plan-replaced-directory-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const candidates=path.join(root,'private'),published=path.join(root,'public'),retired=path.join(root,'retired');
  await mkdir(candidates,{mode:0o700}); await chmod(candidates,0o700);
  await mkdir(published,{mode:0o755}); await chmod(published,0o755);
  const expected=await stat(published),bytes=Buffer.from('{"schema":"plan","generation":4}\n'),candidate=path.join(candidates,'candidate.json');
  await writeFile(candidate,bytes,{mode:0o644}); await chmod(candidate,0o644);
  const {rename}=await import('node:fs/promises'); await rename(published,retired); await mkdir(published,{mode:0o755}); await chmod(published,0o755);
  const result=spawnSync('/usr/bin/python3',[helper,candidate,published,String(expected.dev),String(expected.ino)],{encoding:'utf8'});
  assert.notEqual(result.status,0); assert.match(result.stderr,/content-addressed plan publication failed/);
  assert.deepEqual(await readFile(candidate),bytes);
});

for(const fault of ['after-temporary-fsync','after-create-once-link']) test(`content-addressed publisher recovers SIGKILL at ${fault}`,async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-plan-crash-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const candidates=path.join(root,'private'),published=path.join(root,'public');
  await mkdir(candidates,{mode:0o700}); await chmod(candidates,0o700);
  await mkdir(published,{mode:0o755}); await chmod(published,0o755);
  const bytes=Buffer.from(`{"schema":"plan","fault":"${fault}"}\n`),candidate=path.join(candidates,'candidate.json');
  await writeFile(candidate,bytes,{mode:0o644}); await chmod(candidate,0o644);
  const identity=await stat(published),args=[helper,candidate,published,String(identity.dev),String(identity.ino)];
  const killed=spawnSync('/usr/bin/python3',args,{encoding:'utf8',env:{PATH:'/usr/bin:/bin',USDOM_TEST_PLAN_INSTALL_FAULT:fault}});
  assert.equal(killed.signal,'SIGKILL');
  const recovered=spawnSync('/usr/bin/python3',args,{encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  assert.equal(recovered.status,0,recovered.stderr);
  const destination=path.join(published,`open-claims-execution-plan-v1-${digest(bytes)}.json`);
  assert.deepEqual(await readFile(destination),bytes); assert.equal((await stat(destination)).nlink,1);
  const directoryEntries=await (await import('node:fs/promises')).readdir(published);
  assert.deepEqual(directoryEntries.filter(value=>value.endsWith('.tmp')),[]);
});

test('content-addressed publisher rejects an arbitrary temporary hardlink',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-plan-hardlink-temp-')); t.after(()=>rm(root,{recursive:true,force:true}));
  const candidates=path.join(root,'private'),published=path.join(root,'public'); await mkdir(candidates,{mode:0o700}); await chmod(candidates,0o700); await mkdir(published,{mode:0o755}); await chmod(published,0o755);
  const candidate=path.join(candidates,'candidate.json'),foreign=path.join(published,'foreign'); await writeFile(candidate,'{"candidate":true}\n',{mode:0o644}); await chmod(candidate,0o644); await writeFile(foreign,'{"foreign":true}\n',{mode:0o644}); await chmod(foreign,0o644);
  await link(foreign,path.join(published,'.open-claims-execution-plan-v1-2147483647.0123456789abcdef01234567.tmp'));
  const identity=await stat(published),result=spawnSync('/usr/bin/python3',[helper,candidate,published,String(identity.dev),String(identity.ino)],{encoding:'utf8'});
  assert.notEqual(result.status,0); assert.match(result.stderr,/temporary hardlink/);
});
