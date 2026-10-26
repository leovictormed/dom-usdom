import test from 'node:test';
import assert from 'node:assert/strict';
import {chmod,link,mkdtemp,mkdir,symlink,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {readDirectFile,readDirectProjectFile} from '../../sdk/direct-project-file.mjs';

test('release files must be direct regular files below the exact project root',async t=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-direct-file-'));
  t.after(async()=>{
    const {rm}=await import('node:fs/promises');
    await rm(root,{recursive:true,force:true});
  });
  const config=path.join(root,'config');
  await mkdir(config);
  await writeFile(path.join(config,'release.json'),'{}\n');
  assert.equal((await readDirectProjectFile(root,'config/release.json')).toString(),'{}\n');

  await symlink(path.join(config,'release.json'),path.join(config,'linked.json'));
  await assert.rejects(readDirectProjectFile(root,'config/linked.json'),/direct regular file/);
  await link(path.join(config,'release.json'),path.join(config,'hard-linked.json'));
  await assert.rejects(readDirectProjectFile(root,'config/release.json'),/direct regular file/);
  await assert.rejects(readDirectProjectFile(root,'config/hard-linked.json'),/direct regular file/);
  await writeFile(path.join(config,'single.json'),'{}\n');
  await symlink(config,path.join(root,'linked-config'));
  await assert.rejects(readDirectProjectFile(root,'linked-config/single.json'),/direct regular file/);
  await assert.rejects(readDirectProjectFile(root,'config/single.json',{maximum:2}),/size limit|direct regular file/);
  await writeFile(path.join(config,'private.json'),'{}\n',{mode:0o600});
  assert.equal((await readDirectFile(path.join(config,'private.json'),{
    minimum:1,maximum:16,privateMode:true,label:'private input'})).toString(),'{}\n');
  assert.equal((await readDirectProjectFile(root,'config/private.json',{
    minimum:1,maximum:16,privateMode:true,label:'private release input'})).toString(),'{}\n');
  await writeFile(path.join(config,'public.json'),'{}\n',{mode:0o644});
  await chmod(path.join(config,'public.json'),0o644);
  assert.equal((await readDirectFile(path.join(config,'public.json'),{
    exactMode:0o644,label:'public input'})).toString(),'{}\n');
  await chmod(path.join(config,'public.json'),0o664);
  await assert.rejects(readDirectFile(path.join(config,'public.json'),{
    label:'group-writable release input'}),/safe direct regular file/);
  await chmod(path.join(config,'public.json'),0o644);
  await assert.rejects(readDirectFile(path.join(config,'public.json'),{
    exactMode:0o600,label:'public input'}),/safe direct regular file/);
  await assert.rejects(readDirectFile(path.join(config,'public.json'),{
    exactMode:0o1000,label:'public input'}),/invalid public input mode/);
  await assert.rejects(readDirectFile(path.join(config,'public.json'),{
    privateMode:true,label:'private input'}),/safe direct regular file/);
  await assert.rejects(readDirectProjectFile(root,'config/public.json',{
    privateMode:true,label:'private release input'}),/safe direct regular file/);
  await assert.rejects(readDirectProjectFile(root,'config'),/direct regular file/);
  await assert.rejects(readDirectProjectFile(root,'.'),/escapes project root/);
  await assert.rejects(readDirectProjectFile(root,'../outside.json'),/escapes project root/);
  await assert.rejects(readDirectProjectFile(root,null),/not a string/);

  await chmod(root,0o770);
  await assert.rejects(readDirectProjectFile(root,'config/single.json'),
    /project root is not a safe direct directory/);
  await chmod(root,0o700);
  assert.equal((await readDirectProjectFile(root,'config/single.json')).toString(),'{}\n');
});
