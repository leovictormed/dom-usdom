import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,symlink,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {readDirectProjectFile} from '../../sdk/direct-project-file.mjs';

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
  await assert.rejects(readDirectProjectFile(root,'config'),/direct regular file/);
  await assert.rejects(readDirectProjectFile(root,'.'),/escapes project root/);
  await assert.rejects(readDirectProjectFile(root,'../outside.json'),/escapes project root/);
  await assert.rejects(readDirectProjectFile(root,null),/not a string/);
});
