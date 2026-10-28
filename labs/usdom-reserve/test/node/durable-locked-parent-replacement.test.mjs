import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {createHash} from 'node:crypto';
import {chmod,chown,link,lstat,mkdtemp,readFile,readdir,realpath,rm,stat,symlink,unlink,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {promisify} from 'node:util';
import {durableReplacementFailureExitCode,replaceLockedParentFileDurable as replaceDurable}
  from '../../sdk/durable-locked-parent-replacement.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const execFileAsync=promisify(execFile),metadataInspectorExecutable=await realpath('/usr/bin/python3');
const inspectorAuthority={metadataInspectorExecutable,
  metadataInspectorSha256:sha(await readFile(metadataInspectorExecutable))};
const replaceLockedParentFileDurable=arguments_=>replaceDurable({...inspectorAuthority,...arguments_});
test('CLI exit status distinguishes unapplied rejection from applied state requiring revalidation',()=>{
  assert.equal(durableReplacementFailureExitCode(new Error('rejected before rename')),1);
  assert.equal(durableReplacementFailureExitCode({replacementApplied:true}),80);
});
test('replacement installs authenticated buffered bytes despite candidate pathname mutation',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-replacement-')); await chmod(root,0o700);
  const target=path.join(root,'source.sol'),candidate=path.join(root,'candidate.sol');
  const expected=Buffer.from('expected source\n'),hostile=Buffer.from('hostile source\n');
  await writeFile(target,'old source\n',{mode:0o644}); await writeFile(candidate,expected,{mode:0o600});
  await chmod(target,0o644);
  const identity=await stat(root,{bigint:true}),captured=await readFile(candidate);
  try {
    await replaceLockedParentFileDurable({target,contents:captured,expectedSha256:sha(expected),
      expectedPreviousSha256:sha(Buffer.from('old source\n')),
      expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino),
      faultInjection:async phase=>{if(phase==='after-input-authentication')await writeFile(candidate,hostile);}});
    assert.deepEqual(await readFile(target),expected); assert.deepEqual(await readFile(candidate),hostile);
    await assert.rejects(replaceLockedParentFileDurable({target,contents:hostile,
      expectedSha256:sha(expected),expectedPreviousSha256:sha(expected),
      expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino)}),
    /bytes differ from expected SHA-256/);
    await assert.rejects(replaceLockedParentFileDurable({target,contents:expected,
      expectedSha256:sha(expected),expectedPreviousSha256:sha(expected),expectedParentDevice:String(identity.dev),
      expectedParentInode:String(identity.ino+1n)}),/differs from the locked directory/);
    assert.deepEqual(await readFile(target),expected);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('replacement preserves a private 0600 evidence target when explicitly authorized',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-private-replacement-')); await chmod(root,0o700);
  const target=path.join(root,'evidence.json'),old=Buffer.from('{"old":true}\n');
  const expected=Buffer.from('{"new":true}\n');
  try {
    await writeFile(target,old,{mode:0o600}); await chmod(target,0o600);
    const identity=await stat(root,{bigint:true});
    await replaceLockedParentFileDurable({target,contents:expected,expectedSha256:sha(expected),
      expectedPreviousSha256:sha(old),expectedParentDevice:String(identity.dev),
      expectedParentInode:String(identity.ino),expectedMode:0o600});
    const installed=await stat(target,{bigint:true});
    assert.equal(installed.mode&0o777n,0o600n); assert.deepEqual(await readFile(target),expected);
    await assert.rejects(replaceLockedParentFileDurable({target,contents:old,
      expectedSha256:sha(old),expectedPreviousSha256:sha(Buffer.from('stale\n')),
      expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino),
      expectedMode:0o600}),/unsafe or stale/);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('replacement recovers a dead-process temporary and rejects an unsafe stale alias',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-recovery-')); await chmod(root,0o700);
  const target=path.join(root,'source.sol'),expected=Buffer.from('expected source\n');
  const identity=await stat(root,{bigint:true});
  const stale=path.join(root,'.source.sol.99999999.1.0123456789abcdef01234567.tmp');
  try {
    await writeFile(target,'old\n',{mode:0o644}); await writeFile(stale,'partial',{mode:0o644});
    await chmod(target,0o644); await chmod(stale,0o644);
    await replaceLockedParentFileDurable({target,contents:expected,expectedSha256:sha(expected),
      expectedPreviousSha256:sha(Buffer.from('old\n')),
      expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino)});
    await assert.rejects(lstat(stale),error=>error?.code==='ENOENT');
    const alias=path.join(root,'.source.sol.99999998.1.0123456789abcdef01234567.tmp');
    await symlink('source.sol',alias);
    await assert.rejects(replaceLockedParentFileDurable({target,contents:expected,
      expectedSha256:sha(expected),expectedPreviousSha256:sha(expected),expectedParentDevice:String(identity.dev),
      expectedParentInode:String(identity.ino)}),/stale replacement temporary is unsafe/);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('replacement recovers more than 64 stale files and distinguishes PID reuse',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-pid-reuse-')); await chmod(root,0o700);
  const target=path.join(root,'source.sol'),expected=Buffer.from('expected source\n');
  const identity=await stat(root,{bigint:true});
  try {
    await writeFile(target,'old\n',{mode:0o644}); await chmod(target,0o644);
    for(let index=0;index<65;index++) {
      const nonce=index.toString(16).padStart(24,'0');
      const stale=path.join(root,`.source.sol.${process.pid}.1.${nonce}.tmp`);
      await writeFile(stale,'partial',{mode:0o644}); await chmod(stale,0o644);
    }
    await replaceLockedParentFileDurable({target,contents:expected,expectedSha256:sha(expected),
      expectedPreviousSha256:sha(Buffer.from('old\n')),
      expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino)});
    assert.deepEqual(await readFile(target),expected);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('replacement refuses a genuinely active installer identity',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-active-')); await chmod(root,0o700);
  const target=path.join(root,'source.sol'),expected=Buffer.from('expected source\n');
  const identity=await stat(root,{bigint:true});
  const proc=(await readFile(`/proc/${process.pid}/stat`,'utf8'));
  const ticks=proc.slice(proc.lastIndexOf(')')+2).trim().split(/\s+/)[19];
  const active=path.join(root,`.source.sol.${process.pid}.${ticks}.0123456789abcdef01234567.tmp`);
  try {
    await writeFile(target,'old\n',{mode:0o644}); await writeFile(active,'partial',{mode:0o644});
    await chmod(target,0o644); await chmod(active,0o644);
    await assert.rejects(replaceLockedParentFileDurable({target,contents:expected,
      expectedSha256:sha(expected),expectedPreviousSha256:sha(Buffer.from('old\n')),
      expectedParentDevice:String(identity.dev),
      expectedParentInode:String(identity.ino)}),/active replacement temporary already exists/);
    assert.equal((await readFile(target,'utf8')),'old\n');
  } finally {await rm(root,{recursive:true,force:true});}
});

test('replacement refuses destination symlinks, hardlinks and stale bytes',async()=>{
  for(const variant of ['symlink','hardlink','stale']) {
    const root=await mkdtemp(path.join(tmpdir(),'locked-destination-')); await chmod(root,0o700);
    const target=path.join(root,'source.sol'),other=path.join(root,'other.sol');
    const old=Buffer.from('old\n'),expected=Buffer.from('expected\n');
    try {
      await writeFile(target,old,{mode:0o644}); await chmod(target,0o644);
      if(variant==='symlink') {await writeFile(other,old,{mode:0o644});await unlink(target);await symlink('other.sol',target);}
      if(variant==='hardlink') await link(target,other);
      if(variant==='stale') await writeFile(target,'changed\n');
      const identity=await stat(root,{bigint:true});
      await assert.rejects(replaceLockedParentFileDurable({target,contents:expected,
        expectedSha256:sha(expected),expectedPreviousSha256:sha(old),
        expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino)}),
      /existing replacement target is unsafe|unsafe or stale/);
    } finally {await rm(root,{recursive:true,force:true});}
  }
});

test('retry closes the rename to directory-fsync interruption window',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-rename-crash-')); await chmod(root,0o700);
  const target=path.join(root,'source.sol'),old=Buffer.from('old\n'),expected=Buffer.from('expected\n');
  try {
    await writeFile(target,old,{mode:0o644}); await chmod(target,0o644);
    const identity=await stat(root,{bigint:true}),arguments_={target,contents:expected,
      expectedSha256:sha(expected),expectedPreviousSha256:sha(old),
      expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino)};
    await assert.rejects(replaceLockedParentFileDurable({...arguments_,faultInjection:phase=>{
      if(phase==='after-rename-before-directory-fsync')throw new Error('simulated interruption');
    }}),error=>error?.code==='DURABLE_REPLACEMENT_APPLIED_REQUIRES_REVALIDATION'
      &&error?.replacementApplied===true);
    assert.deepEqual(await readFile(target),expected);
    await replaceLockedParentFileDurable({...arguments_,expectedPreviousSha256:sha(expected)});
    assert.deepEqual(await readFile(target),expected);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('replacement preserves the exact destination owner and group across rename',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-ownership-')); await chmod(root,0o700);
  const target=path.join(root,'source.sol'),old=Buffer.from('old\n'),expected=Buffer.from('expected\n');
  try {
    await writeFile(target,old,{mode:0o644}); await chmod(target,0o644);
    const effectiveGid=process.getegid(),alternateGid=process.getgroups().find(gid=>gid!==effectiveGid);
    assert.notEqual(alternateGid,undefined,'test requires one supplementary group');
    await chown(target,process.geteuid(),alternateGid);
    const before=await stat(target,{bigint:true}),identity=await stat(root,{bigint:true});
    assert.notEqual(before.gid,BigInt(effectiveGid));
    await replaceLockedParentFileDurable({target,contents:expected,expectedSha256:sha(expected),
      expectedPreviousSha256:sha(old),expectedParentDevice:String(identity.dev),
      expectedParentInode:String(identity.ino)});
    const after=await stat(target,{bigint:true});
    assert.equal(after.uid,before.uid); assert.equal(after.gid,before.gid);
    assert.equal(after.mode&0o777n,0o644n); assert.equal(after.nlink,1n);
    assert.deepEqual(await readFile(target),expected);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('replacement rejects ACL, capability or other extended metadata instead of dropping it',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-xattr-')); await chmod(root,0o700);
  const target=path.join(root,'source.sol'),old=Buffer.from('old\n'),expected=Buffer.from('expected\n');
  try {
    await writeFile(target,old,{mode:0o644}); await chmod(target,0o644);
    await execFileAsync(metadataInspectorExecutable,['-I','-S','-E','-c',
      'import os,sys; os.setxattr(sys.argv[1],"user.security-marker",b"present")',target]);
    const identity=await stat(root,{bigint:true});
    await assert.rejects(replaceLockedParentFileDurable({target,contents:expected,
      expectedSha256:sha(expected),expectedPreviousSha256:sha(old),
      expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino)}),
    /unsupported extended attributes/);
    assert.deepEqual(await readFile(target),old);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('replacement detects xattrs injected after temporary fsync and cleans the rejected temporary',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-staged-xattr-')); await chmod(root,0o700);
  const target=path.join(root,'source.sol'),old=Buffer.from('old\n'),expected=Buffer.from('expected\n');
  try {
    await writeFile(target,old,{mode:0o644}); await chmod(target,0o644);
    const identity=await stat(root,{bigint:true});
    await assert.rejects(replaceLockedParentFileDurable({target,contents:expected,
      expectedSha256:sha(expected),expectedPreviousSha256:sha(old),
      expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino),
      faultInjection:async phase=>{
        if(phase!=='after-temporary-fsync') return;
        const names=(await readdir(root))
          .filter(name=>name.startsWith('.source.sol.')&&name.endsWith('.tmp'));
        assert.equal(names.length,1);
        await execFileAsync(metadataInspectorExecutable,['-I','-S','-E','-c',
          'import os,sys; os.setxattr(sys.argv[1],"user.injected-after-fsync",b"present")',
          path.join(root,names[0])]);
      }}),/unsupported extended attributes/);
    assert.deepEqual(await readFile(target),old);
    const remaining=(await readdir(root))
      .filter(name=>name.startsWith('.source.sol.')&&name.endsWith('.tmp'));
    assert.deepEqual(remaining,[]);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('a random temporary-name collision never deletes the pre-existing entry',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-random-collision-')); await chmod(root,0o700);
  const target=path.join(root,'source.sol'),old=Buffer.from('old\n'),expected=Buffer.from('expected\n');
  let collision;
  try {
    await writeFile(target,old,{mode:0o644}); await chmod(target,0o644);
    const identity=await stat(root,{bigint:true});
    await assert.rejects(replaceLockedParentFileDurable({target,contents:expected,
      expectedSha256:sha(expected),expectedPreviousSha256:sha(old),
      expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino),
      faultInjection:async (phase,context)=>{
        if(phase!=='before-temporary-open') return;
        collision=path.join(root,path.basename(context.temporary));
        await writeFile(collision,'owned by another writer\n',{mode:0o644});
      }}),error=>error?.code==='EEXIST');
    assert.deepEqual(await readFile(target),old);
    assert.equal(await readFile(collision,'utf8'),'owned by another writer\n');
  } finally {await rm(root,{recursive:true,force:true});}
});

test('rename CAS rejects destination xattrs injected after the preceding CAS',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-final-cas-xattr-')); await chmod(root,0o700);
  const target=path.join(root,'source.sol'),old=Buffer.from('old\n'),expected=Buffer.from('expected\n');
  try {
    await writeFile(target,old,{mode:0o644}); await chmod(target,0o644);
    const identity=await stat(root,{bigint:true});
    await assert.rejects(replaceLockedParentFileDurable({target,contents:expected,
      expectedSha256:sha(expected),expectedPreviousSha256:sha(old),
      expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino),
      faultInjection:async phase=>{
        if(phase!=='after-final-target-cas') return;
        await execFileAsync(metadataInspectorExecutable,['-I','-S','-E','-c',
          'import os,sys; os.setxattr(sys.argv[1],"user.injected-before-rename",b"present")',target]);
      }}),/existing replacement target changed before rename|unsupported extended attributes/);
    assert.deepEqual(await readFile(target),old);
    assert.deepEqual((await readdir(root)).filter(name=>name.endsWith('.tmp')),[]);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('final parent check rejects permission drift before rename',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-parent-mode-drift-')); await chmod(root,0o700);
  const target=path.join(root,'source.sol'),old=Buffer.from('old\n'),expected=Buffer.from('expected\n');
  try {
    await writeFile(target,old,{mode:0o644}); await chmod(target,0o644);
    const identity=await stat(root,{bigint:true});
    await assert.rejects(replaceLockedParentFileDurable({target,contents:expected,
      expectedSha256:sha(expected),expectedPreviousSha256:sha(old),
      expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino),
      faultInjection:async phase=>{
        if(phase==='before-final-target-cas') await chmod(root,0o777);
      }}),/replacement parent changed during installation/);
    assert.deepEqual(await readFile(target),old);
    assert.deepEqual((await readdir(root)).filter(name=>name.endsWith('.tmp')),[]);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('post-rename checks never report success after parent permission drift',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'locked-post-rename-parent-')); await chmod(root,0o700);
  const target=path.join(root,'source.sol'),old=Buffer.from('old\n'),expected=Buffer.from('expected\n');
  try {
    await writeFile(target,old,{mode:0o644}); await chmod(target,0o644);
    const identity=await stat(root,{bigint:true});
    await assert.rejects(replaceLockedParentFileDurable({target,contents:expected,
      expectedSha256:sha(expected),expectedPreviousSha256:sha(old),
      expectedParentDevice:String(identity.dev),expectedParentInode:String(identity.ino),
      faultInjection:async phase=>{
        if(phase==='after-rename-fsync') await chmod(root,0o777);
      }}),error=>error?.code==='DURABLE_REPLACEMENT_APPLIED_REQUIRES_REVALIDATION'
        &&error?.replacementApplied===true);
    assert.deepEqual(await readFile(target),expected);
    assert.equal((await stat(root)).mode&0o777,0o777);
    assert.deepEqual((await readdir(root)).filter(name=>name.endsWith('.tmp')),[]);
  } finally {await rm(root,{recursive:true,force:true});}
});
