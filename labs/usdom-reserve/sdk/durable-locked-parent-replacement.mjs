import {createHash,randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {constants,renameSync} from 'node:fs';
import {lstat,open,readFile,readdir,realpath,rm,unlink} from 'node:fs/promises';
import path from 'node:path';

const sha256=value=>createHash('sha256').update(value).digest('hex');
const escapeRegex=value=>value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
export class DurableReplacementAppliedError extends Error {
  constructor() {
    super('replacement was applied but its terminal postcondition was not verified');
    this.name='DurableReplacementAppliedError';
    this.code='DURABLE_REPLACEMENT_APPLIED_REQUIRES_REVALIDATION';
    this.replacementApplied=true;
  }
}
export const durableReplacementFailureExitCode=error=>error?.replacementApplied===true?80:1;
async function processStartTicks(pid) {
  let stat;
  try {stat=await readFile(`/proc/${pid}/stat`,'utf8');}
  catch(error) {if(error?.code==='ENOENT')return null;throw error;}
  const close=stat.lastIndexOf(')');
  if(close<0) throw new Error('process identity record is malformed');
  const fields=stat.slice(close+2).trim().split(/\s+/),ticks=fields[19];
  if(!/^[1-9][0-9]*$/.test(ticks??'')) throw new Error('process identity record is malformed');
  return ticks;
}
async function recoverTemporaries(directory,descriptorParent,basename,expectedUid,expectedMode) {
  const pattern=new RegExp(`^\\.${escapeRegex(basename)}\\.([1-9][0-9]*)\\.([1-9][0-9]*)\\.([0-9a-f]{24})\\.tmp$`);
  const matches=(await readdir(descriptorParent)).filter(name=>pattern.test(name)).sort();
  if(matches.length>4096) throw new Error('replacement temporary namespace is unbounded');
  let removed=false;
  for(const name of matches) {
    const match=pattern.exec(name),pid=Number(match[1]),startTicks=match[2];
    if(!Number.isSafeInteger(pid)||pid<1) throw new Error('replacement temporary identity is invalid');
    if(await processStartTicks(pid)===startTicks) {
      throw new Error('active replacement temporary already exists');
    }
    const temporary=path.join(descriptorParent,name),metadata=await lstat(temporary,{bigint:true});
    if(!metadata.isFile()||metadata.isSymbolicLink()||metadata.nlink!==1n
        ||metadata.uid!==expectedUid||(metadata.mode&0o777n)!==BigInt(expectedMode)
        ||metadata.size>BigInt(4*1024*1024)) {
      throw new Error('stale replacement temporary is unsafe');
    }
    await unlink(temporary); removed=true;
  }
  if(removed) await directory.sync();
}
async function openExistingTarget(descriptorParent,basename,expectedUid,expectedSha256,expectedMode) {
  let handle;
  try {handle=await open(path.join(descriptorParent,basename),constants.O_RDONLY|constants.O_NOFOLLOW);}
  catch(error) {
    if(error?.code==='ELOOP'||error?.code==='ENOENT'||error?.code==='EISDIR') {
      throw new Error('existing replacement target is unsafe');
    }
    throw error;
  }
  try {
    const metadata=await handle.stat({bigint:true}),contents=await handle.readFile();
    if(!metadata.isFile()||metadata.isSymbolicLink()||metadata.uid!==expectedUid
        ||metadata.nlink!==1n||(metadata.mode&0o777n)!==BigInt(expectedMode)
        ||sha256(contents)!==expectedSha256) throw new Error('existing replacement target is unsafe or stale');
    return {handle,snapshot:{dev:metadata.dev,ino:metadata.ino,uid:metadata.uid,gid:metadata.gid,
      size:metadata.size,mtimeNs:metadata.mtimeNs,ctimeNs:metadata.ctimeNs}};
  } catch(error) {await handle.close();throw error;}
}
function sameTarget(left,right) {
  return ['dev','ino','uid','gid','size','mtimeNs','ctimeNs'].every(field=>left[field]===right[field]);
}
async function requireStableParent(directory,parent,before) {
  const named=await open(parent,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
  try {
    const current=await named.stat({bigint:true}),held=await directory.stat({bigint:true});
    for(const metadata of [current,held]) {
      if(!metadata.isDirectory()||metadata.dev!==before.dev||metadata.ino!==before.ino
          ||metadata.uid!==before.uid||metadata.gid!==before.gid||metadata.mode!==before.mode) {
        throw new Error('replacement parent changed during installation');
      }
    }
    if(await realpath(`/proc/self/fd/${named.fd}`)!==parent
        ||await realpath(`/proc/self/fd/${directory.fd}`)!==parent) {
      throw new Error('replacement parent changed during installation');
    }
  } finally {await named.close();}
}
async function rejectExtendedAttributes(handle,inspector) {
  const program=[
    'import errno,os,sys',
    'if not hasattr(os,"listxattr"): sys.exit(74)',
    'try: attributes=os.listxattr(4)',
    'except OSError as error:',
    '  if error.errno in (errno.ENOSYS,errno.ENOTSUP,getattr(errno,"EOPNOTSUPP",errno.ENOTSUP)): sys.exit(74)',
    '  raise',
    'sys.exit(73 if attributes else 0)',
  ].join('\n');
  await new Promise((resolve,reject)=>{
    const child=spawn(`/proc/self/fd/${inspector.fd}`,
      ['-I','-S','-E','-c',program],
      {stdio:['ignore','ignore','ignore',inspector.fd,handle.fd],env:{PATH:'/usr/bin:/bin'},cwd:'/'});
    child.once('error',reject);
    child.once('exit',(code,signal)=>{
      if(signal!==null) reject(new Error('extended-attribute inspector was interrupted'));
      else if(code===73) reject(new Error('replacement target has unsupported extended attributes'));
      else if(code===74) reject(new Error('extended-attribute inspection is unavailable'));
      else if(code!==0) reject(new Error('extended-attribute inspection failed'));
      else resolve();
    });
  });
}

/** Replace one public file atomically inside the exact directory inode already
 * locked by the caller. Bytes are authenticated before any temporary exists. */
export async function replaceLockedParentFileDurable({target,contents,expectedSha256,
  expectedPreviousSha256,expectedParentDevice,expectedParentInode,metadataInspectorExecutable,
  metadataInspectorSha256,expectedMode=0o644,faultInjection=null}={}) {
  const bytes=Buffer.isBuffer(contents)?contents:Buffer.from(contents??'');
  if(bytes.length<1||bytes.length>4*1024*1024||!/^[0-9a-f]{64}$/.test(expectedSha256??'')
      ||sha256(bytes)!==expectedSha256) throw new Error('replacement bytes differ from expected SHA-256');
  if(!/^[0-9a-f]{64}$/.test(expectedPreviousSha256??'')) {
    throw new Error('previous replacement SHA-256 is invalid');
  }
  if(!/^[1-9][0-9]*$/.test(String(expectedParentDevice??''))
      ||!/^[1-9][0-9]*$/.test(String(expectedParentInode??''))) {
    throw new Error('locked parent identity is invalid');
  }
  if(expectedMode!==0o600&&expectedMode!==0o644) {
    throw new Error('replacement target mode is invalid');
  }
  if(faultInjection!==null&&typeof faultInjection!=='function') throw new Error('fault injection is invalid');
  if(typeof metadataInspectorExecutable!=='string'||!path.isAbsolute(metadataInspectorExecutable)
      ||!/^[0-9a-f]{64}$/.test(metadataInspectorSha256??'')) {
    throw new Error('extended-attribute inspector authority is invalid');
  }
  const absolute=path.resolve(target),parent=path.dirname(absolute),basename=path.basename(absolute);
  let directory,file,inspector,previousFile,temporary,temporaryOwned=false,replacementApplied=false;
  const expectedUid=typeof process.geteuid==='function'?BigInt(process.geteuid()):
    typeof process.getuid==='function'?BigInt(process.getuid()):null;
  try {
    directory=await open(parent,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
    inspector=await open(metadataInspectorExecutable,constants.O_RDONLY|constants.O_NOFOLLOW);
    const inspectorMetadata=await inspector.stat({bigint:true}),inspectorBytes=await inspector.readFile();
    if(!inspectorMetadata.isFile()||inspectorMetadata.isSymbolicLink()||inspectorMetadata.nlink!==1n
        ||(inspectorMetadata.uid!==0n&&(expectedUid===null||inspectorMetadata.uid!==expectedUid))
        ||(inspectorMetadata.mode&0o022n)!==0n||sha256(inspectorBytes)!==metadataInspectorSha256) {
      throw new Error('extended-attribute inspector differs from its authority');
    }
    const before=await directory.stat({bigint:true});
    if(!before.isDirectory()||String(before.dev)!==String(expectedParentDevice)
        ||String(before.ino)!==String(expectedParentInode)
        ||(expectedUid!==null&&before.uid!==expectedUid)||(before.mode&0o022n)!==0n
        ||await realpath(`/proc/self/fd/${directory.fd}`)!==parent) {
      throw new Error('replacement parent differs from the locked directory');
    }
    await faultInjection?.('after-input-authentication');
    const descriptorParent=`/proc/self/fd/${directory.fd}`;
    await recoverTemporaries(directory,descriptorParent,basename,expectedUid??before.uid,expectedMode);
    const previousTarget=await openExistingTarget(descriptorParent,basename,expectedUid??before.uid,
      expectedPreviousSha256,expectedMode);
    previousFile=previousTarget.handle; const previous=previousTarget.snapshot;
    await faultInjection?.('before-existing-xattr-inspection');
    await rejectExtendedAttributes(previousFile,inspector);
    await faultInjection?.('after-existing-xattr-inspection');
    const startTicks=await processStartTicks(process.pid);
    if(startTicks===null) throw new Error('installer process identity disappeared');
    temporary=path.join(descriptorParent,
      `.${basename}.${process.pid}.${startTicks}.${randomBytes(12).toString('hex')}.tmp`);
    await faultInjection?.('before-temporary-open',{temporary});
    file=await open(temporary,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,
      expectedMode);
    temporaryOwned=true;
    const temporaryMetadata=await file.stat({bigint:true});
    if(temporaryMetadata.uid!==previous.uid||temporaryMetadata.gid!==previous.gid) {
      await file.chown(Number(previous.uid),Number(previous.gid));
    }
    await file.chmod(expectedMode); await rejectExtendedAttributes(file,inspector);
    await file.writeFile(bytes); await file.sync(); await rejectExtendedAttributes(file,inspector);
    await file.close(); file=null;
    await faultInjection?.('after-temporary-fsync');
    const staged=await open(temporary,constants.O_RDONLY|constants.O_NOFOLLOW);
    try {
      const metadata=await staged.stat({bigint:true}),stored=await staged.readFile();
      if(!metadata.isFile()||metadata.isSymbolicLink()||metadata.nlink!==1n
          ||metadata.uid!==previous.uid||metadata.gid!==previous.gid
          ||(metadata.mode&0o777n)!==BigInt(expectedMode)
          ||stored.length!==bytes.length||!stored.equals(bytes)||sha256(stored)!==expectedSha256) {
        throw new Error('replacement temporary changed before rename');
      }
      await rejectExtendedAttributes(staged,inspector);
    } finally {await staged.close();}
    await requireStableParent(directory,parent,before);
    await faultInjection?.('before-final-target-cas');
    await requireStableParent(directory,parent,before);
    const currentTarget=await openExistingTarget(descriptorParent,basename,expectedUid??before.uid,
      expectedPreviousSha256,expectedMode);
    try {
      if(!sameTarget(previous,currentTarget.snapshot)) {
        throw new Error('existing replacement target changed before rename');
      }
      await rejectExtendedAttributes(currentTarget.handle,inspector);
      await faultInjection?.('after-final-target-cas');
      const renameTarget=await openExistingTarget(descriptorParent,basename,expectedUid??before.uid,
        expectedPreviousSha256,expectedMode);
      try {
        if(!sameTarget(previous,renameTarget.snapshot)) {
          throw new Error('existing replacement target changed before rename');
        }
        await rejectExtendedAttributes(renameTarget.handle,inspector);
        // Keep both authenticated target descriptors live and avoid another
        // event-loop turn between the last CAS and the overwrite syscall.
        renameSync(temporary,path.join(descriptorParent,basename)); temporary=null; temporaryOwned=false;
        replacementApplied=true;
      } finally {await renameTarget.handle.close();}
    } finally {await currentTarget.handle.close();}
    await faultInjection?.('after-rename-before-directory-fsync');
    await requireStableParent(directory,parent,before);
    await directory.sync(); await faultInjection?.('after-rename-fsync');
    await requireStableParent(directory,parent,before);
    const installed=await open(path.join(descriptorParent,basename),constants.O_RDONLY|constants.O_NOFOLLOW);
    try {
      const metadata=await installed.stat({bigint:true}),stored=await installed.readFile();
      if(!metadata.isFile()||metadata.isSymbolicLink()||metadata.nlink!==1n
          ||metadata.uid!==previous.uid||metadata.gid!==previous.gid
          ||(metadata.mode&0o777n)!==BigInt(expectedMode)
          ||stored.length!==bytes.length||!stored.equals(bytes)||sha256(stored)!==expectedSha256) {
        throw new Error('installed replacement failed its postcondition');
      }
      await rejectExtendedAttributes(installed,inspector);
    } finally {await installed.close();}
    await requireStableParent(directory,parent,before);
  } catch(error) {
    if(replacementApplied) throw new DurableReplacementAppliedError();
    throw error;
  } finally {
    await file?.close(); if(temporary&&temporaryOwned) await rm(temporary,{force:true});
    await previousFile?.close(); await inspector?.close(); await directory?.close();
  }
}
