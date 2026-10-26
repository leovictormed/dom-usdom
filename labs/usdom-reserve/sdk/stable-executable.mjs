import {constants} from 'node:fs';
import {access,open,realpath} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const MAX_EXECUTABLE_BYTES=512*1024*1024;
function same(left,right) {
  return left.dev===right.dev&&left.ino===right.ino&&left.size===right.size
    &&left.mtimeNs===right.mtimeNs&&left.ctimeNs===right.ctimeNs;
}
function safeOwner(statValue) {
  const current=typeof process.getuid==='function'?BigInt(process.getuid()):statValue.uid;
  return statValue.uid===0n||statValue.uid===current;
}

function sameDirectory(left,right) {
  return left.dev===right.dev&&left.ino===right.ino&&left.uid===right.uid
    &&left.mode===right.mode&&left.mtimeNs===right.mtimeNs&&left.ctimeNs===right.ctimeNs;
}

async function readPinnedExecutable(resolved,name,expected=null) {
  const directoryPath=path.dirname(resolved),basename=path.basename(resolved);
  let directoryHandle,fileHandle;
  try {
    directoryHandle=await open(directoryPath,
      constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
    const directoryBefore=await directoryHandle.stat({bigint:true});
    const descriptorDirectory=`/proc/self/fd/${directoryHandle.fd}`;
    if(!directoryBefore.isDirectory()||!safeOwner(directoryBefore)
        ||(directoryBefore.mode&0o022n)!==0n
        ||await realpath(descriptorDirectory)!==directoryPath) {
      throw new Error(`${name} is not installed in a safely owned immutable directory`);
    }
    fileHandle=await open(path.join(descriptorDirectory,basename),
      constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
    const before=await fileHandle.stat({bigint:true});
    if(!before.isFile()||before.nlink!==1n||!safeOwner(before)||(before.mode&0o022n)!==0n
        ||before.size<1n||before.size>BigInt(MAX_EXECUTABLE_BYTES)
        ||await realpath(`/proc/self/fd/${fileHandle.fd}`)!==resolved) {
      throw new Error(`${name} is not a safely owned immutable executable`);
    }
    const bytes=await fileHandle.readFile(),after=await fileHandle.stat({bigint:true});
    const directoryAfter=await directoryHandle.stat({bigint:true});
    let namedDirectory;
    try {
      namedDirectory=await open(directoryPath,
        constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
      const namedAfter=await namedDirectory.stat({bigint:true});
      if(!same(before,after)||BigInt(bytes.length)!==before.size
          ||!sameDirectory(directoryBefore,directoryAfter)
          ||!sameDirectory(directoryBefore,namedAfter)
          ||await realpath(`/proc/self/fd/${namedDirectory.fd}`)!==directoryPath) {
        throw new Error(`${name} changed while hashed`);
      }
    } finally { await namedDirectory?.close(); }
    if(expected&&(!same(expected.stat,before)||!sameDirectory(expected.directoryStat,directoryBefore)
        ||sha(bytes)!==expected.sha256)) throw new Error('build executable changed during materialization');
    return {bytes,stat:before,directoryStat:directoryBefore};
  } catch(error) {
    if(error?.code==='ELOOP') throw new Error(`${name} is not a safely owned immutable executable`);
    throw error;
  } finally {
    await fileHandle?.close();
    await directoryHandle?.close();
  }
}

export async function snapshotExecutable(name,{pathValue=process.env.PATH}={}) {
  if(typeof name!=='string'||!/^[A-Za-z0-9._+-]+$/.test(name)) throw new Error('executable name is invalid');
  let resolved=null;
  for(const directory of String(pathValue??'').split(path.delimiter)) {
    if(!path.isAbsolute(directory)) continue;
    const candidate=path.join(directory,name);
    try { await access(candidate,constants.X_OK); resolved=await realpath(candidate); break; }
    catch { /* continue */ }
  }
  if(!resolved) throw new Error(`${name} is unavailable through absolute PATH entries`);
  return snapshotResolvedExecutable(resolved,name);
}

async function snapshotResolvedExecutable(resolved,name) {
  const {bytes,stat,directoryStat}=await readPinnedExecutable(resolved,name);
  return Object.freeze({path:resolved,sha256:sha(bytes),stat,directoryStat});
}

export async function snapshotExecutablePath(target) {
  if(typeof target!=='string'||!path.isAbsolute(target)) {
    throw new Error('executable path must be absolute');
  }
  await access(target,constants.X_OK);
  return snapshotResolvedExecutable(await realpath(target),target);
}

export async function assertExecutableUnchanged(snapshot) {
  if(!snapshot||typeof snapshot.path!=='string'||typeof snapshot.sha256!=='string') {
    throw new Error('executable snapshot is invalid');
  }
  await readPinnedExecutable(snapshot.path,snapshot.path,snapshot);
  return true;
}
