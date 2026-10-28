import {constants} from 'node:fs';
import {open,realpath} from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_MAXIMUM_BYTES=512*1024*1024;

function sameFile(before,after) {
  return before.dev===after.dev&&before.ino===after.ino&&before.size===after.size
    &&before.mtimeNs===after.mtimeNs&&before.ctimeNs===after.ctimeNs;
}

function sameDirectory(before,after) {
  return before.dev===after.dev&&before.ino===after.ino&&before.uid===after.uid
    &&before.mode===after.mode;
}

export async function readDirectFile(target,{minimum=0,maximum=DEFAULT_MAXIMUM_BYTES,
  privateMode=false,exactMode=null,label='file'}={}) {
  if(typeof target!=='string'||target.length===0) throw new Error(`${label} path is required`);
  if(!Number.isSafeInteger(minimum)||minimum<0||!Number.isSafeInteger(maximum)
      ||maximum<minimum) throw new Error(`invalid ${label} size limit`);
  if(exactMode!==null&&(!Number.isSafeInteger(exactMode)||exactMode<0||exactMode>0o777)) {
    throw new Error(`invalid ${label} mode`);
  }
  if(privateMode&&exactMode!==null&&exactMode!==0o600) throw new Error(`invalid ${label} mode`);
  const absolute=path.resolve(target);
  let directoryHandle,directoryBefore,handle;
  try {
    const directory=path.dirname(absolute),basename=path.basename(absolute);
    directoryHandle=await open(directory,
      constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
    directoryBefore=await directoryHandle.stat({bigint:true});
    const directoryUid=typeof process.getuid==='function'?BigInt(process.getuid()):directoryBefore.uid;
    const descriptorDirectory=`/proc/self/fd/${directoryHandle.fd}`;
    if(!directoryBefore.isDirectory()||directoryBefore.uid!==directoryUid
        ||(directoryBefore.mode&0o022n)!==0n
        ||(privateMode&&(directoryBefore.mode&0o777n)!==0o700n)
        ||await realpath(descriptorDirectory)!==directory) {
      throw new Error(`${label} parent is not a safe direct directory`);
    }
    handle=await open(path.join(descriptorDirectory,basename),
      constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    const directoryBeforeRead=await directoryHandle.stat({bigint:true});
    const namedDirectory=await open(directory,
      constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
    try {
      const namedAfter=await namedDirectory.stat({bigint:true});
      if(!sameDirectory(directoryBefore,directoryBeforeRead)
          ||!sameDirectory(directoryBefore,namedAfter)
          ||await realpath(`/proc/self/fd/${namedDirectory.fd}`)!==directory) {
        throw new Error(`${label} parent changed before read`);
      }
    } finally {
      await namedDirectory.close();
    }
    const before=await handle.stat({bigint:true});
    const expectedUid=typeof process.getuid==='function'?BigInt(process.getuid()):before.uid;
    if(!before.isFile()||before.nlink!==1n||before.uid!==expectedUid
        ||before.size<BigInt(minimum)||before.size>BigInt(maximum)
        ||(before.mode&0o022n)!==0n
        ||(privateMode&&(before.mode&0o777n)!==0o600n)
        ||(exactMode!==null&&(before.mode&0o777n)!==BigInt(exactMode))) {
      throw new Error(`${label} is not a safe direct regular file`);
    }
    // Resolve the already-open descriptor. This binds the path check to the inode
    // that is read instead of checking a pathname that could be swapped afterward.
    const openedPath=await realpath(`/proc/self/fd/${handle.fd}`);
    if(openedPath!==absolute) throw new Error(`${label} is not a safe direct regular file`);
    const bytes=await handle.readFile();
    const after=await handle.stat({bigint:true});
    if(BigInt(bytes.length)!==before.size||!sameFile(before,after)) {
      throw new Error(`${label} changed while it was read`);
    }
    const directoryAfter=await directoryHandle.stat({bigint:true});
    const namedDirectoryAfter=await open(directory,
      constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
    try {
      const namedAfter=await namedDirectoryAfter.stat({bigint:true});
      if(!sameDirectory(directoryBefore,directoryAfter)
          ||!sameDirectory(directoryBefore,namedAfter)
          ||await realpath(`/proc/self/fd/${namedDirectoryAfter.fd}`)!==directory) {
        throw new Error(`${label} parent changed while it was read`);
      }
    } finally {
      await namedDirectoryAfter.close();
    }
    return bytes;
  } catch(error) {
    // Linux may report an O_NOFOLLOW directory boundary as ELOOP when the
    // final component is a symlink, or ENOTDIR when path resolution encounters
    // a symlinked/non-directory intermediate component.  Expose one stable,
    // fail-closed boundary instead of leaking filesystem-dependent errno.
    if(error?.code==='ELOOP'||error?.code==='ENOTDIR') {
      throw new Error(`${label} is not a safe direct regular file`);
    }
    throw error;
  } finally {
    await handle?.close();
    await directoryHandle?.close();
  }
}

export async function readDirectProjectFile(root,relative,{minimum=0,maximum=DEFAULT_MAXIMUM_BYTES,
  privateMode=false,exactMode=null,label='release path'}={}) {
  if(typeof relative!=='string') throw new Error('release path is not a string');
  const projectRoot=path.resolve(root);
  let rootHandle;
  try {
    rootHandle=await open(projectRoot,
      constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
    const rootBefore=await rootHandle.stat({bigint:true});
    const expectedUid=typeof process.getuid==='function'?BigInt(process.getuid()):rootBefore.uid;
    if(!rootBefore.isDirectory()||rootBefore.uid!==expectedUid
        ||(rootBefore.mode&0o022n)!==0n
        ||await realpath(`/proc/self/fd/${rootHandle.fd}`)!==projectRoot) {
      throw new Error('project root is not a safe direct directory');
    }
    const absolute=path.resolve(projectRoot,relative);
    if(absolute===projectRoot || !absolute.startsWith(projectRoot+path.sep)) {
      throw new Error('release path escapes project root');
    }
    const bytes=await readDirectFile(absolute,{minimum,maximum,privateMode,exactMode,label});
    const rootAfter=await rootHandle.stat({bigint:true});
    const namedRoot=await open(projectRoot,
      constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
    try {
      const namedAfter=await namedRoot.stat({bigint:true});
      if(!sameDirectory(rootBefore,rootAfter)||!sameDirectory(rootBefore,namedAfter)
          ||await realpath(`/proc/self/fd/${namedRoot.fd}`)!==projectRoot) {
        throw new Error('project root changed while release file was read');
      }
    } finally {
      await namedRoot.close();
    }
    return bytes;
  } catch(error) {
    if(error?.code==='ELOOP'||error?.code==='ENOTDIR') {
      throw new Error('project root is not a safe direct directory');
    }
    throw error;
  } finally {
    await rootHandle?.close();
  }
}
