import {randomBytes} from 'node:crypto';
import {constants} from 'node:fs';
import {link,lstat,open,readdir,realpath,rename,rm,unlink} from 'node:fs/promises';
import path from 'node:path';
import {readDirectFile} from './direct-project-file.mjs';

const DEFAULT_MAXIMUM_BYTES=16*1024*1024;
const MAXIMUM_RECOVERABLE_TEMPORARIES=64;

function regexEscape(value) { return value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'); }
function processIsAlive(pid) {
  try { process.kill(pid,0); return true; }
  catch(error) { if(error?.code==='ESRCH') return false; throw error; }
}

async function recoverDurableTemporaries(directoryHandle,descriptorDirectory,basename,{expectedUid,mode,maximum}) {
  const pattern=new RegExp(`^\\.${regexEscape(basename)}\\.([1-9][0-9]*)\\.([0-9a-f]{24})\\.tmp$`);
  const matches=(await readdir(descriptorDirectory)).filter(name=>pattern.test(name)).sort();
  if(matches.length>MAXIMUM_RECOVERABLE_TEMPORARIES) throw new Error('too many durable temporary files');
  let changed=false;
  for(const name of matches) {
    const pid=Number(pattern.exec(name)[1]);
    if(!Number.isSafeInteger(pid)||pid<1||processIsAlive(pid)) continue;
    const temporaryPath=path.join(descriptorDirectory,name),metadata=await lstat(temporaryPath,{bigint:true});
    if(!metadata.isFile()||metadata.isSymbolicLink()||metadata.uid!==expectedUid
        ||(metadata.mode&0o777n)!==BigInt(mode)||metadata.size<1n||metadata.size>BigInt(maximum)
        ||(metadata.nlink!==1n&&metadata.nlink!==2n)) throw new Error('durable temporary file is unsafe');
    if(metadata.nlink===2n) {
      let target;
      try { target=await lstat(path.join(descriptorDirectory,basename),{bigint:true}); }
      catch(error) { if(error?.code==='ENOENT') throw new Error('durable temporary hardlink has no target'); throw error; }
      if(!target.isFile()||target.isSymbolicLink()||target.dev!==metadata.dev||target.ino!==metadata.ino
          ||target.nlink!==2n||target.uid!==expectedUid||(target.mode&0o777n)!==BigInt(mode)) {
        throw new Error('durable temporary hardlink is not the create-once target');
      }
    }
    await unlink(temporaryPath); changed=true;
  }
  if(changed) await directoryHandle.sync();
}

export async function writeFileDurable(target,content,{
  maximum=DEFAULT_MAXIMUM_BYTES,mode=0o600,replace=true,privateParent=false,faultInjection=null,
}={}) {
  if(typeof target!=='string'||target.length===0) throw new Error('durable target path is required');
  if(!Number.isSafeInteger(maximum)||maximum<1) throw new Error('invalid durable file size limit');
  if(!Number.isSafeInteger(mode)||mode<0||mode>0o777||(mode&0o600)!==0o600
      ||(mode&0o022)!==0||(mode&0o111)!==0) throw new Error('invalid durable file mode');
  if(typeof replace!=='boolean') throw new Error('invalid durable replace policy');
  if(typeof privateParent!=='boolean') throw new Error('invalid durable parent policy');
  if(faultInjection!==null&&typeof faultInjection!=='function') throw new Error('invalid durable fault injection');
  const bytes=Buffer.isBuffer(content)?content:Buffer.from(content);
  if(bytes.length<1||bytes.length>maximum) throw new Error('durable file content exceeds its size bound');
  const absolute=path.resolve(target),directory=path.dirname(absolute),basename=path.basename(absolute);
  let directoryHandle,file,temporary,stored,temporaryCreated=false;
  try {
    try {
      directoryHandle=await open(directory,
        constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
    } catch(error) {
      if(error?.code==='ELOOP'||error?.code==='ENOTDIR') {
        throw new Error('durable target directory is unsafe');
      }
      throw error;
    }
    const directoryMetadata=await directoryHandle.stat({bigint:true});
    const expectedUid=typeof process.getuid==='function'?BigInt(process.getuid()):directoryMetadata.uid;
    const descriptorDirectory=`/proc/self/fd/${directoryHandle.fd}`;
    const resolvedDirectory=await realpath(descriptorDirectory);
    if(resolvedDirectory!==directory||!directoryMetadata.isDirectory()
        ||directoryMetadata.uid!==expectedUid||(directoryMetadata.mode&0o022n)!==0n
        ||(privateParent&&(directoryMetadata.mode&0o777n)!==0o700n)) {
      throw new Error('durable target directory is unsafe');
    }
    const targetViaDescriptor=path.join(descriptorDirectory,basename);
    await recoverDurableTemporaries(directoryHandle,descriptorDirectory,basename,{expectedUid,mode,maximum});
    try {
      const existing=await lstat(targetViaDescriptor,{bigint:true});
      if(!existing.isFile()||existing.isSymbolicLink()||existing.uid!==expectedUid
          ||existing.nlink!==1n) throw new Error('durable target is unsafe');
      if(!replace) { faultInjection?.('after-existing-target-validation'); throw new Error('durable target already exists'); }
    } catch(error) {
      if(error?.code!=='ENOENT') throw error;
    }

    temporary=path.join(descriptorDirectory,
      `.${basename}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`);
    file=await open(temporary,
      constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,mode);
    temporaryCreated=true;
    await file.chmod(mode);
    await file.writeFile(bytes);
    await file.sync();
    faultInjection?.('after-temporary-fsync');
    await file.close(); file=null;
    if(replace) {
      await rename(temporary,targetViaDescriptor);
      temporaryCreated=false; temporary=null;
    } else {
      await link(temporary,targetViaDescriptor);
      faultInjection?.('after-create-once-link');
      await unlink(temporary);
      temporaryCreated=false; temporary=null;
    }
    await directoryHandle.sync();
    const [namedDirectory,namedMetadata]=await Promise.all([
      realpath(directory),lstat(directory,{bigint:true}),
    ]);
    if(namedDirectory!==directory||namedMetadata.dev!==directoryMetadata.dev
        ||namedMetadata.ino!==directoryMetadata.ino||namedMetadata.uid!==directoryMetadata.uid
        ||namedMetadata.mode!==directoryMetadata.mode) {
      throw new Error('durable target directory changed during write');
    }
    stored=await readDirectFile(absolute,{
      minimum:bytes.length,maximum:bytes.length,exactMode:mode,label:'durable target',
    });
    if(!stored.equals(bytes)) throw new Error('durable target content mismatch');
  } finally {
    stored?.fill(0);
    await file?.close();
    if(temporaryCreated) await rm(temporary,{force:true});
    await directoryHandle?.close();
  }
}

export async function writePrivateFileDurable(target,content,{maximum=DEFAULT_MAXIMUM_BYTES}={}) {
  return writeFileDurable(target,content,{maximum,mode:0o600,privateParent:true});
}

export async function writePrivateFileDurableNew(target,content,{maximum=DEFAULT_MAXIMUM_BYTES,faultInjection=null}={}) {
  return writeFileDurable(target,content,{maximum,mode:0o600,replace:false,privateParent:true,faultInjection});
}

/** Create one private artifact, or prove that the already-published inode has exact bytes. */
export async function writePrivateFileDurableNewOrEqual(target,content,{
  maximum=DEFAULT_MAXIMUM_BYTES,faultInjection=null,
}={}) {
  const bytes=Buffer.isBuffer(content)?content:Buffer.from(content);
  if(bytes.length<1||bytes.length>maximum) {
    throw new Error('durable file content exceeds its size bound');
  }
  try {
    await writePrivateFileDurableNew(target,bytes,{maximum,faultInjection});
  } catch(error) {
    if(error?.message!=='durable target already exists') throw error;
  }
  let installed;
  try {
    installed=await readDirectFile(target,{
      minimum:1,maximum,privateMode:true,exactMode:0o600,
      label:'immutable durable target',
    });
    if(!installed.equals(bytes)) {
      throw new Error('immutable durable target contains different bytes');
    }
  } finally { installed?.fill(0); }
}

/** Durably invalidate one direct private completion artifact, if present. */
export async function removePrivateFileDurableIfExists(target) {
  if(typeof target!=='string'||target.length===0) throw new Error('durable target path is required');
  const absolute=path.resolve(target),directory=path.dirname(absolute),basename=path.basename(absolute);
  let directoryHandle;
  try {
    directoryHandle=await open(directory,
      constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
    const metadata=await directoryHandle.stat({bigint:true});
    const expectedUid=typeof process.getuid==='function'?BigInt(process.getuid()):metadata.uid;
    const descriptorDirectory=`/proc/self/fd/${directoryHandle.fd}`;
    if(await realpath(descriptorDirectory)!==directory||!metadata.isDirectory()
        ||metadata.uid!==expectedUid||(metadata.mode&0o777n)!==0o700n) {
      throw new Error('durable target directory is unsafe');
    }
    const targetViaDescriptor=path.join(descriptorDirectory,basename);
    try {
      const existing=await lstat(targetViaDescriptor,{bigint:true});
      if(!existing.isFile()||existing.isSymbolicLink()||existing.uid!==expectedUid
          ||existing.nlink!==1n||(existing.mode&0o777n)!==0o600n) {
        throw new Error('durable target is unsafe');
      }
      await unlink(targetViaDescriptor);
      await directoryHandle.sync();
    } catch(error) {
      if(error?.code!=='ENOENT') throw error;
    }
    const [namedDirectory,namedMetadata]=await Promise.all([
      realpath(directory),lstat(directory,{bigint:true}),
    ]);
    if(namedDirectory!==directory||namedMetadata.dev!==metadata.dev
        ||namedMetadata.ino!==metadata.ino||namedMetadata.uid!==metadata.uid
        ||namedMetadata.mode!==metadata.mode) {
      throw new Error('durable target directory changed during removal');
    }
  } finally {
    await directoryHandle?.close();
  }
}

export async function writePrivateJsonDurable(target,value,options) {
  return writePrivateFileDurable(target,`${JSON.stringify(value,null,2)}\n`,options);
}
