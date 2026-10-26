import {
  closeSync,constants,fstatSync,lstatSync,openSync,readSync,realpathSync,
} from 'node:fs';
import path from 'node:path';
import {parseStrictJson} from './strict-json.mjs';

const liveSecretObjects=new Set();
process.once('exit',()=>{ for(const value of liveSecretObjects) clearRuntimeSecretJson(value); });

function reject(message) { throw new Error(message); }

/**
 * Read credential-bearing runtime JSON through an owner-only file whose path,
 * and only whose path, is carried in the environment.
 *
 * The former value variable is rejected explicitly so an old service unit
 * cannot appear to work while continuing to expose provider credentials.
 */
export function readRuntimeSecretJsonFile(secretVariable,{label,maxBytes,maxDepth=8}) {
  const fileVariable=`${secretVariable}_FILE`;
  if(Object.hasOwn(process.env,secretVariable)) {
    reject(`${secretVariable} is forbidden; provide ${fileVariable}`);
  }
  const file=process.env[fileVariable];
  delete process.env[fileVariable];
  if(typeof file!=='string'||!path.isAbsolute(file)||file.length>4096) {
    reject(`${fileVariable} must name a direct absolute owner-only file`);
  }
  let canonical;
  try { canonical=realpathSync(file); }
  catch { reject(`${label} file is unavailable`); }
  if(canonical!==file) reject(`${label} file path must not traverse symbolic links`);
  const parent=path.dirname(file);
  const parentMetadata=lstatSync(parent);
  if(!parentMetadata.isDirectory()||parentMetadata.isSymbolicLink()
      ||parentMetadata.uid!==process.geteuid()||(parentMetadata.mode&0o077)!==0
      ||realpathSync(parent)!==parent) {
    reject(`${label} parent directory must be direct and owner-only`);
  }
  const namedBefore=lstatSync(file);
  if(!namedBefore.isFile()||namedBefore.isSymbolicLink()||namedBefore.uid!==process.geteuid()
      ||(namedBefore.mode&0o777)!==0o600||namedBefore.nlink!==1
      ||namedBefore.size<1||namedBefore.size>maxBytes) {
    reject(`${label} file must be a current-user 0600 single-link bounded file`);
  }
  const descriptor=openSync(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
  let bytes;
  let verification;
  try {
    const openedBefore=fstatSync(descriptor);
    if(openedBefore.dev!==namedBefore.dev||openedBefore.ino!==namedBefore.ino) {
      reject(`${label} file changed while opening`);
    }
    bytes=Buffer.alloc(maxBytes+1);
    let length=0;
    while(length<=maxBytes) {
      const count=readSync(descriptor,bytes,length,maxBytes+1-length,length);
      if(count===0) break;
      length+=count;
    }
    if(length<1||length>maxBytes) reject(`${label} file exceeds its byte bounds`);
    bytes=bytes.subarray(0,length);
    const openedAfter=fstatSync(descriptor);
    const namedAfter=lstatSync(file);
    if(openedAfter.dev!==openedBefore.dev||openedAfter.ino!==openedBefore.ino
        ||openedAfter.size!==openedBefore.size||openedAfter.mtimeMs!==openedBefore.mtimeMs
        ||namedAfter.dev!==openedBefore.dev||namedAfter.ino!==openedBefore.ino
        ||namedAfter.uid!==process.geteuid()||(namedAfter.mode&0o777)!==0o600
        ||namedAfter.nlink!==1) {
      reject(`${label} file changed during capture`);
    }
    verification=Buffer.alloc(length+1);
    let verifiedLength=0;
    while(verifiedLength<=length) {
      const count=readSync(descriptor,verification,verifiedLength,
        length+1-verifiedLength,verifiedLength);
      if(count===0) break;
      verifiedLength+=count;
    }
    if(verifiedLength!==length||!verification.subarray(0,length).equals(bytes)) {
      reject(`${label} file was not stable across capture`);
    }
    let text;
    try { text=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
    catch { reject(`${label} file is not valid UTF-8`); }
    bytes.fill(0);
    const parsed=parseStrictJson(text,{label,maxBytes,maxDepth});
    liveSecretObjects.add(parsed);
    return parsed;
  } finally {
    if(bytes) bytes.fill(0);
    if(verification) verification.fill(0);
    closeSync(descriptor);
  }
}

/** Best-effort removal of parsed secret strings once a synchronous consumer is done. */
export function clearRuntimeSecretJson(value) {
  liveSecretObjects.delete(value);
  if(Array.isArray(value)) {
    for(let index=0;index<value.length;index++) {
      const item=value[index]; clearRuntimeSecretJson(item);
      if(typeof item==='string') value[index]='';
    }
  } else if(value&&typeof value==='object') {
    for(const key of Object.keys(value)) {
      const item=value[key]; clearRuntimeSecretJson(item);
      if(typeof item==='string') value[key]='';
    }
  }
}
