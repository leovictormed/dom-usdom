import {chmod,mkdtemp,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {readDirectFile} from './direct-project-file.mjs';
import {writePrivateFileDurableNew} from './durable-private-file.mjs';

const CATALOG=Object.freeze([
  Object.freeze({key:'report',name:'report.json',maximum:16*1024*1024,exactMode:0o600}),
  Object.freeze({key:'release',name:'release.json',maximum:16*1024*1024}),
  Object.freeze({key:'evidence',name:'evidence.json',maximum:16*1024*1024}),
  Object.freeze({key:'requirements',name:'requirements.json',maximum:16*1024*1024}),
  Object.freeze({key:'riscZero',name:'risc-zero.json',maximum:1024*1024}),
]);

function validatePaths(paths) {
  if(!paths || typeof paths!=='object' || Array.isArray(paths)
      || JSON.stringify(Object.keys(paths).sort())!==JSON.stringify(CATALOG.map(x=>x.key).sort())
      || CATALOG.some(entry=>typeof paths[entry.key]!=='string'||!path.isAbsolute(paths[entry.key]))) {
    throw new Error('mainnet preflight snapshot paths must match the fixed absolute catalog');
  }
}

async function readEntry(target,entry,label) {
  return readDirectFile(target,{minimum:2,maximum:entry.maximum,exactMode:entry.exactMode,label});
}

/** Capture every preflight materialization input in one private, fixed catalog. */
export async function captureMainnetPreflightInputs(paths,{beforeOriginRecheck}={}) {
  validatePaths(paths);
  if(beforeOriginRecheck!==undefined&&typeof beforeOriginRecheck!=='function') {
    throw new Error('beforeOriginRecheck must be a function');
  }
  const captured=await Promise.all(CATALOG.map(entry=>readEntry(paths[entry.key],entry,
    `mainnet preflight ${entry.key} input`)));
  const replica=await mkdtemp(path.join(os.tmpdir(),'usdom-mainnet-preflight-inputs.'));
  await chmod(replica,0o700);
  try {
    await Promise.all(CATALOG.map((entry,index)=>writePrivateFileDurableNew(
      path.join(replica,entry.name),captured[index],{maximum:entry.maximum},
    )));
    const values=Object.fromEntries(await Promise.all(CATALOG.map(async entry=>[
      entry.key,await readDirectFile(path.join(replica,entry.name),{
        minimum:2,maximum:entry.maximum,exactMode:0o600,label:`snapshot ${entry.key}`,
      }),
    ])));
    const assertOriginsUnchanged=async()=>{
      if(beforeOriginRecheck) await beforeOriginRecheck();
      const current=await Promise.all(CATALOG.map(entry=>readEntry(paths[entry.key],entry,
        `current mainnet preflight ${entry.key} input`)));
      if(current.some((bytes,index)=>!bytes.equals(captured[index]))) {
        throw new Error('mainnet preflight inputs changed during materialization');
      }
    };
    return Object.freeze({...values,assertOriginsUnchanged,
      cleanup:()=>rm(replica,{recursive:true,force:true})});
  } catch(error) { await rm(replica,{recursive:true,force:true}); throw error; }
}
