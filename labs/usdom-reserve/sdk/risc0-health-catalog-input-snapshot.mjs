import {chmod,mkdtemp,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {readDirectFile} from './direct-project-file.mjs';
import {writePrivateFileDurableNew} from './durable-private-file.mjs';

const MAXIMUM=4*1024*1024;
const KEYS=Object.freeze(['catalog','evidence']);

function validatePaths(paths) {
  if(!paths||typeof paths!=='object'||Array.isArray(paths)
      ||JSON.stringify(Object.keys(paths).sort())!==JSON.stringify([...KEYS].sort())
      ||KEYS.some(key=>typeof paths[key]!=='string'||!path.isAbsolute(paths[key]))) {
    throw new Error('RISC Zero health catalog snapshot paths must match the fixed absolute catalog');
  }
}

async function directRead(target,label) {
  return readDirectFile(target,{minimum:2,maximum:MAXIMUM,label});
}

/** Capture the catalog and release-evidence inputs in one owner-only replica. */
export async function captureRiscZeroHealthCatalogInputs(paths,{beforeOriginRecheck}={}) {
  validatePaths(paths);
  if(beforeOriginRecheck!==undefined&&typeof beforeOriginRecheck!=='function') {
    throw new Error('beforeOriginRecheck must be a function');
  }
  const captured=await Promise.all(KEYS.map(key=>directRead(paths[key],`RISC Zero health ${key}`)));
  const replica=await mkdtemp(path.join(os.tmpdir(),'usdom-risc0-health-catalog.'));
  await chmod(replica,0o700);
  try {
    await Promise.all(KEYS.map((key,index)=>writePrivateFileDurableNew(
      path.join(replica,`${key}.json`),captured[index],{maximum:MAXIMUM},
    )));
    const values=Object.fromEntries(await Promise.all(KEYS.map(async key=>[
      key,await readDirectFile(path.join(replica,`${key}.json`),{
        minimum:2,maximum:MAXIMUM,exactMode:0o600,label:`snapshot ${key}`,
      }),
    ])));
    const assertOriginsUnchanged=async()=>{
      if(beforeOriginRecheck) await beforeOriginRecheck();
      const current=await Promise.all(KEYS.map(key=>directRead(paths[key],`current ${key}`)));
      if(current.some((bytes,index)=>!bytes.equals(captured[index]))) {
        throw new Error('RISC Zero health catalog inputs changed during materialization');
      }
    };
    return Object.freeze({...values,assertOriginsUnchanged,
      cleanup:()=>rm(replica,{recursive:true,force:true})});
  } catch(error) { await rm(replica,{recursive:true,force:true}); throw error; }
}
