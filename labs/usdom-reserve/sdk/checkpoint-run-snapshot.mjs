import {createHash} from 'node:crypto';
import {chmod,mkdtemp,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {readDirectFile} from './direct-project-file.mjs';
import {writePrivateFileDurableNew} from './durable-private-file.mjs';

const MAXIMUM=4*1024*1024;
const sha256=value=>createHash('sha256').update(value).digest('hex');
const privateRead=(target,label)=>readDirectFile(target,{
  minimum:1,maximum:MAXIMUM,privateMode:true,label,
});

/** Capture and later revalidate one checkpoint-capacity completion pair. */
export async function captureCheckpointCapacityRun(runRoot,{beforeOriginRecheck}={}) {
  if(typeof runRoot!=='string' || !path.isAbsolute(runRoot)) {
    throw new Error('checkpoint run root must be absolute');
  }
  if(beforeOriginRecheck!==undefined && typeof beforeOriginRecheck!=='function') {
    throw new Error('beforeOriginRecheck must be a function');
  }
  const names=['run-status.json','capacity-report.json'];
  const origins=names.map(name=>path.join(runRoot,name));
  const retained=[];
  const retainedRead=async(target,label)=>{
    const bytes=await privateRead(target,label); retained.push(bytes); return bytes;
  };
  const clearRetained=()=>{ for(const bytes of retained) bytes.fill(0); };
  let replica;
  try {
    const captured=await Promise.all(origins.map((target,index)=>retainedRead(target,
      index===0?'checkpoint run status':'checkpoint capacity report')));
    const hashes=captured.map(sha256);
    replica=await mkdtemp(path.join(os.tmpdir(),'usdom-checkpoint-capacity-run.'));
    await chmod(replica,0o700);
    await Promise.all(names.map((name,index)=>writePrivateFileDurableNew(
      path.join(replica,name),captured[index],{maximum:MAXIMUM},
    )));
    const installed=await Promise.all(names.map((name,index)=>retainedRead(path.join(replica,name),
      index===0?'snapshot checkpoint status':'snapshot checkpoint report')));
    if(installed.some((bytes,index)=>!bytes.equals(captured[index])
        || sha256(bytes)!==hashes[index])) {
      throw new Error('checkpoint capacity run replica differs after installation');
    }
    const assertOriginsUnchanged=async()=>{
      if(beforeOriginRecheck) await beforeOriginRecheck();
      const current=[];
      try {
        await Promise.all(origins.map(async(target,index)=>{
          const bytes=await privateRead(target,
            index===0?'current checkpoint status':'current checkpoint report');
          current[index]=bytes; return bytes;
        }));
        if(current.some((bytes,index)=>!bytes.equals(captured[index])
            || sha256(bytes)!==hashes[index])) {
          throw new Error('checkpoint capacity run changed during materialization');
        }
      } finally { for(const bytes of current) bytes?.fill(0); }
    };
    return Object.freeze({statusBytes:installed[0],reportBytes:installed[1],hashes,
      assertOriginsUnchanged,
      cleanup:async()=>{ clearRetained(); await rm(replica,{recursive:true,force:true}); }});
  } catch(error) {
    clearRetained();
    if(replica) await rm(replica,{recursive:true,force:true});
    throw error;
  }
}
