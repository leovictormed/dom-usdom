import {chmod,mkdtemp,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {readDirectFile} from './direct-project-file.mjs';
import {writePrivateFileDurableNew} from './durable-private-file.mjs';

const MAXIMUM=4*1024*1024;

async function privateRead(target,label) {
  return readDirectFile(target,{minimum:1,maximum:MAXIMUM,privateMode:true,label});
}

/** Capture and later revalidate one finalized-burn release run completion pair. */
export async function captureFinalizedBurnReleaseRun(runRoot,{beforeOriginRecheck}={}) {
  if(typeof runRoot!=='string' || !path.isAbsolute(runRoot)) {
    throw new Error('release run root must be absolute');
  }
  if(beforeOriginRecheck!==undefined && typeof beforeOriginRecheck!=='function') {
    throw new Error('beforeOriginRecheck must be a function');
  }
  const origins=[
    path.join(runRoot,'run-status.json'),
    path.join(runRoot,'finalized-burn-e2e-report.json'),
  ];
  const retained=[];
  const retainedRead=async(target,label)=>{
    const bytes=await privateRead(target,label); retained.push(bytes); return bytes;
  };
  const clearRetained=()=>{ for(const bytes of retained) bytes.fill(0); };
  let replica;
  try {
    const captured=await Promise.all(origins.map((target,index)=>
      retainedRead(target,index===0?'finalized-burn run status':'finalized-burn E2E report')));
    replica=await mkdtemp(path.join(os.tmpdir(),'usdom-finalized-burn-release-run.'));
    await chmod(replica,0o700);
    const names=['run-status.json','finalized-burn-e2e-report.json'];
    await Promise.all(names.map((name,index)=>writePrivateFileDurableNew(
      path.join(replica,name),captured[index],{maximum:MAXIMUM},
    )));
    const [statusBytes,reportBytes]=await Promise.all(names.map((name,index)=>
      retainedRead(path.join(replica,name),index===0?'snapshot run status':'snapshot E2E report')));
    const assertOriginsUnchanged=async()=>{
      if(beforeOriginRecheck) await beforeOriginRecheck();
      const current=[];
      try {
        await Promise.all(origins.map(async(target,index)=>{
          const bytes=await privateRead(target,index===0?'current run status':'current E2E report');
          current[index]=bytes; return bytes;
        }));
        if(current.some((bytes,index)=>!bytes.equals(captured[index]))) {
          throw new Error('finalized-burn release run changed during materialization');
        }
      } finally { for(const bytes of current) bytes?.fill(0); }
    };
    return Object.freeze({statusBytes,reportBytes,assertOriginsUnchanged,
      cleanup:async()=>{ clearRetained(); await rm(replica,{recursive:true,force:true}); }});
  } catch(error) {
    clearRetained();
    if(replica) await rm(replica,{recursive:true,force:true});
    throw error;
  }
}
