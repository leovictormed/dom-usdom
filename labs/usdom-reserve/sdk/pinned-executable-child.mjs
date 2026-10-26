import {spawn} from 'node:child_process';
import {assertExecutableUnchanged} from './stable-executable.mjs';

function childError(message,{stdout=Buffer.alloc(0),stderr=Buffer.alloc(0),code=null,signal=null}={}) {
  const error=new Error(message); error.stdout=stdout; error.stderr=stderr;
  error.code=code; error.signal=signal; return error;
}

export async function runPinnedExecutable(snapshot,args,{cwd,maxBuffer,timeout,env}={}) {
  if(!Array.isArray(args) || !Number.isSafeInteger(maxBuffer) || maxBuffer<1
      || !Number.isSafeInteger(timeout) || timeout<1) {
    throw new Error('pinned child bounds are invalid');
  }
  await assertExecutableUnchanged(snapshot);
  let child;
  try {
    child=spawn(snapshot.path,args,{cwd,env,detached:true,stdio:['ignore','pipe','pipe']});
    const stdout=[],stderr=[]; let stdoutLength=0,stderrLength=0,reason=null,killTimer;
    const killGroup=signal=>{ try { process.kill(-child.pid,signal); } catch(error) {
      if(error?.code!=='ESRCH') throw error;
    }};
    const terminate=message=>{
      if(reason) return; reason=message; killGroup('SIGTERM');
      killTimer=setTimeout(()=>killGroup('SIGKILL'),2000); killTimer.unref();
    };
    child.stdout.on('data',chunk=>{
      stdoutLength+=chunk.length;
      if(stdoutLength>maxBuffer) terminate('pinned child stdout exceeded its bound');
      else stdout.push(Buffer.from(chunk));
    });
    child.stderr.on('data',chunk=>{
      stderrLength+=chunk.length;
      if(stderrLength>maxBuffer) terminate('pinned child stderr exceeded its bound');
      else stderr.push(Buffer.from(chunk));
    });
    const deadline=setTimeout(()=>terminate('pinned child timed out'),timeout); deadline.unref();
    const result=await new Promise((resolve,reject)=>{
      child.once('error',reject);
      child.once('close',(code,signal)=>resolve({code,signal}));
    });
    clearTimeout(deadline); if(killTimer) clearTimeout(killTimer);
    const output={stdout:Buffer.concat(stdout,stdoutLength<=maxBuffer?stdoutLength:undefined),
      stderr:Buffer.concat(stderr,stderrLength<=maxBuffer?stderrLength:undefined),...result};
    if(reason) throw childError(reason,output);
    if(result.code!==0) throw childError(`pinned child exited with ${result.signal??result.code}`,output);
    return {stdout:output.stdout,stderr:output.stderr};
  } finally {
    if(child?.pid) { try { process.kill(-child.pid,'SIGKILL'); } catch(error) {
      if(error?.code!=='ESRCH') throw error;
    }}
    await assertExecutableUnchanged(snapshot);
  }
}
